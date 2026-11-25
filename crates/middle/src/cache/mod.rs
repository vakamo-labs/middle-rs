//! A token cache that a background task keeps fresh.
//!
//! [`TokenCache::start`] requests the first token and spawns the refresh task. After that, only the task requests tokens.
//! Readers take the current token from a [`watch`] channel: a read never waits for a request and needs no runtime.
//! The task builds each value before it sends it, so the lock of the channel is held only to swap values, and that lock ignores poisoning.
//! The task sleeps until the refresh point on the monotonic clock. A reader wakes it when it finds no usable token, or when the wall clock has passed
//! the refresh point, as after the machine slept; [`TokenCache::invalidate`] wakes it for a rejected token. The task then requests a token,
//! at the earliest one second after the last one, unless it waits after a failure.
//!
//! If the server rejects tokens before their refresh point again and again, each further rejection in a row waits longer before the next request,
//! counted from the request of the rejected token. A rejection counts only while that wait still lies ahead, so a token that lasted longer than
//! the wait starts a new series. A token that reaches its refresh point ends the series.
//!
//! The task owns the only [`watch::Sender`]. When the task ends, because its runtime shut down or the last handle aborted it,
//! the channel closes, and readers know that no refresh will come. The task also ends when every reader is gone.
//! Each request runs in a task of its own, so a panic in a request does not end the refresh task.

mod lifetime;
mod schedule;

use std::{
    fmt,
    future::{Future, poll_fn},
    pin::{Pin, pin},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::Poll,
    time::{Duration, SystemTime},
};

use http::HeaderValue;
use tokio::{
    sync::{Notify, watch},
    task::JoinHandle,
    time::Instant,
};
use tracing::Instrument as _;

use crate::{
    error::{DisplayChain, Error},
    token_endpoint::{MAX_EXPIRES_IN, TokenResponse},
};

/// The shortest timeout of one request, and the shortest wait after a failed one, while the old token is still valid.
const MIN_HALF_TIME_LEFT: Duration = Duration::from_secs(1);

/// The id of the next cache, unique in the process.
static NEXT_CACHE_ID: AtomicU64 = AtomicU64::new(1);

/// Identifies one token: the cache that holds it and its generation there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TokenId {
    cache: u64,
    generation: u64,
}

/// A boxed future, so that [`TokenSource`] can be used as a trait object.
pub(crate) type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Where the cache gets its tokens from, such as a token endpoint with one grant.
pub(crate) trait TokenSource: fmt::Debug + Send + Sync + 'static {
    /// Requests one token. The cache runs the request in a task of its own, bounds it with a timeout and retries failures.
    fn fetch(&self) -> BoxFuture<'_, Result<TokenResponse, Error>>;
}

/// How the cache requests and refreshes tokens.
#[derive(Debug, Clone)]
pub(crate) struct CacheConfig {
    /// Names the client in log messages.
    pub(crate) client_id: String,
    /// The longest time one request may take. [`TokenCache::start`] and [`TokenCache::wait`] take at most this long too.
    pub(crate) timeout: Duration,
    /// How long before expiry a refresh comes at the latest.
    pub(crate) tolerance: Duration,
    /// The lifetime of a token whose answer has no `expires_in`, unless the access token is a JWT with an `exp` in the future.
    pub(crate) default_lifetime: Duration,
    /// How often [`TokenCache::start`] retries the first request after an error a retry can fix.
    pub(crate) first_token_retries: u32,
    /// Whether a task refreshes the token.
    pub(crate) refresh: bool,
    /// The wall clock: [`SystemTime::now`], or a clock that tests move.
    pub(crate) wall_clock: fn() -> SystemTime,
}

impl CacheConfig {
    /// Durations of at most one year, so that adding them to an instant cannot overflow.
    fn capped(mut self) -> Self {
        self.timeout = self.timeout.min(MAX_EXPIRES_IN);
        self.tolerance = self.tolerance.min(MAX_EXPIRES_IN);
        self.default_lifetime = self.default_lifetime.min(MAX_EXPIRES_IN);
        self
    }
}

/// A token, with what the cache needs to know about its validity.
#[derive(Clone, veil::Redact)]
pub(crate) struct Token {
    #[redact]
    header: Arc<HeaderValue>,
    /// The header as tonic metadata, built once so that the interceptor only clones it.
    #[cfg(feature = "tonic")]
    #[redact]
    metadata: tonic::metadata::MetadataValue<tonic::metadata::Ascii>,
    /// The cache, and the generation that counts its tokens from 1.
    id: TokenId,
    /// When the request for this token was sent.
    requested_at: Instant,
    /// The expiry on the monotonic clock.
    expires_at: Instant,
    /// The expiry on the wall clock, `None` if the wall clock cannot represent it.
    expires_at_wall: Option<SystemTime>,
    /// When the refresh is due on the monotonic clock.
    refresh_at: Instant,
    /// When the refresh is due on the wall clock, `None` if the wall clock cannot represent it.
    refresh_at_wall: Option<SystemTime>,
}

impl Token {
    /// A token that lives `lifetime` from its request. `lifetime` is at most one year.
    fn new(
        response: &TokenResponse,
        id: TokenId,
        requested_at: (Instant, SystemTime),
        lifetime: Duration,
        tolerance: Duration,
    ) -> Result<Self, Error> {
        let built = crate::authorizers::bearer_header(response.access_token.as_str())?;
        let (requested_at, requested_at_wall) = requested_at;
        let refresh_delay = schedule::refresh_delay(lifetime, tolerance, schedule::random());
        Ok(Self {
            header: built.header,
            #[cfg(feature = "tonic")]
            metadata: built.metadata,
            id,
            requested_at,
            expires_at: requested_at + lifetime,
            expires_at_wall: requested_at_wall.checked_add(lifetime),
            refresh_at: requested_at + refresh_delay,
            refresh_at_wall: requested_at_wall.checked_add(refresh_delay),
        })
    }

    pub(crate) fn header(&self) -> &Arc<HeaderValue> {
        &self.header
    }

    #[cfg(feature = "tonic")]
    pub(crate) fn metadata(&self) -> &tonic::metadata::MetadataValue<tonic::metadata::Ascii> {
        &self.metadata
    }

    pub(crate) fn id(&self) -> TokenId {
        self.id
    }

    #[cfg(test)]
    fn generation(&self) -> u64 {
        self.id.generation
    }

    fn is_usable(&self, shared: &Shared) -> bool {
        self.is_usable_at(shared, Instant::now(), (shared.wall_clock)())
    }

    fn is_usable_at(&self, shared: &Shared, now: Instant, now_wall: SystemTime) -> bool {
        !self.is_invalidated(shared) && !self.is_expired_at(now, now_wall)
    }

    fn is_invalidated(&self, shared: &Shared) -> bool {
        self.id.generation <= shared.invalidated.load(Ordering::Acquire)
    }

    /// Whether either clock has passed the refresh point.
    fn is_due_at(&self, now: Instant, now_wall: SystemTime) -> bool {
        now >= self.refresh_at || self.is_due_by_wall_clock(now_wall)
    }

    /// Whether the wall clock has passed the refresh point. The refresh task sleeps on the monotonic clock, so after the machine slept, a reader wakes it.
    fn is_due_by_wall_clock(&self, now_wall: SystemTime) -> bool {
        self.refresh_at_wall.is_some_and(|due| now_wall >= due)
    }

    /// A token has expired when either clock says so: on some systems the monotonic clock stops while the machine sleeps, and the wall clock can jump.
    fn is_expired_at(&self, now: Instant, now_wall: SystemTime) -> bool {
        now >= self.expires_at
            || self
                .expires_at_wall
                .is_some_and(|expiry| now_wall >= expiry)
    }
}

/// What readers and the refresh task share besides the channel.
#[derive(Debug)]
struct Shared {
    /// Wakes the refresh task while it waits for the refresh point: a reader that finds no usable token, a token due by the wall clock, or an invalidation.
    wake: Notify,
    /// The newest invalidated generation. Tokens of this generation and older are not used.
    invalidated: AtomicU64,
    wall_clock: fn() -> SystemTime,
    /// How often the refresh task was woken.
    #[cfg(test)]
    wakes: std::sync::atomic::AtomicUsize,
}

impl Shared {
    fn new(wall_clock: fn() -> SystemTime) -> Self {
        Self {
            wake: Notify::new(),
            invalidated: AtomicU64::new(0),
            wall_clock,
            #[cfg(test)]
            wakes: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn wake_task(&self) {
        #[cfg(test)]
        self.wakes.fetch_add(1, Ordering::Relaxed);
        self.wake.notify_one();
    }
}

/// The value of the channel.
#[derive(Debug)]
struct State {
    /// The newest token, kept after it expired.
    token: Token,
    /// The error of the last request, until a request succeeds.
    error: Option<Error>,
    /// When the next request starts, while the task waits after a failure or a fresh rejection.
    retry_at: Option<Instant>,
}

impl State {
    fn new(token: Token) -> Self {
        Self {
            token,
            error: None,
            retry_at: None,
        }
    }

    /// The error for a reader that finds no usable token.
    fn unusable(&self, refreshing: bool) -> Error {
        if refreshing {
            self.error.clone().unwrap_or(Error::TokenExpired)
        } else {
            Error::RefreshStopped
        }
    }
}

/// Whether the refresh task still runs.
fn is_refreshing(state: &watch::Receiver<State>) -> bool {
    state.has_changed().is_ok()
}

/// Whether the refresh task waits after a failure or a rejection until a published time. A wake-up does not shorten that wait.
fn waits_for_retry(state: &State, now: Instant) -> bool {
    state.retry_at.is_some_and(|at| at > now)
}

/// Whether a wake-up can reach the refresh task: it runs, the monotonic clock has not reached the refresh point, and the task does not wait until a published time.
///
/// The task sleeps until the refresh point on the monotonic clock, so before that point only a reader can tell it that the wall clock has passed the refresh point
/// or the expiry, as after the machine slept. After that point the task is awake: it requests a token, or it waits until a published time.
/// Readers check this first, so that a read writes to the shared [`Notify`] only before the refresh point. A wake-up while the task is awake, as during a refresh
/// that a reader or an invalidation started before the refresh point, only causes one extra check.
fn task_listens(state: &State, refreshing: bool, now: Instant) -> bool {
    refreshing && now < state.token.refresh_at && !waits_for_retry(state, now)
}

/// A token cache. The refresh task stops when the [`JoinHandle`] that [`TokenCache::start`] returns is aborted, and when the cache and every wait on it are gone.
#[derive(Debug)]
pub(crate) struct TokenCache {
    /// Unique in the process, so that a token of another cache cannot invalidate a token of this one.
    id: u64,
    state: watch::Receiver<State>,
    shared: Arc<Shared>,
    timeout: Duration,
}

impl TokenCache {
    /// Requests the first token and, if `config.refresh` is set, spawns the refresh task.
    ///
    /// The first request is retried with backoff after an error a retry can fix, at most `config.first_token_retries` times and within `config.timeout`.
    ///
    /// # Errors
    ///
    /// The error of the last request.
    pub(crate) async fn start(
        source: Arc<dyn TokenSource>,
        config: CacheConfig,
    ) -> Result<(Self, Option<JoinHandle<()>>), Error> {
        let id = NEXT_CACHE_ID.fetch_add(1, Ordering::Relaxed);
        let mut refresher = Refresher {
            source,
            config: config.capped(),
            cache: id,
            generation: 0,
            logged_missing_expires_in: false,
            fresh_rejections: 0,
        };
        let token = refresher.first_token().await?;
        let timeout = refresher.config.timeout;
        let shared = Arc::new(Shared::new(refresher.config.wall_clock));
        let (sender, state) = watch::channel(State::new(token));
        let task = if refresher.config.refresh {
            let span = tracing::debug_span!(
                "token_refresh",
                client_id = %refresher.config.client_id
            );
            let shared = Arc::clone(&shared);
            Some(tokio::spawn(
                async move { refresher.run(&sender, &shared).await }.instrument(span),
            ))
        } else {
            // With the only sender gone, readers know that no refresh comes.
            drop(sender);
            None
        };
        Ok((
            Self {
                id,
                state,
                shared,
                timeout,
            },
            task,
        ))
    }

    /// Passes the usable token to `read`. Never waits.
    ///
    /// # Errors
    ///
    /// Without a usable token: [`Error::RefreshStopped`] if no refresh task runs, else the error of the last request, else [`Error::TokenExpired`].
    pub(crate) fn read<T>(&self, read: impl FnOnce(&Token) -> T) -> Result<T, Error> {
        let (result, wake) = {
            let state = self.state.borrow();
            let now = Instant::now();
            let now_wall = (self.shared.wall_clock)();
            if state.token.is_usable_at(&self.shared, now, now_wall) {
                let due = state.token.is_due_by_wall_clock(now_wall);
                (
                    Ok(read(&state.token)),
                    due && task_listens(&state, is_refreshing(&self.state), now),
                )
            } else {
                (
                    Err(state.unusable(is_refreshing(&self.state))),
                    task_listens(&state, is_refreshing(&self.state), now),
                )
            }
        };
        if wake {
            self.shared.wake_task();
        }
        result
    }

    /// Passes the usable token to `read`. Without one, wakes the refresh task and waits for a token, at most the timeout.
    ///
    /// Returns early when the task waits after a failure or a fresh rejection until after the timeout. Cancelling the wait does not cancel the request.
    ///
    /// # Errors
    ///
    /// As [`Self::read`], once the wait ends without a usable token.
    pub(crate) async fn wait<T>(&self, read: impl Fn(&Token) -> T) -> Result<T, Error> {
        let deadline = Instant::now() + self.timeout;
        let mut state = self.state.clone();
        loop {
            let refreshing = is_refreshing(&state);
            let wake = {
                let current = state.borrow_and_update();
                let now = Instant::now();
                let now_wall = (self.shared.wall_clock)();
                if current.token.is_usable_at(&self.shared, now, now_wall) {
                    let value = read(&current.token);
                    let wake = current.token.is_due_by_wall_clock(now_wall)
                        && task_listens(&current, refreshing, now);
                    drop(current);
                    if wake {
                        self.shared.wake_task();
                    }
                    return Ok(value);
                }
                if !refreshing || current.retry_at.is_some_and(|at| at > deadline) {
                    return Err(current.unusable(refreshing));
                }
                task_listens(&current, refreshing, now)
            };
            if wake {
                self.shared.wake_task();
            }
            // A closed channel ends the wait on the next round.
            if tokio::time::timeout_at(deadline, state.changed())
                .await
                .is_err()
            {
                return Err(state.borrow().unusable(is_refreshing(&state)));
            }
        }
    }

    /// Stops using the token `token` and wakes the refresh task.
    ///
    /// A token of a later generation stays in use, so a late call for an old token does not discard a newer one.
    /// A token of another cache changes nothing.
    pub(crate) fn invalidate(&self, token: TokenId) {
        if token.cache != self.id {
            return;
        }
        if self
            .shared
            .invalidated
            .fetch_max(token.generation, Ordering::AcqRel)
            < token.generation
        {
            self.shared.wake_task();
        }
    }
}

/// Requests tokens: the first one for [`TokenCache::start`], then the refreshes in the task.
struct Refresher {
    source: Arc<dyn TokenSource>,
    config: CacheConfig,
    /// The id of the cache.
    cache: u64,
    /// The generation of the newest token.
    generation: u64,
    logged_missing_expires_in: bool,
    /// Fresh tokens rejected in a row: tokens invalidated before their refresh point by either clock, while the wait after the rejection still lay ahead.
    /// A rejection whose wait has passed starts a new series at 1. A token that reaches its refresh point resets the count to 0,
    /// also when it is invalidated after that point. An expired token neither counts nor resets.
    fresh_rejections: u32,
}

impl Refresher {
    async fn first_token(&mut self) -> Result<Token, Error> {
        let deadline = Instant::now() + self.config.timeout;
        let mut timeout = self.config.timeout;
        let mut failures: u32 = 0;
        loop {
            let error = match self.request(timeout).await {
                Ok(token) => return Ok(token),
                Err(error) => error,
            };
            failures = failures.saturating_add(1);
            let wait = schedule::retry_delay(&error, failures, None, schedule::random());
            if !error.is_retryable()
                || failures > self.config.first_token_retries
                || Instant::now() + wait >= deadline
            {
                tracing::error!(
                    "Failed to fetch a token for client `{}`: {}",
                    self.config.client_id,
                    DisplayChain(&error)
                );
                return Err(error);
            }
            tracing::debug!(
                "Failed to fetch a token for client `{}`: {}. Retrying in {wait:?}",
                self.config.client_id,
                DisplayChain(&error)
            );
            tokio::time::sleep(wait).await;
            timeout = deadline.saturating_duration_since(Instant::now());
        }
    }

    /// Refreshes the token until every reader is gone.
    async fn run(mut self, sender: &watch::Sender<State>, shared: &Shared) {
        loop {
            if until_readers_gone(sender, self.wait_until_due(sender, shared))
                .await
                .is_err()
                || self.refresh(sender, shared).await.is_err()
            {
                break;
            }
        }
        tracing::debug!(
            "Every reader of the token of client `{}` is gone, so the refresh task ends",
            self.config.client_id
        );
    }

    /// Requests tokens until one arrives. After a failure, the old token stays in use while it is valid,
    /// and the wait before the next request is at most [`half_time_left`], unless a `Retry-After` asks for longer.
    async fn refresh(
        &mut self,
        sender: &watch::Sender<State>,
        shared: &Shared,
    ) -> Result<(), ReadersGone> {
        let mut failures: u32 = 0;
        loop {
            let timeout = attempt_timeout(&sender.borrow().token, shared, self.config.timeout);
            let error = match until_readers_gone(sender, self.request(timeout)).await? {
                Ok(token) => {
                    drop(sender.send_replace(State::new(token)));
                    return Ok(());
                }
                Err(error) => error,
            };
            failures = failures.saturating_add(1);
            let token = sender.borrow().token.clone();
            let wait = schedule::retry_delay(
                &error,
                failures,
                half_time_left(&token, shared),
                schedule::random(),
            );
            if token.is_usable(shared) {
                tracing::warn!(
                    "Failed to refresh the token for client `{}`: {}. The current token stays in use while it is valid. Retrying in {wait:?}",
                    self.config.client_id,
                    DisplayChain(&error)
                );
            } else {
                tracing::error!(
                    "Failed to refresh the token for client `{}`, which has no valid token: {}. Retrying in {wait:?}",
                    self.config.client_id,
                    DisplayChain(&error)
                );
            }
            let retry_at = Instant::now() + wait;
            drop(sender.send_replace(State {
                token,
                error: Some(error),
                retry_at: Some(retry_at),
            }));
            until_readers_gone(sender, tokio::time::sleep_until(retry_at)).await?;
        }
    }

    /// One request, in a task of its own so that a panic ends only this request.
    async fn request(&mut self, timeout: Duration) -> Result<Token, Error> {
        let requested_at = (Instant::now(), (self.config.wall_clock)());
        let source = Arc::clone(&self.source);
        let mut task = AbortOnDrop(tokio::spawn(async move { source.fetch().await }));
        let response = match tokio::time::timeout(timeout, &mut task.0).await {
            Ok(Ok(response)) => response?,
            Ok(Err(error)) if error.is_panic() => return Err(Error::TokenRequestPanicked),
            // Only a runtime that shuts down cancels the request.
            Ok(Err(_)) => return Err(Error::RefreshStopped),
            Err(_) => return Err(Error::Timeout(timeout)),
        };

        let (lifetime, origin) =
            lifetime::lifetime(&response, requested_at.1, self.config.default_lifetime);
        let id = TokenId {
            cache: self.cache,
            generation: self.generation + 1,
        };
        let token = Token::new(&response, id, requested_at, lifetime, self.config.tolerance)?;
        self.generation = id.generation;
        self.log_missing_expires_in(origin, lifetime);
        tracing::debug!(
            "Fetched a token for client `{}`. It is valid for {lifetime:?}",
            self.config.client_id
        );
        Ok(token)
    }

    fn log_missing_expires_in(&mut self, origin: lifetime::Origin, lifetime: Duration) {
        if self.logged_missing_expires_in {
            return;
        }
        match origin {
            lifetime::Origin::ExpiresIn => return,
            lifetime::Origin::JwtExp => tracing::info!(
                "The token endpoint sent no `expires_in` for client `{}`. middle uses the `exp` of the JWT access token, which is {lifetime:?} after the request",
                self.config.client_id
            ),
            lifetime::Origin::Default => tracing::warn!(
                "The token endpoint sent no `expires_in` for client `{}`. middle uses the default lifetime of {lifetime:?}",
                self.config.client_id
            ),
        }
        self.logged_missing_expires_in = true;
    }

    /// Waits until the token is due for refresh by either clock, expired or invalidated, and at least [`schedule::MIN_REFRESH_INTERVAL`] after its request.
    ///
    /// The wait sleeps until the refresh point on the monotonic clock. A reader wakes it when the wall clock has passed the refresh point or the token is not usable,
    /// and [`TokenCache::invalidate`] wakes it for a rejected token.
    /// A token that reaches its refresh point resets the count of fresh rejections, also when it is invalidated after that point.
    /// A token that expired before its refresh point neither counts nor resets. An invalidated token goes to [`Self::wait_after_rejection`].
    async fn wait_until_due(&mut self, sender: &watch::Sender<State>, shared: &Shared) {
        let (refresh_at, requested_at) = {
            let state = sender.borrow();
            (state.token.refresh_at, state.token.requested_at)
        };
        loop {
            let woken = shared.wake.notified();
            let now = Instant::now();
            let now_wall = (shared.wall_clock)();
            let (due, expired, invalidated) = {
                let state = sender.borrow();
                (
                    state.token.is_due_at(now, now_wall),
                    state.token.is_expired_at(now, now_wall),
                    state.token.is_invalidated(shared),
                )
            };
            if due {
                self.fresh_rejections = 0;
                break;
            }
            if expired {
                break;
            }
            if invalidated {
                self.wait_after_rejection(sender, requested_at, now).await;
                return;
            }
            if tokio::time::timeout_at(refresh_at, woken).await.is_err() {
                self.fresh_rejections = 0;
                return;
            }
        }
        tokio::time::sleep_until(requested_at + schedule::MIN_REFRESH_INTERVAL).await;
    }

    /// Waits after the server rejected a token before its refresh point, counted from the request of the rejected token:
    /// [`schedule::MIN_REFRESH_INTERVAL`] for the first rejection in a row, [`schedule::backoff`] for the further ones.
    ///
    /// The rejection counts only while that wait still lies ahead. A token that lasted longer than the wait keeps the requests under the rate the wait allows,
    /// so the rejection starts a new series as its first one, and the next token is requested at once.
    /// A wait that lies ahead is published as `retry_at`, so that a waiter whose deadline comes first returns early. From the second rejection in a row on, it is logged as a warning.
    async fn wait_after_rejection(
        &mut self,
        sender: &watch::Sender<State>,
        requested_at: Instant,
        now: Instant,
    ) {
        let rejections = self.fresh_rejections.saturating_add(1);
        let wait = if rejections <= 1 {
            schedule::MIN_REFRESH_INTERVAL
        } else {
            schedule::backoff(rejections, schedule::random())
        };
        let next = requested_at + wait;
        if next <= now {
            // The wait is at least `MIN_REFRESH_INTERVAL`, so the next request may go out at once.
            self.fresh_rejections = 1;
            return;
        }
        self.fresh_rejections = rejections;
        if rejections >= 2 {
            tracing::warn!(
                "The server rejected {rejections} fresh tokens of client `{}` in a row; the next token is requested in {:.1?}",
                self.config.client_id,
                next.saturating_duration_since(now)
            );
        }
        sender.send_modify(|state| state.retry_at = Some(next));
        tokio::time::sleep_until(next).await;
    }
}

/// The timeout of one request of a refresh: the configured timeout, and at most [`half_time_left`] while the old token is usable.
fn attempt_timeout(token: &Token, shared: &Shared, timeout: Duration) -> Duration {
    half_time_left(token, shared).map_or(timeout, |half| timeout.min(half))
}

/// Half the time the old token has left, but at least [`MIN_HALF_TIME_LEFT`]; `None` if the token is not usable. The time left is the shorter one by the two clocks.
///
/// The expiry of the old token is the deadline of the refresh. One request may take at most this long, and so may the wait after a failed one,
/// so that a request without an answer or a failure leaves time for another request before the token expires.
fn half_time_left(token: &Token, shared: &Shared) -> Option<Duration> {
    let now = Instant::now();
    let now_wall = (shared.wall_clock)();
    if !token.is_usable_at(shared, now, now_wall) {
        return None;
    }
    let left = token.expires_at.saturating_duration_since(now);
    let left_wall = token
        .expires_at_wall
        .and_then(|expiry| expiry.duration_since(now_wall).ok())
        .unwrap_or(left);
    Some((left.min(left_wall) / 2).max(MIN_HALF_TIME_LEFT))
}

/// Every reader of the token is gone: the cache and every receiver cloned from it were dropped.
#[derive(Debug)]
struct ReadersGone;

/// Runs `future` until it completes or every reader is gone. If both happen at once, the readers being gone wins, so that no further request starts.
async fn until_readers_gone<F: Future>(
    sender: &watch::Sender<State>,
    future: F,
) -> Result<F::Output, ReadersGone> {
    let mut future = pin!(future);
    let mut closed = pin!(sender.closed());
    poll_fn(|cx| {
        if closed.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(ReadersGone));
        }
        future.as_mut().poll(cx).map(Ok)
    })
    .await
}

/// Aborts the task when dropped, so that a request ends with its timeout or with the refresh task.
struct AbortOnDrop<T>(JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
mod tests;
