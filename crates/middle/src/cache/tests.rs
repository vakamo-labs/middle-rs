//! The cache against a scripted token source, with tokio's clock paused so that timing is exact.

use std::{cell::Cell, sync::Mutex};

use http::StatusCode;

use super::*;
use crate::{
    error::{ErrorCode, HttpError, OAuthError},
    token_endpoint::AccessToken,
};

/// What the scripted source does for one request.
enum Step {
    /// Answers with this access token and `expires_in` in seconds.
    Token(&'static str, Option<u64>),
    /// Answers with this access token and a lifetime that may be shorter than a second.
    Lasting(&'static str, Duration),
    /// Answers after a delay.
    Slow(Duration, &'static str, Option<u64>),
    Fail(Error),
    Hang,
    Panic,
}

struct ScriptedSource {
    script: Box<dyn Fn(usize) -> Step + Send + Sync>,
    requests: Mutex<Vec<Instant>>,
}

impl fmt::Debug for ScriptedSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScriptedSource")
    }
}

impl TokenSource for ScriptedSource {
    fn fetch(&self) -> BoxFuture<'_, Result<TokenResponse, Error>> {
        let number = {
            let mut requests = self.requests.lock().unwrap();
            requests.push(Instant::now());
            requests.len()
        };
        let step = (self.script)(number);
        Box::pin(async move {
            match step {
                Step::Token(token, expires_in) => Ok(response(token, expires_in)),
                Step::Lasting(token, lifetime) => Ok(TokenResponse {
                    access_token: AccessToken::parse(token).unwrap(),
                    expires_in: Some(lifetime),
                }),
                Step::Slow(delay, token, expires_in) => {
                    tokio::time::sleep(delay).await;
                    Ok(response(token, expires_in))
                }
                Step::Fail(error) => Err(error),
                Step::Hang => std::future::pending().await,
                Step::Panic => panic!("the scripted source panics"),
            }
        })
    }
}

impl ScriptedSource {
    /// The times of the requests, counted from the first one.
    fn request_times(&self) -> Vec<Duration> {
        let requests = self.requests.lock().unwrap();
        requests
            .iter()
            .map(|at| at.duration_since(requests[0]))
            .collect()
    }

    /// The time between each request and the one before it.
    fn gaps(&self) -> Vec<Duration> {
        let requests = self.requests.lock().unwrap();
        requests
            .windows(2)
            .map(|pair| pair[1].duration_since(pair[0]))
            .collect()
    }

    fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
}

fn response(token: &str, expires_in: Option<u64>) -> TokenResponse {
    TokenResponse {
        access_token: AccessToken::parse(token).unwrap(),
        expires_in: expires_in.map(Duration::from_secs),
    }
}

fn unavailable(retry_after: Option<u64>) -> Error {
    HttpError {
        status: StatusCode::SERVICE_UNAVAILABLE,
        content_type: None,
        retry_after: retry_after.map(Duration::from_secs),
    }
    .into()
}

fn invalid_client() -> Error {
    OAuthError {
        status: StatusCode::UNAUTHORIZED,
        code: ErrorCode::InvalidClient,
        description: None,
        uri: None,
        retry_after: None,
    }
    .into()
}

thread_local! {
    /// The wall clock of this test thread. It stands still unless a test moves it, so that neither the time a test takes nor a sleeping machine
    /// interferes with tokio's paused clock. Paused tests run all their tasks on the test thread.
    static WALL_CLOCK: Cell<SystemTime> = Cell::new(SystemTime::now());
}

fn wall_clock() -> SystemTime {
    WALL_CLOCK.with(Cell::get)
}

/// Moves the wall clock of this test thread ahead, as if the machine slept that long.
fn sleep_machine(duration: Duration) {
    WALL_CLOCK.with(|clock| clock.set(clock.get() + duration));
}

fn config() -> CacheConfig {
    CacheConfig {
        client_id: "my-client".to_string(),
        timeout: Duration::from_secs(30),
        tolerance: Duration::from_secs(30),
        default_lifetime: Duration::from_secs(300),
        first_token_retries: 3,
        refresh: true,
        wall_clock,
    }
}

fn secs(seconds: f64) -> Duration {
    Duration::from_secs_f64(seconds)
}

struct Started {
    cache: Arc<TokenCache>,
    task: Option<JoinHandle<()>>,
    source: Arc<ScriptedSource>,
}

impl Drop for Started {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

async fn try_start(
    config: CacheConfig,
    script: impl Fn(usize) -> Step + Send + Sync + 'static,
) -> (Result<Arc<TokenCache>, Error>, Arc<ScriptedSource>) {
    let source = Arc::new(ScriptedSource {
        script: Box::new(script),
        requests: Mutex::default(),
    });
    let result = TokenCache::start(Arc::clone(&source) as Arc<dyn TokenSource>, config)
        .await
        .map(|(cache, _task)| Arc::new(cache));
    (result, source)
}

async fn start(
    config: CacheConfig,
    script: impl Fn(usize) -> Step + Send + Sync + 'static,
) -> Started {
    let source = Arc::new(ScriptedSource {
        script: Box::new(script),
        requests: Mutex::default(),
    });
    let (cache, task) = TokenCache::start(Arc::clone(&source) as Arc<dyn TokenSource>, config)
        .await
        .unwrap();
    Started {
        cache: Arc::new(cache),
        task,
        source,
    }
}

fn header(cache: &TokenCache) -> Result<String, Error> {
    cache.read(|token| token.header().to_str().unwrap().to_string())
}

fn generation(cache: &TokenCache) -> Result<u64, Error> {
    cache.read(Token::generation)
}

/// Invalidates the token of `generation` in `cache`.
fn invalidate(cache: &TokenCache, generation: u64) {
    cache.invalidate(TokenId {
        cache: cache.id,
        generation,
    });
}

/// Sleeps until `at`, counted from `start`.
async fn sleep_until(start: Instant, at: f64) {
    tokio::time::sleep_until(start + secs(at)).await;
}

/// Asserts that `actual` lies between `low` and `high` seconds, both included.
///
/// tokio's timers fire on whole milliseconds, so a measured time can be a few milliseconds longer than the wait behind it.
#[track_caller]
fn assert_between(actual: Duration, low: f64, high: f64) {
    const TIMER_SLACK: Duration = Duration::from_millis(5);
    assert!(
        actual >= secs(low) && actual <= secs(high) + TIMER_SLACK,
        "{actual:?} is not between {low} s and {high} s"
    );
}

#[tokio::test(start_paused = true)]
async fn test_a_long_token_refreshes_between_75_and_85_percent_of_its_lifetime() {
    let started = start(config(), |_| Step::Token("t", Some(1000))).await;

    tokio::time::sleep(secs(1700.0)).await;

    let gaps = started.source.gaps();
    assert!(gaps.len() >= 2, "{gaps:?}");
    for gap in &gaps[..2] {
        assert_between(*gap, 750.0, 850.0);
    }
}

#[tokio::test(start_paused = true)]
async fn test_a_token_shorter_than_twice_the_tolerance_refreshes_in_a_window_ending_at_half_its_lifetime()
 {
    for (lifetime, start_s, end_s) in [(31, 12.4, 15.5), (29, 11.6, 14.5)] {
        let started = start(config(), move |_| Step::Token("t", Some(lifetime))).await;

        tokio::time::sleep(secs(2.0 * end_s + 1.0)).await;

        let gaps = started.source.gaps();
        assert!(gaps.len() >= 2, "{gaps:?}");
        for gap in &gaps[..2] {
            assert_between(*gap, start_s, end_s);
        }
    }
}

#[tokio::test(start_paused = true)]
async fn test_a_token_that_expires_at_once_is_requested_once_per_second() {
    let started = start(config(), |_| Step::Token("t", Some(0))).await;
    let begin = Instant::now();

    // Every failed read wakes the refresh task.
    let mut reads = 0;
    while begin.elapsed() < secs(10.5) {
        assert!(matches!(header(&started.cache), Err(Error::TokenExpired)));
        reads += 1;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    assert_eq!(reads, 1050);
    let expected: Vec<Duration> = (0..=10).map(Duration::from_secs).collect();
    assert_eq!(started.source.request_times(), expected);
}

#[tokio::test(start_paused = true)]
async fn test_retries_back_off_from_one_second_up_to_thirty() {
    let mut config = config();
    config.tolerance = Duration::from_secs(1000);
    // The refresh window ends at half the lifetime, at 1000 s.
    let started = start(config, |number| match number {
        1 => Step::Token("t", Some(2000)),
        _ => Step::Fail(unavailable(None)),
    })
    .await;

    tokio::time::sleep(secs(1000.0 + 120.0)).await;

    let gaps = started.source.gaps();
    assert_between(gaps[0], 800.0, 1000.0);
    let bounds = [
        (1.0, 2.0),
        (2.0, 4.0),
        (4.0, 8.0),
        (8.0, 16.0),
        (15.0, 30.0),
        (15.0, 30.0),
    ];
    for (index, (low, high)) in bounds.into_iter().enumerate() {
        let gap = gaps[index + 1];
        assert_between(gap, low, high);
    }
}

#[tokio::test(start_paused = true)]
async fn test_an_error_a_retry_cannot_fix_is_retried_at_half_the_time_left_then_about_every_five_minutes()
 {
    let started = start(config(), |number| match number {
        1 => Step::Token("t", Some(60)),
        _ => Step::Fail(invalid_client()),
    })
    .await;

    tokio::time::sleep(secs(60.0 + 3.0 * 330.0)).await;

    // The refresh between 24 s and 30 s fails. While the token is valid, each retry waits half the time it has left, at least 1 s.
    let times = started.source.request_times();
    assert_between(times[1], 24.0, 30.0);
    let expired = times
        .iter()
        .position(|time| *time >= secs(60.0))
        .expect("a request after expiry");
    for pair in times[1..=expired].windows(2) {
        let half_left = ((secs(60.0) - pair[0]) / 2).max(secs(1.0));
        assert_between(
            pair[1] - pair[0],
            half_left.as_secs_f64(),
            half_left.as_secs_f64(),
        );
    }
    assert!(expired <= 8, "{times:?}");
    // After expiry, about every five minutes.
    assert_eq!(times.len(), expired + 4, "{times:?}");
    for pair in times[expired..].windows(2) {
        assert_between(pair[1] - pair[0], 270.0, 330.0);
    }
    let error = header(&started.cache).unwrap_err();
    assert!(
        matches!(&error, Error::OAuth(oauth) if oauth.code() == &ErrorCode::InvalidClient),
        "{error:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn test_retry_after_is_followed_up_to_five_minutes() {
    let started = start(config(), |number| match number {
        1 => Step::Token("t", Some(60)),
        2 => Step::Fail(unavailable(Some(20))),
        3 => Step::Fail(unavailable(Some(3600))),
        _ => Step::Token("t", Some(3600)),
    })
    .await;

    tokio::time::sleep(secs(400.0)).await;

    let gaps = started.source.gaps();
    assert_between(gaps[0], 24.0, 30.0);
    assert_eq!(&gaps[1..], &[secs(20.0), secs(300.0)]);
}

#[tokio::test(start_paused = true)]
async fn test_a_failed_refresh_keeps_the_old_token_while_it_is_valid() {
    let started = start(config(), |number| match number {
        1 => Step::Token("t", Some(100)),
        _ => Step::Fail(unavailable(None)),
    })
    .await;
    let begin = Instant::now();

    // The refresh between 60 s and 70 s fails, and so does every retry.
    sleep_until(begin, 99.9).await;
    assert_between(started.source.gaps()[0], 60.0, 70.0);
    assert_eq!(header(&started.cache).unwrap(), "Bearer t");

    sleep_until(begin, 100.0).await;
    let error = header(&started.cache).unwrap_err();
    assert!(
        matches!(&error, Error::Http(http) if http.status() == StatusCode::SERVICE_UNAVAILABLE),
        "readers get the error of the last request: {error:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn test_a_request_without_an_answer_leaves_time_for_another_before_expiry() {
    let started = start(config(), |number| match number {
        1 => Step::Token("first", Some(60)),
        2 => Step::Hang,
        _ => Step::Token("second", Some(60)),
    })
    .await;
    let begin = Instant::now();

    // The refresh between 24 s and 30 s may take half of the time left, so it times out between 42 s and 45 s,
    // and the next request comes 1 s to 2 s later.
    let mut failed_reads = 0;
    while begin.elapsed() < secs(61.0) {
        if header(&started.cache).is_err() {
            failed_reads += 1;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let times = started.source.request_times();
    assert_between(times[1], 24.0, 30.0);
    let timed_out = times[1] + secs(60.0).checked_sub(times[1]).unwrap() / 2;
    assert_between(times[2].checked_sub(timed_out).unwrap(), 1.0, 2.0);
    assert_eq!(failed_reads, 0);
    assert_eq!(header(&started.cache).unwrap(), "Bearer second");
}

#[tokio::test(start_paused = true)]
async fn test_a_panic_in_a_request_does_not_end_the_refresh() {
    let started = start(config(), |number| match number {
        1 => Step::Token("first", Some(60)),
        2 => Step::Panic,
        _ => Step::Token("second", Some(3600)),
    })
    .await;
    let begin = Instant::now();

    // The refresh between 24 s and 30 s panics.
    sleep_until(begin, 31.0).await;
    let error = started.cache.state.borrow().error.clone();
    assert!(
        matches!(error, Some(Error::TokenRequestPanicked)),
        "{error:?}"
    );
    assert!(!error.unwrap().is_retryable());

    // The retry at half the time left brings the next token before the first one expires.
    sleep_until(begin, 60.0).await;
    assert_eq!(header(&started.cache).unwrap(), "Bearer second");
    assert!(!started.task.as_ref().unwrap().is_finished());
}

#[tokio::test(start_paused = true)]
async fn test_readers_get_refresh_stopped_once_the_task_has_ended() {
    let mut started = start(config(), |_| Step::Token("t", Some(60))).await;
    let task = started.task.take().unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let begin = Instant::now();

    assert_eq!(header(&started.cache).unwrap(), "Bearer t");
    assert_eq!(
        started.cache.wait(Token::generation).await.unwrap(),
        1,
        "a usable token is served without waiting"
    );

    sleep_until(begin, 60.0).await;
    let error = header(&started.cache).unwrap_err();
    assert!(matches!(error, Error::RefreshStopped), "{error:?}");
    assert!(!error.is_retryable());
    let error = started.cache.wait(Token::generation).await.unwrap_err();
    assert!(matches!(error, Error::RefreshStopped), "{error:?}");
    assert_eq!(Instant::now(), begin + secs(60.0), "no wait");
    assert_eq!(started.source.count(), 1);
}

#[tokio::test(start_paused = true)]
async fn test_without_refresh_no_task_runs() {
    let mut config = config();
    config.refresh = false;
    let started = start(config, |_| Step::Token("t", Some(60))).await;

    assert!(started.task.is_none());
    assert_eq!(header(&started.cache).unwrap(), "Bearer t");
    tokio::time::sleep(secs(60.0)).await;

    assert!(matches!(header(&started.cache), Err(Error::RefreshStopped)));
    assert_eq!(started.source.count(), 1);
}

#[tokio::test(start_paused = true)]
async fn test_the_lifetime_counts_from_the_request() {
    let mut config = config();
    config.refresh = false;
    let started = start(config, |_| Step::Slow(secs(10.0), "t", Some(60))).await;
    let requested_at = Instant::now() - secs(10.0);

    sleep_until(requested_at, 59.9).await;
    assert!(header(&started.cache).is_ok());
    sleep_until(requested_at, 60.0).await;
    assert!(header(&started.cache).is_err());
}

#[tokio::test(start_paused = true)]
async fn test_without_expires_in_the_default_lifetime_is_used() {
    let mut config = config();
    config.default_lifetime = Duration::from_secs(100);
    let started = start(config, |_| Step::Token("t", None)).await;

    tokio::time::sleep(secs(150.0)).await;

    // A token of 100 s is refreshed between 60 s and 70 s.
    let gaps = started.source.gaps();
    assert_eq!(gaps.len(), 2, "{gaps:?}");
    for gap in gaps {
        assert_between(gap, 60.0, 70.0);
    }
}

#[tokio::test(start_paused = true)]
#[tracing_test::traced_test]
async fn test_a_missing_expires_in_is_logged_once() {
    let mut config = config();
    config.default_lifetime = Duration::from_secs(10);
    let started = start(config, |_| Step::Token("t", None)).await;

    tokio::time::sleep(secs(30.0)).await;

    assert!(started.source.count() >= 4);
    logs_assert(|lines| {
        let count = lines
            .iter()
            .filter(|line| line.contains("sent no `expires_in`"))
            .count();
        if count == 1 {
            Ok(())
        } else {
            Err(format!("logged {count} times"))
        }
    });
}

#[tokio::test(start_paused = true)]
async fn test_invalidate_drops_only_the_rejected_generation() {
    let started = start(config(), |number| match number {
        1 => Step::Token("first", Some(3600)),
        _ => Step::Token("second", Some(3600)),
    })
    .await;
    assert_eq!(generation(&started.cache).unwrap(), 1);

    invalidate(&started.cache, 1);
    assert!(matches!(header(&started.cache), Err(Error::TokenExpired)));
    let header_after = started
        .cache
        .wait(|token| token.header().to_str().unwrap().to_string())
        .await
        .unwrap();
    assert_eq!(header_after, "Bearer second");

    // A late invalidation of the first token keeps the second.
    invalidate(&started.cache, 1);
    assert_eq!(generation(&started.cache).unwrap(), 2);
    tokio::time::sleep(secs(10.0)).await;
    assert_eq!(started.source.count(), 2);
}

#[tokio::test(start_paused = true)]
async fn test_invalidated_tokens_are_requested_at_most_once_per_second() {
    let started = start(config(), |_| Step::Token("t", Some(3600))).await;

    for _ in 0..5 {
        let generation = started.cache.wait(Token::generation).await.unwrap();
        invalidate(&started.cache, generation);
    }
    started.cache.wait(Token::generation).await.unwrap();

    // The waits grow with each rejection in a row, see the test of growing waits below.
    let gaps = started.source.gaps();
    assert_eq!(gaps.len(), 5, "{gaps:?}");
    assert_eq!(gaps[0], secs(1.0), "{gaps:?}");
    assert!(gaps.iter().all(|gap| *gap >= secs(1.0)), "{gaps:?}");
}

#[tokio::test(start_paused = true)]
async fn test_waiters_share_one_request() {
    let started = start(config(), |number| match number {
        1 => Step::Token("first", Some(3600)),
        _ => Step::Slow(secs(2.0), "second", Some(3600)),
    })
    .await;
    invalidate(&started.cache, 1);

    let waiters: Vec<_> = (0..10)
        .map(|_| {
            let cache = Arc::clone(&started.cache);
            tokio::spawn(async move { cache.wait(Token::generation).await })
        })
        .collect();
    for waiter in waiters {
        assert_eq!(waiter.await.unwrap().unwrap(), 2);
    }

    assert_eq!(started.source.count(), 2);
}

#[tokio::test(start_paused = true)]
async fn test_a_cancelled_waiter_does_not_cancel_the_request() {
    let started = start(config(), |number| match number {
        1 => Step::Token("first", Some(3600)),
        _ => Step::Slow(secs(5.0), "second", Some(3600)),
    })
    .await;
    invalidate(&started.cache, 1);

    let cancelled = tokio::time::timeout(secs(2.0), started.cache.wait(Token::generation)).await;
    assert!(cancelled.is_err());

    tokio::time::sleep(secs(10.0)).await;
    assert_eq!(header(&started.cache).unwrap(), "Bearer second");
    assert_eq!(started.source.count(), 2);
}

#[tokio::test(start_paused = true)]
async fn test_a_waiter_waits_through_a_short_backoff() {
    let started = start(config(), |number| match number {
        1 => Step::Token("first", Some(3600)),
        2 => Step::Fail(unavailable(None)),
        _ => Step::Token("second", Some(3600)),
    })
    .await;
    invalidate(&started.cache, 1);
    let begin = Instant::now();

    let header_after = started
        .cache
        .wait(|token| token.header().to_str().unwrap().to_string())
        .await
        .unwrap();

    assert_eq!(header_after, "Bearer second");
    let waited = begin.elapsed();
    assert_between(waited, 2.0, 3.0);
}

#[tokio::test(start_paused = true)]
async fn test_a_waiter_gets_the_error_at_once_when_the_next_request_comes_after_its_deadline() {
    let started = start(config(), |number| match number {
        1 => Step::Token("first", Some(3600)),
        _ => Step::Fail(invalid_client()),
    })
    .await;
    invalidate(&started.cache, 1);
    let begin = Instant::now();

    let error = started.cache.wait(Token::generation).await.unwrap_err();

    assert!(matches!(error, Error::OAuth(_)), "{error:?}");
    assert_eq!(
        begin.elapsed(),
        secs(1.0),
        "the request comes 1 s after the last one"
    );
}

#[tokio::test(start_paused = true)]
async fn test_a_waiter_gives_up_after_the_timeout() {
    let started = start(config(), |number| match number {
        1 => Step::Token("first", Some(3600)),
        _ => Step::Hang,
    })
    .await;
    invalidate(&started.cache, 1);
    let begin = Instant::now();

    let error = started.cache.wait(Token::generation).await.unwrap_err();

    assert!(matches!(error, Error::TokenExpired), "{error:?}");
    assert_eq!(begin.elapsed(), secs(30.0));
}

#[tokio::test(start_paused = true)]
async fn test_the_first_request_is_retried_after_an_error_a_retry_can_fix() {
    let mut config = config();
    config.first_token_retries = 1;
    let (cache, source) = try_start(config, |_| Step::Fail(unavailable(None))).await;

    assert!(matches!(cache.unwrap_err(), Error::Http(_)));
    assert_eq!(source.count(), 2);
}

#[tokio::test(start_paused = true)]
async fn test_the_first_request_gives_up_when_retry_after_passes_the_timeout() {
    let mut config = config();
    config.timeout = Duration::from_secs(5);
    let (cache, source) = try_start(config, |_| Step::Fail(unavailable(Some(10)))).await;

    assert!(matches!(cache.unwrap_err(), Error::Http(_)));
    assert_eq!(source.count(), 1);
}

#[tokio::test(start_paused = true)]
async fn test_the_first_request_takes_at_most_the_timeout() {
    let mut config = config();
    config.timeout = Duration::from_secs(5);
    config.first_token_retries = 100;
    let begin = Instant::now();

    let (cache, source) = try_start(config.clone(), |_| Step::Hang).await;
    assert!(matches!(cache.unwrap_err(), Error::Timeout(timeout) if timeout == secs(5.0)));
    assert_eq!(source.count(), 1);
    assert_eq!(begin.elapsed(), secs(5.0));

    let begin = Instant::now();
    let (cache, source) = try_start(config, |_| Step::Fail(unavailable(None))).await;
    assert!(matches!(cache.unwrap_err(), Error::Http(_)));
    assert!(source.count() >= 2, "{:?}", source.request_times());
    assert!(begin.elapsed() < secs(5.0));
}

#[tokio::test(start_paused = true)]
async fn test_a_panic_in_the_first_request_fails_start() {
    let (cache, _) = try_start(config(), |_| Step::Panic).await;

    assert!(matches!(cache.unwrap_err(), Error::TokenRequestPanicked));
}

#[tokio::test(start_paused = true)]
async fn test_a_token_expires_when_either_clock_says_so() {
    let now = (Instant::now(), SystemTime::now());
    let token = Token::new(
        &response("t", None),
        TokenId {
            cache: 1,
            generation: 1,
        },
        now,
        secs(60.0),
        Duration::from_secs(30),
    )
    .unwrap();

    assert!(!token.is_expired_at(now.0 + secs(59.0), now.1 + secs(59.0)));
    assert!(token.is_expired_at(now.0 + secs(61.0), now.1 + secs(59.0)));
    assert!(token.is_expired_at(now.0 + secs(59.0), now.1 + secs(61.0)));
}

#[test]
fn test_the_cache_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync + 'static>() {}
    assert_send_sync::<TokenCache>();
}

/// A source whose first token lives 100 s, so its refresh is due between 60 s and 70 s.
fn refreshed_by_70_seconds(number: usize) -> Step {
    match number {
        1 => Step::Token("first", Some(100)),
        _ => Step::Token("second", Some(100)),
    }
}

#[tokio::test(start_paused = true)]
async fn test_a_read_after_the_machine_slept_past_the_refresh_point_starts_the_refresh() {
    let started = start(config(), refreshed_by_70_seconds).await;
    let begin = Instant::now();

    // The paused clock does not move the wall clock. At 10 s on the monotonic clock, the wall clock then says 85 s after the request:
    // the refresh is due, and the token is valid until 100 s.
    sleep_until(begin, 10.0).await;
    sleep_machine(secs(85.0));
    assert_eq!(header(&started.cache).unwrap(), "Bearer first");
    tokio::time::sleep(Duration::from_millis(1)).await;

    assert_eq!(
        started.source.request_times(),
        vec![Duration::ZERO, secs(10.0)]
    );
    assert_eq!(header(&started.cache).unwrap(), "Bearer second");
}

#[tokio::test(start_paused = true)]
async fn test_a_wait_after_the_machine_slept_past_the_refresh_point_starts_the_refresh() {
    let started = start(config(), refreshed_by_70_seconds).await;
    let begin = Instant::now();

    sleep_until(begin, 10.0).await;
    sleep_machine(secs(85.0));
    assert_eq!(started.cache.wait(Token::generation).await.unwrap(), 1);
    tokio::time::sleep(Duration::from_millis(1)).await;

    assert_eq!(
        started.source.request_times(),
        vec![Duration::ZERO, secs(10.0)]
    );
}

#[tokio::test(start_paused = true)]
async fn test_a_refresh_request_after_the_machine_slept_leaves_time_for_another_before_expiry() {
    let started = start(config(), |number| match number {
        1 => Step::Token("first", Some(100)),
        2 => Step::Hang,
        _ => Step::Token("second", Some(100)),
    })
    .await;
    let begin = Instant::now();

    // At 10 s on the monotonic clock, the wall clock says 90 s after the request: the token has 10 s left.
    sleep_until(begin, 10.0).await;
    sleep_machine(secs(90.0));
    assert_eq!(header(&started.cache).unwrap(), "Bearer first");
    sleep_until(begin, 18.0).await;

    // The request may take half of the 10 s left, so it times out at 15 s, and the next one comes 1 s to 2 s later.
    let times = started.source.request_times();
    assert_eq!(times.len(), 3, "{times:?}");
    assert_eq!(&times[..2], &[Duration::ZERO, secs(10.0)]);
    assert_between(times[2], 16.0, 17.0);
    assert_eq!(header(&started.cache).unwrap(), "Bearer second");
}

#[tokio::test(start_paused = true)]
async fn test_the_refresh_task_ends_when_the_cache_is_dropped() {
    let mut started = start(config(), |_| Step::Token("t", Some(60))).await;
    let task = started.task.take().unwrap();
    let source = Arc::clone(&started.source);

    drop(started);
    tokio::time::sleep(secs(120.0)).await;

    assert!(task.is_finished());
    assert_eq!(source.count(), 1);
}

#[tokio::test(start_paused = true)]
async fn test_the_refresh_task_ends_when_the_cache_is_dropped_while_it_waits_after_a_failure() {
    let mut started = start(config(), |number| match number {
        1 => Step::Token("t", Some(60)),
        _ => Step::Fail(invalid_client()),
    })
    .await;
    let task = started.task.take().unwrap();
    let source = Arc::clone(&started.source);
    // The refresh at 30 s fails, and the next request would come about 5 minutes later.
    tokio::time::sleep(secs(31.0)).await;
    assert_eq!(source.count(), 2);

    drop(started);
    tokio::time::sleep(Duration::from_millis(1)).await;

    assert!(task.is_finished());
    assert_eq!(source.count(), 2);
}

#[tokio::test(start_paused = true)]
async fn test_a_lifetime_above_one_year_is_capped() {
    let started = start(config(), |_| Step::Token("t", Some(u64::MAX))).await;

    assert_eq!(header(&started.cache).unwrap(), "Bearer t");
}

#[tokio::test(start_paused = true)]
#[tracing_test::traced_test]
async fn test_fresh_tokens_rejected_in_a_row_are_requested_with_growing_waits() {
    let mut config = config();
    // Long enough for a waiter to sit out the longest wait.
    config.timeout = Duration::from_secs(60);
    let started = start(config, |_| Step::Token("t", Some(3600))).await;

    for _ in 0..6 {
        let generation = started.cache.wait(Token::generation).await.unwrap();
        invalidate(&started.cache, generation);
    }
    assert_eq!(started.cache.wait(Token::generation).await.unwrap(), 7);

    // Each wait counts from the request of the rejected token, which the server rejected at once.
    let gaps = started.source.gaps();
    assert_eq!(gaps.len(), 6, "{gaps:?}");
    assert_eq!(gaps[0], secs(1.0), "{gaps:?}");
    let bounds = [
        (2.0, 4.0),
        (4.0, 8.0),
        (8.0, 16.0),
        (15.0, 30.0),
        (15.0, 30.0),
    ];
    for (gap, (low, high)) in gaps[1..].iter().zip(bounds) {
        assert_between(*gap, low, high);
    }
    assert!(!logs_contain("rejected 1 fresh"));
    assert!(logs_contain(
        "The server rejected 2 fresh tokens of client `my-client` in a row; the next token is requested in"
    ));
    assert!(logs_contain("rejected 6 fresh tokens"));
}

#[tokio::test(start_paused = true)]
async fn test_a_token_that_reaches_its_refresh_point_resets_the_count_of_rejections() {
    // A token of 100 s is refreshed between 60 s and 70 s after its request.
    let started = start(config(), |_| Step::Token("t", Some(100))).await;
    for _ in 0..2 {
        let generation = started.cache.wait(Token::generation).await.unwrap();
        invalidate(&started.cache, generation);
    }
    assert_eq!(started.cache.wait(Token::generation).await.unwrap(), 3);

    // The third token reaches its refresh point, so the fourth replaces it without a rejection.
    while generation(&started.cache).unwrap() < 4 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    invalidate(&started.cache, 4);
    assert_eq!(started.cache.wait(Token::generation).await.unwrap(), 5);

    // A first rejection again: 1 s after the request of the rejected token.
    let gaps = started.source.gaps();
    assert_eq!(gaps.len(), 4, "{gaps:?}");
    assert_eq!(gaps[3], secs(1.0), "{gaps:?}");
}

#[tokio::test(start_paused = true)]
async fn test_a_waiter_gets_an_error_at_once_when_the_wait_after_rejections_ends_after_its_deadline()
 {
    let mut config = config();
    config.timeout = secs(1.5);
    let started = start(config, |_| Step::Token("t", Some(3600))).await;
    invalidate(&started.cache, 1);
    assert_eq!(started.cache.wait(Token::generation).await.unwrap(), 2);
    let begin = Instant::now();

    // The second rejection in a row waits 2 s to 4 s, longer than the waiter's 1.5 s.
    invalidate(&started.cache, 2);
    let error = started.cache.wait(Token::generation).await.unwrap_err();

    assert!(matches!(error, Error::TokenExpired), "{error:?}");
    assert_eq!(begin.elapsed(), Duration::ZERO);
    let retry_at = started.cache.state.borrow().retry_at.unwrap();
    assert_between(retry_at - begin, 2.0, 4.0);
}

/// The generation of the newest token, usable or not.
fn newest_generation(cache: &TokenCache) -> u64 {
    cache.state.borrow().token.id.generation
}

/// Waits for the token of `generation`, usable or not.
async fn until_generation(cache: &TokenCache, generation: u64) {
    while newest_generation(cache) < generation {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Waits for the token of `generation` and invalidates it `after` its request.
async fn reject_after(cache: &TokenCache, generation: u64, after: Duration) {
    until_generation(cache, generation).await;
    let requested_at = cache.state.borrow().token.requested_at;
    tokio::time::sleep_until(requested_at + after).await;
    invalidate(cache, generation);
}

fn wakes(cache: &TokenCache) -> usize {
    cache.shared.wakes.load(Ordering::Relaxed)
}

#[tokio::test(start_paused = true)]
#[tracing_test::traced_test]
async fn test_a_late_rejection_of_a_long_token_starts_no_series() {
    let started = start(config(), |_| Step::Token("t", Some(3600))).await;

    // The server rejects each token 600 s after its request, long after any wait would have ended.
    for generation in 1..=5 {
        reject_after(&started.cache, generation, secs(600.0)).await;
    }
    until_generation(&started.cache, 6).await;

    assert_eq!(started.source.gaps(), vec![secs(600.0); 5]);
    assert!(!logs_contain("fresh tokens"));
}

#[tokio::test(start_paused = true)]
#[tracing_test::traced_test]
async fn test_a_short_token_rejected_after_a_third_of_its_lifetime_is_replaced_at_once() {
    // A token of 60 s is refreshed between 24 s and 30 s, so a rejection at 20 s comes before the refresh point.
    let started = start(config(), |_| Step::Token("t", Some(60))).await;

    for generation in 1..=7 {
        reject_after(&started.cache, generation, secs(20.0)).await;
    }
    until_generation(&started.cache, 8).await;

    assert_eq!(started.source.gaps(), vec![secs(20.0); 7]);
    assert!(!logs_contain("fresh tokens"));
}

#[tokio::test(start_paused = true)]
async fn test_an_expired_token_that_is_invalidated_is_no_rejection() {
    // Each token expires after 500 ms, but its refresh comes 1 s after its request at the earliest.
    let started = start(config(), |_| Step::Lasting("t", Duration::from_millis(500))).await;

    // A server rejects each token after it expired.
    for generation in 1..=4 {
        reject_after(&started.cache, generation, Duration::from_millis(600)).await;
    }
    until_generation(&started.cache, 5).await;

    assert_eq!(started.source.gaps(), vec![secs(1.0); 4]);
}

#[tokio::test(start_paused = true)]
async fn test_a_token_invalidated_after_its_refresh_point_resets_the_count_of_rejections() {
    let started = start(config(), |_| Step::Token("t", Some(3600))).await;
    for _ in 0..2 {
        let generation = started.cache.wait(Token::generation).await.unwrap();
        invalidate(&started.cache, generation);
    }
    assert_eq!(started.cache.wait(Token::generation).await.unwrap(), 3);

    // The machine slept past the refresh point of the third token, between 2700 s and 3060 s, and a server rejects it.
    sleep_machine(secs(3100.0));
    invalidate(&started.cache, 3);
    assert_eq!(started.cache.wait(Token::generation).await.unwrap(), 4);
    invalidate(&started.cache, 4);
    assert_eq!(started.cache.wait(Token::generation).await.unwrap(), 5);

    // The fourth token comes 1 s after the third, and the fifth again 1 s after the fourth: a first rejection.
    let gaps = started.source.gaps();
    assert_eq!(gaps.len(), 4, "{gaps:?}");
    assert_eq!(&gaps[2..], &[secs(1.0), secs(1.0)], "{gaps:?}");
}

#[tokio::test(start_paused = true)]
async fn test_a_read_without_a_refresh_task_wakes_nothing() {
    let mut config = config();
    config.refresh = false;
    let started = start(config, refreshed_by_70_seconds).await;

    // Due by the wall clock and still valid.
    sleep_machine(secs(85.0));
    assert_eq!(header(&started.cache).unwrap(), "Bearer first");
    assert_eq!(started.cache.wait(Token::generation).await.unwrap(), 1);
    // Expired by the wall clock.
    sleep_machine(secs(20.0));
    assert!(header(&started.cache).is_err());

    assert_eq!(wakes(&started.cache), 0);
}

#[tokio::test(start_paused = true)]
async fn test_reads_during_a_refresh_wake_nothing() {
    // Each refresh request takes 1 s.
    let started = start(config(), |number| match number {
        1 => Step::Token("first", Some(100)),
        _ => Step::Slow(secs(1.0), "next", Some(100)),
    })
    .await;
    let begin = Instant::now();

    // In a running process, the wall clock moves with the monotonic clock. The refresh comes between 60 s and 70 s.
    while begin.elapsed() < secs(75.0) {
        tokio::time::sleep(Duration::from_millis(10)).await;
        sleep_machine(Duration::from_millis(10));
        assert!(header(&started.cache).is_ok());
    }

    assert_eq!(started.source.count(), 2);
    assert_eq!(header(&started.cache).unwrap(), "Bearer next");
    assert_eq!(wakes(&started.cache), 0);
}

#[tokio::test(start_paused = true)]
async fn test_a_read_while_the_task_waits_after_a_failure_wakes_nothing() {
    let started = start(config(), |number| match number {
        1 => Step::Token("first", Some(100)),
        _ => Step::Fail(unavailable(Some(60))),
    })
    .await;
    let begin = Instant::now();
    // The refresh between 60 s and 70 s fails, and the next request comes 60 s later.
    sleep_until(begin, 71.0).await;
    assert_eq!(started.source.count(), 2);
    let before = wakes(&started.cache);

    // Due by the wall clock and still valid.
    sleep_machine(secs(85.0));
    assert_eq!(header(&started.cache).unwrap(), "Bearer first");
    assert_eq!(started.cache.wait(Token::generation).await.unwrap(), 1);
    // Expired by the wall clock.
    sleep_machine(secs(20.0));
    assert!(header(&started.cache).is_err());

    assert_eq!(wakes(&started.cache), before);
}

#[tokio::test(start_paused = true)]
async fn test_a_read_of_a_token_expired_by_the_wall_clock_starts_the_refresh() {
    let started = start(config(), refreshed_by_70_seconds).await;
    let begin = Instant::now();

    // At 10 s on the monotonic clock, the wall clock says 105 s after the request: the token has expired.
    sleep_until(begin, 10.0).await;
    sleep_machine(secs(105.0));
    assert!(matches!(header(&started.cache), Err(Error::TokenExpired)));
    tokio::time::sleep(Duration::from_millis(1)).await;

    assert_eq!(
        started.source.request_times(),
        vec![Duration::ZERO, secs(10.0)]
    );
    assert_eq!(header(&started.cache).unwrap(), "Bearer second");
}

#[tokio::test(start_paused = true)]
async fn test_the_refresh_task_ends_when_the_cache_is_dropped_during_a_request() {
    let mut started = start(config(), |number| match number {
        1 => Step::Token("first", Some(60)),
        _ => Step::Slow(secs(10.0), "second", Some(60)),
    })
    .await;
    let task = started.task.take().unwrap();
    let source = Arc::clone(&started.source);
    // The refresh between 24 s and 30 s takes 10 s.
    tokio::time::sleep(secs(31.0)).await;
    assert_eq!(source.count(), 2);

    drop(started);
    tokio::time::sleep(Duration::from_millis(1)).await;

    assert!(task.is_finished());
}

#[tokio::test(start_paused = true)]
async fn test_readers_gone_wins_over_a_wait_that_ends_at_the_same_time() {
    let token = Token::new(
        &response("t", None),
        TokenId {
            cache: 1,
            generation: 1,
        },
        (Instant::now(), SystemTime::now()),
        secs(60.0),
        Duration::from_secs(30),
    )
    .unwrap();
    let (sender, receiver) = watch::channel(State::new(token));
    drop(receiver);

    let result = until_readers_gone(&sender, std::future::ready(())).await;

    assert!(
        result.is_err(),
        "no request starts once every reader is gone"
    );
}

#[tokio::test(start_paused = true)]
async fn test_a_refresh_tolerance_of_zero_still_refreshes_before_expiry() {
    let mut config = config();
    config.tolerance = Duration::ZERO;
    // A token of 2 s is refreshed between 1.5 s and 1.7 s.
    let started = start(config, |_| Step::Token("t", Some(2))).await;
    let begin = Instant::now();

    let mut failed_reads = 0;
    while begin.elapsed() < secs(3.5) {
        if header(&started.cache).is_err() {
            failed_reads += 1;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }

    assert_eq!(failed_reads, 0);
    let gaps = started.source.gaps();
    assert_eq!(gaps.len(), 2, "{gaps:?}");
    for gap in gaps {
        assert_between(gap, 1.5, 1.7);
    }
}
