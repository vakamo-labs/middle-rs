#[cfg(not(feature = "runtime-tokio"))]
compile_error!(
    "If `client-credentials` feature is enabled, an async runtime, such as `runtime-tokio`, must be enabled too."
);

use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use http::HeaderValue;
use tracing::Instrument;

use super::Authorizer;
use crate::{
    error::{ConfigError, DisplayChain, Error},
    token_endpoint::{self, ClientAuth, Secret, TokenRequest, TokenResponse},
};

/// Minimum delay the refresh loop waits between refresh attempts, even when the
/// token is already within (or past) its refresh tolerance. Prevents hammering
/// the identity provider for very short-lived tokens or during an outage.
const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(1);

/// How long one token request may take, reading the answer included.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// How long connecting to the token endpoint may take with the HTTP client middle builds.
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
/// Authenticate with an `OAuth2` server using client credentials.
///
/// Fetches a new token from the token endpoint of the Identity Provider.
/// The token is refreshed automatically refreshed before expiration. The amount of time before
/// expiration that the token is refreshed can be set with [`ClientCredentialAuthorizerBuilder::refresh_tolerance`].
/// If the server token response does not contain the `expires_in` field, the token is assumed to be valid
/// indefinitely and will not be refreshed.
///
/// A handle to the refresh task is returned by [`ClientCredentialAuthorizer::refresh_task`].
/// When the handle to the `ClientCredentialAuthorizer` is dropped, the refresh task is aborted.
///
/// Uses `Arc` internally for cheap cloning.
///
/// ## Tonic
/// If the `tonic` feature is enabled, [`tonic::service::Interceptor`] is implemented for
/// [`ClientCredentialAuthorizer`]. The interceptor does not insert the access token if the intercepted call
/// already has an `Authorization` header. The request fails with an `unauthenticated` status if the token
/// could not be refreshed.
///
pub struct ClientCredentialAuthorizer {
    inner: Arc<Inner>,
    refresh_task: Option<Arc<RefreshTask>>,
}

/// Another name for [`ClientCredentialAuthorizer`].
pub type BasicClientCredentialAuthorizer = ClientCredentialAuthorizer;

#[derive(Debug)]
pub struct RefreshTask {
    #[cfg(feature = "runtime-tokio")]
    task: tokio::task::JoinHandle<()>,
}

impl RefreshTask {
    /// Get a reference to the task.
    #[cfg(feature = "runtime-tokio")]
    #[must_use]
    pub fn task(&self) -> &tokio::task::JoinHandle<()> {
        &self.task
    }
}

impl ClientCredentialAuthorizer {
    /// Create a new [`ClientCredentialAuthorizerBuilder`]. The client authenticates with HTTP Basic (RFC 6749, section 2.3.1).
    #[must_use]
    pub fn basic_builder(
        client_id: &str,
        client_secret: &str,
        token_url: url::Url,
    ) -> ClientCredentialAuthorizerBuilder {
        ClientCredentialAuthorizerBuilder::new(client_id, client_secret, token_url)
    }

    #[cfg(feature = "runtime-tokio")]
    #[must_use]
    /// Get a reference to the refresh task.
    pub fn refresh_task(&self) -> Option<&RefreshTask> {
        self.refresh_task.as_deref()
    }
}

impl Drop for RefreshTask {
    fn drop(&mut self) {
        tracing::debug!("Stopping credential refresh task.");
        #[cfg(feature = "runtime-tokio")]
        self.task.abort();
    }
}

#[derive(Debug)]
struct Inner {
    request: TokenRequest,
    http_client: reqwest::Client,
    timeout: Duration,
    max_retries: u32,
    retry_interval: Duration,
    token: RwLock<Result<Token, Error>>,
    tolerance: Duration,
}

#[derive(veil::Redact, Clone)]
// `token` / `token_expiry` intentionally share the struct name for clarity.
#[allow(clippy::struct_field_names)]
struct Token {
    #[redact]
    token: Arc<HeaderValue>,
    // Pre-computed tonic representation, cloned cheaply on the interceptor hot
    // path instead of re-parsing the header on every request.
    #[cfg(feature = "tonic")]
    #[redact]
    metadata: tonic::metadata::MetadataValue<tonic::metadata::Ascii>,
    token_expiry: Option<Instant>,
}

impl Token {
    fn from_response(response: &TokenResponse) -> Result<Self, Error> {
        let built = super::bearer_header(response.access_token.as_str())?;
        Ok(Token {
            token: built.header,
            #[cfg(feature = "tonic")]
            metadata: built.metadata,
            // `expires_in` is at most one year, so the addition does not overflow.
            token_expiry: response
                .expires_in
                .and_then(|expires_in| Instant::now().checked_add(expires_in)),
        })
    }

    /// Returns `true` if the token has a known expiry that has already passed.
    /// Tokens without an expiry are treated as never expiring.
    fn is_expired(&self) -> bool {
        self.token_expiry
            .is_some_and(|expiry| Instant::now() >= expiry)
    }
}

/// Builder for [`ClientCredentialAuthorizer`].
///
/// The following configurations are available:
/// * `max_retries`: Number of consecutive retries for token requests. Default is 3. Only errors a retry can fix are retried, see [`Error::is_retryable`].
/// * `retry_interval`: Interval between consecutive retries. Default is 10ms.
/// * `timeout`: How long one token request may take, reading the answer included. Default is 30 seconds.
/// * `http_client`: Custom `reqwest::Client` to use for token requests. Default is a client with redirects disabled and a connect timeout of 10 seconds.
/// * `scopes`: Scopes to request in the token. Empty by default.
/// * `extra_params`: Extra parameters to include in the token request. Empty by default.
/// * `enable_refresh`: Enable automatic token refresh. Default is `true`.
///
/// `Debug` shows the names of the extra parameters, not their values, and never the client secret.
#[derive(Clone)]
pub struct ClientCredentialAuthorizerBuilder {
    token_url: url::Url,
    client_auth: ClientAuth,
    max_retries: Option<u32>,
    retry_interval: Option<Duration>,
    timeout: Option<Duration>,
    http_client: Option<reqwest::Client>,
    scopes: Vec<String>,
    extra_params: HashMap<String, String>,
    enable_refresh: bool,
    refresh_tolerance: Option<Duration>,
}

/// Another name for [`ClientCredentialAuthorizerBuilder`].
pub type BasicClientCredentialAuthorizerBuilder = ClientCredentialAuthorizerBuilder;

impl fmt::Debug for ClientCredentialAuthorizerBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let token_url = token_endpoint::redacted_url(&self.token_url);
        let extra_param_names: Vec<&String> = self.extra_params.keys().collect();
        f.debug_struct("ClientCredentialAuthorizerBuilder")
            .field("token_url", &token_url.as_str())
            .field("client_auth", &self.client_auth)
            .field("max_retries", &self.max_retries)
            .field("retry_interval", &self.retry_interval)
            .field("timeout", &self.timeout)
            .field("http_client", &self.http_client)
            .field("scopes", &self.scopes)
            .field("extra_param_names", &extra_param_names)
            .field("enable_refresh", &self.enable_refresh)
            .field("refresh_tolerance", &self.refresh_tolerance)
            .finish()
    }
}

impl ClientCredentialAuthorizerBuilder {
    #[must_use]
    /// Create a new [`ClientCredentialAuthorizer`] from a client id, client secret and token url.
    /// The client authenticates with HTTP Basic (RFC 6749, section 2.3.1).
    /// Initializes with 3 retries and a retry interval of 10ms.
    pub fn new(client_id: &str, client_secret: &str, token_url: url::Url) -> Self {
        Self {
            token_url,
            client_auth: ClientAuth::SecretBasic {
                client_id: client_id.to_string(),
                secret: Secret::new(client_secret),
            },
            max_retries: None,
            retry_interval: None,
            timeout: None,
            http_client: None,
            scopes: Vec::new(),
            extra_params: HashMap::new(),
            enable_refresh: true,
            refresh_tolerance: None,
        }
    }

    /// Optionally specify the `reqwest::Client` to use for token requests.
    ///
    /// middle uses the client as it is. If the client follows redirects, which reqwest does by default,
    /// a 307 or 308 answer of the token endpoint makes reqwest send the form body again to the URL the answer names.
    /// middle refuses an answer whose final URL is not the token URL, but the other URL has already received the request,
    /// and an answer after a chain of redirects that ends at the token URL counts as the token endpoint's answer.
    /// Set `redirect(reqwest::redirect::Policy::none())` on the client to prevent this.
    ///
    /// If not set, middle builds a client with redirects disabled and a connect timeout of 10 seconds.
    ///
    /// Use this method if you want to set custom headers or timeouts.
    #[must_use]
    pub fn set_http_client(mut self, client: reqwest::Client) -> Self {
        self.http_client = Some(client);
        self
    }

    /// Optionally set the maximum number of retries when fetching a new token.
    /// Only errors a retry can fix are retried, see [`Error::is_retryable`].
    /// The default is 3.
    #[must_use]
    pub fn set_max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = Some(max_retries);
        self
    }

    /// Optionally set the retry interval when fetching a new token.
    /// The default is 10ms.
    #[must_use]
    pub fn set_retry_interval(mut self, retry_interval: std::time::Duration) -> Self {
        self.retry_interval = Some(retry_interval);
        self
    }

    /// Optionally set how long one token request may take, reading the answer included.
    /// This also applies to a client set with [`Self::set_http_client`].
    /// The default is 30 seconds.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Add a scope to the token request. An empty scope is skipped.
    /// [`Self::build`] fails if the scope is not valid (RFC 6749, section 3.3), for example if it contains a space.
    #[must_use]
    pub fn add_scope(self, scope: &str) -> Self {
        self.add_scopes(&[scope])
    }

    /// Add multiple scopes to the token request. Empty scopes are skipped, so a setting split on single spaces works with doubled or trailing spaces.
    /// [`Self::build`] fails if a scope is not valid (RFC 6749, section 3.3), for example if it contains a space.
    #[must_use]
    pub fn add_scopes<I>(mut self, scopes: &[I]) -> Self
    where
        I: AsRef<str>,
    {
        self.scopes.extend(
            scopes
                .iter()
                .map(AsRef::as_ref)
                .filter(|scope| !scope.is_empty())
                .map(str::to_string),
        );
        self
    }

    /// Appends an extra param to the token request.
    /// A second call with the same name replaces the value.
    ///
    /// [`Self::build`] fails for a parameter middle sets itself: `grant_type`, `scope`, `client_id`, `client_secret`,
    /// `client_assertion`, `client_assertion_type` and `assertion`.
    #[must_use]
    pub fn add_extra_param(mut self, name: &str, value: &str) -> Self {
        self.extra_params
            .insert(name.to_string(), value.to_string());
        self
    }

    /// Disable automatic token refresh.
    #[must_use]
    pub fn disable_refresh(mut self) -> Self {
        self.enable_refresh = false;
        self
    }

    /// Set the refresh tolerance.
    /// Tokens are refreshed `tolerance` before expiry.
    /// Default is 30 seconds.
    #[must_use]
    pub fn refresh_tolerance(mut self, tolerance: Duration) -> Self {
        self.refresh_tolerance = Some(tolerance);
        self
    }

    /// Build the [`ClientCredentialAuthorizer`].
    /// This triggers an initial token fetch.
    ///
    /// # Errors
    ///
    /// - [`Error::Config`] if the token URL, a scope or an extra parameter is not valid, or the HTTP client cannot be built.
    /// - Any error of the initial token fetch.
    pub async fn build(self) -> Result<ClientCredentialAuthorizer, Error> {
        let request = TokenRequest::new(
            self.token_url,
            self.client_auth,
            &self.scopes,
            self.extra_params,
        )?;
        let http_client = match self.http_client {
            Some(http_client) => http_client,
            None => reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(DEFAULT_CONNECT_TIMEOUT)
                .build()
                .map_err(|error| ConfigError::HttpClient(Arc::new(error)))?,
        };

        let retry_interval = self
            .retry_interval
            .unwrap_or_else(|| std::time::Duration::from_millis(10));
        let max_retries = self.max_retries.unwrap_or(3);
        let timeout = self.timeout.unwrap_or(DEFAULT_TIMEOUT);

        // Fetch initial token
        let response =
            fetch_token(&request, &http_client, timeout, max_retries, retry_interval).await?;
        let token = Token::from_response(&response)?;

        let inner = Inner {
            request,
            http_client,
            timeout,
            max_retries,
            retry_interval,
            token: RwLock::new(Ok(token)),
            tolerance: self.refresh_tolerance.unwrap_or(Duration::from_secs(30)),
        };

        let inner_arc = Arc::new(inner);

        // Launch refresh task in background
        let refresh_task = if self.enable_refresh && response.expires_in.is_some() {
            tracing::debug!(
                "Starting refresh task to refresh tokens for client `{}` before expiry.",
                inner_arc.request.client_id()
            );
            let inner_cloned = inner_arc.clone();
            #[cfg(feature = "runtime-tokio")]
            let refresh_task = tokio::spawn(async move {
                refresh_task(inner_cloned).await;
            });

            Some(Arc::new(RefreshTask { task: refresh_task }))
        } else {
            tracing::debug!(
                "Token does not expire. Disabling refresh task for client `{}`.",
                inner_arc.request.client_id()
            );
            None
        };

        Ok(ClientCredentialAuthorizer {
            inner: inner_arc,
            refresh_task,
        })
    }
}

/// Background task to refresh the token before it expires.
/// If refresh fails, the error is stored in the token state. Retries continue every 60 seconds.
async fn refresh_task(inner: Arc<Inner>) {
    tracing::debug!(
        "Starting the refresh loop for client `{}`",
        inner.request.client_id()
    );
    loop {
        // Determine if the token needs to be refreshed
        let now = Instant::now();

        let span = tracing::span!(
            tracing::Level::TRACE,
            "refresh_task",
            client_id = inner.request.client_id()
        );

        // Decide how long to sleep before the next refresh. Returns `None` when the
        // token never expires and the refresh loop should stop entirely.
        // The lock is only held inside this synchronous closure, never across an
        // `.await` (see issue #11).
        let sleep_duration = span.in_scope(|| -> Option<Duration> {
            let state_read_guard = inner.token.read().expect("Non-poisoned lock");

            // No valid token cached (a previous refresh failed and the old token
            // has expired): retry after `tolerance`.
            let Ok(token) = &*state_read_guard else {
                // Floor the retry delay so a small/zero `tolerance` can't turn a
                // sustained outage into a tight loop against the IdP.
                let retry_in = inner.tolerance.max(MIN_REFRESH_INTERVAL);
                tracing::trace!(
                    "No valid token available. Retrying in {}s",
                    retry_in.as_secs()
                );
                return Some(retry_in);
            };

            // Token never expires: stop the refresh loop entirely.
            let Some(expiry) = token.token_expiry else {
                tracing::debug!("Token does not expire. Disabling refresh task.");
                return None;
            };

            let expires_in = expiry.saturating_duration_since(now);
            if expires_in < inner.tolerance {
                // The token already lives for less than `tolerance`, so we cannot
                // honour the full tolerance. Refresh roughly halfway through the
                // remaining lifetime (never below `MIN_REFRESH_INTERVAL`) so the
                // token is renewed before it expires without busy-looping the IdP.
                let next_refresh = (expires_in / 2).max(MIN_REFRESH_INTERVAL);
                tracing::debug!(
                    "Token lifetime ({}s) is shorter than the refresh tolerance ({}s). Refreshing in {}s.",
                    expires_in.as_secs(),
                    inner.tolerance.as_secs(),
                    next_refresh.as_secs()
                );
                Some(next_refresh)
            } else {
                // Refresh `tolerance` before expiry, but never below the floor so a
                // token whose lifetime only barely exceeds `tolerance` can't spin
                // the loop against the IdP.
                let next_refresh = expires_in
                    .saturating_sub(inner.tolerance)
                    .max(MIN_REFRESH_INTERVAL);
                tracing::trace!(
                    "Token expires in {}s. Refreshing in {}s.",
                    expires_in.as_secs(),
                    next_refresh.as_secs()
                );
                Some(next_refresh)
            }
        });

        let Some(sleep_duration) = sleep_duration else {
            return;
        };

        // `refresh_token` already records the result, including failures.
        // Instrument the async work with the span instead of holding an `enter`
        // guard across the `.await` points.
        async {
            tracing::trace!("Sleeping for {}s", sleep_duration.as_secs());
            #[cfg(feature = "runtime-tokio")]
            tokio::time::sleep(sleep_duration).await;
            tracing::trace!("Refreshing token");
            inner.refresh_token().await.ok();
        }
        .instrument(span)
        .await;
    }
}

/// Requests a token, retrying errors a retry can fix up to `max_retries` times.
async fn fetch_token(
    request: &TokenRequest,
    http_client: &reqwest::Client,
    timeout: Duration,
    max_retries: u32,
    retry_interval: Duration,
) -> Result<TokenResponse, Error> {
    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        match token_endpoint::request_token(http_client, request, timeout).await {
            Ok(response) => {
                tracing::debug!(
                    "Successfully fetched a token for client `{}`. Token expires in {:?}s",
                    request.client_id(),
                    response.expires_in.map(|d| d.as_secs())
                );
                return Ok(response);
            }
            Err(error) if !error.is_retryable() => {
                tracing::error!(
                    "Failed to fetch a token for client `{}`; a retry cannot fix this: {}",
                    request.client_id(),
                    DisplayChain(&error)
                );
                return Err(error);
            }
            Err(error) if attempt > max_retries => {
                tracing::error!(
                    "Failed to fetch a token for client `{}` after {attempt} attempts: {}",
                    request.client_id(),
                    DisplayChain(&error)
                );
                return Err(error);
            }
            Err(error) => {
                tracing::debug!(
                    "Failed to fetch a token for client `{}`: {}. Retrying in {}ms",
                    request.client_id(),
                    DisplayChain(&error),
                    retry_interval.as_millis()
                );
                #[cfg(feature = "runtime-tokio")]
                tokio::time::sleep(retry_interval).await;
            }
        }
    }
}

impl Inner {
    /// Refresh the token.
    /// If token refresh fails, the error is stored in the token state and returned.
    async fn refresh_token(&self) -> Result<TokenResponse, Error> {
        let response = fetch_token(
            &self.request,
            &self.http_client,
            self.timeout,
            self.max_retries,
            self.retry_interval,
        )
        .await;

        // Unwrap RWLock to propagate poison (writer panicked)
        let mut state_write_guard = self.token.write().expect("Non-poisoned lock");

        match response.as_ref() {
            Ok(response) => {
                // Successful refresh: store the new token (or a conversion error if
                // the access token is not a valid header value).
                *state_write_guard = Token::from_response(response);
            }
            Err(e) => {
                tracing::error!("Failed to refresh token: {}", DisplayChain(e));
                // Keep serving the currently cached token while it is still valid;
                // only surface the refresh error once we no longer have a usable
                // token. This prevents a transient IdP outage during the refresh
                // window (which fires `tolerance` before expiry) from discarding an
                // otherwise-valid token.
                let keep_existing = matches!(&*state_write_guard, Ok(token) if !token.is_expired());
                if !keep_existing {
                    *state_write_guard = Err(e.clone());
                }
            }
        }

        drop(state_write_guard);
        response
    }
}

impl Authorizer for ClientCredentialAuthorizer {
    fn authorization_header(&self) -> Result<Arc<HeaderValue>, Error> {
        // Unwrap RWLock to propagate poison (writer panicked)
        let state_read_guard = self.inner.token.read().expect("Non-poisoned lock");

        match &*state_read_guard {
            // A cached token that has outlived its expiry (a refresh has been
            // failing) must not be handed out, even though we keep it around so
            // the refresh task can decide when to give up.
            Ok(token) if token.is_expired() => Err(Error::TokenExpired),
            Ok(token) => Ok(token.token.clone()),
            Err(e) => Err(e.clone()),
        }
    }

    #[cfg(feature = "tonic")]
    fn authorization_header_tonic(
        &self,
    ) -> std::result::Result<tonic::metadata::MetadataValue<tonic::metadata::Ascii>, tonic::Status>
    {
        // Clone the pre-computed metadata value (cheap, `Bytes`-backed) instead of
        // re-parsing the header string on every request.
        let state_read_guard = self.inner.token.read().expect("Non-poisoned lock");
        match &*state_read_guard {
            Ok(token) if token.is_expired() => Err(tonic::Status::unauthenticated(
                Error::TokenExpired.to_string(),
            )),
            Ok(token) => Ok(token.metadata.clone()),
            Err(e) => Err(tonic::Status::unauthenticated(e.to_string())),
        }
    }
}

#[cfg(feature = "tonic")]
impl tonic::service::Interceptor for ClientCredentialAuthorizer {
    fn call(
        &mut self,
        request: tonic::Request<()>,
    ) -> std::result::Result<tonic::Request<()>, tonic::Status> {
        let mut request = request;
        let metadata = request.metadata_mut();
        if !metadata.contains_key(http::header::AUTHORIZATION.as_str()) {
            metadata.insert(
                http::header::AUTHORIZATION.as_str(),
                self.authorization_header_tonic()?,
            );
        }
        Ok(request)
    }
}

#[cfg(test)]
mod test {
    use http::header::CONTENT_TYPE;
    use tracing_test::traced_test;

    use super::*;

    #[tokio::test]
    #[traced_test]
    async fn test_client_credentials() {
        let mut oauth_server = mockito::Server::new_async().await;
        let url = oauth_server.url();
        let mock = oauth_server
            .mock("POST", "/my-tenant/oauth2/token")
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::Regex("grant_type=client_credentials".to_string()),
                mockito::Matcher::Regex("scope=my-scope\\+my-other-scope".to_string()),
            ]))
            .match_header("authorization", "Basic bXktY2xpZW50Om15LXNlY3JldA==")
            .match_header("accept", "application/json")
            .match_header("content-type", "application/x-www-form-urlencoded")
            .with_status(200)
            .with_header(CONTENT_TYPE.as_str(), "application/json")
            .with_body(
                serde_json::json!({
                    "access_token": "my-issued-token",
                    "token_type": "Bearer",
                    "expires_in": 3600
                })
                .to_string(),
            )
            .create();
        let authorizer = BasicClientCredentialAuthorizerBuilder::new(
            "my-client",
            "my-secret",
            format!("{url}/my-tenant/oauth2/token").parse().unwrap(),
        )
        .add_scope("my-scope")
        .add_scope("my-other-scope")
        .build()
        .await;

        // verify mock was called
        mock.assert();

        let authorizer = authorizer.unwrap();

        let header = authorizer.authorization_header().unwrap();
        assert_eq!(header.to_str().unwrap(), "Bearer my-issued-token");
    }

    #[tokio::test]
    #[traced_test]
    async fn test_refresh() {
        let mut oauth_server = mockito::Server::new_async().await;
        let url = oauth_server.url();
        let mock = oauth_server
            .mock("POST", "/my-tenant/oauth2/token")
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::Regex("grant_type=client_credentials".to_string()),
                mockito::Matcher::Regex("scope=my-scope\\+my-other-scope".to_string()),
            ]))
            .match_header("authorization", "Basic bXktY2xpZW50Om15LXNlY3JldA==")
            .match_header("accept", "application/json")
            .match_header("content-type", "application/x-www-form-urlencoded")
            .with_status(200)
            .with_header(CONTENT_TYPE.as_str(), "application/json")
            .with_body(
                serde_json::json!({
                    "access_token": "my-issued-token",
                    "token_type": "Bearer",
                    "expires_in": 1
                })
                .to_string(),
            )
            .expect(2)
            .create();
        let authorizer = BasicClientCredentialAuthorizerBuilder::new(
            "my-client",
            "my-secret",
            format!("{url}/my-tenant/oauth2/token").parse().unwrap(),
        )
        .add_scope("my-scope")
        .add_scope("my-other-scope")
        .refresh_tolerance(Duration::from_secs(1))
        .build()
        .await;

        tokio::time::sleep(tokio::time::Duration::from_millis(1500)).await;

        mock.assert();

        let authorizer = authorizer.unwrap();

        let header = authorizer.authorization_header().unwrap();
        assert_eq!(header.to_str().unwrap(), "Bearer my-issued-token");
    }

    #[tokio::test]
    #[traced_test]
    async fn test_second_refresh() {
        let mut oauth_server = mockito::Server::new_async().await;
        let url = oauth_server.url();
        let mock = oauth_server
            .mock("POST", "/my-tenant/oauth2/token")
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::Regex("grant_type=client_credentials".to_string()),
                mockito::Matcher::Regex("scope=my-scope\\+my-other-scope".to_string()),
            ]))
            .match_header("authorization", "Basic bXktY2xpZW50Om15LXNlY3JldA==")
            .match_header("accept", "application/json")
            .match_header("content-type", "application/x-www-form-urlencoded")
            .with_status(200)
            .with_header(CONTENT_TYPE.as_str(), "application/json")
            .with_body(
                serde_json::json!({
                    "access_token": "my-issued-token",
                    "token_type": "Bearer",
                    "expires_in": 2
                })
                .to_string(),
            )
            .expect(3)
            .create();
        let authorizer = BasicClientCredentialAuthorizerBuilder::new(
            "my-client",
            "my-secret",
            format!("{url}/my-tenant/oauth2/token").parse().unwrap(),
        )
        .add_scope("my-scope")
        .add_scope("my-other-scope")
        .refresh_tolerance(Duration::from_secs(0))
        .build()
        .await;

        tokio::time::sleep(tokio::time::Duration::from_millis(4500)).await;

        mock.assert();

        let authorizer = authorizer.unwrap();

        let header = authorizer.authorization_header().unwrap();
        assert_eq!(header.to_str().unwrap(), "Bearer my-issued-token");
    }

    #[tokio::test]
    #[traced_test]
    async fn test_no_refresh_required() {
        let mut oauth_server = mockito::Server::new_async().await;
        let url = oauth_server.url();
        let mock = oauth_server
            .mock("POST", "/my-tenant/oauth2/token")
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::Regex("grant_type=client_credentials".to_string()),
                mockito::Matcher::Regex("scope=my-scope\\+my-other-scope".to_string()),
            ]))
            .match_header("authorization", "Basic bXktY2xpZW50Om15LXNlY3JldA==")
            .match_header("accept", "application/json")
            .match_header("content-type", "application/x-www-form-urlencoded")
            .with_status(200)
            .with_header(CONTENT_TYPE.as_str(), "application/json")
            .with_body(
                serde_json::json!({
                    "access_token": "my-issued-token",
                    "token_type": "Bearer"
                })
                .to_string(),
            )
            .expect(1)
            .create();
        let authorizer = BasicClientCredentialAuthorizerBuilder::new(
            "my-client",
            "my-secret",
            format!("{url}/my-tenant/oauth2/token").parse().unwrap(),
        )
        .add_scope("my-scope")
        .add_scope("my-other-scope")
        .build()
        .await;

        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        mock.assert();

        let authorizer = authorizer.unwrap();

        let header = authorizer.authorization_header().unwrap();
        assert_eq!(header.to_str().unwrap(), "Bearer my-issued-token");
    }

    #[tokio::test]
    #[traced_test]
    async fn test_refresh_failure_keeps_valid_token() {
        let mut oauth_server = mockito::Server::new_async().await;
        let url = oauth_server.url();
        // Initial fetch succeeds with a long-lived token. Refresh is disabled so
        // the background task cannot race with the manual refresh below.
        let success = oauth_server
            .mock("POST", "/token")
            .with_status(200)
            .with_header(CONTENT_TYPE.as_str(), "application/json")
            .with_body(
                serde_json::json!({
                    "access_token": "first-token",
                    "token_type": "bearer",
                    "expires_in": 3600
                })
                .to_string(),
            )
            .expect(1)
            .create_async()
            .await;

        let authorizer = BasicClientCredentialAuthorizerBuilder::new(
            "my-client",
            "my-secret",
            format!("{url}/token").parse().unwrap(),
        )
        .disable_refresh()
        .build()
        .await
        .unwrap();

        success.assert_async().await;
        assert_eq!(
            authorizer.authorization_header().unwrap().to_str().unwrap(),
            "Bearer first-token"
        );

        // The IdP now fails for every token request.
        let failure = oauth_server
            .mock("POST", "/token")
            .with_status(500)
            .expect_at_least(1)
            .create_async()
            .await;

        // A failed refresh must NOT discard the still-valid cached token.
        let result = authorizer.inner.refresh_token().await;
        assert!(result.is_err(), "refresh should report the failure");
        failure.assert_async().await;
        assert_eq!(
            authorizer.authorization_header().unwrap().to_str().unwrap(),
            "Bearer first-token",
            "a still-valid token must be retained when refresh fails"
        );
    }

    #[tokio::test]
    #[traced_test]
    async fn test_refresh_failure_surfaces_error_once_token_expired() {
        let mut oauth_server = mockito::Server::new_async().await;
        let url = oauth_server.url();
        let success = oauth_server
            .mock("POST", "/token")
            .with_status(200)
            .with_header(CONTENT_TYPE.as_str(), "application/json")
            .with_body(
                serde_json::json!({
                    "access_token": "first-token",
                    "token_type": "bearer",
                    "expires_in": 3600
                })
                .to_string(),
            )
            .expect(1)
            .create_async()
            .await;

        let authorizer = BasicClientCredentialAuthorizerBuilder::new(
            "my-client",
            "my-secret",
            format!("{url}/token").parse().unwrap(),
        )
        .disable_refresh()
        .build()
        .await
        .unwrap();
        success.assert_async().await;

        // Force the cached token to be already expired.
        {
            let mut guard = authorizer.inner.token.write().unwrap();
            if let Ok(token) = guard.as_mut() {
                token.token_expiry = Some(
                    Instant::now()
                        .checked_sub(Duration::from_secs(1))
                        .expect("monotonic clock is at least 1s past its epoch"),
                );
            }
        }

        let _failure = oauth_server
            .mock("POST", "/token")
            .with_status(500)
            .expect_at_least(1)
            .create_async()
            .await;

        // With no usable token left, the refresh error must be surfaced.
        let result = authorizer.inner.refresh_token().await;
        assert!(result.is_err());
        assert!(
            authorizer.authorization_header().is_err(),
            "an expired token must not be served after a failed refresh"
        );
    }

    #[tokio::test]
    #[traced_test]
    async fn test_expired_token_not_served_on_read() {
        let mut oauth_server = mockito::Server::new_async().await;
        let url = oauth_server.url();
        let success = oauth_server
            .mock("POST", "/token")
            .with_status(200)
            .with_header(CONTENT_TYPE.as_str(), "application/json")
            .with_body(
                serde_json::json!({
                    "access_token": "first-token",
                    "token_type": "bearer",
                    "expires_in": 3600
                })
                .to_string(),
            )
            .expect(1)
            .create_async()
            .await;

        let authorizer = BasicClientCredentialAuthorizerBuilder::new(
            "my-client",
            "my-secret",
            format!("{url}/token").parse().unwrap(),
        )
        .disable_refresh()
        .build()
        .await
        .unwrap();
        success.assert_async().await;
        assert!(authorizer.authorization_header().is_ok());

        // Force-expire the cached token. The read path must reject it without any
        // refresh having run.
        {
            let mut guard = authorizer.inner.token.write().unwrap();
            if let Ok(token) = guard.as_mut() {
                token.token_expiry = Some(
                    Instant::now()
                        .checked_sub(Duration::from_secs(1))
                        .expect("monotonic clock is at least 1s past its epoch"),
                );
            }
        }

        assert!(matches!(
            authorizer.authorization_header(),
            Err(Error::TokenExpired)
        ));
    }

    #[tokio::test]
    #[traced_test]
    async fn test_short_lived_token_refreshes_before_expiry() {
        let mut oauth_server = mockito::Server::new_async().await;
        let url = oauth_server.url();
        // Token lifetime (2s) is shorter than the refresh tolerance (10s), so the
        // loop must take the "refresh partway through remaining life" branch and
        // keep renewing (~1s cadence) instead of sleeping the full tolerance. With
        // the old behaviour it would sleep ~10s and only the initial fetch would
        // happen within the window below.
        let mock = oauth_server
            .mock("POST", "/token")
            .with_status(200)
            .with_header(CONTENT_TYPE.as_str(), "application/json")
            .with_body(
                serde_json::json!({
                    "access_token": "tok",
                    "token_type": "bearer",
                    "expires_in": 2
                })
                .to_string(),
            )
            .expect_at_least(2)
            .create_async()
            .await;

        let authorizer = BasicClientCredentialAuthorizerBuilder::new(
            "my-client",
            "my-secret",
            format!("{url}/token").parse().unwrap(),
        )
        .refresh_tolerance(Duration::from_secs(10))
        .build()
        .await
        .unwrap();

        tokio::time::sleep(tokio::time::Duration::from_millis(2500)).await;
        mock.assert_async().await;
        assert!(authorizer.authorization_header().is_ok());
    }
}
