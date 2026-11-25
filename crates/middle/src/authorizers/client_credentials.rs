#[cfg(not(feature = "runtime-tokio"))]
compile_error!(
    "If `client-credentials` feature is enabled, an async runtime, such as `runtime-tokio`, must be enabled too."
);

use std::{
    collections::HashMap,
    fmt,
    sync::Arc,
    time::{Duration, SystemTime},
};

use http::HeaderValue;

use super::Authorizer;
use crate::{
    cache::{BoxFuture, CacheConfig, Token, TokenCache, TokenId, TokenSource},
    error::{ConfigError, Error},
    token_endpoint::{self, ClientAuth, Secret, TokenRequest, TokenResponse},
};

/// How long one token request may take, reading the answer included.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// How long connecting to the token endpoint may take with the HTTP client middle builds.
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long before expiry a token is refreshed at the latest.
const DEFAULT_REFRESH_TOLERANCE: Duration = Duration::from_secs(30);

/// The lifetime of a token if the token endpoint does not say.
const DEFAULT_TOKEN_LIFETIME: Duration = Duration::from_secs(5 * 60);

/// The shortest default token lifetime: a token is refreshed 1 s after its request at the earliest, so this lifetime makes the refresh come before expiry.
const MIN_DEFAULT_TOKEN_LIFETIME: Duration = Duration::from_secs(2);

/// How often `build()` retries the first token request.
const DEFAULT_MAX_RETRIES: u32 = 3;

#[derive(Debug, Clone)]
/// Authenticate with an `OAuth2` server using client credentials.
///
/// [`ClientCredentialAuthorizerBuilder::build`] fetches a token from the token endpoint of the identity provider.
/// A background task refreshes it at a random point in a window, which [`ClientCredentialAuthorizerBuilder::refresh_tolerance`] describes.
/// If a refresh fails, the current token stays in use while it is valid, and the task retries with a backoff,
/// at the latest after half the time the token has left.
/// If the token endpoint sends no `expires_in`, the token lives until the `exp` of the access token if it is a JWT,
/// or else for [`ClientCredentialAuthorizerBuilder::default_token_lifetime`].
///
/// [`Authorizer::authorization_header`] and [`Self::token_header`] never wait. [`Self::wait_for_header`] waits for a refresh if the token has expired,
/// and [`Self::invalidate`] drops a token that a server rejected.
///
/// A handle to the refresh task is returned by [`ClientCredentialAuthorizer::refresh_task`].
/// When the last clone of the `ClientCredentialAuthorizer` is dropped, the refresh task is aborted.
/// If the task ends for another reason, such as its runtime shutting down, the authorizer answers with
/// [`Error::RefreshStopped`] once the token has expired.
///
/// Uses `Arc` internally for cheap cloning.
///
/// ## Tonic
/// If the `tonic` feature is enabled, [`tonic::service::Interceptor`] is implemented for
/// [`ClientCredentialAuthorizer`]. The interceptor does not insert the access token if the intercepted call
/// already has an `Authorization` header. The request fails with an `unauthenticated` status if no valid token
/// is available.
///
pub struct ClientCredentialAuthorizer {
    inner: Arc<Inner>,
    refresh_task: Option<Arc<RefreshTask>>,
}

/// Another name for [`ClientCredentialAuthorizer`].
pub type BasicClientCredentialAuthorizer = ClientCredentialAuthorizer;

// The authorizer is shared between threads and tasks.
const _: () = {
    const fn assert_send_sync_static<T: Send + Sync + 'static>() {}
    assert_send_sync_static::<ClientCredentialAuthorizer>();
};

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
    /// Get a reference to the refresh task. `None` if refresh is disabled.
    pub fn refresh_task(&self) -> Option<&RefreshTask> {
        self.refresh_task.as_deref()
    }

    /// The header of the valid token, without waiting. Send it, and pass it to [`Self::invalidate`] if the server rejects it.
    ///
    /// # Errors
    ///
    /// If the token has expired or was invalidated: [`Error::RefreshStopped`] if no refresh task runs, else the error of the last token request,
    /// else [`Error::TokenExpired`].
    pub fn token_header(&self) -> Result<TokenHeader, Error> {
        self.inner.cache.read(token_header)
    }

    /// The header of a valid token.
    ///
    /// If the token has expired or was invalidated, asks the refresh task for a new token and waits for it,
    /// at most the [`ClientCredentialAuthorizerBuilder::timeout`]. After a failed request or repeated rejections (see [`Self::invalidate`]),
    /// the refresh task waits before the next request; if that wait ends after the timeout, this method returns at once.
    ///
    /// Cancelling the returned future cancels only the wait, never the request for a new token.
    ///
    /// # Errors
    ///
    /// If no valid token arrives: [`Error::RefreshStopped`] if no refresh task runs, else the error of the last token request,
    /// else [`Error::TokenExpired`].
    pub async fn wait_for_header(&self) -> Result<TokenHeader, Error> {
        self.inner.cache.wait(token_header).await
    }

    /// Drops the token of `rejected`, for example after a server answered with HTTP 401, and asks the refresh task for a new token.
    ///
    /// Does nothing if the authorizer has a newer token already, so concurrent calls for the same rejected token request one new token.
    /// Does nothing for a header of another authorizer.
    ///
    /// The new token is requested 1 s after the rejected one at the earliest. If the server keeps rejecting tokens soon after they arrive,
    /// for example because of a wrong audience or scope, each further rejection in a row waits longer: 2 s to 4 s after the rejected token was requested,
    /// then 4 s to 8 s, 8 s to 16 s, and then 15 s to 30 s. While middle waits like this, it logs a warning.
    /// A rejection counts only while its wait still lies ahead: a token that lasted longer than the wait is replaced at once and starts a new series.
    /// A token that lasts until its refresh is due ends the series.
    ///
    /// The token is dropped for every user of this authorizer and its clones. If one server rejects tokens that another one accepts,
    /// use one authorizer per server, so that the rejections of one server do not take the token away from the other.
    pub fn invalidate(&self, rejected: &TokenHeader) {
        self.inner.cache.invalidate(rejected.token);
    }
}

impl Drop for RefreshTask {
    fn drop(&mut self) {
        tracing::debug!("Stopping credential refresh task.");
        #[cfg(feature = "runtime-tokio")]
        self.task.abort();
    }
}

struct Inner {
    source: Arc<ClientCredentials>,
    cache: TokenCache,
}

impl fmt::Debug for Inner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Inner")
            .field("request", &self.source.request)
            .field("cache", &self.cache)
            .finish()
    }
}

/// The `Authorization` header of one token, as [`ClientCredentialAuthorizer::token_header`] and [`ClientCredentialAuthorizer::wait_for_header`] return it.
///
/// Pass it to [`ClientCredentialAuthorizer::invalidate`] if a server rejects the token.
#[derive(Clone, veil::Redact)]
pub struct TokenHeader {
    #[redact]
    header: Arc<HeaderValue>,
    /// The authorizer and the generation of the token.
    token: TokenId,
}

impl TokenHeader {
    /// The header value: `Bearer` and the access token.
    #[must_use]
    pub fn header(&self) -> &Arc<HeaderValue> {
        &self.header
    }

    /// The header value: `Bearer` and the access token.
    #[must_use]
    pub fn into_header(self) -> Arc<HeaderValue> {
        self.header
    }
}

fn token_header(token: &Token) -> TokenHeader {
    TokenHeader {
        header: Arc::clone(token.header()),
        token: token.id(),
    }
}

/// Builder for [`ClientCredentialAuthorizer`].
///
/// The following configurations are available:
/// * `max_retries`: How often `build()` retries the first token request. Default is 3. Only errors a retry can fix are retried, see [`Error::is_retryable`].
/// * `timeout`: How long one token request may take, reading the answer included, and how long `build()` may take. Default is 30 seconds.
/// * `http_client`: Custom `reqwest::Client` to use for token requests. Default is a client with redirects disabled and a connect timeout of 10 seconds.
/// * `scopes`: Scopes to request in the token. Empty by default.
/// * `extra_params`: Extra parameters to include in the token request. Empty by default.
/// * `enable_refresh`: Enable automatic token refresh. Default is `true`.
/// * `refresh_tolerance`: How long before expiry a token is refreshed at the latest. Default is 30 seconds.
/// * `default_token_lifetime`: The lifetime of a token if the token endpoint does not say. Default is 5 minutes.
///
/// `Debug` shows the names of the extra parameters, not their values, and never the client secret.
#[derive(Clone)]
pub struct ClientCredentialAuthorizerBuilder {
    token_url: url::Url,
    client_auth: ClientAuth,
    max_retries: Option<u32>,
    timeout: Option<Duration>,
    http_client: Option<reqwest::Client>,
    scopes: Vec<String>,
    extra_params: HashMap<String, String>,
    enable_refresh: bool,
    refresh_tolerance: Option<Duration>,
    default_token_lifetime: Option<Duration>,
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
            .field("timeout", &self.timeout)
            .field("http_client", &self.http_client)
            .field("scopes", &self.scopes)
            .field("extra_param_names", &extra_param_names)
            .field("enable_refresh", &self.enable_refresh)
            .field("refresh_tolerance", &self.refresh_tolerance)
            .field("default_token_lifetime", &self.default_token_lifetime)
            .finish()
    }
}

impl ClientCredentialAuthorizerBuilder {
    #[must_use]
    /// Create a new [`ClientCredentialAuthorizer`] from a client id, client secret and token url.
    /// The client authenticates with HTTP Basic (RFC 6749, section 2.3.1).
    pub fn new(client_id: &str, client_secret: &str, token_url: url::Url) -> Self {
        Self {
            token_url,
            client_auth: ClientAuth::SecretBasic {
                client_id: client_id.to_string(),
                secret: Secret::new(client_secret),
            },
            max_retries: None,
            timeout: None,
            http_client: None,
            scopes: Vec::new(),
            extra_params: HashMap::new(),
            enable_refresh: true,
            refresh_tolerance: None,
            default_token_lifetime: None,
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

    /// Optionally set how often [`Self::build`] retries the first token request, within the [`Self::timeout`].
    /// Only errors a retry can fix are retried, see [`Error::is_retryable`].
    /// The default is 3.
    ///
    /// The refresh task retries until a request succeeds.
    ///
    /// After a failed token request, middle waits between 1 s and 2 s, doubling with each further failure up to 30 s,
    /// and longer if the token endpoint sends a `Retry-After` header.
    /// After an error a retry cannot fix, the refresh task waits about 5 minutes.
    #[must_use]
    pub fn set_max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = Some(max_retries);
        self
    }

    /// Optionally set how long one token request may take, reading the answer included.
    /// [`Self::build`] takes at most this long, retries included.
    /// While a token is valid, one refresh request may take at most half of the time the token has left, but at least 1 s.
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
    /// Once the first token has expired, the authorizer answers with [`Error::RefreshStopped`].
    #[must_use]
    pub fn disable_refresh(mut self) -> Self {
        self.enable_refresh = false;
        self
    }

    /// Set the refresh tolerance: how long before expiry the refresh window ends at the latest.
    ///
    /// A token is refreshed at a random point in a window that is 10 % of its lifetime wide and ends at 85 % of it.
    /// If that end is less than `tolerance` before expiry, the window moves earlier, so that it ends `tolerance` before expiry, but not before half the lifetime.
    /// For example, a token of 120 s with a tolerance of 30 s is refreshed between 78 s and 90 s, and a token shorter than twice the tolerance between 40 % and 50 % of its lifetime.
    /// A refresh never comes sooner than 1 s after the request, also when that is less than `tolerance` before expiry, so a token that lives 1 s or less expires before its refresh.
    /// Default is 30 seconds.
    #[must_use]
    pub fn refresh_tolerance(mut self, tolerance: Duration) -> Self {
        self.refresh_tolerance = Some(tolerance);
        self
    }

    /// Set how long a token lives if the token endpoint sends no `expires_in` and the access token is not a JWT with an `exp` in the future.
    /// Longer lifetimes are shortened to one year.
    /// Default is 5 minutes.
    ///
    /// [`Self::build`] fails for a lifetime shorter than 2 s: a token is refreshed 1 s after its request at the earliest, so a lifetime of at least 2 s makes the refresh come before the token expires.
    #[must_use]
    pub fn default_token_lifetime(mut self, lifetime: Duration) -> Self {
        self.default_token_lifetime = Some(lifetime);
        self
    }

    /// Build the [`ClientCredentialAuthorizer`].
    /// This triggers an initial token fetch, which takes at most the [`Self::timeout`], retries included.
    ///
    /// # Errors
    ///
    /// - [`Error::Config`] if the token URL, a scope or an extra parameter is not valid, the default token lifetime is shorter than 2 s, or the HTTP client cannot be built.
    /// - Any error of the initial token fetch.
    pub async fn build(self) -> Result<ClientCredentialAuthorizer, Error> {
        let default_lifetime = self
            .default_token_lifetime
            .unwrap_or(DEFAULT_TOKEN_LIFETIME);
        if default_lifetime < MIN_DEFAULT_TOKEN_LIFETIME {
            return Err(ConfigError::DefaultTokenLifetimeTooShort(default_lifetime).into());
        }
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
        let source = Arc::new(ClientCredentials {
            request,
            http_client,
        });
        let config = CacheConfig {
            client_id: source.request.client_id().to_string(),
            timeout: self.timeout.unwrap_or(DEFAULT_TIMEOUT),
            tolerance: self.refresh_tolerance.unwrap_or(DEFAULT_REFRESH_TOLERANCE),
            default_lifetime,
            first_token_retries: self.max_retries.unwrap_or(DEFAULT_MAX_RETRIES),
            refresh: self.enable_refresh,
            wall_clock: SystemTime::now,
        };

        let (cache, task) =
            TokenCache::start(Arc::clone(&source) as Arc<dyn TokenSource>, config).await?;
        Ok(ClientCredentialAuthorizer {
            inner: Arc::new(Inner { source, cache }),
            refresh_task: task.map(|task| Arc::new(RefreshTask { task })),
        })
    }
}

/// The client credentials grant (RFC 6749, section 4.4).
#[derive(Debug)]
struct ClientCredentials {
    request: TokenRequest,
    http_client: reqwest::Client,
}

impl TokenSource for ClientCredentials {
    fn fetch(&self) -> BoxFuture<'_, Result<TokenResponse, Error>> {
        Box::pin(token_endpoint::request_token(
            &self.http_client,
            &self.request,
        ))
    }
}

impl Authorizer for ClientCredentialAuthorizer {
    fn authorization_header(&self) -> Result<Arc<HeaderValue>, Error> {
        self.inner.cache.read(|token| Arc::clone(token.header()))
    }

    #[cfg(feature = "tonic")]
    fn authorization_header_tonic(
        &self,
    ) -> std::result::Result<tonic::metadata::MetadataValue<tonic::metadata::Ascii>, tonic::Status>
    {
        // The metadata value was built with the token, so this only clones it (cheap, `Bytes`-backed).
        self.inner
            .cache
            .read(|token| token.metadata().clone())
            .map_err(|error| tonic::Status::unauthenticated(error.to_string()))
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
    async fn test_a_token_without_expires_in_is_not_refreshed_at_once() {
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
    async fn test_waiting_for_a_header_can_run_in_another_task() {
        let mut oauth_server = mockito::Server::new_async().await;
        let url = oauth_server.url();
        let _mock = oauth_server
            .mock("POST", "/token")
            .with_status(200)
            .with_header(CONTENT_TYPE.as_str(), "application/json")
            .with_body(
                serde_json::json!({
                    "access_token": "tok",
                    "token_type": "bearer",
                    "expires_in": 3600
                })
                .to_string(),
            )
            .create_async()
            .await;
        let authorizer = BasicClientCredentialAuthorizerBuilder::new(
            "my-client",
            "my-secret",
            format!("{url}/token").parse().unwrap(),
        )
        .build()
        .await
        .unwrap();

        // `tokio::spawn` needs a future that is `Send` and `'static`.
        let header = tokio::spawn(async move { authorizer.wait_for_header().await })
            .await
            .unwrap()
            .unwrap();

        assert_eq!(header.header().to_str().unwrap(), "Bearer tok");
        assert!(!format!("{header:?}").contains("Bearer"), "{header:?}");
    }
}
