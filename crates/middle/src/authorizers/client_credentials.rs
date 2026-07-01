#[cfg(not(feature = "runtime-tokio"))]
compile_error!(
    "If `client-credentials` feature is enabled, an async runtime, such as `runtime-tokio`, must be enabled too."
);

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use http::HeaderValue;
use oauth2::{
    Client, ClientId, ClientSecret, EndpointNotSet, EndpointSet, EndpointState, ErrorResponse,
    RequestTokenError, RevocableToken, Scope, StandardRevocableToken, TokenIntrospectionResponse,
    TokenResponse, TokenUrl,
    basic::{
        BasicErrorResponse, BasicRevocationErrorResponse, BasicTokenIntrospectionResponse,
        BasicTokenResponse,
    },
};
use tracing::Instrument;

use super::Authorizer;
use crate::error::Error;

/// Minimum delay the refresh loop waits between refresh attempts, even when the
/// token is already within (or past) its refresh tolerance. Prevents hammering
/// the identity provider for very short-lived tokens or during an outage.
const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(1);

impl<TE: ErrorResponse> From<RequestTokenError<oauth2::HttpClientError<reqwest::Error>, TE>>
    for Error
{
    fn from(value: RequestTokenError<oauth2::HttpClientError<reqwest::Error>, TE>) -> Self {
        match value {
            RequestTokenError::Request(e) => Error::OAuth2RequestFailed(e.to_string()),
            RequestTokenError::Parse(e, _) => Error::OAuth2ParseError(e.to_string()),
            RequestTokenError::ServerResponse(e) => Error::OAuth2RequestFailed(e.to_string()),
            RequestTokenError::Other(e) => Error::OAuth2RequestFailed(e.clone()),
        }
    }
}

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
#[allow(clippy::type_complexity)]
pub struct ClientCredentialAuthorizer<
    TE,
    TR,
    TIR,
    RT,
    TRE,
    HasAuthUrl = EndpointNotSet,
    HasDeviceAuthUrl = EndpointNotSet,
    HasIntrospectionUrl = EndpointNotSet,
    HasRevocationUrl = EndpointNotSet,
> where
    TE: ErrorResponse,
    TR: TokenResponse,
    TIR: TokenIntrospectionResponse,
    RT: RevocableToken,
    TRE: ErrorResponse,
    HasAuthUrl: EndpointState,
    HasDeviceAuthUrl: EndpointState,
    HasIntrospectionUrl: EndpointState,
    HasRevocationUrl: EndpointState,
{
    inner: Arc<
        Inner<
            TE,
            TR,
            TIR,
            RT,
            TRE,
            HasAuthUrl,
            HasDeviceAuthUrl,
            HasIntrospectionUrl,
            HasRevocationUrl,
        >,
    >,
    refresh_task: Option<Arc<RefreshTask>>,
}

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

impl<
    TE: ErrorResponse + Send + Sync + 'static,
    TR: TokenResponse + Send + Sync + 'static,
    TIR: TokenIntrospectionResponse + Send + Sync + 'static,
    RT: RevocableToken + Send + Sync + 'static,
    TRE: ErrorResponse + Send + Sync + 'static,
    HasAuthUrl: EndpointState + Send + Sync + 'static,
    HasDeviceAuthUrl: EndpointState + Send + Sync + 'static,
    HasIntrospectionUrl: EndpointState + Send + Sync + 'static,
    HasRevocationUrl: EndpointState + Send + Sync + 'static,
>
    ClientCredentialAuthorizer<
        TE,
        TR,
        TIR,
        RT,
        TRE,
        HasAuthUrl,
        HasDeviceAuthUrl,
        HasIntrospectionUrl,
        HasRevocationUrl,
    >
{
    /// Create a new [`ClientCredentialAuthorizerBuilder`].
    #[must_use]
    pub fn basic_builder(
        client_id: &str,
        client_secret: &str,
        token_url: url::Url,
    ) -> BasicClientCredentialAuthorizerBuilder {
        BasicClientCredentialAuthorizerBuilder::new(client_id, client_secret, token_url)
    }

    /// Create a new [`ClientCredentialAuthorizerBuilder`] from an existing [`oauth2::Client`].
    /// For most use-cases, it should be sufficient to use the [`BasicClientCredentialAuthorizer::basic_builder`] method.
    #[must_use]
    pub fn builder(
        client: oauth2::Client<
            TE,
            TR,
            TIR,
            RT,
            TRE,
            HasAuthUrl,
            HasDeviceAuthUrl,
            HasIntrospectionUrl,
            HasRevocationUrl,
            EndpointSet,
        >,
    ) -> ClientCredentialAuthorizerBuilder<
        TE,
        TR,
        TIR,
        RT,
        TRE,
        HasAuthUrl,
        HasDeviceAuthUrl,
        HasIntrospectionUrl,
        HasRevocationUrl,
    > {
        ClientCredentialAuthorizerBuilder::new_from_client(client)
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

/// Specialization of [`ClientCredentialAuthorizer`] suitable for most use cases.
pub type BasicClientCredentialAuthorizer = ClientCredentialAuthorizer<
    BasicErrorResponse,
    BasicTokenResponse,
    BasicTokenIntrospectionResponse,
    StandardRevocableToken,
    BasicRevocationErrorResponse,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
>;

#[derive(Debug)]
#[allow(clippy::type_complexity)]
struct Inner<
    TE,
    TR,
    TIR,
    RT,
    TRE,
    HasAuthUrl,
    HasDeviceAuthUrl,
    HasIntrospectionUrl,
    HasRevocationUrl,
> where
    TE: ErrorResponse,
    TR: TokenResponse,
    TIR: TokenIntrospectionResponse,
    RT: RevocableToken,
    TRE: ErrorResponse,
    HasAuthUrl: EndpointState,
    HasDeviceAuthUrl: EndpointState,
    HasIntrospectionUrl: EndpointState,
    HasRevocationUrl: EndpointState,
{
    // The oauth2 library also has a basic client.
    // We can't use it unfortunately as it requires the
    // auth url to be set.
    oauth2_client: oauth2::Client<
        TE,
        TR,
        TIR,
        RT,
        TRE,
        HasAuthUrl,
        HasDeviceAuthUrl,
        HasIntrospectionUrl,
        HasRevocationUrl,
        EndpointSet, // TokenUrl is required
    >,
    extra_params: HashMap<String, String>,
    http_client: reqwest::Client,
    max_retries: u32,
    retry_interval: std::time::Duration,
    scopes: Vec<Scope>,
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
    fn try_from_tr<TR: TokenResponse>(tr: &TR) -> Result<Self, Error> {
        let built = super::bearer_header(tr.access_token().secret())?;
        Ok(Token {
            token: built.header,
            #[cfg(feature = "tonic")]
            metadata: built.metadata,
            token_expiry: tr.expires_in().map(|e| Instant::now() + e),
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
/// * `max_retries`: Number of consecutive retries for token requests. Default is 3.
/// * `retry_interval`: Interval between consecutive retries. Default is 10ms.
/// * `http_client`: Custom `reqwest::Client` to use for token requests. Default is a client with redirects disabled.
/// * `scopes`: Scopes to request in the token. Empty by default.
/// * `extra_params`: Extra parameters to include in the token request. Empty by default.
/// * `enable_refresh`: Enable automatic token refresh. Default is `true`.
///
#[derive(Debug, Clone)]
#[allow(clippy::type_complexity)]
pub struct ClientCredentialAuthorizerBuilder<
    TE,
    TR,
    TIR,
    RT,
    TRE,
    HasAuthUrl = EndpointNotSet,
    HasDeviceAuthUrl = EndpointNotSet,
    HasIntrospectionUrl = EndpointNotSet,
    HasRevocationUrl = EndpointNotSet,
> where
    TE: ErrorResponse,
    TR: TokenResponse,
    TIR: TokenIntrospectionResponse,
    RT: RevocableToken,
    TRE: ErrorResponse,
    HasAuthUrl: EndpointState,
    HasDeviceAuthUrl: EndpointState,
    HasIntrospectionUrl: EndpointState,
    HasRevocationUrl: EndpointState,
{
    oauth2_client: oauth2::Client<
        TE,
        TR,
        TIR,
        RT,
        TRE,
        HasAuthUrl,
        HasDeviceAuthUrl,
        HasIntrospectionUrl,
        HasRevocationUrl,
        EndpointSet, // TokenUrl is required for client credential flow
    >,
    max_retries: Option<u32>,
    retry_interval: Option<std::time::Duration>,
    http_client: Option<reqwest::Client>,
    scopes: Vec<Scope>,
    extra_params: HashMap<String, String>,
    enable_refresh: bool,
    refresh_tolerance: Option<Duration>,
}

/// Specialization of [`ClientCredentialAuthorizer`] suitable for most use cases.
pub type BasicClientCredentialAuthorizerBuilder = ClientCredentialAuthorizerBuilder<
    BasicErrorResponse,
    BasicTokenResponse,
    BasicTokenIntrospectionResponse,
    StandardRevocableToken,
    BasicRevocationErrorResponse,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
>;

impl BasicClientCredentialAuthorizerBuilder {
    #[must_use]
    /// Create a new [`ClientCredentialAuthorizer`] from a client id, client secret and token url.
    /// Initializes with 3 retries and a retry interval of 10ms.
    ///
    /// # Panics
    ///
    /// This method panics if a TLS backend cannot be initialized, or the resolver
    /// cannot load the system configuration. (If `reqwest::Client::new()` panics)
    pub fn new(client_id: &str, client_secret: &str, token_url: url::Url) -> Self {
        let client: Client<
            BasicErrorResponse,
            BasicTokenResponse,
            BasicTokenIntrospectionResponse,
            StandardRevocableToken,
            BasicRevocationErrorResponse,
            EndpointNotSet,
            EndpointNotSet,
            EndpointNotSet,
            EndpointNotSet,
            EndpointSet,
        > = oauth2::Client::new(ClientId::new(client_id.to_string()))
            .set_client_secret(ClientSecret::new(client_secret.to_string()))
            .set_token_uri(TokenUrl::from_url(token_url));

        Self::new_from_client(client)
    }
}

impl<
    TE: ErrorResponse + Send + Sync + 'static,
    TR: TokenResponse + Send + Sync + 'static,
    TIR: TokenIntrospectionResponse + Send + Sync + 'static,
    RT: RevocableToken + Send + Sync + 'static,
    TRE: ErrorResponse + Send + Sync + 'static,
    HasAuthUrl: EndpointState + Send + Sync + 'static,
    HasDeviceAuthUrl: EndpointState + Send + Sync + 'static,
    HasIntrospectionUrl: EndpointState + Send + Sync + 'static,
    HasRevocationUrl: EndpointState + Send + Sync + 'static,
>
    ClientCredentialAuthorizerBuilder<
        TE,
        TR,
        TIR,
        RT,
        TRE,
        HasAuthUrl,
        HasDeviceAuthUrl,
        HasIntrospectionUrl,
        HasRevocationUrl,
    >
{
    /// Create a new [`ClientCredentialAuthorizer`] from an existing [`oauth2::Client`].
    /// This gives gives full control over the authentication process.
    /// For most use cases, [`ClientCredentialAuthorizerBuilder::new`] is sufficient.
    #[must_use]
    pub fn new_from_client(
        client: oauth2::Client<
            TE,
            TR,
            TIR,
            RT,
            TRE,
            HasAuthUrl,
            HasDeviceAuthUrl,
            HasIntrospectionUrl,
            HasRevocationUrl,
            EndpointSet, // TokenUrl is required
        >,
    ) -> Self {
        Self {
            oauth2_client: client,
            max_retries: None,
            retry_interval: None,
            http_client: None,
            scopes: Vec::new(),
            extra_params: HashMap::new(),
            enable_refresh: true,
            refresh_tolerance: None,
        }
    }

    /// Optionally specify the `reqwest::Client` to use for token requests.
    /// When setting a custom client, please make sure to set the `redirect` policy to `Policy::none()`
    /// to prevent SSRF vulnerabilities.
    ///
    /// If not set, a default async client is created with redirects disabled.
    ///
    /// Use this method if you want to set custom headers or timeouts.
    #[must_use]
    pub fn set_http_client(mut self, client: reqwest::Client) -> Self {
        self.http_client = Some(client);
        self
    }

    /// Optionally set the maximum number of retries when fetching a new token.
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

    /// Add a scope to the token request.
    #[must_use]
    pub fn add_scope(mut self, scope: &str) -> Self {
        self.scopes.push(Scope::new(scope.to_string()));
        self
    }

    /// Add multiple scopes to the token request.
    #[must_use]
    pub fn add_scopes<I>(mut self, scopes: &[I]) -> Self
    where
        I: AsRef<str>,
    {
        self.scopes
            .extend(scopes.iter().map(|s| Scope::new(s.as_ref().to_string())));
        self
    }

    /// Appends an extra param to the token request.
    ///
    /// For more information on security considerations and conflict handling,
    /// please check [`oauth2::ClientCredentialsTokenRequest::add_extra_param()`].
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
    /// This method returns an error if the initial token fetch fails.
    ///
    /// # Panics
    ///
    /// This method panics if [`Self::set_http_client`] was not called and `reqwest::Client::new()` panics.
    pub async fn build(
        self,
    ) -> Result<
        ClientCredentialAuthorizer<
            TE,
            TR,
            TIR,
            RT,
            TRE,
            HasAuthUrl,
            HasDeviceAuthUrl,
            HasIntrospectionUrl,
            HasRevocationUrl,
        >,
        Error,
    > {
        let http_client = self.http_client.unwrap_or_else(|| {
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("Failed to create reqwest client")
        });

        let retry_interval = self
            .retry_interval
            .unwrap_or_else(|| std::time::Duration::from_millis(10));
        let max_retries = self.max_retries.unwrap_or(3);

        // Fetch initial token
        let tr: TR = request_new_token(
            &self.oauth2_client,
            &self.scopes,
            &self.extra_params,
            &http_client,
            max_retries,
            retry_interval,
        )
        .await?;

        let inner = Inner {
            oauth2_client: self.oauth2_client,
            max_retries,
            retry_interval,
            token: RwLock::new(Token::try_from_tr(&tr)),
            scopes: self.scopes,
            extra_params: self.extra_params,
            http_client,
            tolerance: self.refresh_tolerance.unwrap_or(Duration::from_secs(30)),
        };

        // Initial refresh
        let expires_in = tr.expires_in();

        let inner_arc = Arc::new(inner);

        // Launch refresh task in background
        let refresh_task = if self.enable_refresh && expires_in.is_some() {
            tracing::debug!(
                "Starting refresh task to refresh tokens for client `{}` before expiry.",
                inner_arc.oauth2_client.client_id().as_str()
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
                inner_arc.oauth2_client.client_id().as_str()
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
#[allow(clippy::type_complexity)]
async fn refresh_task<
    TE: ErrorResponse + 'static,
    TR: TokenResponse,
    TIR: TokenIntrospectionResponse,
    RT: RevocableToken,
    TRE: ErrorResponse + 'static,
    HasAuthUrl: EndpointState,
    HasDeviceAuthUrl: EndpointState,
    HasIntrospectionUrl: EndpointState,
    HasRevocationUrl: EndpointState,
>(
    inner: Arc<
        Inner<
            TE,
            TR,
            TIR,
            RT,
            TRE,
            HasAuthUrl,
            HasDeviceAuthUrl,
            HasIntrospectionUrl,
            HasRevocationUrl,
        >,
    >,
) {
    tracing::debug!(
        "Starting the refresh loop for client `{}`",
        inner.oauth2_client.client_id().as_str()
    );
    loop {
        // Determine if the token needs to be refreshed
        let now = Instant::now();

        let span = tracing::span!(
            tracing::Level::TRACE,
            "refresh_task",
            client_id = inner.oauth2_client.client_id().as_str()
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

async fn request_new_token<
    TE: ErrorResponse + 'static,
    TR: TokenResponse,
    TIR: TokenIntrospectionResponse,
    RT: RevocableToken,
    TRE: ErrorResponse + 'static,
    HasAuthUrl: EndpointState,
    HasDeviceAuthUrl: EndpointState,
    HasIntrospectionUrl: EndpointState,
    HasRevocationUrl: EndpointState,
>(
    oauth2_client: &Client<
        TE,
        TR,
        TIR,
        RT,
        TRE,
        HasAuthUrl,
        HasDeviceAuthUrl,
        HasIntrospectionUrl,
        HasRevocationUrl,
        EndpointSet, // TokenUrl is required
    >,
    scopes: &[Scope],
    extra_params: &HashMap<String, String>,
    http_client: &reqwest::Client,
    max_retries: u32,
    retry_interval: std::time::Duration,
) -> Result<TR, Error> {
    let mut counter = 0;

    let token = loop {
        counter += 1;

        let mut request = oauth2_client.exchange_client_credentials();

        for scope in scopes {
            request = request.add_scope(scope.clone());
        }

        for (name, value) in extra_params {
            request = request.add_extra_param(name, value);
        }

        let auth_response = request.request_async(http_client).await;
        // ToDo: Only retry on 500..599
        // Requires: https://github.com/ramosbugs/oauth2-rs/issues/302

        match auth_response {
            Ok(auth_response) => {
                tracing::debug!(
                    "Successfully refreshed token for client `{}`. Token expires in {:?}s",
                    oauth2_client.client_id().as_str(),
                    auth_response.expires_in().map(|d| d.as_secs())
                );
                break auth_response;
            }
            Err(e) => {
                if counter > max_retries {
                    tracing::error!("Failed to fetch token after {} retries: {e}", counter);
                    return Err(e.into());
                }
                tracing::debug!(
                    "Failed to fetch token: {e}. Retrying in {}ms",
                    retry_interval.as_millis()
                );
                #[cfg(feature = "runtime-tokio")]
                tokio::time::sleep(retry_interval).await;
            }
        }
    };

    Ok(token)
}

impl<
    TE: ErrorResponse + 'static,
    TR: TokenResponse,
    TIR: TokenIntrospectionResponse,
    RT: RevocableToken,
    TRE: ErrorResponse + 'static,
    HasAuthUrl: EndpointState,
    HasDeviceAuthUrl: EndpointState,
    HasIntrospectionUrl: EndpointState,
    HasRevocationUrl: EndpointState,
> Inner<TE, TR, TIR, RT, TRE, HasAuthUrl, HasDeviceAuthUrl, HasIntrospectionUrl, HasRevocationUrl>
{
    /// Refresh the token.
    /// If token refresh fails, the error is stored in the token state and returned.
    async fn refresh_token(&self) -> Result<TR, Error> {
        let tr = request_new_token(
            &self.oauth2_client,
            &self.scopes,
            &self.extra_params,
            &self.http_client,
            self.max_retries,
            self.retry_interval,
        )
        .await;

        // Unwrap RWLock to propagate poison (writer panicked)
        let mut state_write_guard = self.token.write().expect("Non-poisoned lock");

        match tr.as_ref() {
            Ok(tr) => {
                // Successful refresh: store the new token (or a conversion error if
                // the access token is not a valid header value).
                *state_write_guard = Token::try_from_tr(tr);
            }
            Err(e) => {
                tracing::error!("Failed to refresh token: {e}");
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
        tr
    }
}

impl<
    TE: ErrorResponse + 'static,
    TR: TokenResponse,
    TIR: TokenIntrospectionResponse,
    RT: RevocableToken,
    TRE: ErrorResponse + 'static,
    HasAuthUrl: EndpointState,
    HasDeviceAuthUrl: EndpointState,
    HasIntrospectionUrl: EndpointState,
    HasRevocationUrl: EndpointState,
> Authorizer
    for ClientCredentialAuthorizer<
        TE,
        TR,
        TIR,
        RT,
        TRE,
        HasAuthUrl,
        HasDeviceAuthUrl,
        HasIntrospectionUrl,
        HasRevocationUrl,
    >
{
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
impl<
    TE: ErrorResponse + 'static,
    TR: TokenResponse,
    TIR: TokenIntrospectionResponse,
    RT: RevocableToken,
    TRE: ErrorResponse + 'static,
    HasAuthUrl: EndpointState,
    HasDeviceAuthUrl: EndpointState,
    HasIntrospectionUrl: EndpointState,
    HasRevocationUrl: EndpointState,
> tonic::service::Interceptor
    for ClientCredentialAuthorizer<
        TE,
        TR,
        TIR,
        RT,
        TRE,
        HasAuthUrl,
        HasDeviceAuthUrl,
        HasIntrospectionUrl,
        HasRevocationUrl,
    >
{
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
                    "token_type": "my-token-type",
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
                    "token_type": "my-token-type",
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
                    "token_type": "my-token-type",
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
                    "token_type": "my-token-type"
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
