#[cfg(not(feature = "runtime-tokio"))]
compile_error!("If `client-credentials` feature is enabled, an async runtime, such as `runtime-tokio`, must be enabled too.");

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use http::HeaderValue;
use oauth2::{
    basic::{
        BasicErrorResponse, BasicRevocationErrorResponse, BasicTokenIntrospectionResponse,
        BasicTokenResponse,
    },
    Client, ClientId, ClientSecret, EndpointNotSet, EndpointSet, EndpointState, ErrorResponse,
    RequestTokenError, RevocableToken, Scope, StandardRevocableToken, TokenIntrospectionResponse,
    TokenResponse, TokenUrl,
};

use super::Authorizer;
use crate::error::Error;

impl<TE: ErrorResponse> From<RequestTokenError<oauth2::HttpClientError<reqwest::Error>, TE>>
    for Error
{
    fn from(value: RequestTokenError<oauth2::HttpClientError<reqwest::Error>, TE>) -> Self {
        match value {
            RequestTokenError::Request(e) => Error::OAuth2RequestFailed(e.to_string()),
            RequestTokenError::Parse(e, _) => Error::OAuth2ParseError(e.to_string()),
            RequestTokenError::ServerResponse(e) => Error::OAuth2RequestFailed(e.to_string()),
            RequestTokenError::Other(e) => Error::OAuth2RequestFailed(e.to_string()),
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
    #[cfg(feature = "runtime-tokio")]
    refresh_task: Option<Arc<tokio::task::JoinHandle<()>>>,
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
}

impl<
        TE: ErrorResponse,
        TR: TokenResponse,
        TIR: TokenIntrospectionResponse,
        RT: RevocableToken,
        TRE: ErrorResponse,
        HasAuthUrl: EndpointState,
        HasDeviceAuthUrl: EndpointState,
        HasIntrospectionUrl: EndpointState,
        HasRevocationUrl: EndpointState,
    > Drop
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
    fn drop(&mut self) {
        if let Some(refresh_task) = self.refresh_task.take() {
            #[cfg(feature = "runtime-tokio")]
            refresh_task.abort();
        }
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
struct Token {
    #[redact]
    token: Arc<HeaderValue>,
    token_expiry: Option<Instant>,
}

impl Token {
    fn try_from_tr<TR: TokenResponse>(tr: &TR) -> Result<Self, Error> {
        HeaderValue::from_str(tr.access_token().secret())
            .map_err(|_| Error::InvalidHeaderValue)
            .map(|mut token| {
                token.set_sensitive(true);
                Token {
                    token: Arc::new(token),
                    token_expiry: tr.expires_in().map(|e| Instant::now() + e),
                }
            })
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

            Some(Arc::new(refresh_task))
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
    loop {
        // Determine if the token needs to be refreshed
        let now = Instant::now();
        let client_id = inner.oauth2_client.client_id().as_str();

        let span = tracing::span!(tracing::Level::TRACE, "refresh_task", client_id = client_id);
        let _enter = span.enter();

        let sleep_duration = {
            let state_read_guard = inner.token.read().expect("Non-poisoned lock");
            let token = (*state_read_guard).clone();
            drop(state_read_guard);

            if let Ok(token) = token {
                if let Some(expiry) = token.token_expiry {
                    let expires_in = if expiry > now {
                        expiry - now
                    } else {
                        Duration::from_secs(0)
                    };

                    // Token expires in less than TOLERANCE seconds -> Process now
                    if expires_in < inner.tolerance {
                        tracing::warn!("Token expires in {}s which is less than the minimum allowed refresh interval of {}s. Refreshing in {}s.",
                            expires_in.as_secs(),
                            inner.tolerance.as_secs(),
                            inner.tolerance.as_secs()
                        );
                        Duration::from_secs(inner.tolerance.as_secs())
                    } else {
                        let next_refresh = expires_in - inner.tolerance;
                        // Token expires in more than Tolerance seconds -> Sleep until Tolerance seconds before expiry
                        tracing::trace!(
                            "Token expires in {}s. Refreshing in {}s.",
                            expires_in.as_secs(),
                            next_refresh.as_secs()
                        );
                        next_refresh
                    }
                } else {
                    // Token does not expire. We don't need a background task
                    tracing::debug!("Token does not expire. Disabling refresh task.",);
                    return;
                }
            } else {
                tracing::trace!(
                    "Failed to refresh token. Retrying in {}s",
                    inner.tolerance.as_secs()
                );
                Duration::from_secs(inner.tolerance.as_secs())
            }
        };

        #[cfg(feature = "runtime-tokio")]
        tokio::time::sleep(sleep_duration).await;

        // `refresh_token` already records the result, including failures.
        let _tr = inner.refresh_token().await.ok();

        // if let Ok(tr) = tr {
        //     let expires_in = tr.expires_in();
        //     // If it expires in less than tolerance, we wait for at least the tolerance duration
        //     // before checking again.

        //     if let Some(expires_in) = expires_in {
        //         if expires_in < inner.tolerance {
        //             tracing::warn!("Token refreshed. Token expires in {}s which is less than the tolerance of {}s. Refreshing in {}s.",
        //                 expires_in.as_secs(),
        //                 inner.tolerance.as_secs(),
        //                 inner.tolerance.as_secs()
        //             );
        //             #[cfg(feature = "runtime-tokio")]
        //             tokio::time::sleep(inner.tolerance).await;
        //         } else {
        //             let next_refresh = (expires_in - inner.tolerance).max(inner.tolerance);
        //             tracing::trace!(
        //                 "Token refreshed. Next refresh in {}s",
        //                 next_refresh.as_secs()
        //             );
        //             #[cfg(feature = "runtime-tokio")]
        //             tokio::time::sleep(next_refresh).await;
        //         }
        //     };
        // } else {
        //     // Wait at least the TOLERANCE duration before checking again
        //     tracing::trace!(
        //         "Failed to refresh token. Retrying in {}s",
        //         inner.tolerance.as_secs()
        //     );
        //     #[cfg(feature = "runtime-tokio")]
        //     tokio::time::sleep(inner.tolerance).await;
        // }
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
                    "Successfully refreshed token for client `{}`",
                    oauth2_client.client_id().as_str(),
                );
                break auth_response;
            }
            Err(e) => {
                if counter > max_retries {
                    tracing::error!("Failed to fetch token after {} retries: {e}", counter);
                    return Err(e.into());
                };
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
    >
    Inner<TE, TR, TIR, RT, TRE, HasAuthUrl, HasDeviceAuthUrl, HasIntrospectionUrl, HasRevocationUrl>
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
        // Get write lock immediately to not spawn multiple token fetch threads
        let mut state_write_guard = self.token.write().expect("Non-poisoned lock");

        let token = tr
            .as_ref()
            .map_err(|e| {
                tracing::error!("Failed to refresh token: {e}");
                e.clone()
            })
            .and_then(Token::try_from_tr);

        *state_write_guard = token;
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

        let token = state_read_guard
            .as_ref()
            .map(|t| t.token.clone())
            .map_err(Clone::clone);

        drop(state_read_guard);
        token
    }

    #[cfg(feature = "runtime-tokio")]
    fn refresh_task(&self) -> Option<Arc<tokio::task::JoinHandle<()>>> {
        self.refresh_task.as_ref().map(Clone::clone)
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

        let token = authorizer.authorization_header().unwrap();
        assert_eq!(token.to_str().unwrap(), "my-issued-token");
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

        let token = authorizer.authorization_header().unwrap();
        assert_eq!(token.to_str().unwrap(), "my-issued-token");
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

        let token = authorizer.authorization_header().unwrap();
        assert_eq!(token.to_str().unwrap(), "my-issued-token");
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

        let token = authorizer.authorization_header().unwrap();
        assert_eq!(token.to_str().unwrap(), "my-issued-token");
    }
}
