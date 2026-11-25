#[cfg(not(feature = "runtime-tokio"))]
compile_error!(
    "If `client-credentials` feature is enabled, an async runtime, such as `runtime-tokio`, must be enabled too."
);

use std::{
    fmt,
    sync::Arc,
    time::{Duration, SystemTime},
};

use super::{Authorizer, Kind, TokenHeader};
#[cfg(feature = "jwt")]
use crate::jwt::{Audience, ClientAuthenticationJwt, SigningAlgorithm, SigningKey};
use crate::{
    AssertionSource,
    cache::{BoxFuture, CacheConfig, Token, TokenCache, TokenSource},
    error::{ConfigError, Error},
    token_endpoint::{self, ClientAuth, Grant, Secret, TokenRequest, TokenResponse},
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

impl Authorizer {
    /// A builder for the client credentials grant (RFC 6749, section 4.4) at the token endpoint `token_url`, with the client authentication the grant requires.
    #[must_use]
    pub fn client_credentials(
        token_url: url::Url,
        client_authentication: ClientAuthentication,
    ) -> AuthorizerBuilder {
        AuthorizerBuilder::new(
            token_url,
            Grant::ClientCredentials,
            Some(client_authentication.0),
        )
    }

    /// A builder for the JWT bearer grant (RFC 7523, section 2.1) at the token endpoint `token_url`: a JWT from `assertion` is the grant.
    ///
    /// middle asks `assertion` for a new JWT for every token request, retries included, such as a `jwt::JwtAssertion` that middle signs or a [`crate::FileAssertion`].
    /// The grant needs no client authentication. Set one with [`AuthorizerBuilder::client_authentication`] if the authorization server requires it.
    /// Add parameters such as `resource` (RFC 8707) with [`AuthorizerBuilder::append_param`].
    #[must_use]
    pub fn jwt_bearer(token_url: url::Url, assertion: impl AssertionSource) -> AuthorizerBuilder {
        AuthorizerBuilder::new(token_url, Grant::JwtBearer(Arc::new(assertion)), None)
    }
}

impl AuthorizerBuilder {
    fn new(token_url: url::Url, grant: Grant, client_auth: Option<ClientAuth>) -> Self {
        Self {
            token_url,
            grant,
            client_auth,
            max_retries: None,
            timeout: None,
            http_client: None,
            scopes: Vec::new(),
            params: Vec::new(),
            allow_http: false,
            enable_refresh: true,
            refresh_tolerance: None,
            default_token_lifetime: None,
        }
    }
}

/// A token that middle requests from a token endpoint and refreshes.
#[derive(Debug, Clone)]
pub(crate) struct Refreshing {
    inner: Arc<Inner>,
}

impl Refreshing {
    pub(crate) fn token_header(&self) -> Result<TokenHeader, Error> {
        self.inner.cache.read(token_header)
    }

    pub(crate) async fn wait_for_header(&self) -> Result<TokenHeader, Error> {
        self.inner.cache.wait(token_header).await
    }

    pub(crate) fn invalidate(&self, rejected: &TokenHeader) -> bool {
        rejected
            .token
            .is_some_and(|token| self.inner.cache.invalidate(token))
    }

    /// The header as tonic metadata, built with the token, so this only clones it.
    #[cfg(feature = "tonic")]
    pub(crate) fn metadata(
        &self,
    ) -> Result<tonic::metadata::MetadataValue<tonic::metadata::Ascii>, Error> {
        self.inner.cache.read(|token| token.metadata().clone())
    }
}

/// What the clones of an authorizer share.
struct Inner {
    source: Arc<ClientCredentials>,
    cache: TokenCache,
    /// The refresh task, `None` if refresh is disabled. Aborted when the last clone of the authorizer is dropped.
    refresh_task: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        if let Some(task) = &self.refresh_task {
            tracing::debug!(
                "Stopping the token refresh task of client `{}`",
                self.source.request.log_name()
            );
            task.abort();
        }
    }
}

impl fmt::Debug for Inner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Inner")
            .field("request", &self.source.request)
            .field("cache", &self.cache)
            .finish_non_exhaustive()
    }
}

/// The HTTP client for a builder without [`AuthorizerBuilder::danger_http_client`]: no redirects, a connect timeout of 10 s,
/// and a proxy from the environment, except for a token URL with a loopback host.
fn default_http_client(request: &TokenRequest) -> Result<reqwest::Client, ConfigError> {
    let builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(DEFAULT_CONNECT_TIMEOUT);
    // A proxy on another machine cannot reach the loopback address of this one, and would see the credentials of an `http` request.
    let builder = if request.has_loopback_host() {
        builder.no_proxy()
    } else {
        builder
    };
    builder
        .build()
        .map_err(|error| ConfigError::HttpClient(Arc::new(error)))
}

fn token_header(token: &Token) -> TokenHeader {
    TokenHeader {
        header: token.header().clone(),
        token: Some(token.id()),
    }
}

/// How the client authenticates at the token endpoint (RFC 6749, section 2.3).
///
/// `Debug` shows the client id and, for a client assertion, the `Debug` output of its source. It never shows a secret, a key of middle's types or an assertion.
#[derive(Clone, Debug)]
pub struct ClientAuthentication(ClientAuth);

impl ClientAuthentication {
    /// The client id and secret in an HTTP Basic `Authorization` header, each form-urlencoded first (`client_secret_basic`, RFC 6749, section 2.3.1).
    ///
    /// RFC 6749 (section 2.3.1) requires token endpoints to support it; the OAuth 2.1 draft (draft-ietf-oauth-v2-1-17, section 2.4.1) makes it optional.
    /// Some token endpoints do not decode the form-urlencoding, and so reject a secret with characters such as `+`, `/` or `=`;
    /// use [`Self::client_secret_post`] for them.
    #[must_use]
    pub fn client_secret_basic(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Self {
        Self(ClientAuth::SecretBasic {
            client_id: client_id.into(),
            secret: Secret::new(client_secret),
        })
    }

    /// The client id and secret as the form parameters `client_id` and `client_secret` (`client_secret_post`).
    ///
    /// The OAuth 2.1 draft (draft-ietf-oauth-v2-1-17, section 2.4.1) requires token endpoints to support it; RFC 6749 (section 2.3.1) makes it optional.
    ///
    /// The client secret is in the form body. A client set with [`AuthorizerBuilder::danger_http_client`] that follows redirects sends it to the redirect target,
    /// also to another host or over `http`.
    #[must_use]
    pub fn client_secret_post(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Self {
        Self(ClientAuth::SecretPost {
            client_id: client_id.into(),
            secret: Secret::new(client_secret),
        })
    }

    /// A JWT from `source` as the form parameter `client_assertion`, with the client id as `client_id` (RFC 7523, section 2.2; RFC 7521, section 4.2).
    ///
    /// `source` supplies a new assertion for every token request, such as a Kubernetes service account token from a [`crate::FileAssertion`].
    /// middle sends the assertion as it is, so `source` decides its `iss`, `sub` and `aud`.
    #[must_use]
    pub fn client_assertion(client_id: impl Into<String>, source: impl AssertionSource) -> Self {
        Self(ClientAuth::Assertion {
            client_id: client_id.into(),
            source: Arc::new(source),
            send_client_id: true,
        })
    }

    /// Leaves out the form parameter `client_id` of a client assertion, which RFC 7521 (section 4.2) makes optional. The client id still names the client in logs and in the [`crate::AssertionContext`].
    ///
    /// Some authorization servers refuse a `client_id` that differs from the `sub` of the assertion. The `sub` of a Kubernetes service account token is
    /// `system:serviceaccount:<namespace>:<name>`, which differs from most client ids, so leave the parameter out for such a server.
    /// Other servers require `client_id`. Client secrets always send the client id.
    #[must_use]
    pub fn without_client_id_parameter(self) -> Self {
        match self.0 {
            ClientAuth::Assertion {
                client_id, source, ..
            } => Self(ClientAuth::Assertion {
                client_id,
                source,
                send_client_id: false,
            }),
            client_auth @ (ClientAuth::SecretBasic { .. } | ClientAuth::SecretPost { .. }) => {
                Self(client_auth)
            }
        }
    }

    /// A JWT signed with the client's private key as the form parameter `client_assertion` (`private_key_jwt`, RFC 7523, section 2.2; OpenID Connect Core 1.0, section 9).
    ///
    /// middle signs a new assertion for every token request (RFC 7523, section 3): `iss` and `sub` are the client id, `aud` and the header `typ` follow `audience`,
    /// `iat` is 5 seconds before the signing, `exp` 60 seconds after `iat`, and `jti` is new. The client id is also sent as `client_id`.
    ///
    /// [`Audience::Issuer`] is what RFC 10070 requires, and [`Audience::TokenEndpoint`] what OpenID Connect Core 1.0 names. Choose the one the authorization server accepts.
    /// For other claims or another header, pass a [`crate::jwt::JwtAssertion`] to [`Self::client_assertion`].
    /// For a client secret as the key, use [`Self::client_secret_jwt`].
    #[cfg(feature = "jwt")]
    #[must_use]
    pub fn private_key_jwt(
        client_id: impl Into<String>,
        key: SigningKey,
        audience: Audience,
    ) -> Self {
        let client_id = client_id.into();
        let source = ClientAuthenticationJwt::new(key, &client_id, audience);
        Self::client_assertion(client_id, source)
    }

    /// A JWT signed with HS256 and the client secret as the form parameter `client_assertion` (`client_secret_jwt`, OpenID Connect Core 1.0, section 9).
    /// The secret itself is not sent.
    ///
    /// The assertion has the claims and the header that [`Self::private_key_jwt`] describes.
    ///
    /// # Errors
    ///
    /// [`ConfigError::WeakSigningKey`] if the secret is shorter than 32 bytes (RFC 7518, section 3.2).
    #[cfg(feature = "jwt")]
    pub fn client_secret_jwt(
        client_id: impl Into<String>,
        client_secret: impl AsRef<str>,
        audience: Audience,
    ) -> Result<Self, ConfigError> {
        let key = SigningKey::from_secret(client_secret.as_ref(), SigningAlgorithm::Hs256)?;
        Ok(Self::private_key_jwt(client_id, key, audience))
    }
}

/// Builder for an [`Authorizer`] with a token from a token endpoint, made with [`Authorizer::client_credentials`] or [`Authorizer::jwt_bearer`].
///
/// The following settings are available:
/// * [`Self::client_authentication`]: How the client authenticates. The client credentials grant requires it; for the JWT bearer grant it is optional and not set by default.
/// * [`Self::add_scope`] and [`Self::add_scopes`]: Scopes to request in the token. None by default.
/// * [`Self::append_param`]: Further form parameters of the token request. None by default.
/// * [`Self::max_retries`]: How often `build()` retries the first token request. Default is 3. Only errors a retry can fix are retried, see [`Error::is_retryable`].
/// * [`Self::timeout`]: How long one token request may take, reading the answer included, and how long `build()` may take. Default is 30 seconds.
/// * [`Self::danger_http_client`]: The `reqwest::Client` for token requests, used as it is. Default is a client with redirects disabled, a connect timeout of 10 seconds, and no proxy for `localhost` and loopback addresses.
/// * [`Self::danger_allow_http`]: Whether an `http` token URL may have any host. Default is `false`: `http` works only with `localhost` and loopback addresses.
/// * [`Self::disable_refresh`]: Turns off the refresh task. Refresh is on by default.
/// * [`Self::refresh_tolerance`]: How long before expiry a token is refreshed at the latest. Default is 30 seconds.
/// * [`Self::default_token_lifetime`]: The lifetime of a token if the token endpoint does not say. Default is 5 minutes.
///
/// `Debug` shows the names of the parameters, not their values, and never the client secret.
#[derive(Clone)]
pub struct AuthorizerBuilder {
    token_url: url::Url,
    grant: Grant,
    client_auth: Option<ClientAuth>,
    max_retries: Option<u32>,
    timeout: Option<Duration>,
    http_client: Option<reqwest::Client>,
    scopes: Vec<String>,
    params: Vec<(String, String)>,
    allow_http: bool,
    enable_refresh: bool,
    refresh_tolerance: Option<Duration>,
    default_token_lifetime: Option<Duration>,
}

impl fmt::Debug for AuthorizerBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let token_url = token_endpoint::redacted_url(&self.token_url);
        let param_names: Vec<&str> = self.params.iter().map(|(name, _)| name.as_str()).collect();
        f.debug_struct("AuthorizerBuilder")
            .field("token_url", &token_url.as_str())
            .field("grant", &self.grant)
            .field("client_auth", &self.client_auth)
            .field("max_retries", &self.max_retries)
            .field("timeout", &self.timeout)
            // A custom client may carry default headers that hold secrets.
            .field("http_client", &self.http_client.as_ref().map(|_| "custom"))
            .field("scopes", &self.scopes)
            .field("param_names", &param_names)
            .field("allow_http", &self.allow_http)
            .field("enable_refresh", &self.enable_refresh)
            .field("refresh_tolerance", &self.refresh_tolerance)
            .field("default_token_lifetime", &self.default_token_lifetime)
            .finish()
    }
}

impl AuthorizerBuilder {
    /// Sets how the client authenticates at the token endpoint.
    ///
    /// The client credentials grant requires client authentication, so [`Authorizer::client_credentials`] takes it, and this replaces it.
    /// For the JWT bearer grant it is optional (RFC 7523, section 2.1): without it, the request carries no client credentials.
    #[must_use]
    pub fn client_authentication(mut self, client_authentication: ClientAuthentication) -> Self {
        self.client_auth = Some(client_authentication.0);
        self
    }

    /// Sets the `reqwest::Client` for token requests. middle uses it as it is, so its settings decide where the credentials go.
    ///
    /// If the client follows redirects, which reqwest does by default,
    /// a 307 or 308 answer of the token endpoint makes reqwest send the form body again to the URL the answer names, also to another host or over `http`.
    /// With [`ClientAuthentication::client_secret_post`], that body holds the client secret, and with the JWT bearer grant or a client assertion the assertion, which is valid until it expires.
    /// reqwest drops the `Authorization` header of
    /// [`ClientAuthentication::client_secret_basic`] when the host, port or scheme changes, and keeps the body.
    /// middle refuses an answer whose final URL is not the token URL, but the other URL has already received the request,
    /// and an answer after a chain of redirects that ends at the token URL counts as the token endpoint's answer.
    /// Set `redirect(reqwest::redirect::Policy::none())` on the client to prevent this.
    ///
    /// If not set, middle builds a client with redirects disabled and a connect timeout of 10 seconds.
    /// It uses a proxy from the environment (`HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY` and `NO_PROXY`), except for a token URL with `localhost` or a loopback address.
    ///
    /// Use it for a client certificate (RFC 8705), for root certificates that the operating system does not have, for extra headers, or for another connect timeout.
    #[must_use]
    pub fn danger_http_client(mut self, client: reqwest::Client) -> Self {
        self.http_client = Some(client);
        self
    }

    /// Optionally set how often [`Self::build`] retries the first token request, within the [`Self::timeout`].
    /// Only errors a retry can fix are retried, see [`Error::is_retryable`].
    /// The default is 3.
    ///
    /// The refresh task retries until a request succeeds.
    ///
    /// After a failed token request, middle waits between 1 s and 2 s, doubling with each further failure up to 30 s.
    /// After an error a retry cannot fix, the refresh task waits about 5 minutes.
    /// While the current token is still in use, neither expired nor invalidated, a wait is at most half the time the token has left, but at least 1 s.
    /// A `Retry-After` header of the token endpoint makes a wait longer, up to 5 minutes.
    #[must_use]
    pub fn max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = Some(max_retries);
        self
    }

    /// Optionally set how long one token request may take, reading the answer included.
    /// [`Self::build`] takes at most this long, retries included.
    /// While a token is valid, one refresh request may take at most half of the time the token has left, but at least 1 s.
    /// This also applies to a client set with [`Self::danger_http_client`].
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

    /// Appends a form parameter to the token request, after the scope. Each call adds one more parameter.
    /// RFC 6749 (section 3.2) allows each parameter once, so repeat a name only where its specification allows it,
    /// as RFC 8707 (section 2) does with one `resource` parameter for each resource.
    ///
    /// [`Self::build`] fails for a parameter that middle reserves for the grant and the client authentication: `grant_type`, `scope`, `client_id`, `client_secret`,
    /// `client_assertion`, `client_assertion_type` and `assertion`.
    #[must_use]
    pub fn append_param(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.params.push((name.into(), value.into()));
        self
    }

    /// Whether an `http` token URL may have any host. middle then sends the client credentials and the assertion of the JWT bearer grant without TLS, so allow it only in a network you trust.
    ///
    /// The default is `false`: [`Self::build`] fails for an `http` token URL unless its host is `localhost` or a loopback address (`127.0.0.0/8` or `::1`).
    #[must_use]
    pub fn danger_allow_http(mut self, allow: bool) -> Self {
        self.allow_http = allow;
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

    /// Build the [`Authorizer`].
    /// This triggers an initial token fetch, which takes at most the [`Self::timeout`], retries included.
    ///
    /// # Errors
    ///
    /// - [`Error::Config`] if the token URL, a scope or a parameter is not valid, the default token lifetime is shorter than 2 s, or the HTTP client cannot be built.
    /// - Any error of the initial token fetch.
    pub async fn build(self) -> Result<Authorizer, Error> {
        let default_lifetime = self
            .default_token_lifetime
            .unwrap_or(DEFAULT_TOKEN_LIFETIME);
        if default_lifetime < MIN_DEFAULT_TOKEN_LIFETIME {
            return Err(ConfigError::DefaultTokenLifetimeTooShort(default_lifetime).into());
        }
        let request = TokenRequest::new(
            self.token_url,
            self.grant,
            self.client_auth,
            &self.scopes,
            self.params,
            self.allow_http,
        )?;
        let http_client = match self.http_client {
            Some(http_client) => http_client,
            None => default_http_client(&request)?,
        };
        let source = Arc::new(ClientCredentials {
            request,
            http_client,
        });
        let config = CacheConfig {
            client_id: source.request.log_name(),
            timeout: self.timeout.unwrap_or(DEFAULT_TIMEOUT),
            tolerance: self.refresh_tolerance.unwrap_or(DEFAULT_REFRESH_TOLERANCE),
            default_lifetime,
            first_token_retries: self.max_retries.unwrap_or(DEFAULT_MAX_RETRIES),
            refresh: self.enable_refresh,
            wall_clock: SystemTime::now,
        };

        let (cache, refresh_task) =
            TokenCache::start(Arc::clone(&source) as Arc<dyn TokenSource>, config).await?;
        Ok(Authorizer(Kind::Refreshing(Refreshing {
            inner: Arc::new(Inner {
                source,
                cache,
                refresh_task,
            }),
        })))
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
        let authorizer = Authorizer::client_credentials(
            format!("{url}/my-tenant/oauth2/token").parse().unwrap(),
            ClientAuthentication::client_secret_basic("my-client", "my-secret"),
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
        let authorizer = Authorizer::client_credentials(
            format!("{url}/my-tenant/oauth2/token").parse().unwrap(),
            ClientAuthentication::client_secret_basic("my-client", "my-secret"),
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
        let authorizer = Authorizer::client_credentials(
            format!("{url}/my-tenant/oauth2/token").parse().unwrap(),
            ClientAuthentication::client_secret_basic("my-client", "my-secret"),
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
        let authorizer = Authorizer::client_credentials(
            format!("{url}/my-tenant/oauth2/token").parse().unwrap(),
            ClientAuthentication::client_secret_basic("my-client", "my-secret"),
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
        let authorizer = Authorizer::client_credentials(
            format!("{url}/token").parse().unwrap(),
            ClientAuthentication::client_secret_basic("my-client", "my-secret"),
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
