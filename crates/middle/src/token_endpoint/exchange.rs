//! Token exchange (RFC 8693) with a [`TokenEndpoint`]: one request to the token endpoint per call, with a subject token of the caller.

use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime},
};

use url::Url;

use super::{
    ClientAuth, DEFAULT_TIMEOUT, DEFAULT_TOKEN_LIFETIME, GrantRef, MAX_EXPIRES_IN, Request, Secret,
    TokenResponse, check_token_url, default_http_client, redacted_url, request_exchange,
};
use crate::{
    ClientAuthentication,
    authorizers::TokenValue,
    cache::{JwtExpiry, jwt_expiry},
    error::{ConfigError, Error},
};

/// A client of a token endpoint that sends one token exchange (RFC 8693) for each call of [`Self::exchange`],
/// for example for a server that exchanges the token of each of its callers for a token of another service.
///
/// Each call sends one request and returns its answer: middle keeps no token, does not retry, and does not combine calls.
/// Cache the issued tokens in the application, as the [crate documentation](crate#token-exchange) describes.
/// [`IssuedToken::is_bearer`] must be true before you send the issued token as a Bearer token.
///
/// Make it with [`Self::builder`]. Clones are cheap and share the HTTP client, so build one and clone it for each task.
/// `Debug` shows the token URL without its query, the client authentication as [`ClientAuthentication`] shows it, and the timeout. It never shows the client secret.
#[derive(Clone)]
pub struct TokenEndpoint(Arc<Endpoint>);

/// What the clones of a [`TokenEndpoint`] share.
struct Endpoint {
    token_url: Url,
    client_auth: Option<ClientAuth>,
    http_client: reqwest::Client,
    timeout: Duration,
    /// At most one year.
    default_lifetime: Duration,
    /// Whether an answer without `expires_in` was logged, by this endpoint or a clone.
    logged_missing_expires_in: AtomicBool,
}

impl Endpoint {
    /// Logs the first answer without `expires_in` whose lifetime comes from the `exp` of the issued JWT or from the default, once for the endpoint and its clones.
    fn log_missing_expires_in(&self, origin: Origin) {
        let first = || !self.logged_missing_expires_in.swap(true, Ordering::Relaxed);
        match origin {
            Origin::ExpiresIn | Origin::PassedExp => {}
            Origin::JwtExp(time_left) => {
                if first() {
                    tracing::info!(
                        "The token of the token endpoint `{}` has no `expires_in`. middle uses the `exp` of the JWT access token, which is {time_left:?} after the answer arrived",
                        redacted_url(&self.token_url)
                    );
                }
            }
            Origin::Default => {
                if first() {
                    tracing::warn!(
                        "The token of the token endpoint `{}` has no `expires_in`. middle uses the default lifetime of {:?}",
                        redacted_url(&self.token_url),
                        self.default_lifetime
                    );
                }
            }
        }
    }
}

// A token endpoint is shared between threads and tasks, and an exchange can run in a task of its own.
const _: () = {
    const fn assert_send_sync_static<T: Send + Sync + 'static>() {}
    assert_send_sync_static::<TokenEndpoint>();
    assert_send_sync_static::<ExchangeRequest>();
    assert_send_sync_static::<IssuedToken>();
};
const _: fn(&TokenEndpoint, &ExchangeRequest) = |endpoint, request| {
    fn assert_send<T: Send>(_: &T) {}
    assert_send(&endpoint.exchange(request));
};

impl TokenEndpoint {
    /// A builder for a client of the token endpoint `token_url`.
    #[must_use]
    pub fn builder(token_url: Url) -> TokenEndpointBuilder {
        TokenEndpointBuilder {
            token_url,
            client_auth: None,
            timeout: None,
            default_token_lifetime: None,
        }
    }

    /// Exchanges the subject token of `request` for a token of the token endpoint (RFC 8693, section 2.1), with one request.
    ///
    /// middle sends the request once, also after an error that a retry can fix, see [`Error::is_retryable`].
    /// For a client assertion, middle asks its source for a new assertion for each call.
    /// The timeout of the builder bounds the call, creating the client assertion and reading the answer included.
    /// Dropping the returned future cancels the request.
    ///
    /// middle sends the subject token as it is, also a JWT whose `exp` has passed: the token endpoint decides.
    ///
    /// # Panics
    ///
    /// Outside a Tokio runtime, or in a runtime without IO or timers (`enable_all`).
    ///
    /// # Errors
    ///
    /// - [`Error::Config`] if `request` has a parameter without a name, a parameter that middle reserves, or a scope that is not valid. middle then sends nothing.
    /// - [`Error::OAuth`] if the token endpoint refuses the exchange. [`Error::oauth_code`] gives its code.
    /// - [`Error::Http`], [`Error::Transport`] or [`Error::Timeout`] if the request failed, and [`Error::Source`] if the source of the client assertion failed.
    /// - [`Error::InvalidResponse`] if middle cannot use the answer, for example because its `token_type` is neither `Bearer` nor `N_A`.
    pub async fn exchange(&self, request: &ExchangeRequest) -> Result<IssuedToken, Error> {
        let endpoint = &*self.0;
        // The request borrows the token URL and the client authentication of the endpoint, and the subject and parameters of `request`.
        let outgoing = Request {
            url: &endpoint.token_url,
            grant: GrantRef::TokenExchange {
                subject_token: &request.subject_token,
                subject_token_type: &request.subject_token_type,
            },
            client_auth: endpoint.client_auth.as_ref(),
            scopes: &request.scopes,
            params: &request.params,
        };
        outgoing.check()?;
        let answer = tokio::time::timeout(
            endpoint.timeout,
            request_exchange(&endpoint.http_client, outgoing),
        )
        .await
        .map_err(|_| Error::Timeout(endpoint.timeout))??;
        let (lifetime, origin) = lifetime(
            &answer.token,
            request.subject_token.expose(),
            SystemTime::now(),
            endpoint.default_lifetime,
        );
        endpoint.log_missing_expires_in(origin);
        Ok(IssuedToken {
            access_token: answer.token.access_token,
            is_bearer: answer.is_bearer,
            lifetime,
            expires_in: answer.token.expires_in,
            issued_type: answer.issued_token_type,
            refresh_token: answer.refresh_token,
            scope: answer.scope,
        })
    }
}

impl fmt::Debug for TokenEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenEndpoint")
            .field("token_url", &redacted_url(&self.0.token_url).as_str())
            .field("client_auth", &self.0.client_auth)
            .field("timeout", &self.0.timeout)
            .field("default_token_lifetime", &self.0.default_lifetime)
            .finish_non_exhaustive()
    }
}

/// Builder for a [`TokenEndpoint`], made with [`TokenEndpoint::builder`].
///
/// * [`Self::client_authentication`]: How the client authenticates. A token exchange does not require it (RFC 8693, section 2.1), and it is not set by default.
/// * [`Self::timeout`]: How long one exchange may take, creating a client assertion and reading the answer included. Default is 30 seconds.
/// * [`Self::default_token_lifetime`]: The lifetime of an issued token whose lifetime is not known. Default is 5 minutes.
///
/// middle builds the HTTP client as for an [`crate::Authorizer`] without `danger_http_client`: redirects disabled, a connect timeout of 10 seconds,
/// and a proxy from the environment (`HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY` and `NO_PROXY`), except for a token URL with `localhost` or a loopback address.
///
/// `Debug` shows the token URL without its query, the client authentication as [`ClientAuthentication`] shows it, and the timeout. It never shows the client secret.
#[derive(Clone)]
pub struct TokenEndpointBuilder {
    token_url: Url,
    client_auth: Option<ClientAuth>,
    timeout: Option<Duration>,
    default_token_lifetime: Option<Duration>,
}

impl TokenEndpointBuilder {
    /// Sets how the client authenticates at the token endpoint. Every [`ClientAuthentication`] works, with a new client assertion for each exchange.
    ///
    /// A token exchange does not require client authentication (RFC 8693, section 2.1): without it, the request carries no client credentials.
    /// Some servers require it for a token exchange, and others take none.
    #[must_use]
    pub fn client_authentication(mut self, client_authentication: ClientAuthentication) -> Self {
        self.client_auth = Some(client_authentication.0);
        self
    }

    /// Sets how long one call of [`TokenEndpoint::exchange`] may take, creating a client assertion and reading the answer included.
    /// The default is 30 seconds, as for an [`crate::Authorizer`].
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Sets the lifetime of an issued token whose lifetime is not known: the answer has no `expires_in`, and the issued token is not a JWT with an `exp`.
    /// [`IssuedToken::lifetime`] is then this lifetime, and still ends at the `exp` of a JWT subject token at the latest.
    /// Longer lifetimes are shortened to one year. The default is 5 minutes, as for an [`crate::Authorizer`].
    ///
    /// Every lifetime works, also 0: a [`TokenEndpoint`] refreshes no token, so a short lifetime only shortens how long callers keep such a token.
    ///
    /// middle logs the first answer without `expires_in` of an endpoint and its clones, once: as a warning if this lifetime applies to it,
    /// and as info if the `exp` of the issued JWT does.
    #[must_use]
    pub fn default_token_lifetime(mut self, lifetime: Duration) -> Self {
        self.default_token_lifetime = Some(lifetime);
        self
    }

    /// Builds the [`TokenEndpoint`]. It sends no request.
    ///
    /// # Errors
    ///
    /// - [`ConfigError::TokenUrlScheme`] and [`ConfigError::HttpTokenUrl`] unless the token URL uses `https`, or `http` with `localhost` or a loopback address (`127.0.0.0/8` or `::1`).
    /// - [`ConfigError::TokenUrlWithFragment`] and [`ConfigError::TokenUrlWithUserInfo`] if the token URL has a fragment, a user name or a password.
    /// - [`ConfigError::HttpClient`] if the HTTP client cannot be built.
    pub fn build(self) -> Result<TokenEndpoint, ConfigError> {
        check_token_url(&self.token_url, false)?;
        let http_client = default_http_client(&self.token_url)?;
        Ok(TokenEndpoint(Arc::new(Endpoint {
            token_url: self.token_url,
            client_auth: self.client_auth,
            http_client,
            timeout: self.timeout.unwrap_or(DEFAULT_TIMEOUT),
            default_lifetime: self
                .default_token_lifetime
                .unwrap_or(DEFAULT_TOKEN_LIFETIME)
                .min(MAX_EXPIRES_IN),
            logged_missing_expires_in: AtomicBool::new(false),
        })))
    }
}

impl fmt::Debug for TokenEndpointBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenEndpointBuilder")
            .field("token_url", &redacted_url(&self.token_url).as_str())
            .field("client_auth", &self.client_auth)
            .field("timeout", &self.timeout.unwrap_or(DEFAULT_TIMEOUT))
            .field(
                "default_token_lifetime",
                &self
                    .default_token_lifetime
                    .unwrap_or(DEFAULT_TOKEN_LIFETIME),
            )
            .finish()
    }
}

/// One token exchange request (RFC 8693, section 2.1): the subject token and its type, scopes, and further form parameters,
/// such as `audience`, `resource` or `requested_token_type`.
///
/// [`TokenEndpoint::exchange`] checks the request, and fails before it sends anything if a parameter or a scope is not valid.
/// `Debug` shows the subject token type, the scopes and the names of the parameters, never the subject token or the values of the parameters.
#[derive(Clone)]
pub struct ExchangeRequest {
    subject_token: Secret,
    subject_token_type: String,
    scopes: Vec<String>,
    params: Vec<(String, String)>,
}

impl ExchangeRequest {
    /// A request to exchange `subject_token`, a token of the type `subject_token_type`, such as `urn:ietf:params:oauth:token-type:access_token`
    /// or `urn:ietf:params:oauth:token-type:jwt` (RFC 8693, section 3).
    ///
    /// middle sends the subject token as it is. Validate a token of your caller before you exchange it, as the [crate documentation](crate#token-exchange) describes.
    #[must_use]
    pub fn new(subject_token: impl Into<String>, subject_token_type: impl Into<String>) -> Self {
        Self {
            subject_token: Secret::new(subject_token),
            subject_token_type: subject_token_type.into(),
            scopes: Vec::new(),
            params: Vec::new(),
        }
    }

    /// Adds a scope to the request. An empty scope is skipped.
    /// [`TokenEndpoint::exchange`] fails if the scope is not valid (RFC 6749, section 3.3), for example if it contains a space.
    ///
    /// In a token exchange, a scope narrows the scopes of the subject token. It does not ask for the default scopes of your client.
    /// [`IssuedToken::scope`] tells if the server granted other scopes.
    #[must_use]
    pub fn add_scope(mut self, scope: &str) -> Self {
        if !scope.is_empty() {
            self.scopes.push(scope.to_string());
        }
        self
    }

    /// Appends a form parameter to the request, after the scope. Each call adds one more parameter, so a name can repeat.
    /// Repeat a name only where its specification allows it, as RFC 8693 (section 2.1) does for `resource` and `audience`.
    ///
    /// [`TokenEndpoint::exchange`] fails for a parameter without a name and for a parameter that middle reserves for the grant and the client authentication:
    /// `grant_type`, `scope`, `client_id`, `client_secret`, `client_assertion`, `client_assertion_type`, `assertion`,
    /// `subject_token`, `subject_token_type`, `actor_token` and `actor_token_type`.
    #[must_use]
    pub fn append_param(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.params.push((name.into(), value.into()));
        self
    }
}

impl fmt::Debug for ExchangeRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let param_names: Vec<&str> = self.params.iter().map(|(name, _)| name.as_str()).collect();
        f.debug_struct("ExchangeRequest")
            .field("subject_token", &self.subject_token)
            .field("subject_token_type", &self.subject_token_type)
            .field("scopes", &self.scopes)
            .field("param_names", &param_names)
            .finish()
    }
}

/// The token that a token exchange issued (RFC 8693, section 2.2.1), with what the token endpoint said about it.
///
/// `Debug` never shows the issued token or the refresh token.
#[derive(Clone, Debug)]
pub struct IssuedToken {
    access_token: TokenValue,
    is_bearer: bool,
    lifetime: Duration,
    expires_in: Option<Duration>,
    /// The `issued_token_type` of the answer.
    issued_type: Option<String>,
    refresh_token: Option<Secret>,
    scope: Option<String>,
}

impl IssuedToken {
    /// The issued token, from the field `access_token` of the answer, also if it is not an access token, see [`Self::is_bearer`].
    /// It is visible ASCII without space.
    #[must_use]
    pub fn access_token(&self) -> &str {
        self.access_token.as_str()
    }

    /// Whether the `token_type` of the answer is `Bearer`, so that the token can be sent in an `Authorization: Bearer` header (RFC 6750).
    ///
    /// `false` for the `token_type` `N_A`: the issued token is not an access token, for example a refresh token or an ID token (RFC 8693, section 2.2.1).
    /// Check it before you send the token as a Bearer token.
    #[must_use]
    pub fn is_bearer(&self) -> bool {
        self.is_bearer
    }

    /// How long the issued token can be used, counted from when the answer arrived, so that `Instant::now()` after `exchange` returns plus `lifetime()`
    /// never passes the `exp` of the subject token. At most one year.
    ///
    /// The lifetime is `expires_in`, else the time until the `exp` of the issued token if it is a JWT, 0 if that has passed,
    /// else the default token lifetime of the builder, see [`TokenEndpointBuilder::default_token_lifetime`].
    /// It is at most the time until the `exp` of the subject token if that is a JWT, 0 if that has passed, also if the token endpoint issues a longer one.
    /// middle reads `exp` without checking signatures, and an `exp` of 0 or less counts as not set.
    #[must_use]
    pub fn lifetime(&self) -> Duration {
        self.lifetime
    }

    /// The `expires_in` of the answer, the lifetime the token endpoint stated, counted from when the answer arrived. At most one year; `None` if the answer has none.
    ///
    /// Cache by [`Self::lifetime`]: it also ends at the `exp` of the subject token, and it falls back to the `exp` of the issued JWT or the default.
    /// Use `expires_in` for a policy of your own, for example to see whether the token endpoint sent a lifetime at all.
    #[must_use]
    pub fn expires_in(&self) -> Option<Duration> {
        self.expires_in
    }

    /// The `issued_token_type` of the answer, such as `urn:ietf:params:oauth:token-type:access_token`, without control characters.
    ///
    /// RFC 8693 (section 2.2.1) requires it, but some servers leave it out. It need not be the `requested_token_type`, so compare it yourself where that matters.
    #[must_use]
    pub fn issued_token_type(&self) -> Option<&str> {
        self.issued_type.as_deref()
    }

    /// The `refresh_token` of the answer, if the token endpoint issued one. Store it as a secret (RFC 9700, section 4.14).
    #[must_use]
    pub fn refresh_token(&self) -> Option<&str> {
        self.refresh_token.as_ref().map(Secret::expose)
    }

    /// The `scope` of the answer, without control characters. A token endpoint sends it if the scope of the issued token differs from the requested scope (RFC 8693, section 2.2.1).
    #[must_use]
    pub fn scope(&self) -> Option<&str> {
        self.scope.as_deref()
    }
}

/// Where the lifetime of an issued token comes from, before the cap at the `exp` of the subject token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Origin {
    /// The `expires_in` of the answer.
    ExpiresIn,
    /// The `exp` of the issued JWT, this long after the answer arrived.
    JwtExp(Duration),
    /// The `exp` of the issued JWT, at or before the arrival of the answer.
    PassedExp,
    /// The default token lifetime of the builder.
    Default,
}

/// The lifetime of the issued token in `answer`, counted from `arrived_at`, when the answer arrived, and where it comes from.
///
/// The issued lifetime is `expires_in`, else the time until the `exp` of the issued token if it is a JWT, 0 if that has passed, else `default`.
/// It is at most the time until the `exp` of the subject token if that is a JWT, 0 if that has passed.
fn lifetime(
    answer: &TokenResponse,
    subject_token: &str,
    arrived_at: SystemTime,
    default: Duration,
) -> (Duration, Origin) {
    let (issued, origin) = match answer.expires_in {
        Some(expires_in) => (expires_in, Origin::ExpiresIn),
        None => match jwt_expiry(answer.access_token.as_str(), arrived_at) {
            Some(JwtExpiry::After(time_left)) => (time_left, Origin::JwtExp(time_left)),
            Some(JwtExpiry::Passed(_)) => (Duration::ZERO, Origin::PassedExp),
            None => (default, Origin::Default),
        },
    };
    let lifetime = jwt_expiry(subject_token, arrived_at)
        .map_or(issued, |subject| issued.min(subject.time_left()));
    (lifetime, origin)
}

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    use super::*;
    use crate::token_endpoint::MAX_EXPIRES_IN;

    const ARRIVED_AT: u64 = 2_000_000_000;
    const DEFAULT: Duration = Duration::from_secs(300);

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds)
    }

    fn jwt(exp: impl Into<serde_json::Value>) -> String {
        let encode = |json: serde_json::Value| URL_SAFE_NO_PAD.encode(json.to_string());
        format!(
            "{}.{}.c2lnbmF0dXJl",
            encode(serde_json::json!({"alg": "RS256"})),
            encode(serde_json::json!({"sub": "user-1", "exp": exp.into()}))
        )
    }

    fn answer(access_token: &str, expires_in: Option<u64>) -> TokenResponse {
        TokenResponse {
            access_token: TokenValue::parse(access_token).unwrap(),
            expires_in: expires_in.map(Duration::from_secs),
            expires_at: None,
        }
    }

    /// The lifetime of an answer that arrived at [`ARRIVED_AT`], with the default lifetime [`DEFAULT`].
    fn lifetime_on_arrival(answer: &TokenResponse, subject_token: &str) -> Duration {
        lifetime(answer, subject_token, at(ARRIVED_AT), DEFAULT).0
    }

    #[test]
    fn test_the_lifetime_is_expires_in_for_a_subject_that_is_not_a_jwt() {
        assert_eq!(
            lifetime_on_arrival(&answer("t", Some(900)), "opaque-subject"),
            Duration::from_secs(900)
        );
    }

    #[test]
    fn test_without_expires_in_the_lifetime_ends_at_the_exp_of_an_issued_jwt() {
        let issued = jwt(ARRIVED_AT + 600);
        assert_eq!(
            lifetime_on_arrival(&answer(&issued, None), "opaque-subject"),
            Duration::from_secs(600)
        );
    }

    #[test]
    fn test_expires_in_comes_before_the_exp_of_an_issued_jwt() {
        let issued = jwt(ARRIVED_AT + 600);
        assert_eq!(
            lifetime_on_arrival(&answer(&issued, Some(900)), "opaque-subject"),
            Duration::from_secs(900)
        );
    }

    #[test]
    fn test_an_issued_jwt_whose_exp_has_passed_has_no_lifetime_left() {
        for exp in [ARRIVED_AT, ARRIVED_AT - 5] {
            assert_eq!(
                lifetime_on_arrival(&answer(&jwt(exp), None), "opaque-subject"),
                Duration::ZERO,
                "{exp}"
            );
        }
    }

    #[test]
    fn test_without_expires_in_and_without_a_jwt_the_lifetime_is_the_default() {
        assert_eq!(
            lifetime_on_arrival(&answer("t", None), "opaque-subject"),
            DEFAULT
        );
    }

    #[test]
    fn test_the_lifetime_ends_at_the_exp_of_a_jwt_subject() {
        let subject = jwt(ARRIVED_AT + 60);
        assert_eq!(
            lifetime_on_arrival(&answer("t", Some(900)), &subject),
            Duration::from_secs(60)
        );
        assert_eq!(
            lifetime_on_arrival(&answer(&jwt(ARRIVED_AT + 600), None), &subject),
            Duration::from_secs(60)
        );
        assert_eq!(
            lifetime_on_arrival(&answer("t", None), &subject),
            Duration::from_secs(60)
        );
    }

    #[test]
    fn test_a_lifetime_shorter_than_the_subjects_is_kept() {
        let subject = jwt(ARRIVED_AT + 600);
        assert_eq!(
            lifetime_on_arrival(&answer("t", Some(30)), &subject),
            Duration::from_secs(30)
        );
        assert_eq!(lifetime_on_arrival(&answer("t", None), &subject), DEFAULT);
    }

    #[test]
    fn test_a_subject_whose_exp_has_passed_leaves_no_lifetime() {
        for exp in [ARRIVED_AT, ARRIVED_AT - 1] {
            assert_eq!(
                lifetime_on_arrival(&answer("t", Some(900)), &jwt(exp)),
                Duration::ZERO,
                "{exp}"
            );
        }
    }

    #[test]
    fn test_a_subject_exp_of_zero_or_less_counts_as_not_set() {
        for exp in [0, -5] {
            assert_eq!(
                lifetime_on_arrival(&answer("t", Some(900)), &jwt(exp)),
                Duration::from_secs(900),
                "{exp}"
            );
        }
    }

    #[test]
    fn test_an_exp_far_in_the_future_gives_at_most_one_year() {
        let issued = jwt(u64::MAX);
        assert_eq!(
            lifetime_on_arrival(&answer(&issued, None), "opaque-subject"),
            MAX_EXPIRES_IN
        );
        assert_eq!(
            lifetime_on_arrival(&answer(&issued, None), &jwt(u64::MAX)),
            MAX_EXPIRES_IN
        );
    }

    /// A token endpoint that answers every request with `body`, and a [`TokenEndpoint`] for it. Keep the server and the mock while the test runs.
    async fn endpoint_answering(
        body: &serde_json::Value,
    ) -> (mockito::ServerGuard, mockito::Mock, TokenEndpoint) {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body.to_string())
            .create_async()
            .await;
        let endpoint = TokenEndpoint::builder(format!("{}/token", server.url()).parse().unwrap())
            .build()
            .unwrap();
        (server, mock, endpoint)
    }

    fn subject() -> ExchangeRequest {
        ExchangeRequest::new(
            "SECRET-SUBJECT-TOKEN",
            "urn:ietf:params:oauth:token-type:access_token",
        )
    }

    /// The number of log lines of `level` that contain `text`.
    fn count(lines: &[&str], level: &str, text: &str) -> usize {
        lines
            .iter()
            .filter(|line| line.contains(&format!(" {level} ")) && line.contains(text))
            .count()
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_the_default_lifetime_is_logged_as_a_warning_once_for_an_endpoint_and_its_clones()
    {
        let (_server, _mock, endpoint) = endpoint_answering(
            &serde_json::json!({"access_token": "SECRET-ISSUED-TOKEN", "token_type": "Bearer"}),
        )
        .await;

        endpoint.exchange(&subject()).await.unwrap();
        endpoint.exchange(&subject()).await.unwrap();
        endpoint.clone().exchange(&subject()).await.unwrap();

        logs_assert(|lines| {
            let warnings = count(
                lines,
                "WARN",
                "has no `expires_in`. middle uses the default lifetime of 300s",
            );
            if warnings != 1 {
                return Err(format!("{warnings} warnings"));
            }
            match lines.iter().find(|line| line.contains("SECRET")) {
                Some(line) => Err(format!("a token in the log: {line}")),
                None => Ok(()),
            }
        });
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_the_exp_of_an_issued_jwt_is_logged_as_info_once() {
        let (_server, _mock, endpoint) = endpoint_answering(
            &serde_json::json!({"access_token": jwt(u64::MAX), "token_type": "Bearer"}),
        )
        .await;

        endpoint.exchange(&subject()).await.unwrap();
        endpoint.exchange(&subject()).await.unwrap();

        logs_assert(|lines| {
            let infos = count(
                lines,
                "INFO",
                "has no `expires_in`. middle uses the `exp` of the JWT access token, which is 31536000s after the answer arrived",
            );
            let warnings = count(lines, "WARN", "has no `expires_in`");
            if (infos, warnings) == (1, 0) {
                Ok(())
            } else {
                Err(format!("{infos} infos and {warnings} warnings"))
            }
        });
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_an_answer_with_expires_in_logs_nothing_about_its_lifetime() {
        let (_server, _mock, endpoint) = endpoint_answering(
            &serde_json::json!({"access_token": "t", "token_type": "Bearer", "expires_in": 900}),
        )
        .await;

        endpoint.exchange(&subject()).await.unwrap();

        assert!(!logs_contain("has no `expires_in`"));
    }
}
