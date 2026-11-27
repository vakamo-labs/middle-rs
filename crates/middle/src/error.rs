//! The errors of middle.

use std::{borrow::Cow, fmt, sync::Arc, time::Duration};

use http::StatusCode;

/// The result type of middle.
pub type Result<T> = std::result::Result<T, Error>;

/// An error of middle.
///
/// Errors are cheap to clone, so an authorizer can hand the error of its last refresh to every caller.
/// [`std::error::Error::source`] leads to the cause, for example the `reqwest::Error` of a failed connection.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The token endpoint answered with an OAuth error (RFC 6749, section 5.2).
    #[error(transparent)]
    OAuth(#[from] OAuthError),
    /// The token endpoint answered with a status other than 200 and no OAuth error middle can read, such as the error page of a proxy.
    #[error(transparent)]
    Http(#[from] HttpError),
    /// The token endpoint answered, but middle cannot use the answer.
    #[error(transparent)]
    InvalidResponse(#[from] InvalidResponse),
    /// The token request did not complete, for example because the connection failed.
    #[cfg(feature = "oauth")]
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// The token request did not complete within this time, creating an assertion and reading the answer included.
    #[error("the token request did not complete within {0:?}")]
    Timeout(Duration),
    /// The configuration cannot work.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// The token given to [`crate::Authorizer::bearer`] cannot follow `Bearer ` in a header: it is empty or holds a character other than visible ASCII without space.
    #[error(
        "the token cannot follow `Bearer ` in a header; it must be visible ASCII without spaces"
    )]
    InvalidHeaderValue,
    /// The token has expired or was invalidated, and a refresh has not succeeded yet.
    #[error("the token has expired or was invalidated, and a refresh has not succeeded yet")]
    TokenExpired,
    /// The token has expired or was invalidated, and no refresh task is running: refresh is disabled, or the task ended, for example because its runtime shut down.
    #[error("the token has expired or was invalidated, and no refresh task is running")]
    RefreshStopped,
    /// The token request panicked.
    #[error("the token request panicked")]
    TokenRequestPanicked,
    /// The token had expired when the answer arrived: the token endpoint or token source answered later than the token lives, counted from the request,
    /// or handed out a token that had expired. The value is that lifetime.
    #[error(
        "the token had expired when the answer arrived: it lives {0:?}, counted from the request"
    )]
    ExpiredOnArrival(Duration),
    /// A token source or an assertion source failed, for example because signing failed, an assertion file cannot be read, or a service did not answer.
    #[error(transparent)]
    Source(#[from] SourceError),
}

impl Error {
    /// The HTTP status of the token endpoint's answer, if the error comes from one.
    #[must_use]
    pub fn status(&self) -> Option<StatusCode> {
        match self {
            Self::OAuth(error) => Some(error.status()),
            Self::Http(error) => Some(error.status()),
            Self::InvalidResponse(error) => Some(error.status()),
            _ => None,
        }
    }

    /// How long to wait before the next request: from a `Retry-After` header of the token endpoint in seconds, at most one day,
    /// or from [`SourceError::with_retry_after`].
    #[must_use]
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::OAuth(error) => error.retry_after(),
            Self::Http(error) => error.retry_after(),
            Self::Source(error) => error.retry_after,
            _ => None,
        }
    }

    /// The `error` code of the token endpoint's OAuth error answer (RFC 6749, section 5.2), if the error is one. The same as [`OAuthError::code`] of [`Error::OAuth`].
    ///
    /// Check [`Self::is_retryable`] first: a code with HTTP 5xx comes from a server that failed.
    #[must_use]
    pub fn oauth_code(&self) -> Option<&ErrorCode> {
        match self {
            Self::OAuth(error) => Some(error.code()),
            _ => None,
        }
    }

    /// Whether the same request can succeed later.
    ///
    /// Retryable are transport errors, timeouts, and answers with HTTP 408, 429 or 5xx, whatever OAuth error they carry. These statuses ask for a later attempt, and a 5xx comes from a server that failed, so its code is not reliable.
    /// The OAuth errors `server_error` and `temporarily_unavailable` are retryable with any status.
    /// [`Error::TokenExpired`] is retryable, because a refresh is due. [`Error::ExpiredOnArrival`] is retryable, because the next answer can come sooner or bring a token that lives longer.
    /// [`Error::Source`] is retryable unless [`SourceError::permanent`] marks it: a token source or an assertion file or signing service can recover, and a failed assertion costs the token endpoint nothing, because middle creates it before it sends the request.
    /// Not retryable are other OAuth errors with another status, such as `invalid_client` with HTTP 401 or `invalid_grant` with HTTP 400, redirect errors of the HTTP client, answers middle cannot use, configuration errors, a panicked token request, and [`Error::RefreshStopped`].
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::OAuth(error) => {
                is_retryable_status(error.status())
                    || matches!(
                        error.code(),
                        ErrorCode::ServerError | ErrorCode::TemporarilyUnavailable
                    )
            }
            Self::Http(error) => is_retryable_status(error.status()),
            #[cfg(feature = "oauth")]
            Self::Transport(TransportError(error)) => !error.is_builder() && !error.is_redirect(),
            Self::Timeout(_) | Self::TokenExpired | Self::ExpiredOnArrival(_) => true,
            Self::Source(error) => !error.permanent,
            Self::InvalidResponse(_)
            | Self::Config(_)
            | Self::InvalidHeaderValue
            | Self::RefreshStopped
            | Self::TokenRequestPanicked => false,
        }
    }
}

fn is_retryable_status(status: StatusCode) -> bool {
    status.is_server_error()
        || status == StatusCode::TOO_MANY_REQUESTS
        || status == StatusCode::REQUEST_TIMEOUT
}

/// An OAuth error answer of the token endpoint (RFC 6749, section 5.2).
///
/// Texts from the token endpoint are kept without control characters and shortened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthError {
    pub(crate) status: StatusCode,
    pub(crate) code: ErrorCode,
    pub(crate) description: Option<String>,
    pub(crate) uri: Option<String>,
    pub(crate) retry_after: Option<Duration>,
}

impl OAuthError {
    /// The HTTP status of the answer. RFC 6749 asks for 400 or 401, but some token endpoints send an OAuth error with other statuses, even 200.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// The `error` code.
    #[must_use]
    pub fn code(&self) -> &ErrorCode {
        &self.code
    }

    /// The `error_description`.
    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// The `error_uri`.
    #[must_use]
    pub fn uri(&self) -> Option<&str> {
        self.uri.as_deref()
    }

    /// The `Retry-After` header in seconds.
    #[must_use]
    pub fn retry_after(&self) -> Option<Duration> {
        self.retry_after
    }
}

impl fmt::Display for OAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the token endpoint answered with the OAuth error `{}` (HTTP {})",
            self.code, self.status
        )?;
        if let Some(description) = &self.description {
            write!(f, ": {description}")?;
        }
        if let Some(uri) = &self.uri {
            write!(f, " (see {uri})")?;
        }
        Ok(())
    }
}

impl std::error::Error for OAuthError {}

/// The `error` code of an OAuth error (RFC 6749, section 5.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCode {
    /// `invalid_request`
    InvalidRequest,
    /// `invalid_client`
    InvalidClient,
    /// `invalid_grant`
    InvalidGrant,
    /// `unauthorized_client`
    UnauthorizedClient,
    /// `unsupported_grant_type`
    UnsupportedGrantType,
    /// `invalid_scope`
    InvalidScope,
    /// `server_error`
    ServerError,
    /// `temporarily_unavailable`
    TemporarilyUnavailable,
    /// `authorization_pending`: the user has not finished the device authorization yet (RFC 8628, section 3.5).
    AuthorizationPending,
    /// `slow_down`: poll the device authorization less often (RFC 8628, section 3.5).
    SlowDown,
    /// `access_denied`: the resource owner or the authorization server denied the request (RFC 6749, section 4.1.2.1),
    /// for example a user who denied the device authorization (RFC 8628, section 3.5), or a token endpoint that refuses a token exchange.
    AccessDenied,
    /// `expired_token`: the device code has expired (RFC 8628, section 3.5).
    ExpiredToken,
    /// `invalid_target`: a `resource` or `audience` is not acceptable (RFC 8707, section 2; RFC 8693, section 2.2.2).
    InvalidTarget,
    /// `invalid_dpop_proof` (RFC 9449, section 5).
    InvalidDpopProof,
    /// `use_dpop_nonce`: send the proof again with the nonce the server gave (RFC 9449, section 8).
    UseDpopNonce,
    /// Any other code, such as one an extension defines.
    Other(String),
}

impl ErrorCode {
    #[cfg(feature = "oauth")]
    pub(crate) fn parse(code: &str) -> Self {
        match code {
            "invalid_request" => Self::InvalidRequest,
            "invalid_client" => Self::InvalidClient,
            "invalid_grant" => Self::InvalidGrant,
            "unauthorized_client" => Self::UnauthorizedClient,
            "unsupported_grant_type" => Self::UnsupportedGrantType,
            "invalid_scope" => Self::InvalidScope,
            "server_error" => Self::ServerError,
            "temporarily_unavailable" => Self::TemporarilyUnavailable,
            "authorization_pending" => Self::AuthorizationPending,
            "slow_down" => Self::SlowDown,
            "access_denied" => Self::AccessDenied,
            "expired_token" => Self::ExpiredToken,
            "invalid_target" => Self::InvalidTarget,
            "invalid_dpop_proof" => Self::InvalidDpopProof,
            "use_dpop_nonce" => Self::UseDpopNonce,
            other => Self::Other(other.to_string()),
        }
    }

    /// The code as the token endpoint sent it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::InvalidScope => "invalid_scope",
            Self::ServerError => "server_error",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
            Self::AuthorizationPending => "authorization_pending",
            Self::SlowDown => "slow_down",
            Self::AccessDenied => "access_denied",
            Self::ExpiredToken => "expired_token",
            Self::InvalidTarget => "invalid_target",
            Self::InvalidDpopProof => "invalid_dpop_proof",
            Self::UseDpopNonce => "use_dpop_nonce",
            Self::Other(code) => code,
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An answer of the token endpoint with a status other than 200 and no OAuth error middle can read, for example because the body is the error page of a proxy, is too large or breaks off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpError {
    pub(crate) status: StatusCode,
    pub(crate) content_type: Option<String>,
    pub(crate) retry_after: Option<Duration>,
}

impl HttpError {
    /// The HTTP status of the answer.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// The `Content-Type` of the answer.
    #[must_use]
    pub fn content_type(&self) -> Option<&str> {
        self.content_type.as_deref()
    }

    /// The `Retry-After` header in seconds.
    #[must_use]
    pub fn retry_after(&self) -> Option<Duration> {
        self.retry_after
    }
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the token endpoint answered with HTTP {} and no OAuth error",
            self.status
        )?;
        if let Some(content_type) = &self.content_type {
            write!(f, " (content type `{content_type}`)")?;
        }
        Ok(())
    }
}

impl std::error::Error for HttpError {}

/// An answer of the token endpoint that middle cannot use.
///
/// It never holds the body of the answer, which may contain an access token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidResponse {
    pub(crate) status: StatusCode,
    pub(crate) content_type: Option<String>,
    pub(crate) problem: ResponseProblem,
}

impl InvalidResponse {
    /// The HTTP status of the answer.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// The `Content-Type` of the answer.
    #[must_use]
    pub fn content_type(&self) -> Option<&str> {
        self.content_type.as_deref()
    }

    /// What is wrong with the answer.
    #[must_use]
    pub fn problem(&self) -> &ResponseProblem {
        &self.problem
    }
}

impl fmt::Display for InvalidResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the token endpoint answered with HTTP {}, but middle cannot use the answer: {}",
            self.status, self.problem
        )
    }
}

impl std::error::Error for InvalidResponse {}

/// What is wrong with an answer of the token endpoint. Names fields, never their values.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResponseProblem {
    /// The body is not a JSON object.
    NotJsonObject,
    /// The body is larger than `limit` bytes.
    TooLarge {
        /// The largest body middle reads, in bytes.
        limit: usize,
    },
    /// A required field is missing.
    MissingField(&'static str),
    /// A field has the wrong type.
    WrongType {
        /// The field.
        field: &'static str,
        /// What the field must be.
        expected: &'static str,
    },
    /// The `token_type` is not `Bearer`, and in the answer to a token exchange also not `N_A`.
    UnsupportedTokenType(String),
    /// The access token is empty or holds a character other than visible ASCII without space, so that it cannot follow `Bearer ` in a header.
    InvalidAccessToken,
    /// The HTTP client followed a redirect, so the answer comes from another URL.
    Redirected {
        /// The origin of the URL that answered.
        to: String,
    },
}

impl fmt::Display for ResponseProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotJsonObject => f.write_str("the body is not a JSON object"),
            Self::TooLarge { limit } => write!(f, "the body is larger than {limit} bytes"),
            Self::MissingField(field) => write!(f, "the field `{field}` is missing"),
            Self::WrongType { field, expected } => {
                write!(f, "the field `{field}` is not {expected}")
            }
            Self::UnsupportedTokenType(token_type) => write!(
                f,
                "the token type `{token_type}` is not supported; middle supports `Bearer`, and `N_A` in a token exchange"
            ),
            Self::InvalidAccessToken => f.write_str(
                "the access token is empty or holds a character other than visible ASCII without space, so it cannot follow `Bearer ` in a header",
            ),
            Self::Redirected { to } => write!(
                f,
                "the HTTP client followed a redirect, and {to} answered in place of the token endpoint"
            ),
        }
    }
}

/// The error of a token source or an assertion source, for example because signing failed, an assertion file cannot be read, or a service did not answer.
/// [`std::error::Error::source`] is the cause, if there is one.
///
/// A retry may fix it, unless it is marked with [`SourceError::permanent`].
#[derive(Debug, Clone)]
pub struct SourceError {
    message: Cow<'static, str>,
    source: Option<Arc<dyn std::error::Error + Send + Sync>>,
    permanent: bool,
    retry_after: Option<Duration>,
}

impl SourceError {
    /// An error with a message that says what failed. The message and the cause are shown and logged, so they must not hold a token, an assertion, a key or another secret.
    #[must_use]
    pub fn new(message: impl Into<Cow<'static, str>>) -> Self {
        Self {
            message: message.into(),
            source: None,
            permanent: false,
            retry_after: None,
        }
    }

    /// Marks the error as one a retry cannot fix, such as a signing service that denies access.
    /// Building an authorizer then fails at once. The refresh task waits as after other errors a retry cannot fix:
    /// at most half the time the current token has left, but at least 1 s, while it is valid, and about 5 minutes once it expired or was invalidated.
    #[must_use]
    pub fn permanent(mut self) -> Self {
        self.permanent = true;
        self
    }

    /// Asks middle to wait at least this long before the next request, as a `Retry-After` header of a token endpoint does, for example for a service that limits its rate.
    /// middle waits at most 5 minutes.
    #[must_use]
    pub fn with_retry_after(mut self, wait: Duration) -> Self {
        self.retry_after = Some(wait);
        self
    }

    /// Sets the cause, which [`std::error::Error::source`] returns.
    #[must_use]
    pub fn with_source(
        mut self,
        source: impl Into<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        self.source = Some(Arc::from(source.into()));
        self
    }

    /// Whether [`Self::permanent`] marked the error as one a retry cannot fix.
    #[must_use]
    pub fn is_permanent(&self) -> bool {
        self.permanent
    }

    /// The wait that [`Self::with_retry_after`] asks for.
    #[must_use]
    pub fn retry_after(&self) -> Option<Duration> {
        self.retry_after
    }

    #[cfg(feature = "jwt")]
    pub(crate) fn with_shared_source(
        mut self,
        source: Arc<dyn std::error::Error + Send + Sync>,
    ) -> Self {
        self.source = Some(source);
        self
    }
}

impl fmt::Display for SourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for SourceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn std::error::Error + 'static))
    }
}

/// A token request that did not complete, for example because the connection failed.
///
/// [`std::error::Error::source`] is the [`reqwest::Error`].
#[cfg(feature = "oauth")]
#[derive(Debug, Clone)]
pub struct TransportError(pub(crate) Arc<reqwest::Error>);

#[cfg(feature = "oauth")]
impl From<reqwest::Error> for TransportError {
    fn from(error: reqwest::Error) -> Self {
        Self(Arc::new(error))
    }
}

#[cfg(feature = "oauth")]
impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_connect() {
            f.write_str("cannot connect to the token endpoint")
        } else if self.0.is_body() || self.0.is_decode() {
            f.write_str("reading the answer of the token endpoint failed")
        } else {
            f.write_str("the token request failed")
        }
    }
}

#[cfg(feature = "oauth")]
impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.0)
    }
}

/// A configuration that cannot work.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ConfigError {
    /// The scope is not valid (RFC 6749, section 3.3).
    InvalidScope(String),
    /// middle reserves this form parameter for the grant and the client authentication.
    ReservedParameter(String),
    /// A form parameter has an empty name.
    EmptyParameterName,
    /// The token URL uses a scheme other than `http` and `https`.
    TokenUrlScheme(String),
    /// The token URL uses `http` with a host other than `localhost` and the loopback addresses `127.0.0.0/8` and `::1`, and `http` is not allowed with `danger_allow_http`. The value is the host.
    HttpTokenUrl(String),
    /// The token URL has a fragment (RFC 6749, section 3.2).
    TokenUrlWithFragment,
    /// The token URL contains a user name or password.
    TokenUrlWithUserInfo,
    /// reqwest cannot build the HTTP client. [`std::error::Error::source`] is the [`reqwest::Error`].
    #[cfg(feature = "oauth")]
    HttpClient(Arc<reqwest::Error>),
    /// The default token lifetime is shorter than 2 s.
    /// A token is refreshed 1 s after its request at the earliest, so a lifetime of at least 2 s makes the refresh come before the token expires.
    DefaultTokenLifetimeTooShort(Duration),
    /// The name is not an `alg` value middle signs with. `alg` values are case-sensitive, for example `RS256` or `EdDSA`.
    #[cfg(feature = "jwt")]
    UnknownSigningAlgorithm(String),
    /// The signing key does not fit its algorithm, is not in a form middle reads, or cannot sign.
    #[cfg(feature = "jwt")]
    InvalidSigningKey(String),
    /// The signing key is shorter than RFC 7518, section 3, requires for its algorithm.
    #[cfg(feature = "jwt")]
    WeakSigningKey {
        /// The algorithm of the key.
        algorithm: crate::jwt::SigningAlgorithm,
        /// The length of the key in bits.
        bits: usize,
        /// The shortest length the algorithm allows, in bits.
        minimum: usize,
    },
    /// middle sets this claim itself.
    #[cfg(feature = "jwt")]
    ReservedClaim(String),
    /// An assertion lifetime shorter than 10 seconds or longer than one hour.
    #[cfg(feature = "jwt")]
    AssertionLifetime(std::time::Duration),
    /// The certificate is not an X.509 certificate in the form given: PEM with the label `CERTIFICATE`, or DER.
    #[cfg(feature = "jwt")]
    InvalidCertificate,
    /// The public key of the certificate does not belong to the signing key. A shared secret for `HS*` has no certificate.
    #[cfg(feature = "jwt")]
    CertificateKeyMismatch,
    /// The public key of the certificate has an algorithm middle does not sign with, such as RSA-PSS. The value is the OID of the algorithm, such as `1.2.840.113549.1.1.10`.
    #[cfg(feature = "jwt")]
    UnsupportedCertificateKey(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidScope(scope) => write!(
                f,
                "`{scope}` is not a valid scope: a scope has one or more visible ASCII characters other than `\"` and `\\`, and no space (RFC 6749, section 3.3)"
            ),
            Self::ReservedParameter(name) => {
                write!(
                    f,
                    "middle reserves the form parameter `{name}` for the grant and the client authentication"
                )
            }
            Self::EmptyParameterName => f.write_str("a form parameter needs a name"),
            Self::TokenUrlScheme(scheme) => {
                write!(f, "the token URL must use http or https, not `{scheme}`")
            }
            Self::HttpTokenUrl(host) => write!(
                f,
                "the token URL uses http with the host `{host}`, which sends the client credentials or the assertion of the JWT bearer grant without TLS: use https, or allow http with `danger_allow_http`"
            ),
            Self::TokenUrlWithFragment => {
                f.write_str("the token URL must not have a fragment (RFC 6749, section 3.2)")
            }
            Self::TokenUrlWithUserInfo => {
                f.write_str("the token URL must not contain a user name or password")
            }
            #[cfg(feature = "oauth")]
            Self::HttpClient(_) => {
                f.write_str("the HTTP client for the token endpoint cannot be built")
            }
            Self::DefaultTokenLifetimeTooShort(lifetime) => write!(
                f,
                "the default token lifetime is {lifetime:?}, but it must be at least 2 s, so that the refresh 1 s after the request comes before the token expires"
            ),
            #[cfg(feature = "jwt")]
            Self::UnknownSigningAlgorithm(name) => write!(
                f,
                "unknown signing algorithm `{name}`; expected a case-sensitive `alg` value such as `RS256` or `EdDSA`"
            ),
            #[cfg(feature = "jwt")]
            Self::InvalidSigningKey(reason) => write!(f, "invalid signing key: {reason}"),
            #[cfg(feature = "jwt")]
            Self::WeakSigningKey {
                algorithm,
                bits,
                minimum,
            } => write!(
                f,
                "the signing key has {bits} bits, but {algorithm} needs at least {minimum} (RFC 7518, section 3)"
            ),
            #[cfg(feature = "jwt")]
            Self::ReservedClaim(name) => write!(f, "middle sets the claim `{name}` itself"),
            #[cfg(feature = "jwt")]
            Self::AssertionLifetime(lifetime) => write!(
                f,
                "an assertion lifetime must be from 10 seconds to one hour, not {lifetime:?}"
            ),
            #[cfg(feature = "jwt")]
            Self::InvalidCertificate => {
                f.write_str("the certificate cannot be read as an X.509 certificate")
            }
            #[cfg(feature = "jwt")]
            Self::CertificateKeyMismatch => {
                f.write_str("the public key of the certificate does not belong to the signing key")
            }
            #[cfg(feature = "jwt")]
            Self::UnsupportedCertificateKey(algorithm) => write!(
                f,
                "the public key of the certificate has the algorithm {algorithm}, which middle does not sign with"
            ),
        }
    }
}

impl std::error::Error for ConfigError {
    #[cfg(feature = "oauth")]
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::HttpClient(error) => Some(&**error),
            _ => None,
        }
    }
}

/// Displays an error with all its causes, separated by `: `.
#[cfg(feature = "oauth")]
pub(crate) struct DisplayChain<'a>(pub(crate) &'a (dyn std::error::Error + 'static));

#[cfg(feature = "oauth")]
impl fmt::Display for DisplayChain<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)?;
        let mut source = self.0.source();
        while let Some(cause) = source {
            write!(f, ": {cause}")?;
            source = cause.source();
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "oauth"))]
mod tests {
    use super::*;

    #[test]
    fn test_registered_error_codes_have_their_own_variant() {
        for code in [
            "invalid_request",
            "invalid_client",
            "invalid_grant",
            "unauthorized_client",
            "unsupported_grant_type",
            "invalid_scope",
            "server_error",
            "temporarily_unavailable",
            "authorization_pending",
            "slow_down",
            "access_denied",
            "expired_token",
            "invalid_target",
            "invalid_dpop_proof",
            "use_dpop_nonce",
        ] {
            let parsed = ErrorCode::parse(code);
            assert!(!matches!(parsed, ErrorCode::Other(_)), "{code}");
            assert_eq!(parsed.as_str(), code);
        }
    }

    fn oauth(status: StatusCode, code: &str) -> Error {
        OAuthError {
            status,
            code: ErrorCode::parse(code),
            description: None,
            uri: None,
            retry_after: None,
        }
        .into()
    }

    #[test]
    fn test_an_oauth_error_is_retryable_by_its_status_or_its_code() {
        // 408, 429 and 5xx, whatever the code.
        assert!(oauth(StatusCode::SERVICE_UNAVAILABLE, "invalid_client").is_retryable());
        assert!(oauth(StatusCode::INTERNAL_SERVER_ERROR, "invalid_request").is_retryable());
        assert!(oauth(StatusCode::SERVICE_UNAVAILABLE, "Service Unavailable").is_retryable());
        assert!(oauth(StatusCode::REQUEST_TIMEOUT, "invalid_grant").is_retryable());
        assert!(oauth(StatusCode::TOO_MANY_REQUESTS, "invalid_request").is_retryable());
        // `server_error` and `temporarily_unavailable`, whatever the status.
        assert!(oauth(StatusCode::BAD_REQUEST, "temporarily_unavailable").is_retryable());
        assert!(oauth(StatusCode::OK, "server_error").is_retryable());
        // Other codes with other statuses.
        assert!(!oauth(StatusCode::UNAUTHORIZED, "invalid_client").is_retryable());
        assert!(!oauth(StatusCode::BAD_REQUEST, "invalid_request").is_retryable());
        assert!(!oauth(StatusCode::BAD_REQUEST, "account_locked").is_retryable());
    }

    #[test]
    fn test_the_oauth_code_is_that_of_an_oauth_error() {
        assert_eq!(
            oauth(StatusCode::BAD_REQUEST, "invalid_grant").oauth_code(),
            Some(&ErrorCode::InvalidGrant)
        );
        assert_eq!(
            oauth(StatusCode::UNAUTHORIZED, "vendor_specific").oauth_code(),
            Some(&ErrorCode::Other("vendor_specific".to_string()))
        );
        let http: Error = HttpError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            content_type: None,
            retry_after: None,
        }
        .into();
        assert_eq!(http.oauth_code(), None);
        assert_eq!(Error::Timeout(Duration::from_secs(1)).oauth_code(), None);
    }

    #[test]
    fn test_an_unknown_error_code_is_kept_as_it_is() {
        assert_eq!(
            ErrorCode::parse("vendor_specific"),
            ErrorCode::Other("vendor_specific".to_string())
        );
    }
}
