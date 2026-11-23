//! The errors of middle.

use std::{fmt, sync::Arc, time::Duration};

use http::StatusCode;

/// The result type of middle.
pub type Result<T> = std::result::Result<T, Error>;

/// An error of middle.
///
/// Errors are cheap to clone, so an authorizer can hand the error of its last refresh to every caller.
/// [`std::error::Error::source`] leads to the cause, for example the [`reqwest::Error`] of a failed connection.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The token endpoint answered with an OAuth error (RFC 6749, section 5.2).
    #[error(transparent)]
    OAuth(#[from] OAuthError),
    /// The token endpoint answered with a status other than 200 and a body that is not an OAuth error, such as the error page of a proxy.
    #[error(transparent)]
    Http(#[from] HttpError),
    /// The token endpoint answered, but middle cannot use the answer.
    #[error(transparent)]
    InvalidResponse(#[from] InvalidResponse),
    /// The token request did not complete, for example because the connection failed.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// The token endpoint did not answer within this time.
    #[error("the token endpoint did not answer within {0:?}")]
    Timeout(Duration),
    /// The configuration cannot work.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// The token cannot be used as a header value.
    #[error("the token cannot be used as a header value; it must be visible ASCII")]
    InvalidHeaderValue,
    /// The token has expired and a refresh has not succeeded yet.
    #[error("the token has expired and a refresh has not succeeded yet")]
    TokenExpired,
    /// A request sent through [`crate::HttpClient`] failed.
    #[error("Request failed: {0}")]
    ReqwestFailed(#[from] Arc<reqwest::Error>),
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

    /// How long the token endpoint asked to wait before the next request, from a `Retry-After` header in seconds.
    #[must_use]
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::OAuth(error) => error.retry_after(),
            Self::Http(error) => error.retry_after(),
            _ => None,
        }
    }

    /// Whether the same request can succeed later.
    ///
    /// Retryable are transport errors, timeouts, HTTP 408, 429 and 5xx without an OAuth error, the OAuth errors `server_error` and `temporarily_unavailable`, and any OAuth error with HTTP 429.
    /// Not retryable are other OAuth errors such as `invalid_client`, whatever their HTTP status, answers middle cannot use, and configuration errors.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::OAuth(error) => {
                matches!(
                    error.code(),
                    ErrorCode::ServerError | ErrorCode::TemporarilyUnavailable
                ) || error.status() == StatusCode::TOO_MANY_REQUESTS
            }
            Self::Http(error) => is_retryable_status(error.status()),
            Self::Transport(TransportError(error)) | Self::ReqwestFailed(error) => {
                !error.is_builder()
            }
            Self::Timeout(_) | Self::TokenExpired => true,
            Self::InvalidResponse(_) | Self::Config(_) | Self::InvalidHeaderValue => false,
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
    /// `access_denied`: the user denied the device authorization (RFC 8628, section 3.5).
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

/// An answer of the token endpoint with a status other than 200 and a body that is not an OAuth error.
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
    /// The `token_type` is not `Bearer`.
    UnsupportedTokenType(String),
    /// The access token has characters a bearer token cannot have (RFC 6750, section 2.1).
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
                "the token type `{token_type}` is not supported; middle supports `Bearer` only"
            ),
            Self::InvalidAccessToken => f.write_str(
                "the access token has characters a bearer token cannot have (RFC 6750, section 2.1)",
            ),
            Self::Redirected { to } => write!(
                f,
                "the HTTP client followed a redirect, and {to} answered in place of the token endpoint"
            ),
        }
    }
}

/// A token request that did not complete, for example because the connection failed.
///
/// [`std::error::Error::source`] is the [`reqwest::Error`].
#[derive(Debug, Clone)]
pub struct TransportError(pub(crate) Arc<reqwest::Error>);

impl From<reqwest::Error> for TransportError {
    fn from(error: reqwest::Error) -> Self {
        Self(Arc::new(error))
    }
}

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
    /// middle sets this form parameter itself.
    ReservedParameter(String),
    /// A form parameter has an empty name.
    EmptyParameterName,
    /// The token URL uses a scheme other than `http` and `https`.
    TokenUrlScheme(String),
    /// The token URL has a fragment (RFC 6749, section 3.2).
    TokenUrlWithFragment,
    /// The token URL contains a user name or password.
    TokenUrlWithUserInfo,
    /// reqwest cannot build the HTTP client. [`std::error::Error::source`] is the [`reqwest::Error`].
    HttpClient(Arc<reqwest::Error>),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidScope(scope) => write!(
                f,
                "`{scope}` is not a valid scope: a scope has one or more visible ASCII characters other than `\"` and `\\`, and no space (RFC 6749, section 3.3)"
            ),
            Self::ReservedParameter(name) => {
                write!(f, "middle sets the form parameter `{name}` itself")
            }
            Self::EmptyParameterName => f.write_str("a form parameter needs a name"),
            Self::TokenUrlScheme(scheme) => {
                write!(f, "the token URL must use http or https, not `{scheme}`")
            }
            Self::TokenUrlWithFragment => {
                f.write_str("the token URL must not have a fragment (RFC 6749, section 3.2)")
            }
            Self::TokenUrlWithUserInfo => {
                f.write_str("the token URL must not contain a user name or password")
            }
            Self::HttpClient(_) => {
                f.write_str("the HTTP client for the token endpoint cannot be built")
            }
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::HttpClient(error) => Some(&**error),
            _ => None,
        }
    }
}

/// Displays an error with all its causes, separated by `: `.
pub(crate) struct DisplayChain<'a>(pub(crate) &'a (dyn std::error::Error + 'static));

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

#[cfg(test)]
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
    fn test_an_oauth_error_is_retryable_by_its_code_or_a_rate_limit() {
        assert!(!oauth(StatusCode::SERVICE_UNAVAILABLE, "invalid_client").is_retryable());
        assert!(!oauth(StatusCode::INTERNAL_SERVER_ERROR, "invalid_request").is_retryable());
        assert!(oauth(StatusCode::BAD_REQUEST, "temporarily_unavailable").is_retryable());
        assert!(oauth(StatusCode::INTERNAL_SERVER_ERROR, "server_error").is_retryable());
        assert!(oauth(StatusCode::TOO_MANY_REQUESTS, "invalid_request").is_retryable());
    }

    #[test]
    fn test_an_unknown_error_code_is_kept_as_it_is() {
        assert_eq!(
            ErrorCode::parse("vendor_specific"),
            ErrorCode::Other("vendor_specific".to_string())
        );
    }
}
