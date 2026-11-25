//! The authorizer: a bearer token given once, or a token that middle requests from a token endpoint and keeps fresh.

#[cfg(feature = "client-credentials")]
mod builder;

use std::fmt;

#[cfg(feature = "client-credentials")]
pub use builder::*;
use http::HeaderValue;

#[cfg(feature = "client-credentials")]
use crate::cache::TokenId;
use crate::error::{Error, Result};

/// Puts an `Authorization` header on requests: a bearer token given once, or a token that middle requests from a token endpoint and keeps fresh.
///
/// - [`Authorizer::bearer`]: a token that never changes.
/// - `Authorizer::client_credentials`: the client credentials grant (RFC 6749, section 4.4), with the feature `client-credentials`.
/// - `Authorizer::jwt_bearer`: the JWT bearer grant (RFC 7523, section 2.1), with the feature `client-credentials`.
///
/// For a requested token, `AuthorizerBuilder::build` fetches the first token, and a background task refreshes it before it expires.
/// If a refresh fails, the current token stays in use while it is valid, and the task retries with a backoff.
/// When the last clone of the authorizer is dropped, the refresh task is aborted.
/// If the task ends for another reason, such as its runtime shutting down, the authorizer answers with [`Error::RefreshStopped`] once the token has expired.
///
/// [`Self::authorization_header`] and [`Self::token_header`] never wait. With the feature `client-credentials`, `wait_for_header` waits for a refresh
/// if a requested token has expired, and `invalidate` drops a token that a server rejected.
///
/// Clones are cheap and share the token. `Debug` never shows the token or a secret.
///
/// With the feature `tonic`, `Authorizer::interceptor` returns an interceptor for tonic clients.
#[derive(Clone)]
pub struct Authorizer(Kind);

// The authorizer is shared between threads and tasks.
const _: () = {
    const fn assert_send_sync_static<T: Send + Sync + 'static>() {}
    assert_send_sync_static::<Authorizer>();
};

#[derive(Clone)]
enum Kind {
    /// A token given once.
    Static(BearerHeader),
    /// A token that middle requests and refreshes.
    #[cfg(feature = "client-credentials")]
    Refreshing(Refreshing),
}

impl Authorizer {
    /// An authorizer that sends `Bearer` and `token` with every request. Pass the token without the `Bearer` prefix.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidHeaderValue`] if the token is not ASCII or cannot be a header value.
    pub fn bearer(token: &str) -> Result<Self> {
        require_ascii(token)?;
        Ok(Self(Kind::Static(bearer_header(token)?)))
    }

    /// The header value of the current token, `Bearer` and the token, without waiting.
    ///
    /// To drop a token that a server rejects, use [`Self::token_header`] or `wait_for_header`: `invalidate` takes the header they return.
    ///
    /// # Errors
    ///
    /// See [`Self::token_header`].
    pub fn authorization_header(&self) -> Result<HeaderValue> {
        self.token_header().map(TokenHeader::into_header)
    }

    /// The header of the current token, without waiting. Send it, and pass it to `invalidate` if the server rejects it.
    ///
    /// # Errors
    ///
    /// For a requested token that has expired or was invalidated: [`Error::RefreshStopped`] if no refresh task runs, else the error of the last token request,
    /// else [`Error::TokenExpired`].
    pub fn token_header(&self) -> Result<TokenHeader> {
        match &self.0 {
            Kind::Static(header) => Ok(TokenHeader {
                header: header.header.clone(),
                #[cfg(feature = "client-credentials")]
                token: None,
            }),
            #[cfg(feature = "client-credentials")]
            Kind::Refreshing(refreshing) => refreshing.token_header(),
        }
    }

    /// The header of a valid token.
    ///
    /// If a requested token has expired or was invalidated, asks the refresh task for a new token and waits for it, at most the timeout of the builder.
    /// After a failed request or repeated rejections (see [`Self::invalidate`]), the refresh task waits before the next request;
    /// if that wait ends after the timeout, this method returns at once.
    ///
    /// Cancelling the returned future cancels only the wait, never the request for a new token.
    ///
    /// # Errors
    ///
    /// If no valid token arrives: [`Error::RefreshStopped`] if no refresh task runs, else the error of the last token request, else [`Error::TokenExpired`].
    #[cfg(feature = "client-credentials")]
    pub async fn wait_for_header(&self) -> Result<TokenHeader> {
        match &self.0 {
            Kind::Static(_) => self.token_header(),
            Kind::Refreshing(refreshing) => refreshing.wait_for_header().await,
        }
    }

    /// Drops the token of `rejected`, for example after a server answered with HTTP 401, and asks the refresh task for a new token.
    ///
    /// Returns whether a retry can get another token:
    /// - `true` if the authorizer requested the token and its refresh task runs, or it has a newer token that is still valid.
    ///   [`Self::wait_for_header`] then returns a newer token, or an error if the request for it fails or the refresh task waits longer than the timeout.
    /// - `false` for a token given with [`Self::bearer`], for a header of another authorizer, and if no refresh task runs, because refresh is disabled or its runtime shut down,
    ///   and the authorizer has no newer valid token. Fail the request then.
    ///
    /// Retry a rejected request once: if a server rejects every token, for example because of a wrong audience, `invalidate` keeps returning `true`.
    ///
    /// If the authorizer has a newer token already, that token stays in use, so concurrent calls for the same rejected token request one new token.
    ///
    /// The new token is requested 1 s after the rejected one at the earliest. If the server keeps rejecting tokens soon after they arrive,
    /// for example because of a wrong audience or scope, each further rejection in a row waits longer: 2 s to 4 s after the rejected token was requested,
    /// then 4 s to 8 s, 8 s to 16 s, and then 15 s to 30 s. While middle waits like this, it logs a warning.
    /// A rejection counts only while its wait still lies ahead: a token that lasted longer than the wait is replaced at once and starts a new series.
    /// A token that lasts until its refresh is due ends the series.
    ///
    /// The token is dropped for every user of this authorizer and its clones. If one server rejects tokens that another one accepts,
    /// use one authorizer per server, so that the rejections of one server do not take the token away from the other.
    #[cfg(feature = "client-credentials")]
    pub fn invalidate(&self, rejected: &TokenHeader) -> bool {
        match &self.0 {
            Kind::Static(_) => false,
            Kind::Refreshing(refreshing) => refreshing.invalidate(rejected),
        }
    }

    /// An interceptor for tonic clients that puts the header of this authorizer on every request without an `Authorization` header.
    ///
    /// It never waits. Without a valid token, the request fails with the status `unavailable` if a retry can help, for example while the token endpoint
    /// cannot be reached or a refresh is pending, and with `unauthenticated` otherwise. The source of the status is the [`Error`].
    ///
    /// The interceptor does not learn which token a server rejected. To replace a rejected token, put the header of `wait_for_header` on the request yourself,
    /// which the interceptor keeps. If the server answers `unauthenticated`, pass that header to `invalidate`, and retry once if it returns `true`.
    #[cfg(feature = "tonic")]
    #[must_use]
    pub fn interceptor(&self) -> Interceptor {
        Interceptor(self.clone())
    }
}

impl fmt::Debug for Authorizer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Kind::Static(_) => f.write_str("Authorizer::Bearer([redacted])"),
            #[cfg(feature = "client-credentials")]
            Kind::Refreshing(refreshing) => f.debug_tuple("Authorizer").field(refreshing).finish(),
        }
    }
}

/// The `Authorization` header of one token, as [`Authorizer::token_header`] and `Authorizer::wait_for_header` return it.
///
/// Pass it to `Authorizer::invalidate` if a server rejects the token.
#[derive(Clone, veil::Redact)]
pub struct TokenHeader {
    #[redact]
    header: HeaderValue,
    /// The cache and the generation of a requested token.
    #[cfg(feature = "client-credentials")]
    token: Option<TokenId>,
}

impl TokenHeader {
    /// The header value: `Bearer` and the access token.
    #[must_use]
    pub fn header(&self) -> &HeaderValue {
        &self.header
    }

    /// The header value: `Bearer` and the access token.
    #[must_use]
    pub fn into_header(self) -> HeaderValue {
        self.header
    }
}

/// Puts the `Authorization` header of an [`Authorizer`] on tonic requests that have none, see [`Authorizer::interceptor`].
#[cfg(feature = "tonic")]
#[derive(Clone, Debug)]
pub struct Interceptor(Authorizer);

#[cfg(feature = "tonic")]
impl tonic::service::Interceptor for Interceptor {
    fn call(
        &mut self,
        mut request: tonic::Request<()>,
    ) -> std::result::Result<tonic::Request<()>, tonic::Status> {
        let metadata = request.metadata_mut();
        if !metadata.contains_key(http::header::AUTHORIZATION.as_str()) {
            // The metadata value was built with the token, so this only clones it.
            let value = match &(self.0).0 {
                Kind::Static(header) => header.metadata.clone(),
                #[cfg(feature = "client-credentials")]
                Kind::Refreshing(refreshing) => refreshing.metadata().map_err(status)?,
            };
            metadata.insert(http::header::AUTHORIZATION.as_str(), value);
        }
        Ok(request)
    }
}

/// The status of a request that has no valid token: `unavailable` if a retry can help, else `unauthenticated`, with `error` as its source.
#[cfg(all(feature = "tonic", feature = "client-credentials"))]
fn status(error: Error) -> tonic::Status {
    let mut status = if error.is_retryable() {
        tonic::Status::unavailable(error.to_string())
    } else {
        tonic::Status::unauthenticated(error.to_string())
    };
    status.set_source(std::sync::Arc::new(error));
    status
}

/// Fails with [`Error::InvalidHeaderValue`] if the string is not ASCII.
pub(crate) fn require_ascii(s: &str) -> Result<()> {
    if s.is_ascii() {
        Ok(())
    } else {
        Err(Error::InvalidHeaderValue)
    }
}

/// Pre-computed representations of an `Authorization: Bearer <token>` header, so the [`HeaderValue`] and, with the `tonic` feature,
/// the `MetadataValue` are always built and marked sensitive the same way.
#[derive(Clone)]
pub(crate) struct BearerHeader {
    pub(crate) header: HeaderValue,
    #[cfg(feature = "tonic")]
    pub(crate) metadata: tonic::metadata::MetadataValue<tonic::metadata::Ascii>,
}

/// Builds the sensitive `Authorization: Bearer <token>` representations from a token without the `Bearer ` prefix.
///
/// # Errors
///
/// Fails with [`Error::InvalidHeaderValue`] if the header value is not valid, for example not ASCII.
pub(crate) fn bearer_header(token: &str) -> Result<BearerHeader> {
    let bearer = format!("Bearer {token}");
    let mut header = HeaderValue::from_str(&bearer).map_err(|_| Error::InvalidHeaderValue)?;
    header.set_sensitive(true);

    #[cfg(feature = "tonic")]
    let metadata = {
        use std::str::FromStr;
        let mut metadata = tonic::metadata::MetadataValue::from_str(&bearer)
            .map_err(|_| Error::InvalidHeaderValue)?;
        metadata.set_sensitive(true);
        metadata
    };

    Ok(BearerHeader {
        header,
        #[cfg(feature = "tonic")]
        metadata,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_a_bearer_token_is_the_header() {
        let authorizer = Authorizer::bearer("my-token").unwrap();

        let header: HeaderValue = authorizer.authorization_header().unwrap();
        assert_eq!(header.to_str().unwrap(), "Bearer my-token");
        assert!(header.is_sensitive());
        let token_header = authorizer.token_header().unwrap();
        let header: &HeaderValue = token_header.header();
        assert!(header.is_sensitive());
        let header: HeaderValue = token_header.into_header();
        assert!(header.is_sensitive());
        assert_eq!(format!("{authorizer:?}"), "Authorizer::Bearer([redacted])");
    }

    #[test]
    fn test_a_bearer_token_that_is_not_ascii_is_rejected() {
        assert!(matches!(
            Authorizer::bearer("tökén"),
            Err(Error::InvalidHeaderValue)
        ));
    }

    #[cfg(feature = "tonic")]
    #[test]
    fn test_the_interceptor_adds_the_header() {
        use tonic::service::Interceptor as _;

        let mut interceptor = Authorizer::bearer("my-token").unwrap().interceptor();

        let request = interceptor.call(tonic::Request::new(())).unwrap();

        assert!(
            request
                .metadata()
                .get("authorization")
                .unwrap()
                .is_sensitive()
        );
        assert_eq!(
            request
                .metadata()
                .get("authorization")
                .unwrap()
                .to_str()
                .unwrap(),
            "Bearer my-token"
        );
    }

    #[cfg(feature = "tonic")]
    #[test]
    fn test_the_interceptor_keeps_an_existing_authorization_header() {
        use tonic::service::Interceptor as _;

        let mut interceptor = Authorizer::bearer("my-token").unwrap().interceptor();
        let mut request = tonic::Request::new(());
        request
            .metadata_mut()
            .insert("authorization", "Bearer existing-token".parse().unwrap());

        let request = interceptor.call(request).unwrap();

        assert_eq!(
            request
                .metadata()
                .get("authorization")
                .unwrap()
                .to_str()
                .unwrap(),
            "Bearer existing-token"
        );
    }
}
