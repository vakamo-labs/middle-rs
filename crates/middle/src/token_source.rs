//! Token sources of the application's own, see [`TokenSource`].

use std::{fmt, future::Future, sync::Arc, time::Duration};

use crate::{
    authorizers::TokenValue,
    cache::BoxFuture,
    error::SourceError,
    token_endpoint::{MAX_EXPIRES_IN, TokenResponse},
};

/// Supplies the access tokens of an authorizer made with [`crate::Authorizer::from_source`]. Implement it with `async fn token`.
///
/// middle handles the tokens of a source as those of a token endpoint: it keeps the current token, asks the source for a new one before the token expires,
/// retries failures with a backoff, and asks for a new token after `invalidate`. Sources are, for example, a token exchange of your own, a cloud SDK,
/// or a token in a file that another process renews. `Arc<S>` is a source too, so one source can serve several authorizers.
///
/// middle asks for a token for every refresh, retries included. The [`TokenContext`] says why, and the reasons of [`TokenReason`] say what to return:
/// the newest token the source has for a refresh, and a token other than the rejected one after `invalidate`.
///
/// An error fails the attempt, and middle retries it, see [`SourceError`]. A token whose lifetime ends while middle waits for the source fails the attempt
/// with [`crate::Error::ExpiredOnArrival`], which middle retries too. A JWT without a lifetime whose `exp` had passed when middle asked lives the default token lifetime
/// of the builder, because middle cannot tell a stale token from a local clock that runs ahead.
///
/// Each attempt may take at most the timeout of the builder, and during a refresh while the current token is valid, at most half the time it has left,
/// but at least 1 s. middle then drops the future, so the source must cope with being stopped at any `.await`. A source that retries inside should
/// finish its retries within that time. Work that several attempts or callers share, such as a request that
/// a cache of the source starts, belongs in a spawned task, so that dropping one attempt does not cancel it.
///
/// middle shows the `Debug` output of a source in the `Debug` output of the authorizer and its builder, so it must not show secrets or tokens.
/// Log messages name the source by its type.
///
/// # Example
///
/// ```
/// use middle::{AccessToken, SourceError, TokenContext, TokenSource};
///
/// /// Reads a token that another process writes to a file and renews every few minutes.
/// #[derive(Debug)]
/// struct TokenFile(std::path::PathBuf);
///
/// impl TokenSource for TokenFile {
///     async fn token(&self, _context: &TokenContext) -> Result<AccessToken, SourceError> {
///         // Reading a file blocks, so it runs on a thread for blocking work.
///         let path = self.0.clone();
///         let token = tokio::task::spawn_blocking(move || std::fs::read_to_string(path))
///             .await
///             .map_err(|error| SourceError::new("reading the token file failed").with_source(error))?
///             .map_err(|error| SourceError::new("cannot read the token file").with_source(error))?;
///         // The file holds the newest token whatever the reason. Without `with_expires_in`, middle uses
///         // the `exp` of the token if it is a JWT with an `exp` in the future, else the default token lifetime of the builder.
///         AccessToken::new(token.trim())
///     }
/// }
/// ```
pub trait TokenSource: fmt::Debug + Send + Sync + 'static {
    /// A new access token.
    fn token(
        &self,
        context: &TokenContext,
    ) -> impl Future<Output = Result<AccessToken, SourceError>> + Send;
}

impl<S: TokenSource> TokenSource for Arc<S> {
    fn token(
        &self,
        context: &TokenContext,
    ) -> impl Future<Output = Result<AccessToken, SourceError>> + Send {
        (**self).token(context)
    }
}

/// A [`TokenSource`] with a boxed future, so that middle can keep a source of any type behind one pointer.
pub(crate) trait BoxedTokenSource: fmt::Debug + Send + Sync + 'static {
    fn boxed<'a>(
        &'a self,
        context: &'a TokenContext,
    ) -> BoxFuture<'a, Result<AccessToken, SourceError>>;
}

impl<S: TokenSource> BoxedTokenSource for S {
    fn boxed<'a>(
        &'a self,
        context: &'a TokenContext,
    ) -> BoxFuture<'a, Result<AccessToken, SourceError>> {
        Box::pin(self.token(context))
    }
}

/// What a [`TokenSource`] knows about the request for a token.
#[derive(Debug, Clone)]
pub struct TokenContext {
    reason: TokenReason,
}

impl TokenContext {
    /// A context with the reason `reason`, for example to test a token source.
    #[must_use]
    pub fn new(reason: TokenReason) -> Self {
        Self { reason }
    }

    /// Why middle asks for a token.
    #[must_use]
    pub fn reason(&self) -> TokenReason {
        self.reason
    }
}

/// Why middle asks a [`TokenSource`] for a token. A retry of a refresh that failed has the reason `Refresh`, until the current token is invalidated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TokenReason {
    /// The first token, which `build()` requests.
    First,
    /// The current token is due for refresh or has expired. Return the newest token the source has.
    ///
    /// If that is the current token, middle keeps using it and asks again before it expires, as for any token, but not sooner than 1 s after this request,
    /// so a token with 1 s or less left expires first. middle asks more often as the expiry comes closer. A source whose own cache renews its token
    /// at least a few seconds before expiry works well with this; with a cache that hands out its token until it expires, readers may have no token
    /// for up to a second around each expiry. A token without a lifetime that is not a JWT with an `exp` in the future lives the default token lifetime
    /// of the builder, counted from each request, so set that lifetime to at most the time before expiry at which the source renews its token.
    Refresh,
    /// The current token was dropped with `invalidate`, because a server rejected it. Return another token: a retry with the same token fails again.
    /// If an attempt that started before `invalidate` returns the rejected token, middle asks again with this reason.
    Rejected,
}

/// An access token from a [`TokenSource`]. middle sends it as `Bearer` and the token. `Debug` never shows the token.
#[derive(Clone)]
pub struct AccessToken(TokenResponse);

impl AccessToken {
    /// An access token without a lifetime. middle then uses it until the `exp` of the token if it is a JWT with an `exp` in the future,
    /// else for the default token lifetime of the builder. Set the lifetime with [`Self::with_expires_in`] if the source knows it.
    ///
    /// # Errors
    ///
    /// [`SourceError`] if the token is empty or holds a character other than visible ASCII without space, so that it cannot follow `Bearer ` in a header.
    /// A retry may fix it. The message does not show the token.
    pub fn new(token: impl Into<String>) -> Result<Self, SourceError> {
        let access_token = TokenValue::new(token.into()).ok_or_else(|| {
            SourceError::new(
                "the access token of the token source is empty or holds a character other than visible ASCII without space",
            )
        })?;
        Ok(Self(TokenResponse {
            access_token,
            expires_in: None,
        }))
    }

    /// Sets how long the token is valid, counted from when middle asked the source, as `expires_in` of a token endpoint (RFC 6749, section 5.1).
    /// Longer lifetimes are shortened to one year.
    #[must_use]
    pub fn with_expires_in(mut self, expires_in: Duration) -> Self {
        self.0.expires_in = Some(expires_in.min(MAX_EXPIRES_IN));
        self
    }

    /// The token as it is sent after `Bearer `.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.access_token.as_str()
    }

    /// The lifetime set with [`Self::with_expires_in`], at most one year.
    #[must_use]
    pub fn expires_in(&self) -> Option<Duration> {
        self.0.expires_in
    }

    pub(crate) fn into_response(self) -> TokenResponse {
        self.0
    }
}

impl fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccessToken")
            .field("token", &"[redacted]")
            .field("expires_in", &self.0.expires_in)
            .finish()
    }
}
