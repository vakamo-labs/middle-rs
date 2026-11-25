//! Assertions for JWT client authentication (RFC 7523, section 2.2; RFC 7521, section 4.2).

use std::fmt;
#[cfg(feature = "client-credentials")]
use std::{
    future::Future,
    io::Read as _,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
};

#[cfg(feature = "client-credentials")]
use url::Url;

use crate::error::AssertionError;

/// The largest assertion file [`FileAssertion`] reads, in bytes.
#[cfg(feature = "client-credentials")]
const MAX_FILE_BYTES: u64 = 64 * 1024;

const NOT_A_SIGNED_JWT: &str = "is not a signed JWT: three base64url parts separated by dots";

/// A signed JWT in compact form (RFC 7515, section 7.1). `Debug` never shows it.
#[derive(Clone)]
pub struct SignedJwt(String);

impl SignedJwt {
    /// A signed JWT in compact form, such as a Kubernetes service account token.
    ///
    /// # Errors
    ///
    /// [`AssertionError`] unless `jwt` is three base64url parts separated by dots, none of them empty. The message does not show `jwt`.
    pub fn new(jwt: impl Into<String>) -> Result<Self, AssertionError> {
        let jwt = jwt.into();
        if is_compact_jws(&jwt) {
            Ok(Self(jwt))
        } else {
            Err(AssertionError::new(format!(
                "the assertion {NOT_A_SIGNED_JWT}"
            )))
        }
    }

    /// A JWT that middle signed, so it has the compact form.
    #[cfg(feature = "jwt")]
    pub(crate) fn from_signed(jwt: String) -> Self {
        Self(jwt)
    }

    /// The JWT in compact form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The JWT in compact form.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Debug for SignedJwt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SignedJwt([redacted])")
    }
}

/// Three base64url parts separated by dots, none of them empty: the header, the payload and the signature (RFC 7515, section 7.1).
fn is_compact_jws(jwt: &str) -> bool {
    let parts: Vec<&str> = jwt.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        })
}

/// An assertion as middle sends it to the token endpoint (RFC 7521), such as a signed JWT or a base64url-encoded SAML assertion. `Debug` never shows it.
#[cfg(feature = "client-credentials")]
#[derive(Clone)]
pub struct Assertion(String);

#[cfg(feature = "client-credentials")]
impl Assertion {
    /// An assertion of any type. [`SignedJwt`] converts into one with `From`.
    ///
    /// # Errors
    ///
    /// [`AssertionError`] if `value` is empty or holds a character other than visible ASCII, such as a space or a line break. The message does not show `value`.
    pub fn new(value: impl Into<String>) -> Result<Self, AssertionError> {
        let value = value.into();
        if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_graphic()) {
            Ok(Self(value))
        } else {
            Err(AssertionError::new(
                "the assertion is empty or holds a character other than visible ASCII",
            ))
        }
    }

    /// The assertion as it is sent.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The assertion as it is sent.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

#[cfg(feature = "client-credentials")]
impl From<SignedJwt> for Assertion {
    fn from(jwt: SignedJwt) -> Self {
        Self(jwt.0)
    }
}

#[cfg(feature = "client-credentials")]
impl fmt::Debug for Assertion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Assertion([redacted])")
    }
}

/// The future of [`AssertionSource::assertion`].
#[cfg(feature = "client-credentials")]
pub type AssertionFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Assertion, AssertionError>> + Send + 'a>>;

/// Supplies the assertion for JWT client authentication, see [`crate::ClientAuthentication::client_assertion`].
///
/// Sources are, for example, a [`FileAssertion`] for a Kubernetes service account token, a `jwt::JwtAssertion` (feature `jwt`) that middle signs, or a key management service that signs.
/// `Arc<S>` and `Box<S>` are sources too, so one source can serve several authorizers.
///
/// middle asks for a new assertion for every token request, retries included, within the timeout of that request.
/// An error fails the request, and middle retries it, see [`crate::Error::is_retryable`] and [`AssertionError::permanent`].
///
/// middle shows the `Debug` output of a source in its own `Debug` output, which may end up in logs, so it must not show secrets, keys or assertions.
#[cfg(feature = "client-credentials")]
pub trait AssertionSource: fmt::Debug + Send + Sync + 'static {
    /// A new assertion for one token request.
    fn assertion<'a>(&'a self, context: &'a AssertionContext) -> AssertionFuture<'a>;
}

#[cfg(feature = "client-credentials")]
impl<S: AssertionSource + ?Sized> AssertionSource for Arc<S> {
    fn assertion<'a>(&'a self, context: &'a AssertionContext) -> AssertionFuture<'a> {
        (**self).assertion(context)
    }
}

#[cfg(feature = "client-credentials")]
impl<S: AssertionSource + ?Sized> AssertionSource for Box<S> {
    fn assertion<'a>(&'a self, context: &'a AssertionContext) -> AssertionFuture<'a> {
        (**self).assertion(context)
    }
}

/// What an [`AssertionSource`] knows about the token request.
///
/// `Debug` shows the token URL without user name, password and query.
#[cfg(feature = "client-credentials")]
#[derive(Clone)]
pub struct AssertionContext {
    token_url: Url,
    client_id: Option<String>,
}

#[cfg(feature = "client-credentials")]
impl AssertionContext {
    /// A context without a client id, for example to test an assertion source.
    #[must_use]
    pub fn new(token_url: Url) -> Self {
        Self {
            token_url,
            client_id: None,
        }
    }

    /// Sets the client id.
    #[must_use]
    pub fn with_client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// The URL of the token endpoint.
    #[must_use]
    pub fn token_url(&self) -> &Url {
        &self.token_url
    }

    /// The client id, if the client has one.
    #[must_use]
    pub fn client_id(&self) -> Option<&str> {
        self.client_id.as_deref()
    }
}

#[cfg(feature = "client-credentials")]
impl fmt::Debug for AssertionContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AssertionContext")
            .field(
                "token_url",
                &crate::token_endpoint::redacted_url(&self.token_url).as_str(),
            )
            .field("client_id", &self.client_id)
            .finish()
    }
}

/// A signed JWT that is read from a file for every token request, such as a Kubernetes service account token in a projected volume.
///
/// Whitespace at the start and the end of the file is ignored. The file may hold at most 64 KiB, and it must be a regular file or a link to one.
#[cfg(feature = "client-credentials")]
#[derive(Debug, Clone)]
pub struct FileAssertion {
    path: PathBuf,
}

#[cfg(feature = "client-credentials")]
impl FileAssertion {
    /// An assertion from the file at `path`. The file is read with each token request, so it may be missing until then.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

#[cfg(feature = "client-credentials")]
impl AssertionSource for FileAssertion {
    fn assertion<'a>(&'a self, _context: &'a AssertionContext) -> AssertionFuture<'a> {
        let path = self.path.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || read_assertion(&path))
                .await
                .map_err(|error| {
                    AssertionError::new("reading the assertion file failed").with_source(error)
                })?
        })
    }
}

/// Reads the assertion file at `path`. The errors name the file, never its content.
#[cfg(feature = "client-credentials")]
fn read_assertion(path: &Path) -> Result<Assertion, AssertionError> {
    let cannot_read = |error: std::io::Error| {
        AssertionError::new(format!(
            "cannot read the assertion file `{}`",
            path.display()
        ))
        .with_source(error)
    };
    let not_regular = || {
        AssertionError::new(format!(
            "the assertion file `{}` is not a regular file",
            path.display()
        ))
    };
    // Opening a FIFO without a writer blocks, and a blocking read cannot be cancelled. The metadata follows links.
    if !std::fs::metadata(path).map_err(cannot_read)?.is_file() {
        return Err(not_regular());
    }
    let file = std::fs::File::open(path).map_err(cannot_read)?;
    // The path may have changed since the check.
    if !file.metadata().map_err(cannot_read)?.is_file() {
        return Err(not_regular());
    }
    let mut content = Vec::new();
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut content)
        .map_err(cannot_read)?;
    if content.len() as u64 > MAX_FILE_BYTES {
        return Err(AssertionError::new(format!(
            "the assertion file `{}` is larger than 64 KiB",
            path.display()
        )));
    }
    std::str::from_utf8(content.trim_ascii())
        .ok()
        .and_then(|jwt| SignedJwt::new(jwt).ok())
        .map(Assertion::from)
        .ok_or_else(|| {
            AssertionError::new(format!(
                "the assertion file `{}` {NOT_A_SIGNED_JWT}",
                path.display()
            ))
        })
}
