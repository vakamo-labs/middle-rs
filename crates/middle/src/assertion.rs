//! Assertions for JWT client authentication and the JWT bearer grant (RFC 7523, sections 2.1 and 2.2; RFC 7521).

use std::{
    fmt,
    future::Future,
    io::Read as _,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use url::Url;

use crate::{cache::BoxFuture, error::SourceError};

/// The largest assertion file [`FileAssertion`] reads, in bytes.
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
    /// [`SourceError`] unless `jwt` is three base64url parts separated by dots, none of them empty. The message does not show `jwt`.
    pub fn new(jwt: impl Into<String>) -> Result<Self, SourceError> {
        let jwt = jwt.into();
        if is_compact_jws(&jwt) {
            Ok(Self(jwt))
        } else {
            Err(SourceError::new(format!(
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

/// An assertion as middle sends it to the token endpoint, such as a signed or an encrypted JWT (RFC 7523).
/// middle sends it as the `assertion` of the JWT bearer grant, or as a `client_assertion` with the `client_assertion_type`
/// `urn:ietf:params:oauth:client-assertion-type:jwt-bearer`. `Debug` never shows it.
#[derive(Clone)]
pub struct Assertion(String);

impl Assertion {
    /// An assertion that middle does not check for the form of a signed JWT, such as an encrypted JWT. [`SignedJwt`] converts into one with `From`.
    ///
    /// # Errors
    ///
    /// [`SourceError`] if `value` is empty or holds a character other than visible ASCII, such as a space or a line break. The message does not show `value`.
    pub fn new(value: impl Into<String>) -> Result<Self, SourceError> {
        let value = value.into();
        if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_graphic()) {
            Ok(Self(value))
        } else {
            Err(SourceError::new(
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

impl From<SignedJwt> for Assertion {
    fn from(jwt: SignedJwt) -> Self {
        Self(jwt.0)
    }
}

impl fmt::Debug for Assertion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Assertion([redacted])")
    }
}

/// Supplies the assertion for the JWT bearer grant ([`crate::Authorizer::jwt_bearer`]) or for JWT client authentication ([`crate::ClientAuthentication::client_assertion`]).
/// Implement it with `async fn assertion`.
///
/// Sources are, for example, a [`FileAssertion`] for a Kubernetes service account token, a `jwt::JwtAssertion` (feature `jwt`) that middle signs, or a key management service that signs.
/// `Arc<S>` is a source too, so one source can serve several authorizers.
///
/// middle asks for a new assertion for every token request, retries included, within the timeout of that request.
/// When the request times out, middle drops the future, so the source must cope with being stopped at any `.await`.
/// An error fails the request, and middle retries it, see [`crate::Error::is_retryable`] and [`SourceError::permanent`].
///
/// middle shows the `Debug` output of a source in its own `Debug` output, which may end up in logs, so it must not show secrets, keys or assertions.
pub trait AssertionSource: fmt::Debug + Send + Sync + 'static {
    /// A new assertion for one token request.
    fn assertion(
        &self,
        context: &AssertionContext,
    ) -> impl Future<Output = Result<Assertion, SourceError>> + Send;
}

impl<S: AssertionSource> AssertionSource for Arc<S> {
    fn assertion(
        &self,
        context: &AssertionContext,
    ) -> impl Future<Output = Result<Assertion, SourceError>> + Send {
        (**self).assertion(context)
    }
}

/// An [`AssertionSource`] with a boxed future, so that middle can keep a source of any type behind one pointer.
pub(crate) trait BoxedAssertionSource: fmt::Debug + Send + Sync + 'static {
    fn boxed<'a>(
        &'a self,
        context: &'a AssertionContext,
    ) -> BoxFuture<'a, Result<Assertion, SourceError>>;
}

impl<S: AssertionSource> BoxedAssertionSource for S {
    fn boxed<'a>(
        &'a self,
        context: &'a AssertionContext,
    ) -> BoxFuture<'a, Result<Assertion, SourceError>> {
        Box::pin(self.assertion(context))
    }
}

/// What an [`AssertionSource`] knows about the token request.
///
/// `Debug` shows the token URL without user name, password and query.
#[derive(Clone)]
pub struct AssertionContext {
    token_url: Url,
    client_id: Option<String>,
}

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
///
/// middle sends the JWT of the file with every token request until the writer replaces it. Some servers accept an assertion only once, by its `jti`;
/// with them, a JWT from a file works for one token request, and the next one fails with `invalid_grant`.
///
/// If the payload of the JWT has an `exp` (RFC 7519, section 4.1.4) that has passed, middle does not send it. The token request then fails with a [`SourceError`]
/// that names the file, and middle retries the request. When the file holds a new JWT, the next retry sends it.
#[derive(Debug, Clone)]
pub struct FileAssertion {
    path: PathBuf,
}

impl FileAssertion {
    /// An assertion from the file at `path`. The file is read with each token request, so it may be missing until then.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl AssertionSource for FileAssertion {
    async fn assertion(&self, _context: &AssertionContext) -> Result<Assertion, SourceError> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || read_assertion(&path))
            .await
            .map_err(|error| {
                SourceError::new("reading the assertion file failed").with_source(error)
            })?
    }
}

/// Opens the file for reading with `O_NONBLOCK`, so that opening a FIFO that replaced the file after the check of its path returns at once,
/// and the check of the opened file refuses it. The flag has no effect on a regular file.
#[cfg(unix)]
fn open_for_reading(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
}

/// Opens the file for reading.
#[cfg(not(unix))]
fn open_for_reading(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}

/// Reads the assertion file at `path`. The errors name the file, never its content.
fn read_assertion(path: &Path) -> Result<Assertion, SourceError> {
    let cannot_read = |error: std::io::Error| {
        SourceError::new(format!(
            "cannot read the assertion file `{}`",
            path.display()
        ))
        .with_source(error)
    };
    let not_regular = || {
        SourceError::new(format!(
            "the assertion file `{}` is not a regular file",
            path.display()
        ))
    };
    // Opening a FIFO without a writer blocks, and a blocking read cannot be cancelled. The metadata follows links.
    if !std::fs::metadata(path).map_err(cannot_read)?.is_file() {
        return Err(not_regular());
    }
    let file = open_for_reading(path).map_err(cannot_read)?;
    // The path may have changed since the check.
    if !file.metadata().map_err(cannot_read)?.is_file() {
        return Err(not_regular());
    }
    let mut content = Vec::new();
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut content)
        .map_err(cannot_read)?;
    if content.len() as u64 > MAX_FILE_BYTES {
        return Err(SourceError::new(format!(
            "the assertion file `{}` is larger than 64 KiB",
            path.display()
        )));
    }
    let jwt = std::str::from_utf8(content.trim_ascii())
        .ok()
        .and_then(|jwt| SignedJwt::new(jwt).ok())
        .ok_or_else(|| {
            SourceError::new(format!(
                "the assertion file `{}` {NOT_A_SIGNED_JWT}",
                path.display()
            ))
        })?;
    if let Some(exp) = crate::cache::jwt_exp(jwt.as_str()).filter(|exp| has_passed(*exp)) {
        return Err(SourceError::new(format!(
            "the JWT in the assertion file `{}` has expired: its `exp` is {exp}",
            path.display()
        )));
    }
    Ok(Assertion::from(jwt))
}

/// Whether the time `exp`, in seconds since 1970, has come (RFC 7519, section 4.1.4).
fn has_passed(exp: f64) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |now| now.as_secs_f64());
    now >= exp
}

#[cfg(all(test, unix))]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn test_opening_a_fifo_without_a_writer_does_not_block() {
        let path = std::env::temp_dir().join(format!("middle-open-fifo-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );

        // A blocked open never returns, so it runs in a thread of its own.
        let (sender, receiver) = std::sync::mpsc::channel();
        let fifo = path.clone();
        std::thread::spawn(move || {
            let _ = sender.send(open_for_reading(&fifo).map(drop));
        });
        let opened = receiver.recv_timeout(Duration::from_secs(5));
        let _ = std::fs::remove_file(&path);

        assert!(matches!(opened, Ok(Ok(()))), "{opened:?}");
    }
}
