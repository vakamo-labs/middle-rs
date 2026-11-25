//! JWT client authentication with an assertion from a source (RFC 7523, section 2.2; RFC 7521, section 4.2).

mod support;

use std::{
    future::Future,
    path::PathBuf,
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use middle::{
    Assertion, AssertionContext, AssertionSource, Authorizer, ClientAuthentication, Error,
    FileAssertion, SignedJwt, SourceError,
};
use support::{FakeIdp, Reply};

const JWT_BEARER: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// The token URL and the client id of each call of a source.
type Calls = Vec<(url::Url, Option<String>)>;

/// Hands out the assertions `aGVhZGVy.cGF5bG9hZA.c2lnbmF0dXJl1`, `…2`, and so on, and records the context of each call.
#[derive(Debug, Clone, Default)]
struct CountingSource {
    calls: Arc<Mutex<Calls>>,
    /// The calls that fail, counted from 1.
    failing: Vec<usize>,
    /// Whether the failures are permanent.
    permanent: bool,
    /// The calls that never answer, counted from 1.
    hanging: Vec<usize>,
}

impl CountingSource {
    fn assertion(number: usize) -> String {
        format!("aGVhZGVy.cGF5bG9hZA.c2lnbmF0dXJl{number}")
    }

    fn calls(&self) -> Calls {
        self.calls.lock().unwrap().clone()
    }
}

impl AssertionSource for CountingSource {
    fn assertion<'a>(
        &'a self,
        context: &'a AssertionContext,
    ) -> Pin<Box<dyn Future<Output = Result<Assertion, SourceError>> + Send + 'a>> {
        Box::pin(async move {
            let number = {
                let mut calls = self.calls.lock().unwrap();
                calls.push((
                    context.token_url().clone(),
                    context.client_id().map(str::to_string),
                ));
                calls.len()
            };
            if self.hanging.contains(&number) {
                std::future::pending::<()>().await;
            }
            if self.failing.contains(&number) {
                let error = SourceError::new("the signer is not ready");
                return Err(if self.permanent {
                    error.permanent()
                } else {
                    error
                });
            }
            Assertion::new(Self::assertion(number))
        })
    }
}

/// An encrypted JWT (RFC 7516, section 7.1): five parts, which `SignedJwt` refuses.
const ENCRYPTED_JWT: &str = "eyJhbGciOiJSU0EtT0FFUCJ9.a2V5.aXY.Y2lwaGVydGV4dA.dGFn";

/// Hands out [`ENCRYPTED_JWT`].
#[derive(Debug)]
struct EncryptedJwtSource;

impl AssertionSource for EncryptedJwtSource {
    fn assertion<'a>(
        &'a self,
        _context: &'a AssertionContext,
    ) -> Pin<Box<dyn Future<Output = Result<Assertion, SourceError>> + Send + 'a>> {
        Box::pin(async { Assertion::new(ENCRYPTED_JWT) })
    }
}

fn context() -> AssertionContext {
    AssertionContext::new("https://idp.example.com/token".parse().unwrap()).with_client_id("c")
}

/// A file in the temporary directory, removed when dropped.
struct TempFile(PathBuf);

impl TempFile {
    fn new(name: &str, content: impl AsRef<[u8]>) -> Self {
        let path = std::env::temp_dir().join(format!(
            "middle-client-assertion-{}-{name}",
            std::process::id()
        ));
        std::fs::write(&path, content).unwrap();
        Self(path)
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[tokio::test]
async fn test_a_client_assertion_is_sent_with_the_client_id() {
    let idp = FakeIdp::start(|_| Reply::token("t", Some(3600))).await;
    let source = CountingSource::default();

    Authorizer::client_credentials(
        idp.token_url(),
        ClientAuthentication::client_assertion("my client", source.clone()),
    )
    .add_scope("read")
    .build()
    .await
    .unwrap();

    let request = &idp.requests()[0];
    assert_eq!(request.header_all("authorization"), Vec::<&str>::new());
    assert_eq!(
        request.body,
        format!(
            "grant_type=client_credentials&client_id=my+client&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion={}&scope=read",
            CountingSource::assertion(1)
        )
    );
    assert_eq!(
        request.form_value("client_assertion_type").unwrap(),
        JWT_BEARER
    );
    assert_eq!(
        source.calls(),
        vec![(idp.token_url(), Some("my client".to_string()))]
    );
}

#[tokio::test]
async fn test_the_client_id_parameter_can_be_left_out() {
    let idp = FakeIdp::start(|_| Reply::token("t", Some(3600))).await;
    let source = CountingSource::default();

    Authorizer::client_credentials(
        idp.token_url(),
        ClientAuthentication::client_assertion("my-client", source.clone())
            .without_client_id_parameter(),
    )
    .build()
    .await
    .unwrap();

    assert_eq!(
        idp.requests()[0].body,
        format!(
            "grant_type=client_credentials&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion={}",
            CountingSource::assertion(1)
        )
    );
    // The source still learns the client id.
    assert_eq!(
        source.calls(),
        vec![(idp.token_url(), Some("my-client".to_string()))]
    );
}

#[tokio::test]
async fn test_an_encrypted_jwt_is_sent_as_it_is() {
    let idp = FakeIdp::start(|_| Reply::token("t", Some(3600))).await;

    Authorizer::client_credentials(
        idp.token_url(),
        ClientAuthentication::client_assertion("c", EncryptedJwtSource),
    )
    .build()
    .await
    .unwrap();

    assert_eq!(
        idp.requests()[0].form_value("client_assertion").as_deref(),
        Some(ENCRYPTED_JWT)
    );
}

#[tokio::test]
async fn test_one_source_can_serve_several_authorizers() {
    let idp = FakeIdp::start(|_| Reply::token("t", Some(3600))).await;
    let shared = Arc::new(CountingSource::default());
    let boxed: Box<dyn AssertionSource> = Box::new(EncryptedJwtSource);

    for authentication in [
        ClientAuthentication::client_assertion("c", Arc::clone(&shared)),
        ClientAuthentication::client_assertion("c", Arc::clone(&shared)),
        ClientAuthentication::client_assertion("c", boxed),
    ] {
        Authorizer::client_credentials(idp.token_url(), authentication)
            .build()
            .await
            .unwrap();
    }

    assert_eq!(shared.calls().len(), 2);
    assert_eq!(idp.count(), 3);
}

#[test]
fn test_an_assertion_is_visible_ascii() {
    assert_eq!(Assertion::new("a.b+c/=_-~").unwrap().as_str(), "a.b+c/=_-~");
    for value in ["", " a", "a b", "a\n", "a\u{0}", "ä"] {
        let error = Assertion::new(value).expect_err(value);
        assert_eq!(
            error.to_string(),
            "the assertion is empty or holds a character other than visible ASCII"
        );
    }
    let jwt = SignedJwt::new("aGVhZGVy.cGF5bG9hZA.c2ln").unwrap();
    assert_eq!(Assertion::from(jwt).as_str(), "aGVhZGVy.cGF5bG9hZA.c2ln");
    assert_eq!(
        format!("{:?}", Assertion::new("U0VDUkVU").unwrap()),
        "Assertion([redacted])"
    );
}

#[tokio::test]
async fn test_a_permanent_assertion_error_fails_build_at_once() {
    let idp = FakeIdp::start(|_| Reply::token("t", Some(3600))).await;
    let source = CountingSource {
        failing: vec![1],
        permanent: true,
        ..CountingSource::default()
    };

    let error = Authorizer::client_credentials(
        idp.token_url(),
        ClientAuthentication::client_assertion("c", source.clone()),
    )
    .build()
    .await
    .expect_err("a retry cannot fix the error");

    assert!(matches!(&error, Error::Source(_)), "{error:?}");
    assert!(!error.is_retryable());
    assert_eq!(source.calls().len(), 1);
    assert_eq!(idp.count(), 0);
}

#[tokio::test]
async fn test_each_attempt_gets_a_new_assertion() {
    let idp = FakeIdp::start(|number| match number {
        1 => Reply::oauth_error(503, "temporarily_unavailable", "down"),
        _ => Reply::token("t", Some(3600)),
    })
    .await;
    let source = CountingSource::default();

    Authorizer::client_credentials(
        idp.token_url(),
        ClientAuthentication::client_assertion("c", source.clone()),
    )
    .build()
    .await
    .unwrap();

    let assertions: Vec<Option<String>> = idp
        .requests()
        .iter()
        .map(|request| request.form_value("client_assertion"))
        .collect();
    assert_eq!(
        assertions,
        vec![
            Some(CountingSource::assertion(1)),
            Some(CountingSource::assertion(2))
        ]
    );
}

#[tokio::test]
async fn test_a_failed_assertion_is_retried_without_a_request() {
    let idp = FakeIdp::start(|_| Reply::token("t", Some(3600))).await;
    let source = CountingSource {
        failing: vec![1],
        ..CountingSource::default()
    };

    Authorizer::client_credentials(
        idp.token_url(),
        ClientAuthentication::client_assertion("c", source.clone()),
    )
    .build()
    .await
    .unwrap();

    assert_eq!(source.calls().len(), 2);
    assert_eq!(idp.count(), 1);
    assert_eq!(
        idp.requests()[0].form_value("client_assertion"),
        Some(CountingSource::assertion(2))
    );
}

#[tokio::test]
async fn test_a_source_that_does_not_answer_is_bounded_by_the_timeout() {
    let idp = FakeIdp::start(|_| Reply::token("t", Some(3600))).await;
    let source = CountingSource {
        hanging: vec![1],
        ..CountingSource::default()
    };
    let build = Authorizer::client_credentials(
        idp.token_url(),
        ClientAuthentication::client_assertion("c", source.clone()),
    )
    .max_retries(0)
    .timeout(Duration::from_millis(200))
    .build();

    let error = tokio::time::timeout(Duration::from_secs(5), build)
        .await
        .expect("build() returns within its timeout")
        .expect_err("the source never answers");

    assert!(
        matches!(error, Error::Timeout(timeout) if timeout == Duration::from_millis(200)),
        "{error:?}"
    );
    assert_eq!(source.calls().len(), 1);
    assert_eq!(idp.count(), 0);
}

#[tokio::test]
async fn test_an_assertion_error_is_retryable_and_names_its_cause() {
    let error = Error::from(
        SourceError::new("the signer is not ready")
            .with_source(std::io::Error::other("connection refused")),
    );

    assert!(error.is_retryable());
    assert_eq!(error.to_string(), "the signer is not ready");
    assert_eq!(
        std::error::Error::source(&error).unwrap().to_string(),
        "connection refused"
    );
}

#[tokio::test]
async fn test_a_file_assertion_is_read_for_every_request() {
    let file = TempFile::new("every-request", "aGVhZGVy.Zmlyc3Q.c2ln\n");
    let source = FileAssertion::new(&file.0);
    let context = context();

    // The newline at the end is not part of the assertion.
    assert_eq!(
        source.assertion(&context).await.unwrap().as_str(),
        "aGVhZGVy.Zmlyc3Q.c2ln"
    );
    std::fs::write(&file.0, "aGVhZGVy.c2Vjb25k.c2ln").unwrap();
    assert_eq!(
        source.assertion(&context).await.unwrap().as_str(),
        "aGVhZGVy.c2Vjb25k.c2ln"
    );
}

#[tokio::test]
async fn test_a_file_assertion_is_sent() {
    let idp = FakeIdp::start(|_| Reply::token("t", Some(3600))).await;
    let file = TempFile::new("sent", "aGVhZGVy.cGF5bG9hZA.c2ln");

    Authorizer::client_credentials(
        idp.token_url(),
        ClientAuthentication::client_assertion("c", FileAssertion::new(&file.0)),
    )
    .build()
    .await
    .unwrap();

    assert_eq!(
        idp.requests()[0].form_value("client_assertion").as_deref(),
        Some("aGVhZGVy.cGF5bG9hZA.c2ln")
    );
}

#[tokio::test]
async fn test_a_missing_file_is_an_assertion_error_that_names_the_file() {
    let path = std::env::temp_dir().join("middle-client-assertion-does-not-exist");
    let context = context();

    let error = FileAssertion::new(&path)
        .assertion(&context)
        .await
        .expect_err("the file does not exist");

    assert_eq!(
        error.to_string(),
        format!("cannot read the assertion file `{}`", path.display())
    );
    assert_eq!(
        std::error::Error::source(&error)
            .unwrap()
            .downcast_ref::<std::io::Error>()
            .unwrap()
            .kind(),
        std::io::ErrorKind::NotFound
    );
}

#[tokio::test]
async fn test_a_file_that_is_not_a_jwt_is_an_assertion_error_without_its_content() {
    let context = context();
    for (name, content) in [
        ("empty", "".as_bytes()),
        ("two-parts", b"SECRET.SECRET".as_slice()),
        ("not-base64url", b"SECRET.SECRET.SECRET+".as_slice()),
        ("not-utf8", b"\xffSECRET.SECRET.SECRET".as_slice()),
    ] {
        let file = TempFile::new(name, content);

        let error = FileAssertion::new(&file.0)
            .assertion(&context)
            .await
            .expect_err("not a JWT");

        let message = format!("{error} {error:?}");
        assert!(message.contains("is not a signed JWT"), "{name}: {message}");
        assert!(!message.contains("SECRET"), "{name}: {message}");
    }
}

/// A JWT with the payload `claims` and a signature that is never checked.
fn jwt_with_claims(claims: &serde_json::Value) -> String {
    format!(
        "eyJhbGciOiJSUzI1NiJ9.{}.c2ln",
        URL_SAFE_NO_PAD.encode(claims.to_string())
    )
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[tokio::test]
async fn test_a_file_with_an_expired_jwt_is_a_retryable_error_that_names_the_file() {
    let exp = now() - 10;
    let file = TempFile::new(
        "expired",
        jwt_with_claims(&serde_json::json!({"sub": "SECRET", "exp": exp})),
    );

    let error = FileAssertion::new(&file.0)
        .assertion(&context())
        .await
        .expect_err("the JWT has expired");

    assert_eq!(
        error.to_string(),
        format!(
            "the JWT in the assertion file `{}` has expired: its `exp` is {exp}",
            file.0.display()
        )
    );
    assert!(Error::from(error).is_retryable());
}

#[tokio::test]
async fn test_a_file_with_a_jwt_that_has_not_expired_is_sent_as_it_is() {
    let context = context();
    for (name, claims) in [
        ("exp-ahead", serde_json::json!({"exp": now() + 60})),
        ("no-exp", serde_json::json!({"sub": "s"})),
        ("exp-not-a-number", serde_json::json!({"exp": "1"})),
    ] {
        let jwt = jwt_with_claims(&claims);
        let file = TempFile::new(name, &jwt);

        let assertion = FileAssertion::new(&file.0).assertion(&context).await;

        assert_eq!(assertion.unwrap().as_str(), jwt, "{name}");
    }
}

#[tokio::test]
async fn test_an_expired_jwt_in_the_file_is_not_sent() {
    let idp = FakeIdp::start(|_| Reply::token("t", Some(3600))).await;
    let file = TempFile::new(
        "expired-not-sent",
        jwt_with_claims(&serde_json::json!({"exp": now() - 10})),
    );

    let error = Authorizer::client_credentials(
        idp.token_url(),
        ClientAuthentication::client_assertion("c", FileAssertion::new(&file.0)),
    )
    .max_retries(0)
    .build()
    .await
    .expect_err("the JWT has expired");

    assert!(matches!(error, Error::Source(_)), "{error:?}");
    assert!(idp.requests().is_empty());
}

#[tokio::test]
async fn test_a_file_larger_than_64_kib_is_refused() {
    let file = TempFile::new("large", "a".repeat(64 * 1024 + 1));
    let context = context();

    let error = FileAssertion::new(&file.0)
        .assertion(&context)
        .await
        .expect_err("too large");

    assert_eq!(
        error.to_string(),
        format!(
            "the assertion file `{}` is larger than 64 KiB",
            file.0.display()
        )
    );
}

#[tokio::test]
async fn test_a_path_that_is_not_a_regular_file_is_refused() {
    let directory = std::env::temp_dir();

    let error = FileAssertion::new(&directory)
        .assertion(&context())
        .await
        .expect_err("a directory");

    assert_eq!(
        error.to_string(),
        format!(
            "the assertion file `{}` is not a regular file",
            directory.display()
        )
    );
}

/// Opening a FIFO without a writer blocks, and a blocking read cannot be cancelled.
#[cfg(unix)]
#[tokio::test]
async fn test_a_fifo_is_refused_without_opening_it() {
    let path = std::env::temp_dir().join(format!(
        "middle-client-assertion-{}-fifo",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    let source = FileAssertion::new(&path);

    let result = tokio::time::timeout(Duration::from_secs(5), source.assertion(&context())).await;
    if result.is_err() {
        // A writer releases the blocked reader, so that the runtime can shut down.
        let _ = std::fs::OpenOptions::new().write(true).open(&path);
    }
    let _ = std::fs::remove_file(&path);

    let error = result.expect("the FIFO is not opened").expect_err("a FIFO");
    assert_eq!(
        error.to_string(),
        format!(
            "the assertion file `{}` is not a regular file",
            path.display()
        )
    );
}

#[test]
fn test_a_signed_jwt_has_three_base64url_parts() {
    assert_eq!(
        SignedJwt::new("aGVhZGVy.cGF5bG9hZA.c2ln-_09")
            .unwrap()
            .as_str(),
        "aGVhZGVy.cGF5bG9hZA.c2ln-_09"
    );
    for jwt in [
        "",
        "aGVhZGVy.cGF5bG9hZA",
        "aGVhZGVy.cGF5bG9hZA.c2ln.c2ln",
        ".cGF5bG9hZA.c2ln",
        "aGVhZGVy..c2ln",
        // RFC 7523, section 3: the assertion is signed, so the signature is not empty.
        "aGVhZGVy.cGF5bG9hZA.",
        "aGVhZGVy.cGF5bG9hZA.c2ln=",
        "aGVhZGVy.cGF5bG9hZA.c2l+",
        "aGVhZGVy.cGF5bG9hZA.c2ln\n",
        " aGVhZGVy.cGF5bG9hZA.c2ln",
    ] {
        let error = SignedJwt::new(jwt).expect_err(jwt);
        assert_eq!(
            error.to_string(),
            "the assertion is not a signed JWT: three base64url parts separated by dots"
        );
    }
}

#[tokio::test]
async fn test_debug_output_shows_the_client_id_and_the_source() {
    let idp = FakeIdp::start(|_| Reply::token("t", Some(3600))).await;
    let file = TempFile::new("debug", "aGVhZGVy.cGF5bG9hZA.U0VDUkVU");
    let builder = Authorizer::client_credentials(
        idp.token_url(),
        ClientAuthentication::client_assertion("my-client", FileAssertion::new(&file.0)),
    );

    let builder_debug = format!("{builder:?}");
    let authorizer = builder.build().await.unwrap();
    let jwt = SignedJwt::new("aGVhZGVy.cGF5bG9hZA.U0VDUkVU").unwrap();

    for debug in [builder_debug, format!("{authorizer:?}")] {
        assert!(debug.contains("my-client"), "{debug}");
        assert!(debug.contains("FileAssertion"), "{debug}");
        assert!(!debug.contains("U0VDUkVU"), "{debug}");
    }
    assert_eq!(format!("{jwt:?}"), "SignedJwt([redacted])");
}
