//! JWT client authentication with an assertion from a source (RFC 7523, section 2.2; RFC 7521, section 4.2).

mod support;

use std::{
    future::Future,
    path::PathBuf,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};

use middle::{
    AssertionContext, AssertionError, AssertionSource, ClientAuthentication,
    ClientCredentialAuthorizer, Error, FileAssertion, SignedJwt,
};
use support::{FakeIdp, Reply};

const JWT_BEARER: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// Hands out the assertions `aGVhZGVy.cGF5bG9hZA.c2lnbmF0dXJl1`, `…2`, and so on, and records the context of each call.
#[derive(Debug, Clone, Default)]
struct CountingSource {
    calls: Arc<Mutex<Vec<(url::Url, String)>>>,
    /// The calls that fail, counted from 1.
    failing: Vec<usize>,
    /// The calls that never answer, counted from 1.
    hanging: Vec<usize>,
}

impl CountingSource {
    fn assertion(number: usize) -> String {
        format!("aGVhZGVy.cGF5bG9hZA.c2lnbmF0dXJl{number}")
    }

    fn calls(&self) -> Vec<(url::Url, String)> {
        self.calls.lock().unwrap().clone()
    }
}

impl AssertionSource for CountingSource {
    fn assertion<'a>(
        &'a self,
        context: &'a AssertionContext,
    ) -> Pin<Box<dyn Future<Output = Result<SignedJwt, AssertionError>> + Send + 'a>> {
        Box::pin(async move {
            let number = {
                let mut calls = self.calls.lock().unwrap();
                calls.push((context.token_url().clone(), context.client_id().to_string()));
                calls.len()
            };
            if self.hanging.contains(&number) {
                std::future::pending::<()>().await;
            }
            if self.failing.contains(&number) {
                return Err(AssertionError::new("the signer is not ready"));
            }
            SignedJwt::new(Self::assertion(number))
        })
    }
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

    ClientCredentialAuthorizer::builder(
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
        vec![(idp.token_url(), "my client".to_string())]
    );
}

#[tokio::test]
async fn test_each_attempt_gets_a_new_assertion() {
    let idp = FakeIdp::start(|number| match number {
        1 => Reply::oauth_error(503, "temporarily_unavailable", "down"),
        _ => Reply::token("t", Some(3600)),
    })
    .await;
    let source = CountingSource::default();

    ClientCredentialAuthorizer::builder(
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

    ClientCredentialAuthorizer::builder(
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
    let build = ClientCredentialAuthorizer::builder(
        idp.token_url(),
        ClientAuthentication::client_assertion("c", source.clone()),
    )
    .set_max_retries(0)
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
        AssertionError::new("the signer is not ready")
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
    let context = AssertionContext::new("https://idp.example.com/token".parse().unwrap(), "c");

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

    ClientCredentialAuthorizer::builder(
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
    let context = AssertionContext::new("https://idp.example.com/token".parse().unwrap(), "c");

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
    let context = AssertionContext::new("https://idp.example.com/token".parse().unwrap(), "c");
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

#[tokio::test]
async fn test_a_file_larger_than_64_kib_is_refused() {
    let file = TempFile::new("large", "a".repeat(64 * 1024 + 1));
    let context = AssertionContext::new("https://idp.example.com/token".parse().unwrap(), "c");

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
    let builder = ClientCredentialAuthorizer::builder(
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
