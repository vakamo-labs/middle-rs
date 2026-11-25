//! The JWT bearer grant (RFC 7523, section 2.1): the JWT is the grant, with or without client authentication.

mod support;

use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};

use middle::{
    Assertion, AssertionContext, AssertionError, AssertionSource, Authorizer, ClientAuthentication,
    Error,
};
use support::{FakeIdp, Reply};

const JWT_BEARER_GRANT: &str = "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer";
const JWT_BEARER_CLIENT_ASSERTION: &str =
    "urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer";

/// Hands out `<prefix>.cGF5bG9hZA.c2lnbmF0dXJl1`, `…2`, and so on, and records the client id of each call.
#[derive(Debug, Clone)]
struct CountingSource {
    prefix: &'static str,
    client_ids: Arc<Mutex<Vec<Option<String>>>>,
}

impl CountingSource {
    fn new(prefix: &'static str) -> Self {
        Self {
            prefix,
            client_ids: Arc::default(),
        }
    }

    fn assertion(&self, number: usize) -> String {
        format!("{}.cGF5bG9hZA.c2lnbmF0dXJl{number}", self.prefix)
    }

    fn client_ids(&self) -> Vec<Option<String>> {
        self.client_ids.lock().unwrap().clone()
    }
}

impl AssertionSource for CountingSource {
    fn assertion<'a>(
        &'a self,
        context: &'a AssertionContext,
    ) -> Pin<Box<dyn Future<Output = Result<Assertion, AssertionError>> + Send + 'a>> {
        Box::pin(async move {
            let number = {
                let mut client_ids = self.client_ids.lock().unwrap();
                client_ids.push(context.client_id().map(str::to_string));
                client_ids.len()
            };
            Assertion::new(self.assertion(number))
        })
    }
}

#[tokio::test]
async fn test_the_jwt_is_the_grant_without_client_authentication() {
    let idp = FakeIdp::start(|_| Reply::token("issued-token", Some(3600))).await;
    let grant = CountingSource::new("Z3JhbnQ");

    let authorizer = Authorizer::jwt_bearer(idp.token_url(), grant.clone())
        .add_scope("read")
        // RFC 8707, section 2: one `resource` parameter for each resource.
        .append_param("resource", "https://a.example.com")
        .append_param("resource", "https://b.example.com")
        .build()
        .await
        .unwrap();

    let request = &idp.requests()[0];
    assert_eq!(request.header_all("authorization"), Vec::<&str>::new());
    assert_eq!(
        request.body,
        format!(
            "grant_type={JWT_BEARER_GRANT}&assertion={}&scope=read&resource=https%3A%2F%2Fa.example.com&resource=https%3A%2F%2Fb.example.com",
            grant.assertion(1)
        )
    );
    assert_eq!(grant.client_ids(), vec![None]);
    assert_eq!(
        authorizer.authorization_header().unwrap().to_str().unwrap(),
        "Bearer issued-token"
    );
}

#[tokio::test]
async fn test_the_jwt_bearer_grant_can_authenticate_the_client_with_basic() {
    let idp = FakeIdp::start(|_| Reply::token("t", Some(3600))).await;
    let grant = CountingSource::new("Z3JhbnQ");

    Authorizer::jwt_bearer(idp.token_url(), grant.clone())
        .client_authentication(ClientAuthentication::client_secret_basic("my-client", "s"))
        .build()
        .await
        .unwrap();

    let request = &idp.requests()[0];
    assert_eq!(
        request.header_all("authorization"),
        vec!["Basic bXktY2xpZW50OnM="]
    );
    assert_eq!(
        request.body,
        format!(
            "grant_type={JWT_BEARER_GRANT}&assertion={}",
            grant.assertion(1)
        )
    );
    assert_eq!(grant.client_ids(), vec![Some("my-client".to_string())]);
}

#[tokio::test]
async fn test_the_jwt_bearer_grant_can_authenticate_the_client_with_an_assertion() {
    let idp = FakeIdp::start(|_| Reply::token("t", Some(3600))).await;
    let grant = CountingSource::new("Z3JhbnQ");
    let client = CountingSource::new("Y2xpZW50");

    Authorizer::jwt_bearer(idp.token_url(), grant.clone())
        .client_authentication(ClientAuthentication::client_assertion(
            "my-client",
            client.clone(),
        ))
        .build()
        .await
        .unwrap();

    assert_eq!(
        idp.requests()[0].body,
        format!(
            "grant_type={JWT_BEARER_GRANT}&assertion={}&client_id=my-client&client_assertion_type={JWT_BEARER_CLIENT_ASSERTION}&client_assertion={}",
            grant.assertion(1),
            client.assertion(1)
        )
    );
}

#[tokio::test]
async fn test_each_attempt_gets_a_new_grant_assertion() {
    let idp = FakeIdp::start(|number| match number {
        1 => Reply::oauth_error(503, "temporarily_unavailable", "down"),
        _ => Reply::token("t", Some(3600)),
    })
    .await;
    let grant = CountingSource::new("Z3JhbnQ");

    Authorizer::jwt_bearer(idp.token_url(), grant.clone())
        .build()
        .await
        .unwrap();

    let assertions: Vec<Option<String>> = idp
        .requests()
        .iter()
        .map(|request| request.form_value("assertion"))
        .collect();
    assert_eq!(
        assertions,
        vec![Some(grant.assertion(1)), Some(grant.assertion(2))]
    );
}

/// A source that never answers.
#[derive(Debug)]
struct HangingSource;

impl AssertionSource for HangingSource {
    fn assertion<'a>(
        &'a self,
        _context: &'a AssertionContext,
    ) -> Pin<Box<dyn Future<Output = Result<Assertion, AssertionError>> + Send + 'a>> {
        Box::pin(std::future::pending())
    }
}

#[tokio::test]
async fn test_a_grant_source_that_does_not_answer_is_bounded_by_the_timeout() {
    let idp = FakeIdp::start(|_| Reply::token("t", Some(3600))).await;
    let build = Authorizer::jwt_bearer(idp.token_url(), HangingSource)
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
    // The token endpoint got no request, so the message does not blame it.
    assert_eq!(
        error.to_string(),
        "the token request did not complete within 200ms"
    );
    assert_eq!(idp.count(), 0);
}

#[tokio::test]
async fn test_debug_output_shows_the_grant_and_the_client() {
    let idp = FakeIdp::start(|_| Reply::token("t", Some(3600))).await;
    let builder = Authorizer::jwt_bearer(idp.token_url(), CountingSource::new("Z3JhbnQ"))
        .client_authentication(ClientAuthentication::client_secret_basic(
            "my-client",
            "SECRET-CLIENT-SECRET",
        ));

    let builder_debug = format!("{builder:?}");
    let authorizer = builder.build().await.unwrap();

    for debug in [builder_debug, format!("{authorizer:?}")] {
        assert!(debug.contains("JwtBearer"), "{debug}");
        assert!(debug.contains("CountingSource"), "{debug}");
        assert!(debug.contains("my-client"), "{debug}");
        assert!(!debug.contains("SECRET"), "{debug}");
    }
}

/// A key in the form of a service account key file: RS512, a key id, `iss`, `sub` and `aud` from the file, 600 seconds.
#[cfg(feature = "jwt")]
#[tokio::test]
async fn test_a_signed_jwt_assertion_is_the_grant() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use middle::jwt::{JwtAssertion, SigningAlgorithm, SigningKey};

    let idp = FakeIdp::start(|_| Reply::token("t", Some(3600))).await;
    let key = SigningKey::from_pem(
        include_str!("fixtures/jwt/rsa-2048-pkcs8.pem"),
        SigningAlgorithm::Rs512,
    )
    .unwrap()
    .with_key_id("key-1");
    let assertion = JwtAssertion::new(
        key,
        "service-account@example.com",
        "subject-1",
        "https://idp.example.com",
    )
    .with_lifetime(std::time::Duration::from_secs(600))
    .unwrap();

    Authorizer::jwt_bearer(idp.token_url(), assertion)
        .append_param("resource", "https://api.example.com")
        .build()
        .await
        .unwrap();

    let jwt = idp.requests()[0].form_value("assertion").unwrap();
    let parts: Vec<serde_json::Value> = jwt
        .split('.')
        .take(2)
        .map(|part| serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).unwrap()).unwrap())
        .collect();
    assert_eq!(
        parts[0],
        serde_json::json!({"alg": "RS512", "typ": "JWT", "kid": "key-1"})
    );
    let claims = &parts[1];
    assert_eq!(claims["iss"], "service-account@example.com");
    assert_eq!(claims["sub"], "subject-1");
    assert_eq!(claims["aud"], "https://idp.example.com");
    // `exp` lies the lifetime of 600 seconds after `iat`.
    assert_eq!(
        claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap(),
        600
    );
}
