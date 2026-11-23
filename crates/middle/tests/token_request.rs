//! What middle sends to the token endpoint, byte for byte where it matters.

mod support;

use middle::Authorizer as _;
use support::{FakeIdp, Reply};

/// Client credentials with `client_secret_basic`: RFC 6749, sections 2.3.1 and 4.4.2.
#[tokio::test]
async fn test_client_credentials_with_basic_authentication() {
    let idp = FakeIdp::start(|_| Reply::token("issued-token", Some(3600))).await;

    let authorizer = middle::BasicClientCredentialAuthorizer::basic_builder(
        "my client",
        "s3cr3t/+~:",
        idp.token_url(),
    )
    .add_scopes(&["read", "write"])
    .build()
    .await
    .unwrap();

    let requests = idp.requests();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/token");
    assert_eq!(
        request.header("content-type"),
        Some("application/x-www-form-urlencoded")
    );
    assert_eq!(request.header("accept"), Some("application/json"));
    // The id and the secret are form-urlencoded before Base64: `my+client:s3cr3t%2F%2B%7E%3A`.
    assert_eq!(
        request.header_all("authorization"),
        vec!["Basic bXkrY2xpZW50OnMzY3IzdCUyRiUyQiU3RSUzQQ=="]
    );
    assert_eq!(
        request.body,
        "grant_type=client_credentials&scope=read+write"
    );

    assert_eq!(
        authorizer.authorization_header().unwrap().to_str().unwrap(),
        "Bearer issued-token"
    );
}
