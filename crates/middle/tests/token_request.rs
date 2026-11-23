//! What middle sends to the token endpoint, byte for byte where it matters.

mod support;

use middle::{Authorizer as _, ConfigError, Error};
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

#[tokio::test]
async fn test_extra_parameters_follow_the_scope() {
    let idp = FakeIdp::start(|_| Reply::token("t", Some(3600))).await;

    middle::BasicClientCredentialAuthorizer::basic_builder("c", "s", idp.token_url())
        .add_scope("read")
        .add_extra_param("audience", "https://api.example.com")
        .build()
        .await
        .unwrap();

    assert_eq!(
        idp.requests()[0].body,
        "grant_type=client_credentials&scope=read&audience=https%3A%2F%2Fapi.example.com"
    );
}

#[tokio::test]
async fn test_a_scope_with_a_space_is_rejected() {
    let idp = FakeIdp::start(|_| Reply::token("t", Some(3600))).await;

    let error = middle::BasicClientCredentialAuthorizer::basic_builder("c", "s", idp.token_url())
        .add_scope("read write")
        .build()
        .await
        .expect_err("one scope cannot contain a space");

    assert!(
        matches!(&error, Error::Config(ConfigError::InvalidScope(scope)) if scope == "read write"),
        "{error:?}"
    );
    assert_eq!(idp.count(), 0);
}

#[tokio::test]
async fn test_a_parameter_middle_sets_cannot_be_added() {
    for name in [
        "grant_type",
        "scope",
        "client_id",
        "client_secret",
        "client_assertion",
        "client_assertion_type",
        "assertion",
    ] {
        let idp = FakeIdp::start(|_| Reply::token("t", Some(3600))).await;

        let error =
            middle::BasicClientCredentialAuthorizer::basic_builder("c", "s", idp.token_url())
                .add_extra_param(name, "value")
                .build()
                .await
                .expect_err("middle sets this parameter");

        assert!(
            matches!(&error, Error::Config(ConfigError::ReservedParameter(reserved)) if reserved == name),
            "{error:?}"
        );
        assert_eq!(idp.count(), 0);
    }
}

#[tokio::test]
async fn test_a_token_url_with_a_fragment_is_rejected() {
    let error = middle::BasicClientCredentialAuthorizer::basic_builder(
        "c",
        "s",
        "https://idp.example.com/token#part".parse().unwrap(),
    )
    .build()
    .await
    .expect_err("RFC 6749 section 3.2 forbids a fragment");

    assert!(
        matches!(error, Error::Config(ConfigError::TokenUrlWithFragment)),
        "{error:?}"
    );
}

#[tokio::test]
async fn test_a_token_url_with_user_info_is_rejected() {
    let error = middle::BasicClientCredentialAuthorizer::basic_builder(
        "c",
        "s",
        "https://user:password@idp.example.com/token"
            .parse()
            .unwrap(),
    )
    .build()
    .await
    .expect_err("credentials belong in the client authentication");

    assert!(
        matches!(error, Error::Config(ConfigError::TokenUrlWithUserInfo)),
        "{error:?}"
    );
}

#[tokio::test]
async fn test_a_token_url_with_another_scheme_is_rejected() {
    let error = middle::BasicClientCredentialAuthorizer::basic_builder(
        "c",
        "s",
        "ftp://idp.example.com/token".parse().unwrap(),
    )
    .build()
    .await
    .expect_err("only http and https");

    assert!(
        matches!(&error, Error::Config(ConfigError::TokenUrlScheme(scheme)) if scheme == "ftp"),
        "{error:?}"
    );
}

#[tokio::test]
async fn test_debug_output_hides_secrets() {
    let idp = FakeIdp::start(|_| Reply::token("SECRET-ACCESS-TOKEN", Some(3600))).await;
    let mut token_url = idp.token_url();
    token_url.set_query(Some("key=SECRET-QUERY"));
    let builder = middle::BasicClientCredentialAuthorizer::basic_builder(
        "my-client",
        "SECRET-CLIENT-SECRET",
        token_url,
    )
    .add_extra_param("audience", "SECRET-PARAMETER-VALUE");

    let builder_debug = format!("{builder:?}");
    let authorizer = builder.build().await.unwrap();
    let authorizer_debug = format!("{authorizer:?}");

    for debug in [builder_debug, authorizer_debug] {
        assert!(debug.contains("my-client"), "{debug}");
        assert!(debug.contains("audience"), "{debug}");
        assert!(!debug.contains("SECRET"), "{debug}");
    }
}
