//! The tonic interceptor of an authorizer with a requested token.

mod support;

use std::time::Duration;

use middle::{Authorizer, ClientAuthentication, Interceptor};
use support::{FakeIdp, Reply, wait_until};
use tonic::service::Interceptor as _;

async fn authorizer(idp: &FakeIdp) -> Authorizer {
    Authorizer::client_credentials(
        idp.token_url(),
        ClientAuthentication::client_secret_basic("c", "s"),
    )
    .build()
    .await
    .unwrap()
}

/// The `Authorization` metadata the interceptor puts on a new request, or the status it fails with.
fn intercept(interceptor: &mut Interceptor) -> Result<String, tonic::Status> {
    interceptor.call(tonic::Request::new(())).map(|request| {
        let value = request.metadata().get("authorization").unwrap();
        // Sensitive metadata stays out of `Debug` output and out of the HTTP/2 header compression.
        assert!(value.is_sensitive());
        value.to_str().unwrap().to_string()
    })
}

#[tokio::test]
async fn test_the_interceptor_keeps_refreshing_after_the_authorizer_is_dropped() {
    // A token that lives 2 seconds is refreshed after about 1 second.
    let idp = FakeIdp::start(|number| Reply::token(&format!("token-{number}"), Some(2))).await;
    let authorizer = authorizer(&idp).await;
    let mut interceptor = authorizer.interceptor();
    drop(authorizer);

    assert_eq!(intercept(&mut interceptor).unwrap(), "Bearer token-1");
    let refreshed = wait_until(Duration::from_secs(10), || {
        intercept(&mut interceptor).is_ok_and(|header| header == "Bearer token-2")
    })
    .await;
    assert!(refreshed, "{:?}", intercept(&mut interceptor));
}

#[tokio::test]
async fn test_the_interceptor_fails_with_unauthenticated_without_a_valid_token() {
    let idp = FakeIdp::start(|number| match number {
        1 => Reply::token("t", Some(2)),
        _ => Reply::oauth_error(400, "invalid_client", "the client is disabled"),
    })
    .await;
    let mut interceptor = authorizer(&idp).await.interceptor();

    let failed = wait_until(Duration::from_secs(10), || {
        intercept(&mut interceptor).is_err()
    })
    .await;

    assert!(failed);
    let status = intercept(&mut interceptor).unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unauthenticated, "{status:?}");
    assert!(status.message().contains("invalid_client"), "{status:?}");
    assert!(!middle_error(&status).is_retryable());
}

#[tokio::test]
async fn test_the_interceptor_fails_with_unavailable_while_a_retry_can_help() {
    let idp = FakeIdp::start(|number| match number {
        1 => Reply::token("t", Some(2)),
        _ => Reply::oauth_error(503, "temporarily_unavailable", "the server is busy"),
    })
    .await;
    let mut interceptor = authorizer(&idp).await.interceptor();

    let failed = wait_until(Duration::from_secs(10), || {
        intercept(&mut interceptor).is_err()
    })
    .await;

    assert!(failed);
    let status = intercept(&mut interceptor).unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unavailable, "{status:?}");
    assert!(middle_error(&status).is_retryable());
}

/// The error of middle that a failed interceptor attaches to the status.
fn middle_error(status: &tonic::Status) -> &middle::Error {
    std::error::Error::source(status)
        .expect("the status has the error of middle as its source")
        .downcast_ref::<middle::Error>()
        .unwrap()
}
