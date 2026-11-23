//! How middle reads the answers of a token endpoint: tokens, OAuth errors, HTTP errors, timeouts and redirects.

mod support;

use std::{error::Error as _, time::Duration};

use http::StatusCode;
use middle::{Authorizer as _, Error, ErrorCode, ResponseProblem};
use serde_json::json;
use support::{FakeIdp, Reply};

fn builder(token_url: url::Url) -> middle::BasicClientCredentialAuthorizerBuilder {
    middle::BasicClientCredentialAuthorizer::basic_builder(
        "my-client",
        "SECRET-CLIENT-SECRET",
        token_url,
    )
}

/// Starts an identity provider that answers every request with `reply` and returns the error of `build()` with the number of requests it got.
async fn build_error(reply: Reply, max_retries: u32) -> (Error, usize) {
    let idp = FakeIdp::start(move |_| reply.clone()).await;
    let error = builder(idp.token_url())
        .set_max_retries(max_retries)
        .build()
        .await
        .expect_err("build must fail");
    (error, idp.count())
}

fn invalid_response(error: &Error) -> &ResponseProblem {
    match error {
        Error::InvalidResponse(invalid) => invalid.problem(),
        other => panic!("expected an invalid response, got {other:?}"),
    }
}

#[tokio::test]
async fn test_an_oauth_error_is_typed_and_not_retried() {
    let reply = Reply::oauth_error(401, "invalid_client", "Invalid client secret provided.");
    let (error, requests) = build_error(reply, 3).await;

    let Error::OAuth(oauth) = &error else {
        panic!("expected an OAuth error, got {error:?}");
    };
    assert_eq!(oauth.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(oauth.code(), &ErrorCode::InvalidClient);
    assert_eq!(oauth.description(), Some("Invalid client secret provided."));
    assert_eq!(error.status(), Some(StatusCode::UNAUTHORIZED));
    assert!(!error.is_retryable());
    assert_eq!(requests, 1);
}

#[tokio::test]
async fn test_an_oauth_error_in_a_200_response_is_an_oauth_error() {
    let reply = Reply::json(200, json!({"error": "invalid_grant"}).to_string());
    let (error, _) = build_error(reply, 0).await;

    let Error::OAuth(oauth) = &error else {
        panic!("expected an OAuth error, got {error:?}");
    };
    assert_eq!(oauth.status(), StatusCode::OK);
    assert_eq!(oauth.code(), &ErrorCode::InvalidGrant);
    assert_eq!(oauth.description(), None);
}

#[tokio::test]
async fn test_a_temporarily_unavailable_error_is_retried() {
    let reply = Reply::oauth_error(400, "temporarily_unavailable", "try later");
    let (error, requests) = build_error(reply, 1).await;

    let Error::OAuth(oauth) = &error else {
        panic!("expected an OAuth error, got {error:?}");
    };
    assert_eq!(oauth.code(), &ErrorCode::TemporarilyUnavailable);
    assert!(error.is_retryable());
    assert_eq!(requests, 2);
}

#[tokio::test]
async fn test_an_unknown_oauth_error_code_is_kept() {
    let reply = Reply::oauth_error(400, "account_locked", "ask your administrator");
    let (error, _) = build_error(reply, 0).await;

    let Error::OAuth(oauth) = &error else {
        panic!("expected an OAuth error, got {error:?}");
    };
    assert_eq!(
        oauth.code(),
        &ErrorCode::Other("account_locked".to_string())
    );
    assert_eq!(oauth.code().as_str(), "account_locked");
}

#[tokio::test]
async fn test_a_proxy_error_page_keeps_the_status_and_is_retried() {
    let reply = Reply::text(503, "text/html", "<html>upstream unavailable</html>")
        .with_header("retry-after", "7");
    let (error, requests) = build_error(reply, 1).await;

    let Error::Http(http) = &error else {
        panic!("expected an HTTP error, got {error:?}");
    };
    assert_eq!(http.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(http.content_type(), Some("text/html"));
    assert_eq!(http.retry_after(), Some(Duration::from_secs(7)));
    assert_eq!(error.retry_after(), Some(Duration::from_secs(7)));
    assert!(error.is_retryable());
    assert_eq!(requests, 2);
}

#[tokio::test]
async fn test_a_client_error_without_an_oauth_body_is_not_retried() {
    let reply = Reply::text(404, "text/plain", "not found");
    let (error, requests) = build_error(reply, 3).await;

    let Error::Http(http) = &error else {
        panic!("expected an HTTP error, got {error:?}");
    };
    assert_eq!(http.status(), StatusCode::NOT_FOUND);
    assert!(!error.is_retryable());
    assert_eq!(requests, 1);
}

#[tokio::test]
async fn test_a_token_with_a_status_other_than_200_is_refused() {
    let body = json!({"access_token": "t", "token_type": "Bearer", "expires_in": 3600});
    let (error, requests) = build_error(Reply::json(201, body.to_string()), 3).await;

    let Error::Http(http) = &error else {
        panic!("expected an HTTP error, got {error:?}");
    };
    assert_eq!(http.status(), StatusCode::CREATED);
    assert!(!error.is_retryable());
    assert_eq!(requests, 1);
}

#[tokio::test]
async fn test_expires_in_may_be_a_string_of_digits() {
    let body = json!({"access_token": "t", "token_type": "Bearer", "expires_in": "3599"});
    let idp = FakeIdp::start(move |_| Reply::json(200, body.to_string())).await;

    let authorizer = builder(idp.token_url()).build().await.unwrap();

    assert!(authorizer.refresh_task().is_some());
}

#[tokio::test]
async fn test_expires_in_of_another_type_is_rejected() {
    for expires_in in [json!("soon"), json!(-5), json!(3.5), json!("")] {
        let body = json!({"access_token": "t", "token_type": "Bearer", "expires_in": expires_in});
        let (error, requests) = build_error(Reply::json(200, body.to_string()), 3).await;

        assert_eq!(
            invalid_response(&error),
            &ResponseProblem::WrongType {
                field: "expires_in",
                expected: "a non-negative integer"
            },
            "expires_in: {expires_in}"
        );
        assert!(!error.is_retryable());
        assert_eq!(requests, 1);
    }
}

#[tokio::test]
async fn test_a_huge_expires_in_does_not_panic() {
    let idp = FakeIdp::start(|_| Reply::token("t", Some(u64::MAX))).await;

    let authorizer = builder(idp.token_url()).build().await.unwrap();

    assert_eq!(
        authorizer.authorization_header().unwrap().to_str().unwrap(),
        "Bearer t"
    );
}

#[tokio::test]
async fn test_a_huge_expires_in_at_refresh_keeps_the_authorizer_working() {
    let idp = FakeIdp::start(|number| match number {
        1 => Reply::token("first", Some(2)),
        _ => Reply::token("second", Some(u64::MAX)),
    })
    .await;
    let authorizer = builder(idp.token_url()).build().await.unwrap();

    tokio::time::sleep(Duration::from_millis(1500)).await;

    assert_eq!(idp.count(), 2);
    assert_eq!(
        authorizer.authorization_header().unwrap().to_str().unwrap(),
        "Bearer second"
    );
}

#[tokio::test]
async fn test_token_type_is_compared_ignoring_case() {
    let body = json!({"access_token": "t", "token_type": "BEARER"});
    let idp = FakeIdp::start(move |_| Reply::json(200, body.to_string())).await;

    let authorizer = builder(idp.token_url()).build().await.unwrap();

    assert_eq!(
        authorizer.authorization_header().unwrap().to_str().unwrap(),
        "Bearer t"
    );
}

#[tokio::test]
async fn test_a_token_type_other_than_bearer_is_rejected() {
    let body = json!({"access_token": "t", "token_type": "DPoP", "expires_in": 3600});
    let (error, requests) = build_error(Reply::json(200, body.to_string()), 3).await;

    assert_eq!(
        invalid_response(&error),
        &ResponseProblem::UnsupportedTokenType("DPoP".to_string())
    );
    assert!(!error.is_retryable());
    assert_eq!(requests, 1);
}

#[tokio::test]
async fn test_a_response_without_token_type_is_rejected() {
    let body = json!({"access_token": "t", "expires_in": 3600});
    let (error, _) = build_error(Reply::json(200, body.to_string()), 0).await;

    assert_eq!(
        invalid_response(&error),
        &ResponseProblem::MissingField("token_type")
    );
}

#[tokio::test]
async fn test_a_response_without_access_token_is_rejected() {
    let body = json!({"token_type": "Bearer", "expires_in": 3600});
    let (error, _) = build_error(Reply::json(200, body.to_string()), 0).await;

    assert_eq!(
        invalid_response(&error),
        &ResponseProblem::MissingField("access_token")
    );
}

#[tokio::test]
async fn test_an_access_token_that_is_not_a_bearer_token_is_rejected() {
    for access_token in ["bad\u{1}token", "t\u{f6}k\u{e9}n", "two words", "", "a=b"] {
        let body = json!({"access_token": access_token, "token_type": "Bearer"});
        let (error, _) = build_error(Reply::json(200, body.to_string()), 0).await;

        assert_eq!(
            invalid_response(&error),
            &ResponseProblem::InvalidAccessToken,
            "access token {access_token:?}"
        );
    }
}

#[tokio::test]
async fn test_an_access_token_may_end_with_padding() {
    let body = json!({"access_token": "a-b.c_d~e+f/g==", "token_type": "Bearer"});
    let idp = FakeIdp::start(move |_| Reply::json(200, body.to_string())).await;

    let authorizer = builder(idp.token_url()).build().await.unwrap();

    assert_eq!(
        authorizer.authorization_header().unwrap().to_str().unwrap(),
        "Bearer a-b.c_d~e+f/g=="
    );
}

#[tokio::test]
async fn test_a_response_that_is_not_json_is_rejected() {
    let reply = Reply::text(200, "text/html", "<html>login</html>");
    let (error, _) = build_error(reply, 0).await;

    let Error::InvalidResponse(invalid) = &error else {
        panic!("expected an invalid response, got {error:?}");
    };
    assert_eq!(invalid.problem(), &ResponseProblem::NotJsonObject);
    assert_eq!(invalid.status(), StatusCode::OK);
    assert_eq!(invalid.content_type(), Some("text/html"));
}

#[tokio::test]
async fn test_an_unusable_response_never_reveals_the_access_token() {
    let bodies = [
        json!({"access_token": "SECRET-ACCESS-TOKEN", "token_type": "mac"}),
        json!({"access_token": "SECRET-ACCESS-TOKEN", "token_type": "Bearer", "expires_in": "SECRET-ACCESS-TOKEN"}),
        json!({"access_token": "SECRET-ACCESS-TOKEN"}),
    ];
    for body in bodies {
        let (error, _) = build_error(Reply::json(200, body.to_string()), 0).await;

        assert!(matches!(error, Error::InvalidResponse(_)), "{error:?}");
        assert!(!format!("{error}").contains("SECRET"), "{error}");
        assert!(!format!("{error:?}").contains("SECRET"), "{error:?}");
    }
}

#[tokio::test]
async fn test_a_response_larger_than_one_mebibyte_is_rejected() {
    let body = json!({"access_token": "t".repeat(1024 * 1024), "token_type": "Bearer"});
    let (error, _) = build_error(Reply::json(200, body.to_string()), 0).await;

    assert_eq!(
        invalid_response(&error),
        &ResponseProblem::TooLarge { limit: 1024 * 1024 }
    );
}

#[tokio::test]
async fn test_a_token_request_without_an_answer_times_out() {
    let idp = FakeIdp::start(|_| Reply::Hang).await;

    let error = tokio::time::timeout(
        Duration::from_secs(5),
        builder(idp.token_url())
            .timeout(Duration::from_millis(200))
            .set_max_retries(0)
            .build(),
    )
    .await
    .expect("build must give up on its own")
    .expect_err("build must fail");

    assert!(matches!(error, Error::Timeout(timeout) if timeout == Duration::from_millis(200)));
    assert!(error.is_retryable());
}

#[tokio::test]
async fn test_a_refresh_without_an_answer_does_not_stop_refreshing() {
    let idp = FakeIdp::start(|number| match number {
        2 => Reply::Hang,
        _ => Reply::token("t", Some(2)),
    })
    .await;
    let authorizer = builder(idp.token_url())
        .timeout(Duration::from_millis(200))
        .set_max_retries(0)
        .refresh_tolerance(Duration::from_secs(1))
        .build()
        .await
        .unwrap();

    // The first refresh starts after 1 s and times out after 200 ms. The token is still valid until 2 s, so the next refresh starts 1 s later.
    tokio::time::sleep(Duration::from_millis(2600)).await;

    assert_eq!(idp.count(), 3);
    assert!(authorizer.authorization_header().is_ok());
}

#[tokio::test]
async fn test_a_connection_error_keeps_its_cause() {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let token_url = format!("http://127.0.0.1:{port}/token").parse().unwrap();

    let error = builder(token_url)
        .set_max_retries(0)
        .build()
        .await
        .expect_err("nothing listens on the port");

    assert!(matches!(error, Error::Transport(_)), "{error:?}");
    let cause = error
        .source()
        .and_then(|source| source.downcast_ref::<reqwest::Error>())
        .expect("the cause is the reqwest error");
    assert!(cause.is_connect());
    assert!(error.is_retryable());
}

#[tokio::test]
async fn test_redirects_are_not_followed() {
    let target = FakeIdp::start(|_| Reply::token("t", Some(3600))).await;
    let location = target.token_url().to_string();
    let idp = FakeIdp::start(move |_| {
        Reply::text(307, "text/plain", "moved").with_header("location", &location)
    })
    .await;

    let error = builder(idp.token_url())
        .set_max_retries(0)
        .build()
        .await
        .expect_err("a redirect is not a token");

    let Error::Http(http) = &error else {
        panic!("expected an HTTP error, got {error:?}");
    };
    assert_eq!(http.status(), StatusCode::TEMPORARY_REDIRECT);
    assert!(!error.is_retryable());
    assert_eq!(target.count(), 0);
}

#[tokio::test]
async fn test_a_redirect_followed_by_the_callers_client_is_refused() {
    let target = FakeIdp::start(|_| Reply::token("t", Some(3600))).await;
    let location = target.token_url().to_string();
    let idp = FakeIdp::start(move |_| {
        Reply::text(307, "text/plain", "moved").with_header("location", &location)
    })
    .await;

    let error = builder(idp.token_url())
        .set_http_client(reqwest::Client::new())
        .set_max_retries(0)
        .build()
        .await
        .expect_err("a token from another URL is refused");

    assert!(
        matches!(invalid_response(&error), ResponseProblem::Redirected { .. }),
        "{error:?}"
    );
    // reqwest replays the form body on a 307, so the other host got the request.
    assert_eq!(target.count(), 1);
}
