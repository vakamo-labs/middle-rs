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

/// Waits until `condition` holds, for at most 5 s.
async fn eventually(mut condition: impl FnMut() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        if condition() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    condition()
}

fn header(authorizer: &middle::BasicClientCredentialAuthorizer) -> Option<String> {
    authorizer
        .authorization_header()
        .ok()
        .and_then(|header| header.to_str().ok().map(str::to_string))
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
async fn test_an_oauth_error_with_a_5xx_status_is_retried() {
    // A 5xx means the server failed, so the code it sent is not reliable.
    let reply = Reply::oauth_error(503, "invalid_client", "unknown client");
    let (error, requests) = build_error(reply, 1).await;

    assert!(matches!(&error, Error::OAuth(oauth) if oauth.code() == &ErrorCode::InvalidClient));
    assert!(error.is_retryable());
    assert_eq!(requests, 2);
}

#[tokio::test]
async fn test_an_error_field_of_another_type_in_a_200_is_rejected() {
    let body = json!({"error": false, "access_token": "t", "token_type": "Bearer"});
    let (error, _) = build_error(Reply::json(200, body.to_string()), 0).await;

    assert_eq!(
        invalid_response(&error),
        &ResponseProblem::WrongType {
            field: "error",
            expected: "a string"
        }
    );
}

#[tokio::test]
async fn test_an_error_field_of_null_is_no_error() {
    let body = json!({"error": null, "access_token": "t", "token_type": "Bearer"});
    let idp = FakeIdp::start(move |_| Reply::json(200, body.to_string())).await;

    let authorizer = builder(idp.token_url()).build().await.unwrap();

    assert_eq!(header(&authorizer).as_deref(), Some("Bearer t"));
}

#[tokio::test]
async fn test_an_error_object_with_a_server_error_keeps_the_status() {
    let body = json!({"error": {"code": 503, "message": "backend down"}});
    let (error, requests) = build_error(Reply::json(503, body.to_string()), 1).await;

    assert!(
        matches!(&error, Error::Http(http) if http.status() == StatusCode::SERVICE_UNAVAILABLE),
        "{error:?}"
    );
    assert!(error.is_retryable());
    assert_eq!(requests, 2);
}

#[tokio::test]
async fn test_an_unregistered_error_string_is_retried_by_the_status() {
    // The default error page of a web framework, with the reason phrase as `error`.
    let body = json!({"timestamp": "2026-01-01T00:00:00Z", "status": 503, "error": "Service Unavailable", "path": "/token"});
    let (error, requests) = build_error(Reply::json(503, body.to_string()), 1).await;

    let Error::OAuth(oauth) = &error else {
        panic!("expected an OAuth error, got {error:?}");
    };
    assert_eq!(
        oauth.code(),
        &ErrorCode::Other("Service Unavailable".to_string())
    );
    assert!(error.is_retryable());
    assert_eq!(requests, 2);
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
        .with_header("retry-after", "2");
    let idp = FakeIdp::start(move |_| reply.clone()).await;

    let error = builder(idp.token_url())
        .set_max_retries(1)
        .build()
        .await
        .expect_err("build must fail");

    let Error::Http(http) = &error else {
        panic!("expected an HTTP error, got {error:?}");
    };
    assert_eq!(http.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(http.content_type(), Some("text/html"));
    assert_eq!(http.retry_after(), Some(Duration::from_secs(2)));
    assert_eq!(error.retry_after(), Some(Duration::from_secs(2)));
    assert!(error.is_retryable());
    let requests = idp.requests();
    assert_eq!(requests.len(), 2);
    let wait = requests[1].received_at - requests[0].received_at;
    assert!(
        wait >= Duration::from_secs(2),
        "the retry follows Retry-After: {wait:?}"
    );
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
async fn test_a_rejection_whose_body_breaks_off_keeps_its_status_and_is_not_retried() {
    let (error, requests) = build_error(Reply::CutOff { status: 401 }, 3).await;

    let Error::Http(http) = &error else {
        panic!("expected an HTTP error, got {error:?}");
    };
    assert_eq!(http.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(error.status(), Some(StatusCode::UNAUTHORIZED));
    assert!(!error.is_retryable());
    assert_eq!(requests, 1);
}

#[tokio::test]
async fn test_a_token_answer_whose_body_breaks_off_is_a_transport_error_and_retried() {
    let (error, requests) = build_error(Reply::CutOff { status: 200 }, 1).await;

    assert!(
        matches!(error, Error::Transport(_)),
        "expected a transport error, got {error:?}"
    );
    assert!(error.is_retryable());
    assert_eq!(requests, 2);
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
    for expires_in in [
        json!("soon"),
        json!(-5),
        json!(3.5),
        json!(""),
        json!(0),
        json!("0"),
    ] {
        let body = json!({"access_token": "t", "token_type": "Bearer", "expires_in": expires_in});
        let (error, requests) = build_error(Reply::json(200, body.to_string()), 3).await;

        assert_eq!(
            invalid_response(&error),
            &ResponseProblem::WrongType {
                field: "expires_in",
                expected: "a positive integer"
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

    assert!(eventually(|| header(&authorizer).as_deref() == Some("Bearer second")).await);
    assert_eq!(idp.count(), 2);
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
async fn test_an_access_token_that_is_not_visible_ascii_is_rejected() {
    for access_token in ["bad\u{1}token", "t\u{f6}k\u{e9}n", "two words", ""] {
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
async fn test_an_access_token_may_hold_any_visible_ascii() {
    // RFC 6749, appendix A.12. Some providers send percent-encoded tokens or tokens with `!`.
    for access_token in ["AAAA%2Bfake%3Dtoken", "00D000000000000!AQ.fake", "a=b"] {
        let body = json!({"access_token": access_token, "token_type": "Bearer"});
        let idp = FakeIdp::start(move |_| Reply::json(200, body.to_string())).await;

        let authorizer = builder(idp.token_url()).build().await.unwrap();

        assert_eq!(
            authorizer.authorization_header().unwrap().to_str().unwrap(),
            format!("Bearer {access_token}")
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
        1 => Reply::token("first", Some(2)),
        2 => Reply::Hang,
        _ => Reply::token("third", Some(2)),
    })
    .await;
    let authorizer = builder(idp.token_url())
        .timeout(Duration::from_millis(200))
        .set_max_retries(0)
        .refresh_tolerance(Duration::from_secs(1))
        .build()
        .await
        .unwrap();

    // The first refresh starts after 1 s and times out after 200 ms. The token has less than 2 s left, so the next one starts 1 s later.
    assert!(
        eventually(|| header(&authorizer).as_deref() == Some("Bearer third")).await,
        "requests: {:?} ms",
        idp.arrival_ms()
    );
    assert_eq!(idp.count(), 3);
    let arrivals = idp.arrival_ms();
    assert!(
        arrivals[2] - arrivals[1] >= 1200,
        "requests: {arrivals:?} ms"
    );
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
async fn test_a_transport_error_does_not_show_the_query_of_the_token_url() {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let token_url = format!("http://127.0.0.1:{port}/token?key=SECRET-QUERY")
        .parse()
        .unwrap();

    let error = builder(token_url)
        .set_max_retries(0)
        .build()
        .await
        .expect_err("nothing listens on the port");

    let mut chain = vec![format!("{error}"), format!("{error:?}")];
    let mut source = error.source();
    while let Some(cause) = source {
        chain.push(format!("{cause}"));
        source = cause.source();
    }
    for text in chain {
        assert!(!text.contains("SECRET"), "{text}");
    }
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

    assert_eq!(
        invalid_response(&error),
        &ResponseProblem::Redirected {
            to: target.token_url().origin().ascii_serialization()
        }
    );
    // reqwest replays the form body on a 307, so the other host got the request.
    assert_eq!(target.count(), 1);
}

#[tokio::test]
async fn test_a_redirect_loop_of_the_callers_client_is_not_retried() {
    let idp = FakeIdp::start(|_| {
        Reply::text(302, "text/plain", "moved").with_header("location", "/token")
    })
    .await;

    let error = builder(idp.token_url())
        .set_http_client(reqwest::Client::new())
        .set_max_retries(3)
        .build()
        .await
        .expect_err("a redirect loop fails");

    let Error::Transport(transport) = &error else {
        panic!("expected a transport error, got {error:?}");
    };
    let cause = transport
        .source()
        .and_then(|source| source.downcast_ref::<reqwest::Error>())
        .expect("the cause is a reqwest error");
    assert!(cause.is_redirect(), "{cause:?}");
    assert!(!error.is_retryable());
    // The first request and the 10 redirects reqwest follows by default.
    assert_eq!(idp.count(), 11);
}

#[tokio::test]
async fn test_a_response_of_unknown_length_larger_than_one_mebibyte_is_rejected() {
    let (error, _) = build_error(
        Reply::UntilClose {
            body: "t".repeat(1024 * 1024 + 1),
        },
        0,
    )
    .await;

    assert_eq!(
        invalid_response(&error),
        &ResponseProblem::TooLarge { limit: 1024 * 1024 }
    );
}
