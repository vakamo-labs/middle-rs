//! How the authorizer keeps its token fresh: when it refreshes, how it recovers from failures, and what readers get once refresh has stopped.

mod support;

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use middle::{Authorizer as _, ConfigError, Error};
use support::{FakeIdp, Reply, wait_until};

fn builder(token_url: url::Url) -> middle::BasicClientCredentialAuthorizerBuilder {
    middle::BasicClientCredentialAuthorizer::basic_builder(
        "my-client",
        "SECRET-CLIENT-SECRET",
        token_url,
    )
}

fn header(authorizer: &middle::ClientCredentialAuthorizer) -> Option<String> {
    authorizer
        .authorization_header()
        .ok()
        .map(|header| header.to_str().unwrap().to_string())
}

/// A token endpoint that answers the first request with a token valid for 2 s, and later requests with `outage` while the flag is set.
async fn idp_with_outage(outage: Reply) -> (FakeIdp, Arc<AtomicBool>) {
    let failing = Arc::new(AtomicBool::new(true));
    let flag = Arc::clone(&failing);
    let idp = FakeIdp::start(move |number| {
        if number == 1 || !flag.load(Ordering::SeqCst) {
            Reply::token("t", Some(2))
        } else {
            outage.clone()
        }
    })
    .await;
    (idp, failing)
}

#[tokio::test]
async fn test_a_refresh_without_an_answer_recovers_when_the_server_answers_again() {
    let (idp, failing) = idp_with_outage(Reply::Hang).await;
    let authorizer = builder(idp.token_url())
        .timeout(Duration::from_millis(300))
        .build()
        .await
        .unwrap();

    assert!(
        wait_until(Duration::from_secs(5), || header(&authorizer).is_none()).await,
        "the token expires while the token endpoint does not answer"
    );
    failing.store(false, Ordering::SeqCst);

    // Retries back off from 1 s to at most 4 s here; the refresh tolerance of 30 s does not delay them.
    assert!(
        wait_until(Duration::from_secs(6), || header(&authorizer).is_some()).await,
        "requests: {:?} ms",
        idp.arrival_ms()
    );
}

#[tokio::test]
async fn test_recovery_after_an_outage_does_not_wait_for_the_refresh_tolerance() {
    let (idp, failing) =
        idp_with_outage(Reply::oauth_error(503, "temporarily_unavailable", "down")).await;
    let authorizer = builder(idp.token_url()).build().await.unwrap();

    assert!(
        wait_until(Duration::from_secs(5), || header(&authorizer).is_none()).await,
        "the token expires during the outage"
    );
    let error = authorizer.authorization_header().unwrap_err();
    assert!(
        matches!(&error, Error::OAuth(oauth) if oauth.status() == 503),
        "readers get the error of the last refresh: {error:?}"
    );
    failing.store(false, Ordering::SeqCst);

    assert!(
        wait_until(Duration::from_secs(6), || header(&authorizer).is_some()).await,
        "requests: {:?} ms",
        idp.arrival_ms()
    );
}

#[tokio::test]
async fn test_a_refresh_answer_that_expires_at_once_is_not_used() {
    let idp = FakeIdp::start(|number| match number {
        1 => Reply::token("t", Some(2)),
        _ => Reply::token("expired", Some(0)),
    })
    .await;
    let authorizer = builder(idp.token_url()).build().await.unwrap();

    assert!(wait_until(Duration::from_secs(3), || idp.count() == 2).await);
    assert_eq!(header(&authorizer).as_deref(), Some("Bearer t"));
    assert!(
        wait_until(Duration::from_secs(3), || header(&authorizer).is_none()).await,
        "the current token expires"
    );

    let error = authorizer.authorization_header().unwrap_err();
    assert!(matches!(error, Error::InvalidResponse(_)), "{error:?}");
    assert!(!error.is_retryable());
    // A retry cannot fix the answer. While the token was valid, the task retried at half the time it had left, at least 1 s later,
    // so the last retry came at most 1 s after expiry. After that, the next request comes in about 5 minutes.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let requests = idp.count();
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(idp.count(), requests);
}

#[test]
fn test_readers_get_a_final_error_once_the_runtime_has_shut_down() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let (idp, authorizer) = runtime.block_on(async {
        let idp = FakeIdp::start(|_| Reply::token("t", Some(2))).await;
        let authorizer = builder(idp.token_url()).build().await.unwrap();
        (idp, authorizer)
    });

    drop(runtime);

    assert_eq!(header(&authorizer).as_deref(), Some("Bearer t"));
    let start = std::time::Instant::now();
    while header(&authorizer).is_some() && start.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(10));
    }
    let error = authorizer
        .authorization_header()
        .expect_err("the token has expired");
    assert!(matches!(error, Error::RefreshStopped), "{error:?}");
    assert!(
        !error.is_retryable(),
        "no refresh will come, so a retry cannot help"
    );
    assert!(authorizer.refresh_task().unwrap().task().is_finished());
    assert_eq!(idp.count(), 1);
}

#[tokio::test]
async fn test_dropping_the_last_clone_stops_refreshing() {
    let idp = FakeIdp::start(|_| Reply::token("t", Some(2))).await;
    let authorizer = builder(idp.token_url()).build().await.unwrap();
    let clone = authorizer.clone();

    drop(authorizer);
    assert!(
        wait_until(Duration::from_secs(3), || idp.count() >= 2).await,
        "a remaining clone keeps refreshing"
    );

    drop(clone);
    let requests = idp.count();
    // Without the drop, the next refresh would come 1 s after the last one.
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert_eq!(idp.count(), requests);
}

#[tokio::test]
async fn test_refresh_continues_after_a_token_without_expires_in() {
    let idp = FakeIdp::start(|number| match number {
        1 => Reply::token("t", Some(2)),
        _ => Reply::token("t2", None),
    })
    .await;
    let authorizer = builder(idp.token_url()).build().await.unwrap();

    assert!(
        wait_until(Duration::from_secs(3), || header(&authorizer).as_deref()
            == Some("Bearer t2"))
        .await
    );
    assert!(
        !authorizer.refresh_task().unwrap().task().is_finished(),
        "the refresh task keeps running"
    );
}

#[tokio::test]
async fn test_a_jwt_access_token_without_expires_in_is_refreshed_before_its_exp() {
    let exp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 4;
    let idp = FakeIdp::start(move |_| Reply::jwt_token(exp)).await;

    let authorizer = builder(idp.token_url()).build().await.unwrap();

    // The token lives 3 to 4 s, so the refresh comes after half of that.
    assert!(
        wait_until(Duration::from_secs(4), || idp.count() >= 2).await,
        "requests: {:?} ms",
        idp.arrival_ms()
    );
    let arrivals = idp.arrival_ms();
    assert!(
        arrivals[1] - arrivals[0] < 3000,
        "the refresh comes before the earliest `exp`: {arrivals:?} ms"
    );
    assert!(authorizer.authorization_header().is_ok());
}

#[tokio::test]
async fn test_a_default_token_lifetime_below_two_seconds_is_rejected() {
    for lifetime in [Duration::ZERO, Duration::from_millis(1999)] {
        let idp = FakeIdp::start(|_| Reply::token("t", None)).await;

        let error = builder(idp.token_url())
            .default_token_lifetime(lifetime)
            .build()
            .await
            .expect_err("a token of that lifetime expires before its refresh");

        assert!(
            matches!(error, Error::Config(ConfigError::DefaultTokenLifetimeTooShort(too_short)) if too_short == lifetime),
            "{lifetime:?}: {error:?}"
        );
        assert!(!error.is_retryable());
        assert_eq!(idp.count(), 0);
    }

    let idp = FakeIdp::start(|_| Reply::token("t", None)).await;
    let authorizer = builder(idp.token_url())
        .default_token_lifetime(Duration::from_secs(2))
        .build()
        .await;
    assert!(authorizer.is_ok(), "2 s is long enough: {authorizer:?}");
}

#[tokio::test]
async fn test_a_header_of_another_authorizer_does_not_invalidate_a_token() {
    let first_idp = counting_idp().await;
    let second_idp = counting_idp().await;
    let first = builder(first_idp.token_url()).build().await.unwrap();
    let second = builder(second_idp.token_url()).build().await.unwrap();

    second.invalidate(&first.wait_for_header().await.unwrap());

    assert_eq!(header(&second).as_deref(), Some("Bearer token-1"));
    assert_eq!(second_idp.count(), 1);
}

#[tokio::test]
async fn test_the_default_token_lifetime_applies_without_expires_in() {
    let idp = FakeIdp::start(|_| Reply::token("t", None)).await;

    let _authorizer = builder(idp.token_url())
        .default_token_lifetime(Duration::from_secs(2))
        .build()
        .await
        .unwrap();

    assert!(wait_until(Duration::from_secs(3), || idp.count() >= 2).await);
    let arrivals = idp.arrival_ms();
    // A token of 2 s is refreshed 1 s after the first request was sent. That request also opened the connection, so it arrives a few milliseconds later than the refresh does after being sent.
    assert!(
        arrivals[1] - arrivals[0] >= 900,
        "requests: {arrivals:?} ms"
    );
}

/// A token endpoint that numbers its tokens.
async fn counting_idp() -> FakeIdp {
    FakeIdp::start(|number| Reply::token(&format!("token-{number}"), Some(3600))).await
}

#[tokio::test]
async fn test_a_rejected_token_is_replaced_once() {
    let idp = counting_idp().await;
    let authorizer = builder(idp.token_url()).build().await.unwrap();
    let rejected = authorizer.wait_for_header().await.unwrap();
    assert_eq!(rejected.header().to_str().unwrap(), "Bearer token-1");

    // Two calls failed with the same token, and both report it.
    authorizer.invalidate(&rejected);
    authorizer.invalidate(&rejected);
    assert!(matches!(
        authorizer.authorization_header(),
        Err(Error::TokenExpired)
    ));
    let replaced = authorizer.wait_for_header().await.unwrap();
    assert_eq!(replaced.header().to_str().unwrap(), "Bearer token-2");

    // A late report about the first token keeps the second.
    authorizer.invalidate(&rejected);
    assert_eq!(header(&authorizer).as_deref(), Some("Bearer token-2"));
    assert_eq!(idp.count(), 2);
}

#[tokio::test]
async fn test_a_token_shorter_than_the_tolerance_is_replaced_before_it_expires() {
    let idp = FakeIdp::start(|number| Reply::token(&format!("token-{number}"), Some(2))).await;
    // The first token is requested after this instant, so it expires more than 2 s after it.
    let before_build = tokio::time::Instant::now();
    let authorizer = builder(idp.token_url())
        .refresh_tolerance(Duration::from_secs(10))
        .build()
        .await
        .unwrap();

    // The token lives 2 s, shorter than twice the tolerance, so it is refreshed 1 s after its request, the earliest refresh.
    // The second token arrives before the first one expires, and every read until then finds the first one.
    loop {
        let current = header(&authorizer).expect("a valid token at every read");
        assert!(
            before_build.elapsed() < Duration::from_secs(2),
            "the first token expired before the second arrived"
        );
        if current == "Bearer token-2" {
            break;
        }
        assert_eq!(current, "Bearer token-1");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test]
async fn test_a_header_read_without_waiting_can_invalidate_its_token() {
    let idp = counting_idp().await;
    let authorizer = builder(idp.token_url()).build().await.unwrap();

    // A client that cannot wait reads the header, sends it, and reports the rejection.
    let sent = authorizer.token_header().unwrap();
    assert_eq!(sent.header().to_str().unwrap(), "Bearer token-1");
    authorizer.invalidate(&sent);

    assert!(matches!(
        authorizer.token_header(),
        Err(Error::TokenExpired)
    ));
    let replaced = authorizer.wait_for_header().await.unwrap();
    assert_eq!(replaced.header().to_str().unwrap(), "Bearer token-2");
    assert_eq!(idp.count(), 2);
}

#[tokio::test]
async fn test_concurrent_waiters_share_one_token_request() {
    let idp = counting_idp().await;
    let authorizer = builder(idp.token_url()).build().await.unwrap();
    authorizer.invalidate(&authorizer.wait_for_header().await.unwrap());

    let waiters: Vec<_> = (0..20)
        .map(|_| {
            let authorizer = authorizer.clone();
            tokio::spawn(async move { authorizer.wait_for_header().await })
        })
        .collect();
    for waiter in waiters {
        let header = waiter.await.unwrap().unwrap();
        assert_eq!(header.header().to_str().unwrap(), "Bearer token-2");
    }

    assert_eq!(idp.count(), 2);
}

#[tokio::test]
async fn test_waiting_ends_with_the_error_of_a_request_a_retry_cannot_fix() {
    let idp = FakeIdp::start(|number| match number {
        1 => Reply::token("t", Some(3600)),
        _ => Reply::oauth_error(401, "invalid_client", "the secret has expired"),
    })
    .await;
    let authorizer = builder(idp.token_url()).build().await.unwrap();
    authorizer.invalidate(&authorizer.wait_for_header().await.unwrap());

    let error = tokio::time::timeout(Duration::from_secs(5), authorizer.wait_for_header())
        .await
        .expect("the next request comes in about 5 minutes, so the wait ends at once")
        .unwrap_err();

    assert!(
        matches!(&error, Error::OAuth(oauth) if oauth.status() == 401),
        "{error:?}"
    );
    assert!(!error.is_retryable());
    assert_eq!(idp.count(), 2);
}
