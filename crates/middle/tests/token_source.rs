//! A token source of the application's own: middle caches its tokens, refreshes them and retries failures.

mod support;

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime},
};

use middle::{AccessToken, Authorizer, Error, SourceError, TokenContext, TokenReason, TokenSource};
use support::wait_until;

/// Hands out `token-1`, `token-2`, and so on, valid for `expires_in`, fails the calls in `failing`, counted from 1, with `error`,
/// and never answers the calls in `hanging`.
#[derive(Debug, Default)]
struct CountingSource {
    calls: AtomicUsize,
    /// The reason of each call.
    reasons: Mutex<Vec<TokenReason>>,
    expires_in: Option<Duration>,
    expires_at: Option<SystemTime>,
    failing: Vec<usize>,
    error: Option<SourceError>,
    hanging: Vec<usize>,
    /// How long each call after the first takes.
    delay: Duration,
}

impl CountingSource {
    fn valid_for(expires_in: Duration) -> Self {
        Self {
            expires_in: Some(expires_in),
            ..Self::default()
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn reasons(&self) -> Vec<TokenReason> {
        self.reasons.lock().unwrap().clone()
    }
}

impl TokenSource for CountingSource {
    async fn token(&self, context: &TokenContext) -> Result<AccessToken, SourceError> {
        self.reasons.lock().unwrap().push(context.reason());
        let number = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if self.hanging.contains(&number) {
            std::future::pending::<()>().await;
        }
        if number > 1 {
            tokio::time::sleep(self.delay).await;
        }
        if self.failing.contains(&number) {
            return Err(self.error.clone().expect("an error for failing calls"));
        }
        let mut token = AccessToken::new(format!("token-{number}"))?;
        if let Some(expires_in) = self.expires_in {
            token = token.with_expires_in(expires_in);
        }
        if let Some(expires_at) = self.expires_at {
            token = token.with_expires_at(expires_at);
        }
        Ok(token)
    }
}

/// Caches its token as some cloud SDKs do: hands out the cached token for a first token or a refresh, after waiting `delay`,
/// and a new one only for a rejected token.
#[derive(Debug)]
struct CachingSource {
    reasons: Mutex<Vec<TokenReason>>,
    new_tokens: AtomicUsize,
    delay: Duration,
}

impl CachingSource {
    fn new(delay: Duration) -> Self {
        Self {
            reasons: Mutex::new(Vec::new()),
            new_tokens: AtomicUsize::new(1),
            delay,
        }
    }

    fn reasons(&self) -> Vec<TokenReason> {
        self.reasons.lock().unwrap().clone()
    }
}

impl TokenSource for CachingSource {
    async fn token(&self, context: &TokenContext) -> Result<AccessToken, SourceError> {
        let reason = context.reason();
        self.reasons.lock().unwrap().push(reason);
        let number = if reason == TokenReason::Rejected {
            self.new_tokens.fetch_add(1, Ordering::SeqCst) + 1
        } else {
            tokio::time::sleep(self.delay).await;
            self.new_tokens.load(Ordering::SeqCst)
        };
        Ok(AccessToken::new(format!("cached-{number}"))?.with_expires_in(Duration::from_secs(2)))
    }
}

/// Never answers.
#[derive(Debug)]
struct HangingSource;

impl TokenSource for HangingSource {
    async fn token(&self, _context: &TokenContext) -> Result<AccessToken, SourceError> {
        std::future::pending().await
    }
}

fn header(authorizer: &Authorizer) -> Option<String> {
    authorizer
        .authorization_header()
        .ok()
        .map(|header| header.to_str().unwrap().to_string())
}

#[tokio::test(start_paused = true)]
async fn test_the_token_of_the_source_is_the_header() {
    let source = Arc::new(CountingSource::valid_for(Duration::from_secs(3600)));

    let authorizer = Authorizer::from_source(Arc::clone(&source))
        .build()
        .await
        .unwrap();

    let header = authorizer.authorization_header().unwrap();
    assert_eq!(header.to_str().unwrap(), "Bearer token-1");
    assert!(header.is_sensitive());
    assert_eq!(source.calls(), 1);
}

#[tokio::test(start_paused = true)]
async fn test_the_source_is_asked_again_before_the_token_expires() {
    let source = Arc::new(CountingSource::valid_for(Duration::from_secs(2)));
    let authorizer = Authorizer::from_source(Arc::clone(&source))
        .build()
        .await
        .unwrap();
    let built = tokio::time::Instant::now();

    // A token of 2 s is refreshed 1 s after the source was asked.
    tokio::time::sleep_until(built + Duration::from_millis(999)).await;
    assert_eq!(header(&authorizer).as_deref(), Some("Bearer token-1"));
    tokio::time::sleep_until(built + Duration::from_millis(1500)).await;
    assert_eq!(header(&authorizer).as_deref(), Some("Bearer token-2"));
}

#[tokio::test(start_paused = true)]
async fn test_one_source_can_serve_several_authorizers() {
    let source = Arc::new(CountingSource::valid_for(Duration::from_secs(3600)));
    let first = Authorizer::from_source(Arc::clone(&source))
        .build()
        .await
        .unwrap();
    let second = Authorizer::from_source(Arc::clone(&source))
        .build()
        .await
        .unwrap();

    assert_eq!(header(&first).as_deref(), Some("Bearer token-1"));
    assert_eq!(header(&second).as_deref(), Some("Bearer token-2"));
    assert_eq!(source.calls(), 2);
}

#[tokio::test(start_paused = true)]
async fn test_the_source_learns_why_middle_asks_for_a_token() {
    let source = Arc::new(CountingSource::valid_for(Duration::from_secs(2)));
    let authorizer = Authorizer::from_source(Arc::clone(&source))
        .build()
        .await
        .unwrap();
    assert!(
        wait_until(Duration::from_secs(3), || header(&authorizer).as_deref()
            == Some("Bearer token-2"))
        .await
    );

    assert!(authorizer.invalidate(&authorizer.token_header().unwrap()));
    let replaced = authorizer.wait_for_header().await.unwrap();

    assert_eq!(replaced.header().to_str().unwrap(), "Bearer token-3");
    assert_eq!(
        source.reasons()[..3],
        [
            TokenReason::First,
            TokenReason::Refresh,
            TokenReason::Rejected
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn test_a_token_rejected_while_middle_waits_to_retry_is_replaced_with_the_reason_rejected() {
    let source = Arc::new(CountingSource {
        failing: vec![2],
        error: Some(SourceError::new("the token service is busy")),
        ..CountingSource::valid_for(Duration::from_secs(4))
    });
    let authorizer = Authorizer::from_source(Arc::clone(&source))
        .build()
        .await
        .unwrap();
    let first = authorizer.token_header().unwrap();
    // The refresh comes after about 2 s and fails; middle waits about 1 s before the next attempt.
    assert!(wait_until(Duration::from_secs(3), || source.calls() == 2).await);

    assert!(authorizer.invalidate(&first));
    let replaced = authorizer.wait_for_header().await.unwrap();

    assert_eq!(replaced.header().to_str().unwrap(), "Bearer token-3");
    assert_eq!(
        source.reasons()[..3],
        [
            TokenReason::First,
            TokenReason::Refresh,
            TokenReason::Rejected
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn test_a_token_rejected_while_a_refresh_runs_is_not_taken_back_from_that_refresh() {
    let source = Arc::new(CachingSource::new(Duration::from_millis(300)));
    let authorizer = Authorizer::from_source(Arc::clone(&source))
        .build()
        .await
        .unwrap();
    let first = authorizer.token_header().unwrap();
    // The refresh comes after about 1 s and runs for 300 ms.
    assert!(wait_until(Duration::from_secs(3), || source.reasons().len() == 2).await);

    assert!(authorizer.invalidate(&first));
    let replaced = authorizer.wait_for_header().await.unwrap();

    // The refresh returned the rejected token, so middle asked again with the reason `Rejected`.
    assert_eq!(replaced.header().to_str().unwrap(), "Bearer cached-2");
    assert_eq!(
        source.reasons()[..3],
        [
            TokenReason::First,
            TokenReason::Refresh,
            TokenReason::Rejected
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn test_a_new_token_of_a_refresh_that_ran_during_a_rejection_is_kept() {
    let source = Arc::new(CountingSource {
        delay: Duration::from_millis(300),
        ..CountingSource::valid_for(Duration::from_secs(2))
    });
    let authorizer = Authorizer::from_source(Arc::clone(&source))
        .build()
        .await
        .unwrap();
    let first = authorizer.token_header().unwrap();
    // The refresh comes after about 1 s and runs for 300 ms.
    assert!(wait_until(Duration::from_secs(3), || source.calls() == 2).await);

    assert!(authorizer.invalidate(&first));
    let replaced = authorizer.wait_for_header().await.unwrap();

    assert_eq!(replaced.header().to_str().unwrap(), "Bearer token-2");
    assert_eq!(source.reasons(), [TokenReason::First, TokenReason::Refresh]);
}

#[tokio::test(start_paused = true)]
async fn test_a_token_rejected_after_a_refresh_brought_it_back_is_replaced() {
    let source = Arc::new(CachingSource::new(Duration::ZERO));
    let authorizer = Authorizer::from_source(Arc::clone(&source))
        .build()
        .await
        .unwrap();
    // A request takes the header, and the refresh after about 1 s brings back the same token from the cache.
    let sent = authorizer.token_header().unwrap();
    assert!(wait_until(Duration::from_secs(3), || source.reasons().len() == 2).await);
    tokio::time::sleep(Duration::from_millis(100)).await;

    // The server rejects the token of that request.
    assert!(authorizer.invalidate(&sent));
    let replaced = authorizer.wait_for_header().await.unwrap();

    assert_eq!(replaced.header().to_str().unwrap(), "Bearer cached-2");
    assert_eq!(
        source.reasons()[..3],
        [
            TokenReason::First,
            TokenReason::Refresh,
            TokenReason::Rejected
        ]
    );
}

#[test]
fn test_an_access_token_can_be_read() {
    let token = AccessToken::new("token-1")
        .unwrap()
        .with_expires_in(Duration::from_secs(60));

    assert_eq!(token.as_str(), "token-1");
    assert_eq!(token.expires_in(), Some(Duration::from_secs(60)));
    assert_eq!(AccessToken::new("token-1").unwrap().expires_in(), None);
}

#[test]
fn test_a_context_can_be_made_for_tests_of_a_source() {
    assert_eq!(
        TokenContext::new(TokenReason::Rejected).reason(),
        TokenReason::Rejected
    );
}

#[tokio::test(start_paused = true)]
async fn test_a_token_without_a_lifetime_lives_the_default_token_lifetime() {
    // Only the first call answers in time, so the first token expires.
    let source = Arc::new(CountingSource {
        delay: Duration::from_secs(3600),
        ..CountingSource::default()
    });
    let authorizer = Authorizer::from_source(Arc::clone(&source))
        .default_token_lifetime(Duration::from_secs(2))
        .build()
        .await
        .unwrap();
    let built = tokio::time::Instant::now();

    tokio::time::sleep_until(built + Duration::from_millis(1999)).await;
    assert_eq!(header(&authorizer).as_deref(), Some("Bearer token-1"));
    tokio::time::sleep_until(built + Duration::from_millis(2001)).await;
    assert_eq!(header(&authorizer), None);
}

#[tokio::test(start_paused = true)]
async fn test_a_source_error_is_retried() {
    let source = Arc::new(CountingSource {
        failing: vec![1],
        error: Some(SourceError::new("the token service is starting")),
        ..CountingSource::valid_for(Duration::from_secs(3600))
    });

    let authorizer = Authorizer::from_source(Arc::clone(&source))
        .build()
        .await
        .unwrap();

    assert_eq!(header(&authorizer).as_deref(), Some("Bearer token-2"));
    assert_eq!(source.calls(), 2);
}

#[tokio::test(start_paused = true)]
async fn test_a_permanent_source_error_fails_build_at_once() {
    let source = Arc::new(CountingSource {
        failing: vec![1],
        error: Some(SourceError::new("access denied").permanent()),
        ..CountingSource::valid_for(Duration::from_secs(3600))
    });

    let error = Authorizer::from_source(Arc::clone(&source))
        .build()
        .await
        .expect_err("the error is permanent");

    assert!(matches!(&error, Error::Source(_)), "{error:?}");
    assert!(!error.is_retryable());
    assert_eq!(error.to_string(), "access denied");
    assert_eq!(source.calls(), 1);
}

#[test]
fn test_an_access_token_keeps_the_lifetime_it_was_given_last() {
    let expiry = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000_000);
    let token = AccessToken::new("t")
        .unwrap()
        .with_expires_in(Duration::from_secs(60))
        .with_expires_at(expiry);
    assert_eq!(token.expires_at(), Some(expiry));
    assert_eq!(token.expires_in(), None);

    let token = token.with_expires_in(Duration::from_secs(60));
    assert_eq!(token.expires_in(), Some(Duration::from_secs(60)));
    assert_eq!(token.expires_at(), None);
}

#[tokio::test(start_paused = true)]
async fn test_an_expiry_that_had_passed_fails_the_attempt() {
    let source = Arc::new(CountingSource {
        expires_at: Some(SystemTime::now() - Duration::from_secs(3600)),
        ..CountingSource::default()
    });
    let error = Authorizer::from_source(Arc::clone(&source))
        .max_retries(0)
        .build()
        .await
        .unwrap_err();

    assert!(
        matches!(error, Error::ExpiredOnArrival(lifetime) if lifetime.is_zero()),
        "{error:?}"
    );
}

#[test]
fn test_a_source_error_can_ask_for_a_wait() {
    let error =
        Error::from(SourceError::new("rate limited").with_retry_after(Duration::from_secs(10)));

    assert_eq!(error.retry_after(), Some(Duration::from_secs(10)));
    assert!(error.is_retryable());
}

#[test]
fn test_a_source_error_tells_what_it_asks_for() {
    let error = SourceError::new("failed");
    assert!(!error.is_permanent());
    assert_eq!(error.retry_after(), None);

    let error = SourceError::new("rate limited").with_retry_after(Duration::from_secs(10));
    assert_eq!(error.retry_after(), Some(Duration::from_secs(10)));

    assert!(SourceError::new("access denied").permanent().is_permanent());
}

#[tokio::test(start_paused = true)]
async fn test_a_source_that_does_not_answer_is_bounded_by_the_timeout() {
    let build = Authorizer::from_source(HangingSource)
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
}

#[tokio::test(start_paused = true)]
async fn test_a_refresh_without_an_answer_does_not_stop_refreshing() {
    let source = Arc::new(CountingSource {
        hanging: vec![2],
        ..CountingSource::valid_for(Duration::from_secs(2))
    });
    let authorizer = Authorizer::from_source(Arc::clone(&source))
        .timeout(Duration::from_millis(200))
        .build()
        .await
        .unwrap();
    let built = tokio::time::Instant::now();

    // The refresh at 1 s gets no answer and times out at 1.2 s. The token has less than 2 s left, so the next request waits 1 s.
    // The token expires at 2 s, before that request.
    tokio::time::sleep_until(built + Duration::from_millis(2199)).await;
    assert_eq!(source.calls(), 2);
    let error = authorizer.authorization_header().unwrap_err();
    assert!(
        matches!(error, Error::Timeout(timeout) if timeout == Duration::from_millis(200)),
        "{error:?}"
    );

    let header = authorizer.wait_for_header().await.unwrap();
    assert_eq!(header.header().to_str().unwrap(), "Bearer token-3");
    assert_eq!(built.elapsed(), Duration::from_millis(2200));
    assert_eq!(source.calls(), 3);
}

#[tokio::test(start_paused = true)]
async fn test_dropping_the_authorizer_ends_the_refresh_task_and_its_request() {
    let source = Arc::new(CountingSource {
        hanging: vec![2],
        ..CountingSource::valid_for(Duration::from_secs(2))
    });
    let authorizer = Authorizer::from_source(Arc::clone(&source))
        .build()
        .await
        .unwrap();
    // The refresh at 1 s gets no answer, so a request runs when the authorizer is dropped.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(source.calls(), 2);

    drop(authorizer);
    tokio::time::sleep(Duration::from_millis(1)).await;

    // The authorizer, its refresh task and the request each held the source.
    assert_eq!(Arc::strong_count(&source), 1);
}

#[tokio::test(start_paused = true)]
async fn test_invalidate_asks_the_source_for_a_new_token() {
    let source = Arc::new(CountingSource::valid_for(Duration::from_secs(3600)));
    let authorizer = Authorizer::from_source(Arc::clone(&source))
        .build()
        .await
        .unwrap();
    let rejected = authorizer.token_header().unwrap();

    assert!(authorizer.invalidate(&rejected));

    let replaced = authorizer.wait_for_header().await.unwrap();
    assert_eq!(replaced.header().to_str().unwrap(), "Bearer token-2");
    assert_eq!(source.calls(), 2);
}

#[test]
fn test_an_access_token_must_fit_in_a_header() {
    for token in ["", "SECRET token", "SECRET\ttoken", "SECRET-tökén"] {
        let error = AccessToken::new(token).expect_err("not a header value");

        let message = format!("{error} {error:?}");
        assert!(!message.contains("SECRET"), "{message}");
        assert!(Error::from(error).is_retryable());
    }
}

#[tokio::test(start_paused = true)]
async fn test_debug_output_shows_the_source_and_not_the_token() {
    let authorizer = Authorizer::from_source(CountingSource::valid_for(Duration::from_secs(3600)))
        .build()
        .await
        .unwrap();
    let builder = Authorizer::from_source(CountingSource::default());

    let authorizer = format!("{authorizer:?}");
    assert!(authorizer.contains("CountingSource"), "{authorizer}");
    assert!(!authorizer.contains("token-1"), "{authorizer}");
    assert!(
        format!("{builder:?}").contains("CountingSource"),
        "{builder:?}"
    );
    assert!(!format!("{:?}", AccessToken::new("token-1").unwrap()).contains("token-1"));
}
