//! When the refresh task asks for the next token: refresh points, backoff after failures, and jitter.

use std::{
    hash::{BuildHasher, RandomState},
    time::Duration,
};

use crate::error::Error;

/// The shortest time between two token requests after a success, and the earliest refresh point of a token.
pub(super) const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(1);

/// The longest wait between two failed requests of an error a retry can fix.
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// About how long the task waits after an error a retry cannot fix. The fix often happens at the token endpoint, so the task keeps asking.
const SLOW_RETRY: Duration = Duration::from_secs(5 * 60);

/// The longest wait the task takes from a `Retry-After` header. The token endpoint reports up to one day.
const MAX_RETRY_AFTER_WAIT: Duration = Duration::from_secs(5 * 60);

/// When to refresh a token that lives `lifetime`, counted from its request: a random point in a window.
///
/// The window is 10 % of the lifetime wide and ends at 85 % of it. It ends earlier if needed, so that it ends at least `tolerance` before expiry, but not before half the lifetime.
/// The refresh never comes sooner than [`MIN_REFRESH_INTERVAL`]. `random` lies in `[0, 1)` and picks the point in the window.
pub(super) fn refresh_delay(lifetime: Duration, tolerance: Duration, random: f64) -> Duration {
    let width = lifetime / 10;
    let end = lifetime
        .mul_f64(0.85)
        .min(lifetime.saturating_sub(tolerance))
        .max(lifetime / 2);
    let start = end.saturating_sub(width);
    (start + width.mul_f64(random)).max(MIN_REFRESH_INTERVAL)
}

/// How long to wait after the `failures`-th failed request in a row.
///
/// An error a retry can fix backs off exponentially from 1 s to 30 s. An error a retry cannot fix waits about 5 minutes.
/// `limit` shortens both waits, so that the task retries before the current token expires.
/// A `Retry-After` of the token endpoint makes the wait longer, up to 5 minutes, also past `limit`: the server asked for it. `random` lies in `[0, 1)`.
pub(super) fn retry_delay(
    error: &Error,
    failures: u32,
    limit: Option<Duration>,
    random: f64,
) -> Duration {
    let delay = if error.is_retryable() {
        backoff(failures, random)
    } else {
        SLOW_RETRY.mul_f64(0.9 + 0.2 * random)
    };
    let delay = limit.map_or(delay, |limit| delay.min(limit));
    match error.retry_after() {
        Some(retry_after) => delay.max(retry_after.min(MAX_RETRY_AFTER_WAIT)),
        None => delay,
    }
}

/// The wait after the `count`-th failure or rejection in a row: between 1 s and 2 s after the first; each further one doubles both bounds, up to 15 s and 30 s.
pub(super) fn backoff(count: u32, random: f64) -> Duration {
    let ceiling = Duration::from_secs(2)
        .saturating_mul(2_u32.saturating_pow(count.saturating_sub(1)))
        .min(MAX_BACKOFF);
    ceiling.mul_f64(0.5 + 0.5 * random)
}

/// A random number in `[0, 1)` to spread requests of many clients over time. Not for anything secret.
pub(super) fn random() -> f64 {
    // Each `RandomState` has new keys, so hashing the same value gives a new pseudo-random number.
    let bits = RandomState::new().hash_one(0_u8);
    let high = u32::try_from(bits >> 32).unwrap_or(u32::MAX);
    f64::from(high) / (f64::from(u32::MAX) + 1.0)
}

#[cfg(test)]
mod tests {
    use http::StatusCode;

    use super::*;
    use crate::error::{ErrorCode, HttpError, OAuthError};

    /// The largest `random` value, just below 1.
    const ALMOST_ONE: f64 = 1.0 - f64::EPSILON;

    fn secs(seconds: f64) -> Duration {
        Duration::from_secs_f64(seconds)
    }

    fn unavailable(retry_after: Option<u64>) -> Error {
        HttpError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            content_type: None,
            retry_after: retry_after.map(Duration::from_secs),
        }
        .into()
    }

    fn invalid_client() -> Error {
        OAuthError {
            status: StatusCode::UNAUTHORIZED,
            code: ErrorCode::InvalidClient,
            description: None,
            uri: None,
            retry_after: None,
        }
        .into()
    }

    /// Asserts that the refresh window of a token of `lifetime` seconds runs from `start` to `end` seconds.
    fn assert_window(lifetime: f64, tolerance: f64, start: f64, end: f64) {
        let close =
            |actual: Duration, expected: f64| (actual.as_secs_f64() - expected).abs() < 1e-6;
        let lifetime = secs(lifetime);
        let tolerance = secs(tolerance);
        let earliest = refresh_delay(lifetime, tolerance, 0.0);
        let middle = refresh_delay(lifetime, tolerance, 0.5);
        let latest = refresh_delay(lifetime, tolerance, ALMOST_ONE);
        assert!(close(earliest, start), "{lifetime:?}: {earliest:?}");
        assert!(
            close(middle, f64::midpoint(start, end)),
            "{lifetime:?}: {middle:?}"
        );
        assert!(close(latest, end), "{lifetime:?}: {latest:?}");
    }

    #[test]
    fn test_a_long_token_refreshes_between_75_and_85_percent_of_its_lifetime() {
        assert_window(3600.0, 30.0, 2700.0, 3060.0);
        assert_window(300.0, 30.0, 225.0, 255.0);
    }

    #[test]
    fn test_the_window_moves_to_end_at_least_tolerance_before_expiry() {
        assert_window(180.0, 30.0, 132.0, 150.0);
        assert_window(120.0, 30.0, 78.0, 90.0);
        assert_window(60.0, 30.0, 24.0, 30.0);
    }

    #[test]
    fn test_the_window_of_a_token_too_short_for_the_tolerance_ends_at_half_its_lifetime() {
        assert_window(40.0, 30.0, 16.0, 20.0);
        assert_window(31.0, 30.0, 12.4, 15.5);
        assert_window(29.0, 30.0, 11.6, 14.5);
    }

    #[test]
    fn test_a_refresh_never_comes_sooner_than_one_second() {
        assert_window(2.0, 30.0, 1.0, 1.0);
        assert_window(1.5, 30.0, 1.0, 1.0);
        assert_window(0.0, 30.0, 1.0, 1.0);
        assert_window(0.0, 0.0, 1.0, 1.0);
    }

    #[test]
    fn test_a_tolerance_of_zero_keeps_the_window_at_75_to_85_percent() {
        assert_window(2.0, 0.0, 1.5, 1.7);
        assert_window(3600.0, 0.0, 2700.0, 3060.0);
    }

    #[test]
    fn test_backoff_doubles_from_one_second_up_to_thirty() {
        let expected = [
            (1, 1.0, 2.0),
            (2, 2.0, 4.0),
            (3, 4.0, 8.0),
            (4, 8.0, 16.0),
            (5, 15.0, 30.0),
            (6, 15.0, 30.0),
            (40, 15.0, 30.0),
            (u32::MAX, 15.0, 30.0),
        ];
        for (failures, low, high) in expected {
            let error = unavailable(None);
            assert_eq!(
                retry_delay(&error, failures, None, 0.0),
                secs(low),
                "{failures}"
            );
            let longest = retry_delay(&error, failures, None, ALMOST_ONE);
            assert!(
                longest <= secs(high) && longest > secs(high * 0.999),
                "{failures}: {longest:?}"
            );
        }
    }

    #[test]
    fn test_an_error_a_retry_cannot_fix_waits_about_five_minutes() {
        assert_eq!(retry_delay(&invalid_client(), 1, None, 0.0), secs(270.0));
        assert_eq!(retry_delay(&invalid_client(), 7, None, 0.5), secs(300.0));
        let longest = retry_delay(&invalid_client(), 1, None, ALMOST_ONE);
        assert!(
            longest <= secs(330.0) && longest > secs(329.99),
            "{longest:?}"
        );
    }

    #[test]
    fn test_retry_after_lengthens_the_wait_up_to_five_minutes() {
        assert_eq!(
            retry_delay(&unavailable(Some(20)), 1, None, 0.0),
            secs(20.0)
        );
        assert_eq!(
            retry_delay(&unavailable(Some(3600)), 1, None, 0.0),
            secs(300.0)
        );
        // A shorter `Retry-After` does not shorten the backoff.
        assert_eq!(retry_delay(&unavailable(Some(1)), 3, None, 0.0), secs(4.0));
    }

    #[test]
    fn test_a_limit_shortens_the_wait_but_not_retry_after() {
        assert_eq!(
            retry_delay(&invalid_client(), 1, Some(secs(10.0)), 0.5),
            secs(10.0)
        );
        assert_eq!(
            retry_delay(&unavailable(None), 5, Some(secs(3.0)), 0.0),
            secs(3.0)
        );
        // A limit longer than the wait changes nothing.
        assert_eq!(
            retry_delay(&unavailable(None), 1, Some(secs(10.0)), 0.0),
            secs(1.0)
        );
        // The server asked for this wait.
        assert_eq!(
            retry_delay(&unavailable(Some(20)), 1, Some(secs(5.0)), 0.0),
            secs(20.0)
        );
    }

    #[test]
    fn test_random_numbers_lie_between_zero_and_one_and_vary() {
        let numbers: Vec<f64> = (0..100).map(|_| random()).collect();
        assert!(
            numbers.iter().all(|n| (0.0..1.0).contains(n)),
            "{numbers:?}"
        );
        let first = numbers[0];
        assert!(
            numbers.iter().any(|n| (n - first).abs() > 0.01),
            "{numbers:?}"
        );
    }
}
