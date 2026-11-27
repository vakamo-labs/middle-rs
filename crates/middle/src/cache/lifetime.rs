//! How long a token lives, counted from its request.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::token_endpoint::{MAX_EXPIRES_IN, TokenResponse};

/// Where a lifetime comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Origin {
    /// The `expires_in` of the answer.
    ExpiresIn,
    /// The `exp` claim of a JWT access token.
    JwtExp,
    /// The configured default.
    Default,
}

/// The lifetime of the token in `response`, requested at `requested_at`.
///
/// `expires_in` if the answer has it. Otherwise the `exp` claim of the access token if it is a JWT (RFC 9068) and `exp` lies after `requested_at`.
/// Otherwise `default`, which the caller keeps at most one year. The other two are at most one year, whatever the token source sends.
pub(super) fn lifetime(
    response: &TokenResponse,
    requested_at: SystemTime,
    default: Duration,
) -> (Duration, Origin) {
    if let Some(expires_in) = response.expires_in {
        return (expires_in.min(MAX_EXPIRES_IN), Origin::ExpiresIn);
    }
    let requested_at = requested_at
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |since_epoch| since_epoch.as_secs_f64());
    jwt_exp(response.access_token.as_str())
        .map(|exp| exp - requested_at)
        .filter(|seconds| *seconds > 0.0)
        .and_then(|seconds| {
            Duration::try_from_secs_f64(seconds.min(MAX_EXPIRES_IN.as_secs_f64())).ok()
        })
        .map_or((default, Origin::Default), |lifetime| {
            (lifetime, Origin::JwtExp)
        })
}

/// The `exp` claim of a JWT in seconds since 1970, read without checking the signature.
/// `None` if the token is not a JWS with a numeric `exp`: three base64url parts, a header that is a JSON object with `alg` (RFC 7515, sections 4.1.1 and 7.1),
/// and a signature that is empty only for `alg` `none` (RFC 7519, section 6.1).
pub(crate) fn jwt_exp(token: &str) -> Option<f64> {
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    let header: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).ok()?).ok()?;
    let algorithm = header.get("alg")?.as_str()?;
    if signature.is_empty() != (algorithm == "none") {
        return None;
    }
    URL_SAFE_NO_PAD.decode(signature).ok()?;
    let payload = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    claims.get("exp")?.as_f64().filter(|exp| exp.is_finite())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorizers::TokenValue;

    const DEFAULT: Duration = Duration::from_secs(300);

    fn encode(json: &serde_json::Value) -> String {
        URL_SAFE_NO_PAD.encode(json.to_string())
    }

    fn jwt(claims: &serde_json::Value) -> String {
        format!(
            "{}.{}.c2lnbmF0dXJl",
            encode(&serde_json::json!({"alg": "RS256"})),
            encode(claims)
        )
    }

    fn response(access_token: &str, expires_in: Option<u64>) -> TokenResponse {
        TokenResponse {
            access_token: TokenValue::parse(access_token).unwrap(),
            expires_in: expires_in.map(Duration::from_secs),
        }
    }

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds)
    }

    #[test]
    fn test_expires_in_comes_first() {
        let token = jwt(&serde_json::json!({"exp": 2_000_000_100_u64}));
        assert_eq!(
            lifetime(&response(&token, Some(60)), at(2_000_000_000), DEFAULT),
            (Duration::from_secs(60), Origin::ExpiresIn)
        );
    }

    #[test]
    fn test_expires_in_above_one_year_is_capped() {
        // A token source other than the token endpoint client may pass any `expires_in`.
        assert_eq!(
            lifetime(&response("t", Some(u64::MAX)), at(2_000_000_000), DEFAULT),
            (MAX_EXPIRES_IN, Origin::ExpiresIn)
        );
    }

    #[test]
    fn test_the_exp_of_a_jwt_counts_from_the_request() {
        let token = jwt(&serde_json::json!({"sub": "c", "exp": 2_000_000_100_u64}));
        assert_eq!(
            lifetime(&response(&token, None), at(2_000_000_000), DEFAULT),
            (Duration::from_secs(100), Origin::JwtExp)
        );
    }

    #[test]
    fn test_a_fractional_exp_is_read() {
        let token = jwt(&serde_json::json!({"exp": 2_000_000_100.5}));
        assert_eq!(
            lifetime(&response(&token, None), at(2_000_000_000), DEFAULT),
            (Duration::from_millis(100_500), Origin::JwtExp)
        );
    }

    #[test]
    fn test_an_exp_far_in_the_future_is_capped_at_one_year() {
        let token = jwt(&serde_json::json!({"exp": u64::MAX}));
        assert_eq!(
            lifetime(&response(&token, None), at(2_000_000_000), DEFAULT),
            (MAX_EXPIRES_IN, Origin::JwtExp)
        );
    }

    #[test]
    fn test_an_exp_that_has_passed_gives_the_default() {
        for exp in [2_000_000_000_u64, 1_999_999_999, 0] {
            let token = jwt(&serde_json::json!({"exp": exp}));
            assert_eq!(
                lifetime(&response(&token, None), at(2_000_000_000), DEFAULT),
                (DEFAULT, Origin::Default),
                "{exp}"
            );
        }
    }

    #[test]
    fn test_an_unsecured_jwt_without_signature_is_read() {
        // RFC 7519, section 6.1: `alg` is `none` and the signature is empty.
        let token = format!(
            "{}.{}.",
            encode(&serde_json::json!({"alg": "none"})),
            encode(&serde_json::json!({"exp": 2_000_000_100_u64}))
        );
        assert_eq!(
            lifetime(&response(&token, None), at(2_000_000_000), DEFAULT),
            (Duration::from_secs(100), Origin::JwtExp)
        );
    }

    #[test]
    fn test_a_token_that_is_not_a_jwt_with_exp_gives_the_default() {
        let claims = encode(&serde_json::json!({"exp": 2_000_000_100_u64}));
        let tokens = [
            "opaque-token".to_string(),
            "a.b".to_string(),
            "a.b.c.d.e".to_string(),
            format!(
                "a.{}.c",
                encode(&serde_json::json!(["exp", 2_000_000_100_u64]))
            ),
            // Claims with `exp` between parts that are not a JWS header and signature.
            format!("a.{claims}.c"),
            format!(
                "{}.{claims}.c2lnbmF0dXJl",
                encode(&serde_json::json!({"typ": "JWT"}))
            ),
            format!(
                "{}.{claims}.!!",
                encode(&serde_json::json!({"alg": "RS256"}))
            ),
            // A signed algorithm with an empty signature.
            format!("{}.{claims}.", encode(&serde_json::json!({"alg": "RS256"}))),
            jwt(&serde_json::json!({"sub": "c"})),
            jwt(&serde_json::json!({"exp": "2000000100"})),
            jwt(&serde_json::json!({"exp": -5})),
        ];
        for token in tokens {
            assert_eq!(
                lifetime(&response(&token, None), at(2_000_000_000), DEFAULT),
                (DEFAULT, Origin::Default),
                "{token}"
            );
        }
    }
}
