//! Reading the answer of the token endpoint (RFC 6749, sections 5.1 and 5.2).

use std::{fmt, time::Duration};

use http::{HeaderMap, StatusCode, header};
use serde_json::{Map, Value};

use super::MAX_RESPONSE_BYTES;
use crate::error::{Error, ErrorCode, HttpError, InvalidResponse, OAuthError, ResponseProblem};

/// The longest lifetime middle believes. Longer lifetimes are shortened to this, so the expiry never overflows.
pub(crate) const MAX_EXPIRES_IN: Duration = Duration::from_secs(365 * 24 * 60 * 60);

const MAX_CODE_CHARS: usize = 64;
const MAX_TEXT_CHARS: usize = 256;

/// Status and headers of the answer.
pub(super) struct Meta {
    pub(super) status: StatusCode,
    pub(super) content_type: Option<String>,
    retry_after: Option<Duration>,
}

impl Meta {
    pub(super) fn from_headers(status: StatusCode, headers: &HeaderMap) -> Self {
        Self {
            status,
            content_type: headers
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .map(|value| sanitize(value, MAX_TEXT_CHARS)),
            retry_after: super::retry_after(headers),
        }
    }

    /// The error for a status other than 200 without an OAuth error middle can read.
    pub(super) fn http_error(self) -> Error {
        HttpError {
            status: self.status,
            content_type: self.content_type,
            retry_after: self.retry_after,
        }
        .into()
    }

    fn invalid(&self, problem: ResponseProblem) -> Error {
        InvalidResponse {
            status: self.status,
            content_type: self.content_type.clone(),
            problem,
        }
        .into()
    }
}

/// A token answer middle can use.
#[derive(Debug)]
pub(crate) struct TokenResponse {
    pub(crate) access_token: AccessToken,
    /// At most [`MAX_EXPIRES_IN`].
    pub(crate) expires_in: Option<Duration>,
}

/// An access token of visible ASCII characters (RFC 6749, appendix A.12), without spaces, so that it fits after `Bearer ` in a header.
/// It is always a valid header value.
pub(crate) struct AccessToken(String);

impl AccessToken {
    fn parse(token: &str) -> Option<Self> {
        let valid = !token.is_empty() && token.bytes().all(|b| b.is_ascii_graphic());
        valid.then(|| Self(token.to_string()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccessToken([redacted])")
    }
}

/// Reads the answer. `body` is `None` if it was larger than [`MAX_RESPONSE_BYTES`].
///
/// A JSON object with an `error` string is an OAuth error at any status, because some token endpoints send OAuth errors with status 200.
/// Errors never contain the body, which may hold an access token.
pub(super) fn parse(meta: Meta, body: Option<&[u8]>) -> Result<TokenResponse, Error> {
    let object = body.and_then(|body| match serde_json::from_slice(body) {
        Ok(Value::Object(object)) => Some(object),
        _ => None,
    });

    if let Some(object) = &object {
        match present(object, "error") {
            Some(Value::String(code)) => {
                return Err(OAuthError {
                    status: meta.status,
                    code: ErrorCode::parse(&sanitize(code, MAX_CODE_CHARS)),
                    description: text_field(object, "error_description"),
                    uri: text_field(object, "error_uri"),
                    retry_after: meta.retry_after,
                }
                .into());
            }
            // An `error` that is not a string makes a 200 ambiguous. With another status, the status decides.
            Some(_) if meta.status == StatusCode::OK => {
                return Err(meta.invalid(ResponseProblem::WrongType {
                    field: "error",
                    expected: "a string",
                }));
            }
            _ => {}
        }
    }

    // RFC 6749, section 5.1: a token comes with 200.
    if meta.status != StatusCode::OK {
        return Err(meta.http_error());
    }

    if body.is_none() {
        return Err(meta.invalid(ResponseProblem::TooLarge {
            limit: MAX_RESPONSE_BYTES,
        }));
    }
    let Some(object) = object else {
        return Err(meta.invalid(ResponseProblem::NotJsonObject));
    };

    let access_token = match present(&object, "access_token") {
        None => return Err(meta.invalid(ResponseProblem::MissingField("access_token"))),
        Some(Value::String(token)) => AccessToken::parse(token)
            .ok_or_else(|| meta.invalid(ResponseProblem::InvalidAccessToken))?,
        Some(_) => {
            return Err(meta.invalid(ResponseProblem::WrongType {
                field: "access_token",
                expected: "a string",
            }));
        }
    };

    match present(&object, "token_type") {
        None => return Err(meta.invalid(ResponseProblem::MissingField("token_type"))),
        Some(Value::String(token_type)) if token_type.eq_ignore_ascii_case("bearer") => {}
        Some(Value::String(token_type)) => {
            return Err(meta.invalid(ResponseProblem::UnsupportedTokenType(sanitize(
                token_type,
                MAX_CODE_CHARS,
            ))));
        }
        Some(_) => {
            return Err(meta.invalid(ResponseProblem::WrongType {
                field: "token_type",
                expected: "a string",
            }));
        }
    }

    let expires_in = expires_in(present(&object, "expires_in")).map_err(|()| {
        meta.invalid(ResponseProblem::WrongType {
            field: "expires_in",
            expected: "a positive integer",
        })
    })?;

    Ok(TokenResponse {
        access_token,
        expires_in,
    })
}

/// The field, unless it is missing or `null`.
fn present<'a>(object: &'a Map<String, Value>, field: &str) -> Option<&'a Value> {
    object.get(field).filter(|value| !value.is_null())
}

/// A text field of an OAuth error. A field of another type counts as missing.
fn text_field(object: &Map<String, Value>, field: &str) -> Option<String> {
    match object.get(field) {
        Some(Value::String(text)) => Some(sanitize(text, MAX_TEXT_CHARS)),
        _ => None,
    }
}

/// `expires_in` as a positive JSON integer or a string of digits, as some token endpoints send it. At most [`MAX_EXPIRES_IN`].
/// A lifetime of 0 is an error, because such a token has expired on arrival.
fn expires_in(value: Option<&Value>) -> Result<Option<Duration>, ()> {
    let seconds = match value {
        None => return Ok(None),
        Some(Value::Number(number)) => number.as_u64(),
        Some(Value::String(digits))
            if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) =>
        {
            Some(digits.parse().unwrap_or(u64::MAX))
        }
        Some(_) => None,
    };
    seconds
        .filter(|seconds| *seconds > 0)
        .map(|seconds| Some(Duration::from_secs(seconds).min(MAX_EXPIRES_IN)))
        .ok_or(())
}

/// Text from the token endpoint without control characters and at most `max_chars` long, so it is safe to log.
fn sanitize(text: &str, max_chars: usize) -> String {
    let mut visible = text.chars().filter(|c| !c.is_control());
    let mut clean: String = visible.by_ref().take(max_chars).collect();
    if visible.next().is_some() {
        clean.push('…');
    }
    clean
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_removes_control_characters_and_shortens() {
        assert_eq!(sanitize("a\nb\u{1b}[31mc", 10), "ab[31mc");
        assert_eq!(sanitize("abcdef", 3), "abc…");
        assert_eq!(sanitize("abc", 3), "abc");
    }

    #[test]
    fn test_expires_in_is_capped() {
        assert_eq!(
            expires_in(Some(&Value::from(u64::MAX))),
            Ok(Some(MAX_EXPIRES_IN))
        );
        assert_eq!(
            expires_in(Some(&Value::from("99999999999999999999999"))),
            Ok(Some(MAX_EXPIRES_IN))
        );
        assert_eq!(expires_in(Some(&Value::from(0))), Err(()));
        assert_eq!(expires_in(Some(&Value::from("000"))), Err(()));
    }

    #[test]
    fn test_debug_hides_the_access_token() {
        let token = AccessToken::parse("SECRET").unwrap();
        assert_eq!(format!("{token:?}"), "AccessToken([redacted])");
    }
}
