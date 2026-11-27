//! Reading the answer of the token endpoint (RFC 6749, sections 5.1 and 5.2).

use std::time::{Duration, SystemTime};

use http::{HeaderMap, StatusCode, header};
use serde_json::{Map, Value};

use super::{MAX_RESPONSE_BYTES, Secret};
use crate::{
    authorizers::TokenValue,
    error::{Error, ErrorCode, HttpError, InvalidResponse, OAuthError, ResponseProblem},
};

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
    pub(super) fn http_error(&self) -> Error {
        HttpError {
            status: self.status,
            content_type: self.content_type.clone(),
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
#[derive(Debug, Clone)]
pub(crate) struct TokenResponse {
    pub(crate) access_token: TokenValue,
    /// At most [`MAX_EXPIRES_IN`].
    pub(crate) expires_in: Option<Duration>,
    /// The expiry that a token source set with `AccessToken::with_expires_at`. A token endpoint answer has none.
    pub(crate) expires_at: Option<SystemTime>,
}

/// A token exchange answer middle can use (RFC 8693, section 2.2.1).
#[derive(Debug, Clone)]
pub(crate) struct ExchangeResponse {
    /// The issued token, from `access_token`, and `expires_in`.
    pub(crate) token: TokenResponse,
    /// Whether `token_type` is `Bearer`. Otherwise it is `N_A`.
    pub(crate) is_bearer: bool,
    /// Without control characters.
    pub(crate) issued_token_type: Option<String>,
    pub(crate) refresh_token: Option<Secret>,
    /// Without control characters.
    pub(crate) scope: Option<String>,
}

/// A `token_type` that middle accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenType {
    /// `Bearer` (RFC 6750).
    Bearer,
    /// `N_A`: the issued token is not an access token (RFC 8693, section 2.2.1).
    NotApplicable,
}

impl TokenType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Bearer => "Bearer",
            Self::NotApplicable => "N_A",
        }
    }
}

/// Reads the answer to the client credentials grant or the JWT bearer grant, whose `token_type` must be `Bearer`. `body` is `None` if it was larger than [`MAX_RESPONSE_BYTES`].
///
/// A JSON object with an `error` string is an OAuth error at any status, because some token endpoints send OAuth errors with status 200.
/// Errors never contain the body, which may hold an access token.
pub(super) fn parse(meta: &Meta, body: Option<&[u8]>) -> Result<TokenResponse, Error> {
    let object = token_object(meta, body)?;
    let (token, _) = token(meta, &object, &[TokenType::Bearer])?;
    Ok(token)
}

/// Reads the answer to a token exchange (RFC 8693, section 2.2), whose `token_type` must be `Bearer` or `N_A`, as [`parse`] reads other answers.
/// `issued_token_type`, `refresh_token` and `scope` are optional strings.
pub(super) fn parse_exchange(meta: &Meta, body: Option<&[u8]>) -> Result<ExchangeResponse, Error> {
    let object = token_object(meta, body)?;
    let (token, token_type) = token(
        meta,
        &object,
        &[TokenType::Bearer, TokenType::NotApplicable],
    )?;
    Ok(ExchangeResponse {
        token,
        is_bearer: token_type == TokenType::Bearer,
        issued_token_type: optional_string(meta, &object, "issued_token_type")?
            .map(without_control_characters),
        refresh_token: optional_string(meta, &object, "refresh_token")?.map(Secret::new),
        scope: optional_string(meta, &object, "scope")?.map(without_control_characters),
    })
}

/// The JSON object of a token answer with status 200, or the error the answer holds.
fn token_object(meta: &Meta, body: Option<&[u8]>) -> Result<Map<String, Value>, Error> {
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
    object.ok_or_else(|| meta.invalid(ResponseProblem::NotJsonObject))
}

/// The token of a token answer, and its `token_type`, which must be one of `accepted`, compared ignoring upper and lower case (RFC 6749, section 5.1).
fn token(
    meta: &Meta,
    object: &Map<String, Value>,
    accepted: &[TokenType],
) -> Result<(TokenResponse, TokenType), Error> {
    let access_token = match present(object, "access_token") {
        None => return Err(meta.invalid(ResponseProblem::MissingField("access_token"))),
        Some(Value::String(token)) => TokenValue::parse(token)
            .ok_or_else(|| meta.invalid(ResponseProblem::InvalidAccessToken))?,
        Some(_) => {
            return Err(meta.invalid(ResponseProblem::WrongType {
                field: "access_token",
                expected: "a string",
            }));
        }
    };

    let token_type = match present(object, "token_type") {
        None => return Err(meta.invalid(ResponseProblem::MissingField("token_type"))),
        Some(Value::String(token_type)) => accepted
            .iter()
            .copied()
            .find(|accepted| token_type.eq_ignore_ascii_case(accepted.as_str()))
            .ok_or_else(|| {
                meta.invalid(ResponseProblem::UnsupportedTokenType(sanitize(
                    token_type,
                    MAX_CODE_CHARS,
                )))
            })?,
        Some(_) => {
            return Err(meta.invalid(ResponseProblem::WrongType {
                field: "token_type",
                expected: "a string",
            }));
        }
    };

    let expires_in = expires_in(present(object, "expires_in")).map_err(|()| {
        meta.invalid(ResponseProblem::WrongType {
            field: "expires_in",
            expected: "a positive integer",
        })
    })?;

    let token = TokenResponse {
        access_token,
        expires_in,
        expires_at: None,
    };
    Ok((token, token_type))
}

/// The field, unless it is missing or `null`.
fn present<'a>(object: &'a Map<String, Value>, field: &str) -> Option<&'a Value> {
    object.get(field).filter(|value| !value.is_null())
}

/// An optional string field of a token answer. A field of another type is an error.
fn optional_string<'a>(
    meta: &Meta,
    object: &'a Map<String, Value>,
    field: &'static str,
) -> Result<Option<&'a str>, Error> {
    match present(object, field) {
        None => Ok(None),
        Some(Value::String(text)) => Ok(Some(text)),
        Some(_) => Err(meta.invalid(ResponseProblem::WrongType {
            field,
            expected: "a string",
        })),
    }
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
    let mut visible = visible_chars(text);
    let mut clean: String = visible.by_ref().take(max_chars).collect();
    if visible.next().is_some() {
        clean.push('…');
    }
    clean
}

/// Text from the token endpoint without control characters, so it is safe to log. The answer limits its length to [`MAX_RESPONSE_BYTES`].
fn without_control_characters(text: &str) -> String {
    visible_chars(text).collect()
}

fn visible_chars(text: &str) -> impl Iterator<Item = char> + '_ {
    text.chars().filter(|c| !c.is_control())
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

    fn ok() -> Meta {
        Meta::from_headers(StatusCode::OK, &HeaderMap::new())
    }

    fn problem(error: Error) -> ResponseProblem {
        match error {
            Error::InvalidResponse(invalid) => invalid.problem,
            other => panic!("expected an invalid response, got {other:?}"),
        }
    }

    fn exchange_answer(body: &Value) -> Result<ExchangeResponse, Error> {
        parse_exchange(&ok(), Some(body.to_string().as_bytes()))
    }

    #[test]
    fn test_a_token_exchange_answer_may_be_bearer_or_n_a() {
        for (token_type, is_bearer) in [
            ("Bearer", true),
            ("bearer", true),
            ("N_A", false),
            ("n_a", false),
        ] {
            let body = serde_json::json!({"access_token": "t", "token_type": token_type});
            let answer = exchange_answer(&body).unwrap();
            assert_eq!(answer.is_bearer, is_bearer, "{token_type}");
            assert_eq!(answer.token.access_token.as_str(), "t");
        }
    }

    #[test]
    fn test_a_token_exchange_member_of_another_type_is_refused() {
        for field in ["issued_token_type", "refresh_token", "scope"] {
            let mut body = serde_json::json!({"access_token": "t", "token_type": "Bearer"});
            body[field] = serde_json::json!(["SECRET"]);
            let error = exchange_answer(&body).unwrap_err();
            assert!(!format!("{error:?}").contains("SECRET"), "{error:?}");
            assert_eq!(
                problem(error),
                ResponseProblem::WrongType {
                    field,
                    expected: "a string"
                }
            );
        }
    }

    #[test]
    fn test_the_issued_token_type_and_the_scope_lose_control_characters() {
        let body = serde_json::json!({
            "access_token": "t",
            "token_type": "Bearer",
            "issued_token_type": "urn:a\n\u{1b}[31mb",
            "scope": "read\r\nwrite",
        });
        let answer = exchange_answer(&body).unwrap();
        assert_eq!(answer.issued_token_type.as_deref(), Some("urn:a[31mb"));
        assert_eq!(answer.scope.as_deref(), Some("readwrite"));
    }

    #[test]
    fn test_the_scope_of_a_token_exchange_answer_is_not_shortened() {
        let scope = vec!["s"; 1000].join(" ");
        let body = serde_json::json!({"access_token": "t", "token_type": "Bearer", "scope": scope});
        assert_eq!(exchange_answer(&body).unwrap().scope, Some(scope));
    }

    #[test]
    fn test_the_other_grants_ignore_the_token_exchange_members() {
        let body = serde_json::json!({
            "access_token": "t",
            "token_type": "Bearer",
            "issued_token_type": 1,
            "refresh_token": 2,
            "scope": ["read"],
        });
        let answer = parse(&ok(), Some(body.to_string().as_bytes())).unwrap();
        assert_eq!(answer.access_token.as_str(), "t");
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
}
