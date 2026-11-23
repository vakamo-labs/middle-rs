//! The client of the token endpoint: one form POST per token request (RFC 6749, sections 2.3.1, 4.4 and 5).

mod response;

use std::{fmt, time::Duration};

use http::{HeaderMap, HeaderValue, header};
pub(crate) use response::TokenResponse;
use url::Url;

use crate::error::{ConfigError, Error, InvalidResponse, ResponseProblem, TransportError};

/// The largest answer middle reads from a token endpoint, in bytes.
pub(crate) const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// Form parameters middle sets itself, so a caller cannot add them.
const RESERVED_PARAMETERS: [&str; 7] = [
    "grant_type",
    "scope",
    "client_id",
    "client_secret",
    "client_assertion",
    "client_assertion_type",
    "assertion",
];

/// A secret that `Debug` never prints.
#[derive(Clone)]
pub(crate) struct Secret(String);

impl Secret {
    pub(crate) fn new(secret: impl Into<String>) -> Self {
        Self(secret.into())
    }

    fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

/// How the client authenticates at the token endpoint.
#[derive(Clone, Debug)]
pub(crate) enum ClientAuth {
    /// HTTP Basic with the client id and secret, each form-urlencoded first (RFC 6749, section 2.3.1).
    SecretBasic { client_id: String, secret: Secret },
}

impl ClientAuth {
    fn client_id(&self) -> &str {
        match self {
            Self::SecretBasic { client_id, .. } => client_id,
        }
    }
}

/// One OAuth scope (RFC 6749, section 3.3): one or more visible ASCII characters other than `"` and `\`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Scope(String);

impl Scope {
    fn new(scope: &str) -> Result<Self, ConfigError> {
        let valid = !scope.is_empty()
            && scope
                .bytes()
                .all(|b| b == 0x21 || (0x23..=0x5B).contains(&b) || (0x5D..=0x7E).contains(&b));
        if valid {
            Ok(Self(scope.to_string()))
        } else {
            Err(ConfigError::InvalidScope(scope.to_string()))
        }
    }
}

/// A checked client-credentials token request, sent again for every token.
#[derive(Clone)]
pub(crate) struct TokenRequest {
    url: Url,
    client_auth: ClientAuth,
    scopes: Vec<Scope>,
    params: Vec<(String, String)>,
}

impl TokenRequest {
    /// Checks the token URL, the scopes and the extra form parameters.
    pub(crate) fn new(
        url: Url,
        client_auth: ClientAuth,
        scopes: &[String],
        params: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, ConfigError> {
        if !matches!(url.scheme(), "http" | "https") {
            return Err(ConfigError::TokenUrlScheme(url.scheme().to_string()));
        }
        if url.fragment().is_some() {
            return Err(ConfigError::TokenUrlWithFragment);
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(ConfigError::TokenUrlWithUserInfo);
        }
        let scopes = scopes
            .iter()
            .map(|scope| Scope::new(scope))
            .collect::<Result<Vec<_>, _>>()?;
        let params = params
            .into_iter()
            .map(|(name, value)| {
                if name.is_empty() {
                    Err(ConfigError::EmptyParameterName)
                } else if RESERVED_PARAMETERS.contains(&name.as_str()) {
                    Err(ConfigError::ReservedParameter(name))
                } else {
                    Ok((name, value))
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            url,
            client_auth,
            scopes,
            params,
        })
    }

    pub(crate) fn client_id(&self) -> &str {
        self.client_auth.client_id()
    }

    /// The form body: `grant_type`, `scope`, then the extra parameters.
    fn form(&self) -> String {
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        form.append_pair("grant_type", "client_credentials");
        if !self.scopes.is_empty() {
            let scopes: Vec<&str> = self.scopes.iter().map(|scope| scope.0.as_str()).collect();
            form.append_pair("scope", &scopes.join(" "));
        }
        for (name, value) in &self.params {
            form.append_pair(name, value);
        }
        form.finish()
    }
}

impl fmt::Debug for TokenRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let param_names: Vec<&str> = self.params.iter().map(|(name, _)| name.as_str()).collect();
        f.debug_struct("TokenRequest")
            .field("url", &self.url.as_str())
            .field("client_auth", &self.client_auth)
            .field("scopes", &self.scopes)
            .field("param_names", &param_names)
            .finish()
    }
}

/// Asks the token endpoint for a token once. `timeout` bounds the whole exchange, reading the answer included.
pub(crate) async fn request_token(
    http_client: &reqwest::Client,
    request: &TokenRequest,
    timeout: Duration,
) -> Result<TokenResponse, Error> {
    tokio::time::timeout(timeout, exchange(http_client, request))
        .await
        .unwrap_or(Err(Error::Timeout(timeout)))
}

async fn exchange(
    http_client: &reqwest::Client,
    request: &TokenRequest,
) -> Result<TokenResponse, Error> {
    let mut builder = http_client
        .post(request.url.clone())
        .header(header::ACCEPT, HeaderValue::from_static("application/json"))
        .header(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        )
        .body(request.form());
    match &request.client_auth {
        ClientAuth::SecretBasic { client_id, secret } => {
            // reqwest Base64-encodes `id:secret` and marks the header sensitive.
            builder = builder.basic_auth(
                form_urlencode(client_id),
                Some(form_urlencode(secret.expose())),
            );
        }
    }
    let response = builder.send().await.map_err(TransportError::from)?;

    let meta = response::Meta::from_headers(response.status(), response.headers());
    if response.url() != &request.url {
        return Err(InvalidResponse {
            status: meta.status,
            content_type: meta.content_type,
            problem: ResponseProblem::Redirected {
                to: response.url().origin().ascii_serialization(),
            },
        }
        .into());
    }
    let body = read_body(response).await?;
    response::parse(meta, body.as_deref())
}

/// Reads the body, or `None` if it is larger than [`MAX_RESPONSE_BYTES`].
async fn read_body(mut response: reqwest::Response) -> Result<Option<Vec<u8>>, Error> {
    let limit = u64::try_from(MAX_RESPONSE_BYTES).unwrap_or(u64::MAX);
    if response
        .content_length()
        .is_some_and(|length| length > limit)
    {
        return Ok(None);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(TransportError::from)? {
        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Ok(None);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Some(body))
}

fn form_urlencode(text: &str) -> String {
    url::form_urlencoded::byte_serialize(text.as_bytes()).collect()
}

/// The `Retry-After` header in seconds. An HTTP date gives `None`.
fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    let value = headers.get(header::RETRY_AFTER)?.to_str().ok()?.trim();
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(Duration::from_secs(value.parse().unwrap_or(u64::MAX)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(scopes: &[&str], params: &[(&str, &str)]) -> Result<TokenRequest, ConfigError> {
        TokenRequest::new(
            "https://idp.example.com/token".parse().unwrap(),
            ClientAuth::SecretBasic {
                client_id: "c".to_string(),
                secret: Secret::new("s"),
            },
            &scopes.iter().map(ToString::to_string).collect::<Vec<_>>(),
            params
                .iter()
                .map(|(name, value)| ((*name).to_string(), (*value).to_string())),
        )
    }

    #[test]
    fn test_a_request_without_scopes_sends_no_scope() {
        assert_eq!(
            request(&[], &[]).unwrap().form(),
            "grant_type=client_credentials"
        );
    }

    #[test]
    fn test_scopes_are_joined_with_a_space() {
        assert_eq!(
            request(&["a", "b:c", "https://api.example.com/.default"], &[])
                .unwrap()
                .form(),
            "grant_type=client_credentials&scope=a+b%3Ac+https%3A%2F%2Fapi.example.com%2F.default"
        );
    }

    #[test]
    fn test_a_parameter_name_may_repeat() {
        assert_eq!(
            request(&[], &[("resource", "a"), ("resource", "b")])
                .unwrap()
                .form(),
            "grant_type=client_credentials&resource=a&resource=b"
        );
    }

    #[test]
    fn test_a_scope_must_have_visible_ascii_other_than_quote_and_backslash() {
        for scope in ["", " ", "a b", "a\"b", "a\\b", "\u{e9}", "a\tb", "a\u{7f}"] {
            assert!(
                matches!(request(&[scope], &[]), Err(ConfigError::InvalidScope(s)) if s == scope),
                "{scope:?}"
            );
        }
        assert!(request(&["!#[]~"], &[]).is_ok());
    }

    #[test]
    fn test_a_parameter_needs_a_name() {
        assert!(matches!(
            request(&[], &[("", "x")]),
            Err(ConfigError::EmptyParameterName)
        ));
    }

    #[test]
    fn test_debug_shows_parameter_names_only() {
        let debug = format!("{:?}", request(&[], &[("audience", "SECRET")]).unwrap());
        assert!(debug.contains("audience"), "{debug}");
        assert!(!debug.contains("SECRET"), "{debug}");
    }

    #[test]
    fn test_retry_after_in_seconds() {
        let mut headers = HeaderMap::new();
        assert_eq!(retry_after(&headers), None);
        headers.insert(header::RETRY_AFTER, HeaderValue::from_static("120"));
        assert_eq!(retry_after(&headers), Some(Duration::from_secs(120)));
        headers.insert(
            header::RETRY_AFTER,
            HeaderValue::from_static("Wed, 21 Oct 2026 07:28:00 GMT"),
        );
        assert_eq!(retry_after(&headers), None);
        headers.insert(header::RETRY_AFTER, HeaderValue::from_static("-1"));
        assert_eq!(retry_after(&headers), None);
    }
}
