//! The client of the token endpoint: one form POST per token request (RFC 6749, sections 2.3.1, 4.4 and 5).

mod response;

use std::{fmt, sync::Arc, time::Duration};

use http::{HeaderMap, HeaderValue, StatusCode, header};
pub(crate) use response::{MAX_EXPIRES_IN, TokenResponse, TokenValue};
use url::Url;

use crate::{
    assertion::{Assertion, AssertionContext, AssertionSource},
    error::{ConfigError, Error, InvalidResponse, ResponseProblem, SourceError, TransportError},
};

/// The largest answer middle reads from a token endpoint, in bytes.
pub(crate) const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// The longest `Retry-After` middle reports, so that adding it to an instant cannot overflow.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(24 * 60 * 60);

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

/// The `client_assertion_type` of a JWT client assertion (RFC 7523, section 2.2).
const JWT_BEARER_CLIENT_ASSERTION: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// The `grant_type` of the JWT bearer grant (RFC 7523, section 2.1).
const JWT_BEARER_GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// The grant of a token request.
#[derive(Clone, Debug)]
pub(crate) enum Grant {
    /// The client credentials grant (RFC 6749, section 4.4).
    ClientCredentials,
    /// The JWT bearer grant (RFC 7523, section 2.1): an assertion from the source is the grant.
    JwtBearer(Arc<dyn AssertionSource>),
}

/// How the client authenticates at the token endpoint.
#[derive(Clone, Debug)]
pub(crate) enum ClientAuth {
    /// HTTP Basic with the client id and secret, each form-urlencoded first (RFC 6749, section 2.3.1).
    SecretBasic { client_id: String, secret: Secret },
    /// The client id and secret as the form parameters `client_id` and `client_secret` (RFC 6749, section 2.3.1; OAuth 2.1 draft, section 2.4.1).
    SecretPost { client_id: String, secret: Secret },
    /// An assertion from `source` as the form parameter `client_assertion`, with `client_id` unless `send_client_id` is false (RFC 7521, section 4.2; RFC 7523, section 2.2).
    Assertion {
        client_id: String,
        source: Arc<dyn AssertionSource>,
        send_client_id: bool,
    },
}

impl ClientAuth {
    fn client_id(&self) -> &str {
        match self {
            Self::SecretBasic { client_id, .. }
            | Self::SecretPost { client_id, .. }
            | Self::Assertion { client_id, .. } => client_id,
        }
    }
}

/// Checks the token URL: `https`, or `http` with a loopback host or `allow_http`; no fragment (RFC 6749, section 3.2) and no user name or password.
fn check_token_url(url: &Url, allow_http: bool) -> Result<(), ConfigError> {
    match url.scheme() {
        "https" => {}
        "http" if allow_http || is_loopback(url) => {}
        "http" => {
            return Err(ConfigError::HttpTokenUrl(
                url.host_str().unwrap_or_default().to_string(),
            ));
        }
        scheme => return Err(ConfigError::TokenUrlScheme(scheme.to_string())),
    }
    if url.fragment().is_some() {
        return Err(ConfigError::TokenUrlWithFragment);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ConfigError::TokenUrlWithUserInfo);
    }
    Ok(())
}

/// Whether the host of the URL is `localhost` or a loopback address: `127.0.0.0/8` or `::1`. The url crate writes domains in lower case.
fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(domain)) => domain == "localhost",
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        None => false,
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

/// A checked token request, sent again for every token.
#[derive(Clone)]
pub(crate) struct TokenRequest {
    url: Url,
    grant: Grant,
    client_auth: Option<ClientAuth>,
    scopes: Vec<Scope>,
    params: Vec<(String, String)>,
}

/// The grant parameters of one request, with a new assertion for [`Grant::JwtBearer`].
enum GrantForm {
    ClientCredentials,
    JwtBearer(Assertion),
}

/// The client credentials in the form body of one request, with a new assertion for [`ClientAuth::Assertion`].
enum ClientForm<'a> {
    /// No client authentication, or the client credentials are in the `Authorization` header.
    None,
    Secret {
        client_id: &'a str,
        secret: &'a Secret,
    },
    Assertion {
        client_id: Option<&'a str>,
        assertion: Assertion,
    },
}

impl TokenRequest {
    /// Checks the token URL, the scopes and the extra form parameters. `allow_http` allows an `http` token URL with any host.
    pub(crate) fn new(
        url: Url,
        grant: Grant,
        client_auth: Option<ClientAuth>,
        scopes: &[String],
        params: impl IntoIterator<Item = (String, String)>,
        allow_http: bool,
    ) -> Result<Self, ConfigError> {
        check_token_url(&url, allow_http)?;
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
            grant,
            client_auth,
            scopes,
            params,
        })
    }

    /// Names the client in log messages: the client id, or the token URL without user name, password and query if the client does not authenticate.
    pub(crate) fn log_name(&self) -> String {
        self.client_auth.as_ref().map_or_else(
            || redacted_url(&self.url).to_string(),
            |client_auth| client_auth.client_id().to_string(),
        )
    }

    /// Whether the host of the token URL is `localhost` or a loopback address.
    pub(crate) fn has_loopback_host(&self) -> bool {
        is_loopback(&self.url)
    }

    /// The form body, with a new assertion for the JWT bearer grant and for a client assertion.
    async fn form(&self) -> Result<String, SourceError> {
        let mut context = AssertionContext::new(self.url.clone());
        if let Some(client_auth) = &self.client_auth {
            context = context.with_client_id(client_auth.client_id());
        }
        let grant = match &self.grant {
            Grant::ClientCredentials => GrantForm::ClientCredentials,
            Grant::JwtBearer(source) => GrantForm::JwtBearer(source.assertion(&context).await?),
        };
        let client = match &self.client_auth {
            None | Some(ClientAuth::SecretBasic { .. }) => ClientForm::None,
            Some(ClientAuth::SecretPost { client_id, secret }) => {
                ClientForm::Secret { client_id, secret }
            }
            Some(ClientAuth::Assertion {
                client_id,
                source,
                send_client_id,
            }) => ClientForm::Assertion {
                client_id: send_client_id.then_some(client_id.as_str()),
                assertion: source.assertion(&context).await?,
            },
        };
        Ok(self.encode_form(&grant, &client))
    }

    /// The form body: the grant, the client credentials in the body, `scope`, then the extra parameters.
    fn encode_form(&self, grant: &GrantForm, client: &ClientForm<'_>) -> String {
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        match grant {
            GrantForm::ClientCredentials => {
                form.append_pair("grant_type", "client_credentials");
            }
            GrantForm::JwtBearer(assertion) => {
                form.append_pair("grant_type", JWT_BEARER_GRANT);
                form.append_pair("assertion", assertion.as_str());
            }
        }
        match client {
            ClientForm::None => {}
            ClientForm::Secret { client_id, secret } => {
                form.append_pair("client_id", client_id);
                form.append_pair("client_secret", secret.expose());
            }
            ClientForm::Assertion {
                client_id,
                assertion,
            } => {
                if let Some(client_id) = client_id {
                    form.append_pair("client_id", client_id);
                }
                form.append_pair("client_assertion_type", JWT_BEARER_CLIENT_ASSERTION);
                form.append_pair("client_assertion", assertion.as_str());
            }
        }
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
            .field("url", &redacted_url(&self.url).as_str())
            .field("grant", &self.grant)
            .field("client_auth", &self.client_auth)
            .field("scopes", &self.scopes)
            .field("param_names", &param_names)
            .finish()
    }
}

/// Asks the token endpoint for a token once, with new assertions for the JWT bearer grant and for a client assertion. The caller bounds the request with a timeout.
pub(crate) async fn request_token(
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
        .body(request.form().await?);
    if let Some(ClientAuth::SecretBasic { client_id, secret }) = &request.client_auth {
        // reqwest Base64-encodes `id:secret` and marks the header sensitive.
        builder = builder.basic_auth(
            form_urlencode(client_id),
            Some(form_urlencode(secret.expose())),
        );
    }
    let response = builder
        .send()
        .await
        .map_err(|error| transport_error(error, &request.url))?;

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
    let body = match read_body(response).await {
        Ok(body) => body,
        // The status of a rejection decides, also when its body breaks off.
        Err(_) if meta.status != StatusCode::OK => return Err(meta.http_error()),
        Err(error) => return Err(transport_error(error, &request.url)),
    };
    response::parse(meta, body.as_deref())
}

/// Reads the body, or `None` if it is larger than [`MAX_RESPONSE_BYTES`].
async fn read_body(mut response: reqwest::Response) -> Result<Option<Vec<u8>>, reqwest::Error> {
    let limit = u64::try_from(MAX_RESPONSE_BYTES).unwrap_or(u64::MAX);
    if response
        .content_length()
        .is_some_and(|length| length > limit)
    {
        return Ok(None);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Ok(None);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Some(body))
}

/// The URL without user info and query, which can hold credentials, for `Debug` output and errors.
pub(crate) fn redacted_url(url: &Url) -> Url {
    let mut url = url.clone();
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url
}

/// A transport error that names the token URL without its query.
fn transport_error(error: reqwest::Error, url: &Url) -> Error {
    TransportError::from(error.with_url(redacted_url(url))).into()
}

fn form_urlencode(text: &str) -> String {
    url::form_urlencoded::byte_serialize(text.as_bytes()).collect()
}

/// The `Retry-After` header in seconds, at most [`MAX_RETRY_AFTER`]. An HTTP date gives `None`.
fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    let value = headers.get(header::RETRY_AFTER)?.to_str().ok()?.trim();
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let seconds = value.parse().unwrap_or(u64::MAX);
    Some(Duration::from_secs(seconds).min(MAX_RETRY_AFTER))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(scopes: &[&str], params: &[(&str, &str)]) -> Result<TokenRequest, ConfigError> {
        TokenRequest::new(
            "https://idp.example.com/token".parse().unwrap(),
            Grant::ClientCredentials,
            Some(ClientAuth::SecretBasic {
                client_id: "c".to_string(),
                secret: Secret::new("s"),
            }),
            &scopes.iter().map(ToString::to_string).collect::<Vec<_>>(),
            params
                .iter()
                .map(|(name, value)| ((*name).to_string(), (*value).to_string())),
            false,
        )
    }

    #[test]
    fn test_the_log_name_is_the_client_id_or_the_token_url_without_its_query() {
        let url: Url = "https://idp.example.com/token?key=SECRET".parse().unwrap();
        let without_client =
            TokenRequest::new(url.clone(), Grant::ClientCredentials, None, &[], [], false).unwrap();
        let with_client = TokenRequest::new(
            url,
            Grant::ClientCredentials,
            Some(ClientAuth::SecretBasic {
                client_id: "my-client".to_string(),
                secret: Secret::new("s"),
            }),
            &[],
            [],
            false,
        )
        .unwrap();

        assert_eq!(without_client.log_name(), "https://idp.example.com/token");
        assert_eq!(with_client.log_name(), "my-client");
    }

    fn check_url(url: &str, allow_http: bool) -> Result<(), ConfigError> {
        check_token_url(&url.parse().unwrap(), allow_http)
    }

    #[test]
    fn test_http_is_allowed_for_loopback_hosts() {
        for url in [
            "http://localhost/token",
            "http://LOCALHOST:8080/token",
            "http://127.0.0.1/token",
            "http://127.255.0.9/token",
            "http://[::1]:8080/token",
            "https://idp.example.com/token",
        ] {
            assert!(check_url(url, false).is_ok(), "{url}");
        }
    }

    #[test]
    fn test_http_with_another_host_needs_danger_allow_http() {
        for (url, host) in [
            ("http://idp.example.com/token", "idp.example.com"),
            (
                "http://localhost.example.com/token",
                "localhost.example.com",
            ),
            ("http://localhost./token", "localhost."),
            ("http://10.0.0.1/token", "10.0.0.1"),
            ("http://0.0.0.0/token", "0.0.0.0"),
            ("http://[::2]/token", "[::2]"),
            // An IPv4-mapped IPv6 address is not a loopback address.
            ("http://[::ffff:127.0.0.1]/token", "[::ffff:7f00:1]"),
        ] {
            assert!(
                matches!(check_url(url, false), Err(ConfigError::HttpTokenUrl(h)) if h == host),
                "{url}"
            );
            assert!(check_url(url, true).is_ok(), "{url}");
        }
    }

    #[test]
    fn test_danger_allow_http_keeps_the_other_checks() {
        assert!(matches!(
            check_url("ftp://idp.example.com/token", true),
            Err(ConfigError::TokenUrlScheme(scheme)) if scheme == "ftp"
        ));
        assert!(matches!(
            check_url("http://idp.example.com/token#part", true),
            Err(ConfigError::TokenUrlWithFragment)
        ));
        assert!(matches!(
            check_url("http://user:password@idp.example.com/token", true),
            Err(ConfigError::TokenUrlWithUserInfo)
        ));
    }

    #[test]
    fn test_a_request_without_scopes_sends_no_scope() {
        assert_eq!(
            request(&[], &[])
                .unwrap()
                .encode_form(&GrantForm::ClientCredentials, &ClientForm::None),
            "grant_type=client_credentials"
        );
    }

    #[test]
    fn test_scopes_are_joined_with_a_space() {
        assert_eq!(
            request(&["a", "b:c", "https://api.example.com/.default"], &[])
                .unwrap()
                .encode_form(&GrantForm::ClientCredentials, &ClientForm::None),
            "grant_type=client_credentials&scope=a+b%3Ac+https%3A%2F%2Fapi.example.com%2F.default"
        );
    }

    #[test]
    fn test_a_parameter_name_may_repeat() {
        assert_eq!(
            request(&[], &[("resource", "a"), ("resource", "b")])
                .unwrap()
                .encode_form(&GrantForm::ClientCredentials, &ClientForm::None),
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

    #[test]
    fn test_retry_after_is_at_most_one_day() {
        let mut headers = HeaderMap::new();
        for value in ["86400", "86401", "99999999999999999999"] {
            headers.insert(header::RETRY_AFTER, HeaderValue::from_static(value));
            assert_eq!(
                retry_after(&headers),
                Some(Duration::from_secs(86400)),
                "{value}"
            );
        }
    }
}
