//! Token exchange (RFC 8693) with a `TokenEndpoint`: one request per call, with the subject token of the caller.

mod support;

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http::StatusCode;
use middle::{
    Assertion, AssertionContext, AssertionSource, Authorizer, ClientAuthentication, ConfigError,
    Error, ErrorCode, ExchangeRequest, IssuedToken, ResponseProblem, SourceError, TokenEndpoint,
    TokenEndpointBuilder,
};
use serde_json::json;
use support::{FakeIdp, Reply};

const TOKEN_EXCHANGE_GRANT: &str = "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange";
const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
const ACCESS_TOKEN_TYPE_FORM: &str = "urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token";
const REFRESH_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:refresh_token";
const JWT_BEARER_CLIENT_ASSERTION: &str =
    "urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer";
/// 2001-09-09, long past.
const PAST: u64 = 1_000_000_000;
const ONE_YEAR: Duration = Duration::from_secs(365 * 24 * 60 * 60);

/// An endpoint that authenticates the client with `client_secret_basic`.
fn endpoint(token_url: url::Url) -> TokenEndpoint {
    TokenEndpoint::builder(token_url)
        .client_authentication(ClientAuthentication::client_secret_basic("my-client", "s"))
        .build()
        .unwrap()
}

/// An exchange of an access token.
fn request(subject_token: &str) -> ExchangeRequest {
    ExchangeRequest::new(subject_token, ACCESS_TOKEN_TYPE)
}

/// An unsigned JWT with this `exp`.
fn jwt(exp: u64) -> String {
    let encode = |json: serde_json::Value| URL_SAFE_NO_PAD.encode(json.to_string());
    format!(
        "{}.{}.c2lnbmF0dXJl",
        encode(json!({"alg": "RS256", "typ": "JWT"})),
        encode(json!({"sub": "user-1", "exp": exp})),
    )
}

/// A token exchange answer with status 200.
fn answer(body: &serde_json::Value) -> Reply {
    Reply::json(200, body.to_string())
}

/// Starts an identity provider that answers every request with `reply`, and exchanges `subject_token` once.
async fn exchange_once(reply: Reply, subject_token: &str) -> (Result<IssuedToken, Error>, FakeIdp) {
    let idp = FakeIdp::start(move |_| reply.clone()).await;
    let result = endpoint(idp.token_url())
        .exchange(&request(subject_token))
        .await;
    (result, idp)
}

fn invalid_response(error: &Error) -> &ResponseProblem {
    match error {
        Error::InvalidResponse(invalid) => invalid.problem(),
        other => panic!("expected an invalid response, got {other:?}"),
    }
}

/// Hands out `<prefix>.cGF5bG9hZA.c2lnbmF0dXJl1`, `…2`, and so on, and records the client id of each call.
#[derive(Debug, Clone)]
struct CountingSource {
    prefix: &'static str,
    client_ids: Arc<Mutex<Vec<Option<String>>>>,
}

impl CountingSource {
    fn new(prefix: &'static str) -> Self {
        Self {
            prefix,
            client_ids: Arc::default(),
        }
    }

    fn assertion(&self, number: usize) -> String {
        format!("{}.cGF5bG9hZA.c2lnbmF0dXJl{number}", self.prefix)
    }

    fn client_ids(&self) -> Vec<Option<String>> {
        self.client_ids.lock().unwrap().clone()
    }
}

impl AssertionSource for CountingSource {
    async fn assertion(&self, context: &AssertionContext) -> Result<Assertion, SourceError> {
        let number = {
            let mut client_ids = self.client_ids.lock().unwrap();
            client_ids.push(context.client_id().map(str::to_string));
            client_ids.len()
        };
        Assertion::new(self.assertion(number))
    }
}

/// A source that never answers.
#[derive(Debug)]
struct HangingSource;

impl AssertionSource for HangingSource {
    async fn assertion(&self, _context: &AssertionContext) -> Result<Assertion, SourceError> {
        std::future::pending().await
    }
}

#[tokio::test]
async fn test_the_form_holds_the_grant_the_subject_the_scope_and_the_appended_parameters() {
    let idp = FakeIdp::start(|_| Reply::token("issued-token", Some(900))).await;

    let issued = endpoint(idp.token_url())
        .exchange(
            &request("subject.token+1")
                .add_scope("read")
                .add_scope("write")
                // RFC 8707, section 2: one `resource` parameter for each resource.
                .append_param("resource", "https://a.example.com")
                .append_param("resource", "https://b.example.com")
                .append_param("audience", "api")
                .append_param("requested_token_type", ACCESS_TOKEN_TYPE),
        )
        .await
        .unwrap();

    let requests = idp.requests();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/token");
    assert_eq!(
        request.header("content-type"),
        Some("application/x-www-form-urlencoded")
    );
    assert_eq!(request.header("accept"), Some("application/json"));
    assert_eq!(
        request.header_all("authorization"),
        vec!["Basic bXktY2xpZW50OnM="]
    );
    assert_eq!(
        request.body,
        format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&subject_token=subject.token%2B1&subject_token_type={ACCESS_TOKEN_TYPE_FORM}&scope=read+write&resource=https%3A%2F%2Fa.example.com&resource=https%3A%2F%2Fb.example.com&audience=api&requested_token_type={ACCESS_TOKEN_TYPE_FORM}"
        )
    );
    assert_eq!(issued.access_token(), "issued-token");
    assert!(issued.is_bearer());
}

#[tokio::test]
async fn test_an_empty_scope_is_skipped() {
    let idp = FakeIdp::start(|_| Reply::token("t", Some(900))).await;

    endpoint(idp.token_url())
        .exchange(&request("s").add_scope("").add_scope("read"))
        .await
        .unwrap();

    assert_eq!(
        idp.requests()[0].body,
        format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&subject_token=s&subject_token_type={ACCESS_TOKEN_TYPE_FORM}&scope=read"
        )
    );
}

#[tokio::test]
async fn test_an_exchange_can_authenticate_the_client_with_post() {
    let idp = FakeIdp::start(|_| Reply::token("t", Some(900))).await;

    TokenEndpoint::builder(idp.token_url())
        .client_authentication(ClientAuthentication::client_secret_post(
            "my client",
            "s3cr3t/+~:",
        ))
        .build()
        .unwrap()
        .exchange(&request("s").add_scope("read"))
        .await
        .unwrap();

    let request = &idp.requests()[0];
    assert_eq!(request.header_all("authorization"), Vec::<&str>::new());
    assert_eq!(
        request.body,
        format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&subject_token=s&subject_token_type={ACCESS_TOKEN_TYPE_FORM}&client_id=my+client&client_secret=s3cr3t%2F%2B%7E%3A&scope=read"
        )
    );
}

#[tokio::test]
async fn test_an_exchange_without_client_authentication_sends_no_client_credentials() {
    let idp = FakeIdp::start(|_| Reply::token("t", Some(900))).await;

    TokenEndpoint::builder(idp.token_url())
        .build()
        .unwrap()
        .exchange(&request("s"))
        .await
        .unwrap();

    let request = &idp.requests()[0];
    assert_eq!(request.header_all("authorization"), Vec::<&str>::new());
    assert_eq!(
        request.body,
        format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&subject_token=s&subject_token_type={ACCESS_TOKEN_TYPE_FORM}"
        )
    );
}

#[tokio::test]
async fn test_each_exchange_gets_a_new_client_assertion() {
    let idp = FakeIdp::start(|_| Reply::token("t", Some(900))).await;
    let client = CountingSource::new("Y2xpZW50");
    let endpoint = TokenEndpoint::builder(idp.token_url())
        .client_authentication(ClientAuthentication::client_assertion(
            "my-client",
            client.clone(),
        ))
        .build()
        .unwrap();

    endpoint.exchange(&request("s")).await.unwrap();
    endpoint.exchange(&request("s")).await.unwrap();

    let bodies: Vec<String> = idp.requests().into_iter().map(|r| r.body).collect();
    let expected = |number| {
        format!(
            "grant_type={TOKEN_EXCHANGE_GRANT}&subject_token=s&subject_token_type={ACCESS_TOKEN_TYPE_FORM}&client_id=my-client&client_assertion_type={JWT_BEARER_CLIENT_ASSERTION}&client_assertion={}",
            client.assertion(number)
        )
    };
    assert_eq!(bodies, vec![expected(1), expected(2)]);
    assert_eq!(
        client.client_ids(),
        vec![Some("my-client".to_string()), Some("my-client".to_string())]
    );
    assert_eq!(
        idp.requests()[0].header_all("authorization"),
        Vec::<&str>::new()
    );
}

#[tokio::test]
async fn test_a_parameter_middle_reserves_is_refused_before_any_request() {
    let idp = FakeIdp::start(|_| Reply::token("t", Some(900))).await;
    let endpoint = endpoint(idp.token_url());

    for name in [
        "grant_type",
        "scope",
        "client_id",
        "client_secret",
        "client_assertion",
        "client_assertion_type",
        "assertion",
        "subject_token",
        "subject_token_type",
        "actor_token",
        "actor_token_type",
    ] {
        let error = endpoint
            .exchange(&request("s").append_param(name, "value"))
            .await
            .expect_err("middle reserves this parameter");

        assert!(
            matches!(&error, Error::Config(ConfigError::ReservedParameter(reserved)) if reserved == name),
            "{error:?}"
        );
    }
    assert_eq!(idp.count(), 0);
}

#[tokio::test]
async fn test_an_empty_parameter_name_and_an_invalid_scope_are_refused_before_any_request() {
    let idp = FakeIdp::start(|_| Reply::token("t", Some(900))).await;
    let endpoint = endpoint(idp.token_url());

    let error = endpoint
        .exchange(&request("s").append_param("", "value"))
        .await
        .expect_err("a parameter needs a name");
    assert!(
        matches!(error, Error::Config(ConfigError::EmptyParameterName)),
        "{error:?}"
    );

    let error = endpoint
        .exchange(&request("s").add_scope("read write"))
        .await
        .expect_err("one scope cannot contain a space");
    assert!(
        matches!(&error, Error::Config(ConfigError::InvalidScope(scope)) if scope == "read write"),
        "{error:?}"
    );

    assert_eq!(idp.count(), 0);
}

#[tokio::test]
async fn test_an_n_a_token_is_accepted_and_is_not_a_bearer_token() {
    let reply = answer(&json!({
        "access_token": "issued-refresh-token",
        "token_type": "N_A",
        "issued_token_type": REFRESH_TOKEN_TYPE,
    }));

    let (issued, _) = exchange_once(reply, "s").await;

    let issued = issued.unwrap();
    assert_eq!(issued.access_token(), "issued-refresh-token");
    assert!(!issued.is_bearer());
    assert_eq!(issued.issued_token_type(), Some(REFRESH_TOKEN_TYPE));
}

#[tokio::test]
async fn test_another_token_type_is_refused() {
    let reply = answer(&json!({"access_token": "t", "token_type": "DPoP", "expires_in": 900}));

    let (error, idp) = exchange_once(reply, "s").await;

    let error = error.expect_err("middle accepts Bearer and N_A");
    assert_eq!(
        invalid_response(&error),
        &ResponseProblem::UnsupportedTokenType("DPoP".to_string())
    );
    assert!(!error.is_retryable());
    assert_eq!(idp.count(), 1);
}

#[tokio::test]
async fn test_an_authorizer_still_refuses_an_n_a_token() {
    let reply = answer(&json!({"access_token": "t", "token_type": "N_A", "expires_in": 900}));
    let idp = FakeIdp::start(move |_| reply.clone()).await;

    let error = Authorizer::client_credentials(
        idp.token_url(),
        ClientAuthentication::client_secret_basic("my-client", "s"),
    )
    .max_retries(0)
    .build()
    .await
    .expect_err("an authorizer sends its token as Bearer");

    assert_eq!(
        invalid_response(&error),
        &ResponseProblem::UnsupportedTokenType("N_A".to_string())
    );
}

#[tokio::test]
async fn test_an_expires_in_of_zero_gives_no_lifetime() {
    let (issued, _) = exchange_once(Reply::token("t", Some(0)), "s").await;

    let issued = issued.unwrap();
    assert_eq!(issued.lifetime(), Duration::ZERO);
    assert_eq!(issued.expires_in(), Some(Duration::ZERO));
}

#[tokio::test]
async fn test_an_answer_without_issued_token_type_is_accepted() {
    // A member that is `null` counts as missing.
    for reply in [
        Reply::token("t", Some(900)),
        answer(&json!({
            "access_token": "t",
            "token_type": "Bearer",
            "expires_in": 900,
            "issued_token_type": null,
            "refresh_token": null,
            "scope": null,
        })),
    ] {
        let (issued, _) = exchange_once(reply, "s").await;

        let issued = issued.unwrap();
        assert_eq!(issued.access_token(), "t");
        assert!(issued.is_bearer());
        assert_eq!(issued.lifetime(), Duration::from_secs(900));
        assert_eq!(issued.expires_in(), Some(Duration::from_secs(900)));
        assert_eq!(issued.issued_token_type(), None);
        assert_eq!(issued.refresh_token(), None);
        assert_eq!(issued.scope(), None);
    }
}

#[tokio::test]
async fn test_the_issued_token_type_the_refresh_token_and_the_scope_are_exposed() {
    let reply = answer(&json!({
        "access_token": "t",
        "token_type": "Bearer",
        "expires_in": 900,
        "issued_token_type": ACCESS_TOKEN_TYPE,
        "refresh_token": "issued-refresh-token",
        "scope": "read",
    }));

    let (issued, _) = exchange_once(reply, "s").await;

    let issued = issued.unwrap();
    assert_eq!(issued.issued_token_type(), Some(ACCESS_TOKEN_TYPE));
    assert_eq!(issued.refresh_token(), Some("issued-refresh-token"));
    assert_eq!(issued.scope(), Some("read"));
}

#[tokio::test]
async fn test_a_subject_whose_exp_has_passed_leaves_no_lifetime_and_keeps_expires_in() {
    let (issued, idp) = exchange_once(Reply::token("t", Some(900)), &jwt(PAST)).await;

    // middle sends the subject and leaves its check to the server.
    assert_eq!(idp.count(), 1);
    let issued = issued.unwrap();
    assert_eq!(issued.lifetime(), Duration::ZERO);
    assert_eq!(issued.expires_in(), Some(Duration::from_secs(900)));
}

#[tokio::test]
async fn test_without_expires_in_and_without_a_jwt_the_lifetime_is_the_default_token_lifetime() {
    let idp = FakeIdp::start(|_| Reply::token("opaque-token", None)).await;
    let exchange = async |builder: TokenEndpointBuilder| {
        builder
            .build()
            .unwrap()
            .exchange(&request("opaque-subject"))
            .await
            .unwrap()
    };
    let lifetime = async |builder: TokenEndpointBuilder| exchange(builder).await.lifetime();
    let builder = TokenEndpoint::builder(idp.token_url());

    // 5 minutes, as for an authorizer.
    let issued = exchange(builder.clone()).await;
    assert_eq!(issued.lifetime(), Duration::from_secs(300));
    assert_eq!(issued.expires_in(), None);
    assert_eq!(
        lifetime(
            builder
                .clone()
                .default_token_lifetime(Duration::from_secs(120))
        )
        .await,
        Duration::from_secs(120)
    );
    assert_eq!(
        lifetime(builder.clone().default_token_lifetime(Duration::MAX)).await,
        ONE_YEAR
    );
    // An endpoint has no refresh, so a default of 0 works.
    assert_eq!(
        lifetime(builder.default_token_lifetime(Duration::ZERO)).await,
        Duration::ZERO
    );
}

#[tokio::test]
async fn test_a_503_is_retryable_and_not_retried() {
    let reply = Reply::text(503, "text/html", "<html>upstream unavailable</html>");

    let (error, idp) = exchange_once(reply, "s").await;

    let error = error.expect_err("the server is down");
    assert!(
        matches!(&error, Error::Http(http) if http.status() == StatusCode::SERVICE_UNAVAILABLE),
        "{error:?}"
    );
    assert!(error.is_retryable());
    assert_eq!(error.oauth_code(), None);
    assert_eq!(idp.count(), 1);
}

#[tokio::test]
async fn test_a_server_error_is_retryable_and_not_retried() {
    let reply = Reply::oauth_error(400, "server_error", "try again");

    let (error, idp) = exchange_once(reply, "s").await;

    let error = error.expect_err("the server failed");
    assert_eq!(error.oauth_code(), Some(&ErrorCode::ServerError));
    assert!(error.is_retryable());
    assert_eq!(idp.count(), 1);
}

#[tokio::test]
async fn test_the_oauth_code_tells_a_refused_subject_from_a_refused_client() {
    let (error, _) = exchange_once(
        Reply::oauth_error(400, "invalid_grant", "subject token expired"),
        "s",
    )
    .await;
    let error = error.expect_err("the server refuses the subject");
    assert_eq!(error.oauth_code(), Some(&ErrorCode::InvalidGrant));
    assert_eq!(error.status(), Some(StatusCode::BAD_REQUEST));
    assert!(!error.is_retryable());

    let (error, _) = exchange_once(
        Reply::oauth_error(401, "invalid_client", "unknown client"),
        "s",
    )
    .await;
    let error = error.expect_err("the server refuses the client");
    assert_eq!(error.oauth_code(), Some(&ErrorCode::InvalidClient));
    assert!(!error.is_retryable());
}

#[tokio::test]
async fn test_an_exchange_without_an_answer_times_out() {
    let idp = FakeIdp::start(|_| Reply::Hang).await;
    let endpoint = TokenEndpoint::builder(idp.token_url())
        .timeout(Duration::from_millis(200))
        .build()
        .unwrap();

    let error = tokio::time::timeout(Duration::from_secs(5), endpoint.exchange(&request("s")))
        .await
        .expect("the exchange gives up on its own")
        .expect_err("the token endpoint never answers");

    assert!(
        matches!(error, Error::Timeout(timeout) if timeout == Duration::from_millis(200)),
        "{error:?}"
    );
    assert!(error.is_retryable());
}

#[tokio::test]
async fn test_a_client_assertion_that_does_not_answer_is_bounded_by_the_timeout() {
    let idp = FakeIdp::start(|_| Reply::token("t", Some(900))).await;
    let endpoint = TokenEndpoint::builder(idp.token_url())
        .client_authentication(ClientAuthentication::client_assertion(
            "my-client",
            HangingSource,
        ))
        .timeout(Duration::from_millis(200))
        .build()
        .unwrap();

    let error = tokio::time::timeout(Duration::from_secs(5), endpoint.exchange(&request("s")))
        .await
        .expect("the exchange gives up on its own")
        .expect_err("the source never answers");

    assert!(
        matches!(error, Error::Timeout(timeout) if timeout == Duration::from_millis(200)),
        "{error:?}"
    );
    assert_eq!(idp.count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_concurrent_exchanges_in_spawned_tasks_each_send_their_own_request() {
    let idp = FakeIdp::start(|number| Reply::token(&format!("t{number}"), Some(900))).await;
    let endpoint = endpoint(idp.token_url());
    let request = request("same-subject");

    // `tokio::spawn` needs a future that is `Send` and `'static`.
    let tasks: Vec<_> = (0..8)
        .map(|_| {
            let endpoint = endpoint.clone();
            let request = request.clone();
            tokio::spawn(async move { endpoint.exchange(&request).await })
        })
        .collect();
    let mut tokens = Vec::new();
    for task in tasks {
        tokens.push(task.await.unwrap().unwrap().access_token().to_string());
    }

    tokens.sort();
    assert_eq!(tokens, ["t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8"]);
    assert_eq!(idp.count(), 8);
}

#[test]
fn test_the_builder_checks_the_token_url() {
    for (url, check) in [
        (
            "http://idp.example.com/token",
            (|error: &ConfigError| matches!(error, ConfigError::HttpTokenUrl(host) if host == "idp.example.com"))
                as fn(&ConfigError) -> bool,
        ),
        ("https://idp.example.com/token#part", |error| {
            matches!(error, ConfigError::TokenUrlWithFragment)
        }),
        ("https://user:password@idp.example.com/token", |error| {
            matches!(error, ConfigError::TokenUrlWithUserInfo)
        }),
        (
            "ftp://idp.example.com/token",
            |error| matches!(error, ConfigError::TokenUrlScheme(scheme) if scheme == "ftp"),
        ),
    ] {
        let error = TokenEndpoint::builder(url.parse().unwrap())
            .build()
            .expect_err("the token URL is not valid");
        assert!(check(&error), "{url}: {error:?}");
    }
}

#[tokio::test]
async fn test_danger_allow_http_allows_an_http_token_url_with_any_host() {
    let idp = FakeIdp::start(|_| Reply::token("t", Some(900))).await;
    let address = idp.token_url().socket_addrs(|| None).unwrap()[0];
    // The HTTP client of the application resolves `idp.example.com` to the fake token endpoint.
    let http_client = reqwest::Client::builder()
        .resolve("idp.example.com", address)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .unwrap();
    let host = format!("idp.example.com:{}", address.port());
    let builder = TokenEndpoint::builder(format!("http://{host}/token").parse().unwrap())
        .danger_http_client(http_client);

    let error = builder
        .clone()
        .danger_allow_http(false)
        .build()
        .expect_err("http with another host needs danger_allow_http");
    assert!(
        matches!(&error, ConfigError::HttpTokenUrl(h) if h == "idp.example.com"),
        "{error:?}"
    );

    let endpoint = builder.danger_allow_http(true).build().unwrap();
    let issued = endpoint.exchange(&request("s")).await.unwrap();
    assert_eq!(issued.access_token(), "t");
    assert_eq!(idp.count(), 1);
    assert_eq!(idp.requests()[0].header("host"), Some(host.as_str()));
}

#[tokio::test]
async fn test_a_client_of_the_application_is_used_as_it_is() {
    let idp = FakeIdp::start(|_| Reply::token("t", Some(900))).await;
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert("x-api-key", "SECRET-HEADER".parse().unwrap());
    let http_client = reqwest::Client::builder()
        .default_headers(headers)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .unwrap();
    let builder = TokenEndpoint::builder(idp.token_url()).danger_http_client(http_client);
    let builder_debug = format!("{builder:?}");
    let endpoint = builder.build().unwrap();

    endpoint.exchange(&request("s")).await.unwrap();

    assert_eq!(idp.requests()[0].header("x-api-key"), Some("SECRET-HEADER"));
    // A client of the application may carry secrets in its default headers.
    assert!(builder_debug.contains("custom"), "{builder_debug}");
    for debug in [builder_debug, format!("{endpoint:?}")] {
        assert!(!debug.contains("SECRET"), "{debug}");
    }
}

#[tokio::test]
async fn test_redirects_are_not_followed() {
    let target = FakeIdp::start(|_| Reply::token("t", Some(900))).await;
    let location = target.token_url().to_string();
    let reply = Reply::text(307, "text/plain", "moved").with_header("location", &location);

    let (error, _) = exchange_once(reply, "s").await;

    let error = error.expect_err("a redirect is not a token");
    assert!(
        matches!(&error, Error::Http(http) if http.status() == StatusCode::TEMPORARY_REDIRECT),
        "{error:?}"
    );
    assert_eq!(target.count(), 0);
}

#[tokio::test]
async fn test_debug_output_shows_no_token_and_no_secret() {
    let reply = answer(&json!({
        "access_token": "SECRET-ACCESS-TOKEN",
        "token_type": "Bearer",
        "expires_in": 900,
        "issued_token_type": ACCESS_TOKEN_TYPE,
        "refresh_token": "SECRET-REFRESH-TOKEN",
        "scope": "read",
    }));
    let idp = FakeIdp::start(move |_| reply.clone()).await;
    let mut token_url = idp.token_url();
    token_url.set_query(Some("key=SECRET-QUERY"));
    let builder = TokenEndpoint::builder(token_url).client_authentication(
        ClientAuthentication::client_secret_basic("my-client", "SECRET-CLIENT-SECRET"),
    );
    let endpoint = builder.clone().build().unwrap();
    let request = ExchangeRequest::new("SECRET-SUBJECT-TOKEN", ACCESS_TOKEN_TYPE)
        .add_scope("read")
        .append_param("audience", "SECRET-PARAMETER-VALUE");

    let issued = endpoint.exchange(&request).await.unwrap();

    for debug in [format!("{builder:?}"), format!("{endpoint:?}")] {
        assert!(debug.contains("my-client"), "{debug}");
        // The default timeout and default token lifetime are those of an authorizer.
        assert!(debug.contains("timeout: 30s"), "{debug}");
        assert!(debug.contains("default_token_lifetime: 300s"), "{debug}");
        assert!(!debug.contains("SECRET"), "{debug}");
    }
    let debug = format!("{request:?}");
    assert!(debug.contains(ACCESS_TOKEN_TYPE), "{debug}");
    assert!(debug.contains("audience"), "{debug}");
    assert!(!debug.contains("SECRET"), "{debug}");
    let debug = format!("{issued:?}");
    assert!(debug.contains(ACCESS_TOKEN_TYPE), "{debug}");
    assert!(debug.contains("900s"), "{debug}");
    assert!(!debug.contains("SECRET"), "{debug}");
}
