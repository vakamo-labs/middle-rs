//! What middle sends to the token endpoint, byte for byte where it matters.

mod support;

use middle::{Authorizer, AuthorizerBuilder, ClientAuthentication, ConfigError, Error};
use support::{FakeIdp, Reply};

/// A builder with `client_secret_basic`.
fn builder(token_url: url::Url) -> AuthorizerBuilder {
    Authorizer::client_credentials(
        token_url,
        ClientAuthentication::client_secret_basic("c", "s"),
    )
}

/// Client credentials with `client_secret_basic`: RFC 6749, sections 2.3.1 and 4.4.2.
#[tokio::test]
async fn test_client_credentials_with_basic_authentication() {
    let idp = FakeIdp::start(|_| Reply::token("issued-token", Some(3600))).await;

    let authorizer = Authorizer::client_credentials(
        idp.token_url(),
        ClientAuthentication::client_secret_basic("my client", "s3cr3t/+~:"),
    )
    .add_scopes(&["read", "write"])
    .build()
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
    // The id and the secret are form-urlencoded before Base64: `my+client:s3cr3t%2F%2B%7E%3A`.
    assert_eq!(
        request.header_all("authorization"),
        vec!["Basic bXkrY2xpZW50OnMzY3IzdCUyRiUyQiU3RSUzQQ=="]
    );
    assert_eq!(
        request.body,
        "grant_type=client_credentials&scope=read+write"
    );

    assert_eq!(
        authorizer.authorization_header().unwrap().to_str().unwrap(),
        "Bearer issued-token"
    );
}

/// Client credentials with `client_secret_post`: RFC 6749, section 2.3.1, and the OAuth 2.1 draft, section 2.4.1.
#[tokio::test]
async fn test_client_credentials_with_post_authentication() {
    let idp = FakeIdp::start(|_| Reply::token("issued-token", Some(3600))).await;

    Authorizer::client_credentials(
        idp.token_url(),
        ClientAuthentication::client_secret_post("my client", "s3cr3t/+~:"),
    )
    .add_scopes(&["read", "write"])
    .build()
    .await
    .unwrap();

    let request = &idp.requests()[0];
    assert_eq!(request.header_all("authorization"), Vec::<&str>::new());
    assert_eq!(
        request.body,
        "grant_type=client_credentials&client_id=my+client&client_secret=s3cr3t%2F%2B%7E%3A&scope=read+write"
    );
}

#[tokio::test]
async fn test_empty_scopes_are_skipped() {
    let idp = FakeIdp::start(|_| Reply::token("t", Some(3600))).await;
    // A setting split on single spaces, with a doubled and a trailing space.
    let scopes: Vec<&str> = "openid  openfga ".split(' ').collect();

    builder(idp.token_url())
        .add_scopes(&scopes)
        .add_scope("")
        .build()
        .await
        .unwrap();

    assert_eq!(
        idp.requests()[0].body,
        "grant_type=client_credentials&scope=openid+openfga"
    );
}

#[tokio::test]
async fn test_appended_parameters_follow_the_scope_and_may_repeat() {
    let idp = FakeIdp::start(|_| Reply::token("t", Some(3600))).await;

    // RFC 8707, section 2: one `resource` parameter for each resource.
    builder(idp.token_url())
        .add_scope("read")
        .append_param("resource", "https://a.example.com")
        .append_param("resource", "https://b.example.com")
        .build()
        .await
        .unwrap();

    assert_eq!(
        idp.requests()[0].body,
        "grant_type=client_credentials&scope=read&resource=https%3A%2F%2Fa.example.com&resource=https%3A%2F%2Fb.example.com"
    );
}

#[tokio::test]
async fn test_a_scope_with_a_space_is_rejected() {
    let idp = FakeIdp::start(|_| Reply::token("t", Some(3600))).await;

    let error = builder(idp.token_url())
        .add_scope("read write")
        .build()
        .await
        .expect_err("one scope cannot contain a space");

    assert!(
        matches!(&error, Error::Config(ConfigError::InvalidScope(scope)) if scope == "read write"),
        "{error:?}"
    );
    assert_eq!(idp.count(), 0);
}

#[tokio::test]
async fn test_a_parameter_middle_sets_cannot_be_appended() {
    for name in [
        "grant_type",
        "scope",
        "client_id",
        "client_secret",
        "client_assertion",
        "client_assertion_type",
        "assertion",
    ] {
        let idp = FakeIdp::start(|_| Reply::token("t", Some(3600))).await;

        let error = builder(idp.token_url())
            .append_param(name, "value")
            .build()
            .await
            .expect_err("middle sets this parameter");

        assert!(
            matches!(&error, Error::Config(ConfigError::ReservedParameter(reserved)) if reserved == name),
            "{error:?}"
        );
        assert_eq!(idp.count(), 0);
    }
}

#[tokio::test]
async fn test_a_token_url_with_a_fragment_is_rejected() {
    let error = builder("https://idp.example.com/token#part".parse().unwrap())
        .build()
        .await
        .expect_err("RFC 6749 section 3.2 forbids a fragment");

    assert!(
        matches!(error, Error::Config(ConfigError::TokenUrlWithFragment)),
        "{error:?}"
    );
}

#[tokio::test]
async fn test_a_token_url_with_user_info_is_rejected() {
    let error = builder(
        "https://user:password@idp.example.com/token"
            .parse()
            .unwrap(),
    )
    .build()
    .await
    .expect_err("credentials belong in the client authentication");

    assert!(
        matches!(error, Error::Config(ConfigError::TokenUrlWithUserInfo)),
        "{error:?}"
    );
}

#[tokio::test]
async fn test_a_token_url_with_another_scheme_is_rejected() {
    let error = builder("ftp://idp.example.com/token".parse().unwrap())
        .build()
        .await
        .expect_err("only http and https");

    assert!(
        matches!(&error, Error::Config(ConfigError::TokenUrlScheme(scheme)) if scheme == "ftp"),
        "{error:?}"
    );
}

#[tokio::test]
async fn test_an_http_token_url_needs_a_loopback_host() {
    // The fake token endpoint listens on 127.0.0.1, so every other test uses http.
    let error = builder("http://idp.example.com/token".parse().unwrap())
        .build()
        .await
        .expect_err("http sends the secret without TLS");

    assert!(
        matches!(&error, Error::Config(ConfigError::HttpTokenUrl(host)) if host == "idp.example.com"),
        "{error:?}"
    );
}

#[tokio::test]
async fn test_danger_allow_http_allows_an_http_token_url_with_any_host() {
    let idp = FakeIdp::start(|_| Reply::token("t", Some(3600))).await;
    let address = idp.token_url().socket_addrs(|| None).unwrap()[0];
    // The HTTP client resolves `idp.example.com` to the fake token endpoint.
    let http_client = reqwest::Client::builder()
        .resolve("idp.example.com", address)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .unwrap();
    let host = format!("idp.example.com:{}", address.port());
    let builder =
        builder(format!("http://{host}/token").parse().unwrap()).danger_http_client(http_client);

    let error = builder
        .clone()
        .danger_allow_http(false)
        .build()
        .await
        .expect_err("http with another host needs danger_allow_http");
    assert!(
        matches!(&error, Error::Config(ConfigError::HttpTokenUrl(h)) if h == "idp.example.com"),
        "{error:?}"
    );
    assert_eq!(idp.count(), 0);

    builder.danger_allow_http(true).build().await.unwrap();
    assert_eq!(idp.count(), 1);
    assert_eq!(idp.requests()[0].header("host"), Some(host.as_str()));
}

#[tokio::test]
async fn test_debug_output_hides_secrets() {
    let idp = FakeIdp::start(|_| Reply::token("SECRET-ACCESS-TOKEN", Some(3600))).await;
    let mut token_url = idp.token_url();
    token_url.set_query(Some("key=SECRET-QUERY"));
    for builder in [
        Authorizer::client_credentials(
            token_url.clone(),
            ClientAuthentication::client_secret_basic("my-client", "SECRET-CLIENT-SECRET"),
        ),
        Authorizer::client_credentials(
            token_url.clone(),
            ClientAuthentication::client_secret_post("my-client", "SECRET-CLIENT-SECRET"),
        ),
    ] {
        // A custom client whose default header holds a secret.
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("x-api-key", "SECRET-HEADER".parse().unwrap());
        let http_client = reqwest::Client::builder()
            .default_headers(headers)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .unwrap();
        let builder = builder
            .append_param("audience", "SECRET-PARAMETER-VALUE")
            .danger_http_client(http_client);

        let builder_debug = format!("{builder:?}");
        let authorizer = builder.build().await.unwrap();
        let authorizer_debug = format!("{authorizer:?}");

        for debug in [builder_debug, authorizer_debug] {
            assert!(debug.contains("my-client"), "{debug}");
            assert!(debug.contains("audience"), "{debug}");
            assert!(!debug.contains("SECRET"), "{debug}");
        }
    }
}
