//! Which token requests of the client middle builds go through a proxy from the environment.
//!
//! This file has one test: it sets environment variables, which every thread of the process reads.

mod support;

use middle::{Authorizer, ClientAuthentication};
use support::{FakeIdp, Reply};

#[tokio::test]
async fn test_a_loopback_token_url_bypasses_the_proxy() {
    let idp = FakeIdp::start(|_| Reply::token("direct", Some(3600))).await;
    // Answers a request sent through it as if it were the token endpoint.
    let proxy = FakeIdp::start(|_| Reply::token("proxied", Some(3600))).await;
    let proxy_url = proxy.token_url();
    // SAFETY: this test binary has one test, and no other thread reads the environment yet.
    unsafe {
        std::env::set_var("HTTP_PROXY", format!("http://{}", proxy_url.authority()));
        std::env::remove_var("NO_PROXY");
        std::env::remove_var("no_proxy");
    }
    let builder = |token_url: url::Url| {
        Authorizer::client_credentials(
            token_url,
            ClientAuthentication::client_secret_basic("c", "s"),
        )
    };

    // A proxy on another machine cannot reach the loopback address of this one.
    builder(idp.token_url()).build().await.unwrap();
    assert_eq!((idp.count(), proxy.count()), (1, 0));

    // Any other host goes through the proxy.
    builder("http://idp.example.com/token".parse().unwrap())
        .danger_allow_http(true)
        .build()
        .await
        .unwrap();
    assert_eq!((idp.count(), proxy.count()), (1, 1));
    assert_eq!(
        proxy.requests()[0].path,
        "http://idp.example.com/token",
        "a request through an HTTP proxy names the whole URL"
    );
}
