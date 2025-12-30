use std::sync::Arc;

use http::{HeaderValue, header::AUTHORIZATION};
use reqwest::IntoUrl;

use crate::{Authorizer, error::Result};

/// Wrapper around `reqwest::Client` that automatically adds the authorization header,
/// while keeping it up-to-date using an `Authorizer`.
///
/// Designed to be a mostly drop-in replacement for `reqwest::Client`.
#[derive(Debug, Clone)]
pub struct HttpClient<A: Authorizer> {
    authorizer: A,
    client: reqwest::Client,
}

impl<A: Authorizer> HttpClient<A> {
    /// Creates a new `HttpClient` with the given `Authorizer`.
    pub fn new(authorizer: A) -> Self {
        Self {
            authorizer,
            client: reqwest::Client::new(),
        }
    }

    /// Set a custom `reqwest::Client`.
    #[must_use]
    pub fn set_client(mut self, client: reqwest::Client) -> Self {
        self.client = client;
        self
    }

    /// Obtain the currently used authorization header.
    ///
    /// # Errors
    /// Returns an error if the authorizer fails to provide a token, typically because
    /// the token refresh failed.
    pub fn authorization_header(&self) -> Result<Arc<HeaderValue>> {
        self.authorizer.authorization_header()
    }

    /// Start building a `Request`, adding the authorization header.
    ///
    /// # Errors
    /// Returns an error if the authorizer fails to provide a token, typically because
    /// the token refresh failed.
    pub fn request<U: IntoUrl>(
        &self,
        method: reqwest::Method,
        url: U,
    ) -> Result<reqwest::RequestBuilder> {
        let header = self.authorization_header()?;
        let request = self
            .client
            .request(method, url)
            .header(AUTHORIZATION, Arc::unwrap_or_clone(header));
        Ok(request)
    }

    /// Execute a `Request`, adding the authorization header if it is not already set.
    ///
    /// # Errors
    /// - Returns an error if the authorizer fails to provide a token, typically because the token refresh failed.
    /// - Returns an error if the request fails.
    pub async fn execute(&self, mut request: reqwest::Request) -> Result<reqwest::Response> {
        let header = self.authorization_header()?;

        if !request.headers().contains_key(AUTHORIZATION) {
            request
                .headers_mut()
                .insert(AUTHORIZATION, Arc::unwrap_or_clone(header));
        }
        self.client
            .execute(request)
            .await
            .map_err(Arc::new)
            .map_err(Into::into)
    }

    /// Convenience method to make a `GET` request to a URL.
    ///
    /// # Errors
    /// See [`request`](Self::request).
    pub fn get<U: IntoUrl>(&self, url: U) -> Result<reqwest::RequestBuilder> {
        self.request(reqwest::Method::GET, url)
    }

    /// Convenience method to make a `POST` request to a URL.
    ///
    /// # Errors
    /// See [`request`](Self::request).
    pub fn post<U: IntoUrl>(&self, url: U) -> Result<reqwest::RequestBuilder> {
        self.request(reqwest::Method::POST, url)
    }

    /// Convenience method to make a `PUT` request to a URL.
    ///
    /// # Errors
    /// See [`request`](Self::request).
    pub fn put<U: IntoUrl>(&self, url: U) -> Result<reqwest::RequestBuilder> {
        self.request(reqwest::Method::PUT, url)
    }

    /// Convenience method to make a `PATCH` request to a URL.
    ///
    /// # Errors
    /// See [`request`](Self::request).
    pub fn patch<U: IntoUrl>(&self, url: U) -> Result<reqwest::RequestBuilder> {
        self.request(reqwest::Method::PATCH, url)
    }

    /// Convenience method to make a `DELETE` request to a URL.
    ///
    /// # Errors
    /// See [`request`](Self::request).
    pub fn delete<U: IntoUrl>(&self, url: U) -> Result<reqwest::RequestBuilder> {
        self.request(reqwest::Method::DELETE, url)
    }

    /// Convenience method to make a `HEAD` request to a URL.
    ///
    /// # Errors
    /// See [`request`](Self::request).
    pub fn head<U: IntoUrl>(&self, url: U) -> Result<reqwest::RequestBuilder> {
        self.request(reqwest::Method::HEAD, url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorizers::BearerTokenAuthorizer;

    #[tokio::test]
    async fn test_http_client() {
        let authorizer = BearerTokenAuthorizer::new("test").unwrap();
        let client = HttpClient::new(authorizer);

        let response = client
            .get("https://httpbin.org/get")
            .unwrap()
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success());
    }
}
