//! A scriptable token endpoint for integration tests.
//!
//! [`FakeIdp::start`] listens on a random local port and answers every request with what
//! the behavior returns for it. The behavior gets the 1-based number of the request, so a
//! test can script an outage, a recovery or a changing token. Every request is recorded.

#![allow(dead_code)] // Each test binary uses a different part of the support module.

use std::{
    sync::{Arc, Mutex},
    time::Instant,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

/// What the fake identity provider answers.
#[derive(Clone, Debug)]
pub enum Reply {
    /// An HTTP response.
    Respond {
        status: u16,
        headers: Vec<(String, String)>,
        body: String,
    },
    /// Read the request and never answer.
    Hang,
    /// Send the status and the start of a JSON body, then close the connection before the body is complete.
    CutOff { status: u16 },
    /// A 200 without `content-length`, whose body ends when the connection closes.
    UntilClose { body: String },
}

impl Reply {
    /// A JSON response.
    pub fn json(status: u16, body: impl Into<String>) -> Self {
        Self::Respond {
            status,
            headers: vec![("content-type".to_string(), "application/json".to_string())],
            body: body.into(),
        }
    }

    /// A successful token response with `token_type` Bearer.
    pub fn token(access_token: &str, expires_in: Option<u64>) -> Self {
        let mut body = serde_json::json!({"access_token": access_token, "token_type": "Bearer"});
        if let Some(expires_in) = expires_in {
            body["expires_in"] = expires_in.into();
        }
        Self::json(200, body.to_string())
    }

    /// An OAuth error response (RFC 6749, section 5.2).
    pub fn oauth_error(status: u16, error: &str, description: &str) -> Self {
        let body = serde_json::json!({"error": error, "error_description": description});
        Self::json(status, body.to_string())
    }

    /// A response with a body that is not JSON, such as the HTML error page of a proxy.
    pub fn text(status: u16, content_type: &str, body: impl Into<String>) -> Self {
        Self::Respond {
            status,
            headers: vec![("content-type".to_string(), content_type.to_string())],
            body: body.into(),
        }
    }

    /// Adds a response header.
    #[must_use]
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        if let Self::Respond { headers, .. } = &mut self {
            headers.push((name.to_string(), value.to_string()));
        }
        self
    }
}

/// A request the fake identity provider received.
#[derive(Clone, Debug)]
pub struct Request {
    pub received_at: Instant,
    pub method: String,
    pub path: String,
    /// Header names in lower case, in the order received.
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Request {
    /// The first value of a header, compared ignoring upper and lower case.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// All values of a header.
    pub fn header_all(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }

    /// The form-urlencoded body as decoded pairs, in order.
    pub fn form(&self) -> Vec<(String, String)> {
        url::form_urlencoded::parse(self.body.as_bytes())
            .into_owned()
            .collect()
    }

    /// The first value of a form parameter.
    pub fn form_value(&self, name: &str) -> Option<String> {
        self.form()
            .into_iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v)
    }
}

type Behavior = Arc<dyn Fn(usize) -> Reply + Send + Sync>;

/// A token endpoint on a random local port.
pub struct FakeIdp {
    token_url: url::Url,
    requests: Arc<Mutex<Vec<Request>>>,
    started_at: Instant,
}

impl FakeIdp {
    /// Starts listening. `behavior` gets the 1-based number of each request.
    pub async fn start(behavior: impl Fn(usize) -> Reply + Send + Sync + 'static) -> Self {
        let behavior: Behavior = Arc::new(behavior);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests: Arc<Mutex<Vec<Request>>> = Arc::default();
        let recorded = Arc::clone(&requests);
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                tokio::spawn(serve(socket, Arc::clone(&recorded), Arc::clone(&behavior)));
            }
        });
        Self {
            token_url: format!("http://{addr}/token").parse().unwrap(),
            requests,
            started_at: Instant::now(),
        }
    }

    /// The URL of the token endpoint.
    pub fn token_url(&self) -> url::Url {
        self.token_url.clone()
    }

    /// The requests received so far.
    pub fn requests(&self) -> Vec<Request> {
        self.requests.lock().unwrap().clone()
    }

    /// The number of requests received so far.
    pub fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }

    /// When each request arrived, in milliseconds after the start.
    pub fn arrival_ms(&self) -> Vec<u128> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .map(|r| r.received_at.duration_since(self.started_at).as_millis())
            .collect()
    }
}

/// Answers the requests of one connection until the client closes it.
async fn serve(mut socket: TcpStream, requests: Arc<Mutex<Vec<Request>>>, behavior: Behavior) {
    let mut buffer = Vec::new();
    loop {
        let Some(request) = read_request(&mut socket, &mut buffer).await else {
            return;
        };
        let number = {
            let mut requests = requests.lock().unwrap();
            requests.push(request);
            requests.len()
        };
        match behavior(number) {
            Reply::Hang => std::future::pending::<()>().await,
            Reply::CutOff { status } => {
                let response = format!(
                    "HTTP/1.1 {status} {}\r\ncontent-type: application/json\r\ncontent-length: 100\r\n\r\n{{\"error\"",
                    reason(status)
                );
                let _ = socket.write_all(response.as_bytes()).await;
                return;
            }
            Reply::UntilClose { body } => {
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n{body}"
                );
                let _ = socket.write_all(response.as_bytes()).await;
                return;
            }
            Reply::Respond {
                status,
                headers,
                body,
            } => {
                let mut response = format!("HTTP/1.1 {status} {}\r\n", reason(status));
                for (name, value) in &headers {
                    response.push_str(&format!("{name}: {value}\r\n"));
                }
                response.push_str(&format!("content-length: {}\r\n\r\n{body}", body.len()));
                if socket.write_all(response.as_bytes()).await.is_err() {
                    return;
                }
            }
        }
    }
}

/// Reads one HTTP/1.1 request with a `content-length` body. `None` when the client closes
/// the connection.
async fn read_request(socket: &mut TcpStream, buffer: &mut Vec<u8>) -> Option<Request> {
    let head_end = loop {
        if let Some(position) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break position + 4;
        }
        read_more(socket, buffer).await?;
    };
    let head = String::from_utf8_lossy(&buffer[..head_end]).to_string();
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next()?.split(' ');
    let method = request_line.next()?.to_string();
    let path = request_line.next()?.to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_string()))
        .collect();
    let content_length = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .map_or(0, |(_, value)| value.parse::<usize>().unwrap());
    while buffer.len() < head_end + content_length {
        read_more(socket, buffer).await?;
    }
    let body = String::from_utf8_lossy(&buffer[head_end..head_end + content_length]).to_string();
    buffer.drain(..head_end + content_length);
    Some(Request {
        received_at: Instant::now(),
        method,
        path,
        headers,
        body,
    })
}

async fn read_more(socket: &mut TcpStream, buffer: &mut Vec<u8>) -> Option<()> {
    let mut chunk = [0u8; 4096];
    match socket.read(&mut chunk).await {
        Ok(0) | Err(_) => None,
        Ok(n) => {
            buffer.extend_from_slice(&chunk[..n]);
            Some(())
        }
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Status",
    }
}
