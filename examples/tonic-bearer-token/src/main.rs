use hello_world::{SayHelloRequest, greeter_service_client::GreeterServiceClient};
use middle::Authorizer;
use tonic::transport::Endpoint;

pub mod hello_world {
    tonic::include_proto!("helloworld");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let authorizer = Authorizer::bearer("my-super-secret-token")?;

    let channel = Endpoint::from_static("http://service.example.com:50051")
        .connect()
        .await?;
    // The interceptor puts the authorization header on every request.
    let mut client = GreeterServiceClient::with_interceptor(channel, authorizer.interceptor());

    let request = tonic::Request::new(SayHelloRequest {
        name: "Tonic".into(),
    });

    let response = client.say_hello(request).await?;

    println!("RESPONSE={:?}", response);

    Ok(())
}
