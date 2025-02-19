use hello_world::{greeter_service_client::GreeterServiceClient, SayHelloRequest};
use middle::BearerTokenAuthorizer;
use tonic::transport::Endpoint;

pub mod hello_world {
    tonic::include_proto!("helloworld");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // All authorizers provided by the `middle` crate implement the `tonic::Interceptor` trait.
    let authorizer = BearerTokenAuthorizer::new("my-super-secret-token")?;

    let channel = Endpoint::from_static("http://service.example.com:50051")
        .connect()
        .await?;
    // Use the authorizer as an interceptor.
    let mut client = GreeterServiceClient::with_interceptor(channel, authorizer);

    // All following requests include the authorization header.
    let request = tonic::Request::new(SayHelloRequest {
        name: "Tonic".into(),
    });

    let response = client.say_hello(request).await?;

    println!("RESPONSE={:?}", response);

    Ok(())
}
