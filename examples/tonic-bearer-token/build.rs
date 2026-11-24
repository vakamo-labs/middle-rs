use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // protoc is the one `PROTOC` names. Without `PROTOC`, it comes from crates.io, so building the example needs no protoc on the machine.
    println!("cargo:rerun-if-env-changed=PROTOC");
    let protoc = match std::env::var_os("PROTOC") {
        Some(protoc) => PathBuf::from(protoc),
        None => protoc_bin_vendored::protoc_bin_path()?,
    };
    let mut config = tonic_prost_build::Config::new();
    config.protoc_executable(protoc);
    tonic_prost_build::configure().compile_with_config(
        config,
        &["proto/helloworld.proto"],
        &["proto"],
    )?;
    Ok(())
}
