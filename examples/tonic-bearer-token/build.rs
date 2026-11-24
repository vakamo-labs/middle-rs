fn main() -> Result<(), Box<dyn std::error::Error>> {
    // protoc comes from crates.io, so building the example needs no protoc on the machine.
    let mut config = tonic_prost_build::Config::new();
    config.protoc_executable(protoc_bin_vendored::protoc_bin_path()?);
    tonic_prost_build::configure().compile_with_config(
        config,
        &["proto/helloworld.proto"],
        &["proto"],
    )?;
    Ok(())
}
