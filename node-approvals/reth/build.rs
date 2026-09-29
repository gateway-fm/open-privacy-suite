// The delivery service is generated from the one .proto that OPS (Go) and the Besu plugin (Java)
// also generate from, so a method or field rename cannot drift between the three.
fn main() -> std::io::Result<()> {
    tonic_prost_build::configure().compile_protos(
        &["../../proto/ops/approvals/v1/approvals.proto"],
        &["../../proto"],
    )
}
