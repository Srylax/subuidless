//! Generates the Protobuf definitions with the pure rust parsers
fn main() {
    protobuf_codegen::Codegen::new()
        .pure()
        .includes(["src"])
        .input("src/rootlesscontainers.proto")
        .cargo_out_dir("protos")
        .run_from_script();
}
