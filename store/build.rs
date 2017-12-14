extern crate capnpc;

fn capnp(src: &str) {
    println!("rerun-if-changed={}", src);
    ::capnpc::CompilerCommand::new().file(src).run().unwrap();
}

fn main() {
    capnp("src/store_protocol.capnp");
}
