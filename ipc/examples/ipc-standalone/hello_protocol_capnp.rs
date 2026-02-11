// Include the capnp-generated code.
#![allow(unused_parens)]
include!(concat!(
    env!("OUT_DIR"),
    "/examples/ipc-standalone/hello_protocol_capnp.rs"
));
