use std::env::args;
use std::process::exit;

extern crate sequoia_core;
extern crate sequoia_net;
extern crate sequoia_store;

use sequoia_core::Context;
use sequoia_net::ipc::Server;

fn main() {
    let argv: Vec<String> = args().collect();
    let argc = argv.len();

    if argc != 3 || argv[1] != "--home" {
        eprintln!("Usage: {} --home <HOMEDIR>", argv[0]);
        exit(1);
    }

    let ctx = Context::configure("org.example.sequoia")
        .home(&argv[2]).build()
        .expect("Failed to create context.");

    Server::new(sequoia_store::descriptor(&ctx))
        .expect("Failed to create server.")
        .serve()
        .expect("Failed to start server.");
}
