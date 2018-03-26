extern crate clap;

use std::env;
use clap::Shell;

include!("src/cli.rs");

fn main() {
    let outdir = match env::var_os("OUT_DIR") {
        None => return,
        Some(outdir) => outdir,
    };
    let mut app = build();
    for shell in &[Shell::Bash, Shell::Fish] {
        app.gen_completions("sq", *shell, &outdir);
    }
}
