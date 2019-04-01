extern crate clap;

use std::env;
use clap::Shell;

mod sq_cli {
    include!("src/sq_cli.rs");
}

fn main() {
    let outdir = match env::var_os("CARGO_TARGET_DIR") {
        None => return,
        Some(outdir) => outdir,
    };
    let mut sq = sq_cli::build();
    for shell in &[Shell::Bash, Shell::Fish, Shell::Zsh, Shell::PowerShell,
                   Shell::Elvish] {
        sq.gen_completions("sq", *shell, &outdir);
    }
}
