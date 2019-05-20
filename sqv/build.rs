extern crate clap;

use std::env;
use std::fs;
use clap::Shell;

mod sqv_cli {
    include!("src/sqv_cli.rs");
}

fn main() {
    let outdir = match env::var_os("CARGO_TARGET_DIR") {
        None => return,
        Some(outdir) => outdir,
    };
    fs::create_dir_all(&outdir).unwrap();
    let mut sqv = sqv_cli::build();
    for shell in &[Shell::Bash, Shell::Fish, Shell::Zsh, Shell::PowerShell,
                   Shell::Elvish] {
        sqv.gen_completions("sqv", *shell, &outdir);
    }
}
