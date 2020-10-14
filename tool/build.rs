use clap;

use std::env;
use std::fs;
use clap::Shell;

mod sq_cli {
    include!("src/sq_cli.rs");
}

fn main() {
    let outdir = match env::var_os("CARGO_TARGET_DIR") {
        None => return,
        Some(outdir) => outdir,
    };
    fs::create_dir_all(&outdir).unwrap();
    let mut sq = sq_cli::build();
    for shell in &[Shell::Bash, Shell::Fish, Shell::Zsh, Shell::PowerShell,
                   Shell::Elvish] {
        sq.gen_completions("sq", *shell, &outdir);
    }
}
