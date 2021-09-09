use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::exit;

fn main() {
    crypto_backends_sanity_check();
    lalrpop::process_root().unwrap();
    include_test_data().unwrap();
}

/// Builds the index of the test data for use with the `::tests`
/// module.
fn include_test_data() -> io::Result<()> {
    let cwd = env::current_dir()?;
    let mut sink = fs::File::create(
        PathBuf::from(env::var_os("OUT_DIR").unwrap())
            .join("tests.index.rs.inc")).unwrap();

    writeln!(&mut sink, "{{")?;
    let mut dirs = vec![PathBuf::from("tests/data")];
    while let Some(dir) = dirs.pop() {
        println!("rerun-if-changed={}", dir.to_str().unwrap());
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                writeln!(
                    &mut sink, "    add!({:?}, {:?});",
                    path.components().skip(2)
                        .map(|c| c.as_os_str().to_str().expect("valid UTF-8"))
                        .collect::<Vec<_>>().join("/"),
                    cwd.join(path))?;
            } else if path.is_dir() {
                dirs.push(path.clone());
            }
        }
    }
    writeln!(&mut sink, "}}")?;
    Ok(())
}

fn crypto_backends_sanity_check() {
    #[allow(dead_code)]
    struct Backend {
        name: &'static str,
        production_ready: bool,
        constant_time: bool,
    }

    let backends = vec![
        (cfg!(feature = "crypto-nettle"),
         Backend {
             name: "Nettle",
             production_ready: true,
             constant_time: true,
         }),
        (cfg!(feature = "crypto-cng"),
         Backend {
             name: "Windows CNG",
             production_ready: true,
             constant_time: true,
         }),
    ].into_iter().filter_map(|(selected, backend)| {
        if selected { Some(backend) } else { None }
    }).collect::<Vec<_>>();

    match backends.len() {
        0 => {
            eprintln!("No cryptographic backend selected.

Sequoia requires a cryptographic backend.  This backend is selected at compile
time using feature flags.

See https://crates.io/crates/sequoia-openpgp#crypto-backends");
            exit(1);
        },

        1 => {
            eprintln!("Selected cryptographic backend: {}", backends[0].name);
        },

        _ => {
            eprintln!("Multiple cryptographic backends selected.

Sequoia requires exactly one cryptographic backend.  This backend is
selected at compile time using feature flags.

Unfortunately, you have selected multiple backends:

    {}

See https://crates.io/crates/sequoia-openpgp#crypto-backends",
            backends.iter().map(|b| b.name).collect::<Vec<_>>().join(", "));
            exit(1);
        },
    }
}
