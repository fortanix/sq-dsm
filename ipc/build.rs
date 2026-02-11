use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

fn main() {
    lalrpop::Configuration::new().use_cargo_dir_conventions().process().unwrap();
    capnp("examples/ipc-standalone/hello_protocol.capnp");
    include_test_data().unwrap();
}

fn capnp(src: &str) {
    println!("rerun-if-changed={}", src);
    ::capnpc::CompilerCommand::new().file(src).run().unwrap();
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
