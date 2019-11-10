use std::env;
use std::io::{self, Write, BufRead};
use std::fs::{self, DirEntry};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

// one possible implementation of walking a directory only visiting files
fn visit_dirs(dir: &Path, cb: &dyn Fn(&DirEntry) -> io::Result<()>)
              -> io::Result<()> {
    if dir.is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                visit_dirs(&path, cb)?;
            } else {
                cb(&entry)?;
            }
        }
    }
    Ok(())
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap())
}

fn out_dir() -> PathBuf {
    env::var_os("OUT_DIR").unwrap().into()
}

fn lib_path() -> PathBuf {
    out_dir().join("src/lib.rs")
}

fn translate_path(src: &Path) -> PathBuf {
    let src = src.to_str().unwrap();
    format!("{}rs", &src[..src.len() - 2]).into()
}

fn translate2rs(src: &DirEntry) -> io::Result<()> {
    let path = src.path();
    if path.extension() != Some(&OsString::from("md")) {
        return Ok(());
    }

    let sink_filename = out_dir().join(
        translate_path(&path).strip_prefix(&manifest_dir()).unwrap());

    eprintln!("{:?} -> {:?}", path, sink_filename);
    println!("rerun-if-changed={}", path.to_str().unwrap());

    fs::create_dir_all(sink_filename.parent().unwrap())?;
    let mut sink = fs::File::create(sink_filename)?;

    for line in io::BufReader::new(fs::File::open(&path)?).lines() {
        writeln!(&mut sink, "//! {}", line?)?;
    }

    let mut lib =
        fs::OpenOptions::new().create(true).append(true).open(&lib_path())?;
    writeln!(&mut lib, "pub mod {};", path.file_stem().unwrap().to_str().unwrap())?;

    Ok(())
}

fn main() {
    let _ = fs::remove_file(&lib_path());
    visit_dirs(&manifest_dir().join("src"), &translate2rs).unwrap();
}
