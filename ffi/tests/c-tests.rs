extern crate libc;

use std::cmp::min;
use std::env::var_os;
use std::ffi::OsStr;
use std::fs;
use std::io::{self, BufRead, Write};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::time;

/// Hooks into Rust's test system to extract, compile and run c tests.
#[test]
fn c_doctests() {
    let ffi = PathBuf::from(
        var_os("CARGO_MANIFEST_DIR")
            .as_ref()
            .expect("CARGO_MANIFEST_DIR not set")
    );
    let src = ffi.join("src");
    let include = ffi.join("include");
    let debug = ffi.parent().unwrap().join("target").join("debug");
    let target = ffi.parent().unwrap().join("target").join("c-tests");
    fs::create_dir_all(&target).unwrap();
    let mut n = 0;
    let mut passed = 0;
    for_all_rs(&src, |path| {
        for_all_tests(path, |src, lineno, name, lines| {
            n += 1;
            eprint!("  test {} ... ", name);
            match build(&include, &debug, &target, src, lineno, name, lines) {
                Ok(exe) => match run(&debug, &exe) {
                    Ok(()) => {
                        eprintln!("ok");
                        passed += 1;
                    },
                    Err(e) =>
                        eprintln!("{}", e),
                },
                Err(e) =>
                    eprintln!("{}", e),
            }
            Ok(())
        })
    }).unwrap();
    eprintln!("  test result: {} passed; {} failed", passed, n - passed);
    if n != passed {
        panic!("ffi test failures");
    }
}

/// Maps the given function `fun` over all Rust files in `src`.
fn for_all_rs<F>(src: &Path, mut fun: F)
                 -> io::Result<()>
    where F: FnMut(&Path) -> io::Result<()> {
    for entry in fs::read_dir(src).unwrap() {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() && path.extension() == Some(OsStr::new("rs")) {
            fun(&path)?;
        }
    }
    Ok(())
}

/// Maps the given function `fun` over all tests found in `path`.
fn for_all_tests<F>(path: &Path, mut fun: F)
                 -> io::Result<()>
    where F: FnMut(&Path, u32, &str, &[String]) -> io::Result<()> {
    let mut lineno = 0;
    let mut test_starts_at = 0;
    let f = fs::File::open(path)?;
    let reader = io::BufReader::new(f);

    let mut in_test = false;
    let mut test = Vec::new();
    for line in reader.lines() {
        let line = line?;
        lineno += 1;

        if ! in_test {
            if line.starts_with("/// ```c") {
                in_test = true;
                test_starts_at = lineno + 1;
                continue;
            }

            if line.starts_with("pub extern \"system\" fn ") && test.len() > 0 {
                let name = &line[23..].split_whitespace()
                    .next().unwrap().to_owned();
                fun(path, test_starts_at, &name, &test)?;
                test.clear();
            }
        } else {
            if line.starts_with("/// ```") {
                in_test = false;
                continue;
            }

            test.push(String::from_str(&line[min(line.len(), 4)..]).unwrap());
        }
    }
    Ok(())
}

/// Writes and builds the c test iff it is out of date.
fn build(include_dir: &Path, ldpath: &Path, target_dir: &Path,
         src: &Path, lineno: u32, name: &str, lines: &[String])
         -> io::Result<PathBuf> {
    let target = target_dir.join(&format!("{}", name));
    let target_c = target_dir.join(&format!("{}.c", name));
    let meta_rs = fs::metadata(&src).expect("rust source must be there");
    let dirty = if let Ok(meta_c) = fs::metadata(&target_c) {
        meta_rs.modified().unwrap().duration_since(meta_c.modified().unwrap())
            .map(|d| d.as_secs() > 1)
            .unwrap_or(false)
    } else {
        true
    };

    if dirty {
        let mut f = fs::File::create(&target_c)?;
        writeln!(f, "#line {} {:?}", lineno, src)?;
        for line in lines {
            writeln!(f, "{}", line)?
        }

        // Change the modification time of the c source to match the
        // rust source.
        let mtime = meta_rs.modified().unwrap()
            .duration_since(time::UNIX_EPOCH).unwrap();
        let timevals = [
            // Access time.
            libc::timeval {
                tv_sec: mtime.as_secs() as i64,
                tv_usec: mtime.subsec_nanos() as i64 / 1000,
            },
            // Modification time.
            libc::timeval {
                tv_sec: mtime.as_secs() as i64,
                tv_usec: mtime.subsec_nanos() as i64 / 1000,
            },
        ];
        let rc = unsafe {
            libc::futimes(f.as_raw_fd(), timevals.as_ptr())
        };
        assert_eq!(rc, 0);
    }

    let st = Command::new("make")
        .env("CFLAGS", &format!("-I{:?}", include_dir))
        .env("LDFLAGS", &format!("-L{:?} -lsequoia_ffi", ldpath))
        .arg("-C").arg(&target_dir)
        .arg("--quiet")
        .arg(target.file_name().unwrap())
        .status()?;
    if ! st.success() {
        return Err(io::Error::new(io::ErrorKind::Other, "compilation failed"));
    }

    Ok(target)
}

/// Runs the test case.
fn run(ldpath: &Path, exe: &Path) -> io::Result<()> {
    let st = Command::new(exe)
        .env("LD_LIBRARY_PATH", ldpath)
        .status()?;
    if ! st.success() {
        return Err(io::Error::new(io::ErrorKind::Other, "failed"));
    }
    Ok(())
}
