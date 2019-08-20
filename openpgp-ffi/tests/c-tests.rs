extern crate failure;
use failure::{Fallible as Result, ResultExt};
extern crate filetime;
extern crate nettle;

use std::cmp::min;
use std::env::{self, var_os};
use std::ffi::OsStr;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::mem::replace;

/// Hooks into Rust's test system to extract, compile and run c tests.
#[test]
fn c_doctests() {
    // The location of this crate's (i.e., the ffi crate's) source.
    let manifest_dir = PathBuf::from(
        var_os("CARGO_MANIFEST_DIR")
        .as_ref()
        .expect("CARGO_MANIFEST_DIR not set"));

    let src = manifest_dir.join("src");
    let includes = vec![
        manifest_dir.join("include"),
    ];

    // The top-level directory.
    let toplevel = manifest_dir.parent().unwrap();

    // The location of the binaries.
    let target_dir = if let Some(dir) = var_os("CARGO_TARGET_DIR") {
        PathBuf::from(dir)
    } else {
        toplevel.join("target")
    };

    // The debug target.
    let debug = target_dir.join("debug");
    // Where we put our files.
    let target = target_dir.join("c-tests");
    fs::create_dir_all(&target).unwrap();

    // First of all, make sure the shared object is built.
    build_so(toplevel).unwrap();

    let mut n = 0;
    let mut passed = 0;
    for_all_rs(&src, |path| {
        for_all_tests(path, |src, lineno, name, lines, run_it| {
            n += 1;
            eprint!("  test {} ... ", name);
            match build(&includes, &debug, &target, src, lineno, name, lines) {
                Ok(_) if ! run_it => {
                    eprintln!("ok");
                    passed += 1;
                },
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

/// Builds the shared object.
fn build_so(base: &Path) -> Result<()> {
    let st = Command::new("cargo")
        .current_dir(base)
        .arg("build")
        .arg("--quiet")
        .arg("--package")
        .arg("sequoia-openpgp-ffi")
        .status().unwrap();
    if ! st.success() {
        return Err(io::Error::new(io::ErrorKind::Other, "compilation failed")
                   .into());
    }

    Ok(())
}

/// Maps the given function `fun` over all Rust files in `src`.
fn for_all_rs<F>(src: &Path, mut fun: F)
                 -> Result<()>
    where F: FnMut(&Path) -> Result<()> {
    let mut dirs = vec![src.to_path_buf()];

    while let Some(dir) = dirs.pop() {
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() && path.extension() == Some(OsStr::new("rs")) {
                fun(&path)?;
            }
            if path.is_dir() {
                dirs.push(path.clone());
            }
        }
    }
    Ok(())
}

/// If this looks like an exported function, returns its name.
fn exported_function_name(line: &str) -> Option<&str> {
    if line.starts_with("pub extern \"C\" fn ")
        || line.starts_with("fn pgp_")
    {
        let fn_i = line.find("fn ")?;
        let name_start = fn_i + 3;
        (&line[name_start..]).split(|c| !is_valid_identifier(c)).next()
    } else {
        None
    }
}

fn is_valid_identifier(c: char) -> bool {
    char::is_alphanumeric(c) || c == '_'
}

/// Maps the given function `fun` over all tests found in `path`.
///
/// XXX: We need to parse the file properly with syn.
fn for_all_tests<F>(path: &Path, mut fun: F)
                 -> Result<()>
    where F: FnMut(&Path, usize, &str, Vec<String>, bool) -> Result<()> {
    let mut lineno = 0;
    let mut test_starts_at = 0;
    let f = fs::File::open(path)?;
    let reader = io::BufReader::new(f);

    let mut in_test = false;
    let mut test = Vec::new();
    let mut run = false;
    for line in reader.lines() {
        let line = line?;
        lineno += 1;

        if ! in_test {
            if (line.starts_with("/// ```c") || line.starts_with("//! ```c"))
                && ! line.contains("ignore")
            {
                run = ! line.contains("no-run");
                in_test = true;
                test_starts_at = lineno + 1;
                continue;
            }

            if let Some(name) = exported_function_name(&line) {
                if test.len() > 0 {
                    fun(path, test_starts_at, &name, replace(&mut test, vec![]),
                        run)?;
                    test.clear();
                }
            }
        } else {
            if line == "/// ```" {
                in_test = false;
                continue;
            }

            if line == "//! ```" && test.len() > 0 {
                let name = format!("{}_{}",
                                   path.file_stem().unwrap().to_string_lossy(),
                                   lineno); // XXX: nicer to point to the top

                fun(path, test_starts_at, &name, replace(&mut test, Vec::new()),
                    run)?;
                test.clear();
                in_test = false;
                continue;
            }

            test.push(String::from_str(&line[min(line.len(), 4)..]).unwrap());
        }
    }
    Ok(())
}

/// Writes and builds the c test iff it is out of date.
fn build(include_dirs: &[PathBuf], ldpath: &Path, target_dir: &Path,
         src: &Path, lineno: usize, name: &str, mut lines: Vec<String>)
         -> Result<PathBuf> {
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

    wrap_with_main(&mut lines, lineno);

    if dirty {
        let mut f = fs::File::create(&target_c)?;
        writeln!(f, "#line {} {:?}", lineno, src)?;
        for line in lines {
            writeln!(f, "{}", line)?
        }
        drop(f);

        // Change the modification time of the c source to match the
        // rust source.
        use filetime::FileTime;
        let mtime = FileTime::from_last_modification_time(&meta_rs);
        filetime::set_file_times(target_c, mtime.clone(), mtime).unwrap();
    }

    let includes =
        include_dirs.iter().map(|dir| format!("-I{:?}", dir))
        .collect::<Vec<String>>().join(" ");
    let st = Command::new("make")
        .env("CFLAGS", &format!("-Wall -O0 -ggdb {} {}", includes,
                                env::var("CFLAGS").unwrap_or("".into())))
        .env("LDFLAGS", &format!("-L{:?} -lsequoia_openpgp_ffi", ldpath))
        .arg("-C").arg(&target_dir)
        .arg("--quiet")
        .arg(target.file_name().unwrap())
        .status()
        .context("Compiling the C-tests requires Make \
                  and a cc-compatible compiler")?;
    if ! st.success() {
        return Err(io::Error::new(io::ErrorKind::Other, "compilation failed")
                   .into());
    }

    Ok(target)
}

/// Runs the test case.
fn run(ldpath: &Path, exe: &Path) -> Result<()> {
    let st =
        if let Ok(valgrind) = env::var("SEQUOIA_CTEST_VALGRIND") {
            Command::new(valgrind)
                .env("LD_LIBRARY_PATH", ldpath)
                .args(&["--error-exitcode=123",
                        "--leak-check=yes",
                        "--quiet",
                        "--",
                        exe.to_str().unwrap()])
                .status()?
        } else {
            Command::new(exe)
                .env("LD_LIBRARY_PATH", ldpath)
                .status()?
        };
    if ! st.success() {
        return Err(io::Error::new(io::ErrorKind::Other, "failed").into());
    }
    Ok(())
}

/// Wraps the code in a main function if none exists.
fn wrap_with_main(test: &mut Vec<String>, offset: usize) {
    let needs_wrapping = ! has_main(test);

    // Replace glibc-style error handling.
    test.iter_mut().for_each(|l| {
        if l == "#include <error.h>" { *l = "".into() }
    });

    let mut last_include = 0;
    for (n, line) in test.iter().enumerate() {
        if line.starts_with("#include") {
            last_include = n;
        }
    }

    test.insert(last_include + 1,
                "#define error(S, E, F, ...) do {                        \\\n\
                   fprintf (stderr, (F), __VA_ARGS__);                   \\\n\
                   int s = (S), e = (E);                                 \\\n\
                   if (e) { fprintf (stderr, \": %s\", strerror (e)); }    \\\n\
                   fprintf (stderr, \"\\n\");                               \\\n\
                   fflush (stderr);                                      \\\n\
                   if (s) { exit (s); }                                  \\\n\
                   } while (0)".into());

    if needs_wrapping {
        test.insert(last_include + 1, "int main() {".into());
    }
    test.insert(last_include + 2, format!("#line {}", last_include + offset
                                          + if needs_wrapping {1} else {0}));
    if needs_wrapping {
        test.push("}".into());
    }
    test.insert(0, "#include <string.h>".into());
    test.insert(0, "#include <stdlib.h>".into());
    test.insert(0, "#include <stdio.h>".into());
    test.insert(0, "#define _GNU_SOURCE".into());
}

/// Checks if the code contains a main function.
fn has_main(test: &mut Vec<String>) -> bool {
    test.iter().any(|line| {
        line.contains("main()") || line.contains("main ()")
            || line.contains("main(int argc, char **argv)")
            || line.contains("main (int argc, char **argv)")
    })
}
