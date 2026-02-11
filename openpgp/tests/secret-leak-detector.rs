//! Scans a process memory for secret leaks.
//!
//! These tests attempt to detect secrets leaking into the stack and
//! heap without being zeroed after use.  To that end, we do the
//! following:
//!
//! 1. We break free(3) by using a custom allocator that leaks all
//!    heap allocations, so that memory will not be reused and we
//!    can robustly detect secret leaking into the heap because
//!    there is no risk of them being overwritten.
//!
//! 2. We do an operation involving secrets.  We use a fixed secret
//!    with a simple pattern (currently repeated '@'s) that is easy
//!    to find in memory later.
//!
//! 3. After the operation, we scan the processes memory (only
//!    readable and writable regions) for the secret.
//!
//! # Example of a test failure
//!
//! This shows the secret leaking into the stack:
//!
//! ```
//! test_ed25519: running test
//! [stack]: 139264 bytes
//! 7ffed1a8ee10  40 40 40 40 40 40 40 40  40 40 40 40 40 40 40 40   !!!!!!!!!!!!!!!!
//! 7ffed1a8ee20  40 40 40 40 40 40 40 40  40 40 40 40 40 40 40 40   !!!!!!!!!!!!!!!!
//! 7ffed1a90080  40 40 40 40 40 40 40 40  40 40 40 40 40 40 40 40   !!!!!!!!!!!!!!!!
//! 7ffed1a90090  40 40 40 40 40 40 40 40  40 40 40 40 40 40 40 40   !!!!!!!!!!!!!!!!
//! 7ffed1a900a0  40 40 40 40 40 40 40 40  40 40 40 40 40 40 40 40   !!!!!!!!!!!!!!!!
//! 7ffed1a900e0  40 40 40 40 40 40 40 40  40 40 40 40 40 40 40 40   !!!!!!!!!!!!!!!!
//! 7ffed1a90110  40 40 40 40 40 40 40 40  40 40 40 40 40 40 40 40   !!!!!!!!!!!!!!!!
//! 7ffed1a90120  40 40 40 40 40 40 40 40  40 40 40 40 40 40 40 40   !!!!!!!!!!!!!!!!
//! 7ffed1a90130  40 40 40 40 40 40 40 40  40 40 40 40 40 40 40 40   !!!!!!!!!!!!!!!!
//! 7ffed1a90170  40 40 40 40 40 40 40 40  40 40 40 40 40 40 40 40   !!!!!!!!!!!!!!!!
//! test_ed25519: secret leaked
//! test leak_tests::test_ed25519 ... FAILED
//! ```
//!
//! # Debugging secret leaks
//!
//! To find what code leaks the secret, we use rr, the lightweight
//! recording & deterministic debugging tool.  Deterministic is key
//! here, we can see where the secret leaks to, and then replay the
//! execution and set a watchpoint on the address, and know that it
//! will leak to the exact same address again:
//!
//! ```sh
//! $ rr record target/debug/examples/secret-leak-detector test_ed25519
//! [stack]: 139264 bytes
//! 7ffc9119dab0  40 40 40 40 40 40 40 40  40 40 40 40 40 40 40 40   !!!!!!!!!!!!!!!!
//! 7ffc9119dac0  40 40 40 40 40 40 40 40  40 40 40 40 40 40 40 40   !!!!!!!!!!!!!!!!
//! 7ffc9119ece0  40 40 40 40 40 40 40 40  40 40 40 40 40 40 40 40   !!!!!!!!!!!!!!!!
//! 7ffc9119ecf0  40 40 40 40 40 40 40 40  40 40 40 40 40 40 40 40   !!!!!!!!!!!!!!!!
//! 7ffc9119ed00  40 40 40 40 40 40 40 40  40 40 40 40 40 40 40 40   !!!!!!!!!!!!!!!!
//! 7ffc9119ed40  40 40 40 40 40 40 40 40  40 40 40 40 40 40 40 40   !!!!!!!!!!!!!!!!
//! 7ffc9119ed70  40 40 40 40 40 40 40 40  40 40 40 40 40 40 40 40   !!!!!!!!!!!!!!!!
//! 7ffc9119ed80  40 40 40 40 40 40 40 40  40 40 40 40 40 40 40 40   !!!!!!!!!!!!!!!!
//! 7ffc9119ed90  40 40 40 40 40 40 40 40  40 40 40 40 40 40 40 40   !!!!!!!!!!!!!!!!
//! 7ffc9119edd0  40 40 40 40 40 40 40 40  40 40 40 40 40 40 40 40   !!!!!!!!!!!!!!!!
//! test_ed25519: secret leaked
//! $ rr replay -d rust-gdb
//! [...]
//! (rr) watch *(0x7ffc9119dab0 as *u32) if *(0x7ffc9119dab0 as *u32) == 0x40404040
//! Hardware watchpoint 1: *0x7ffc9119dab0
//! (rr) c
//! Continuing.
//! test_ed25519: running test
//!
//! Hardware watchpoint 1: *0x7ffc9119dab0
//!
//! Old value = 0
//! New value = 1077952576
//! 0x000055a463e40969 in sha2::sha512::x86::sha512_update_x_avx (x=0x7ffc9119eba0, k64=...)
//!     at src/sha512/x86.rs:260
//! 260                 let mut t2 = $SRL64(t0, 1);
//! (rr) c
//! Continuing.
//!
//! Hardware watchpoint 1: *0x7ffc9119dab0
//!
//! Old value = -997709592
//! New value = 1077952576
//! 0x000055a463e3bde0 in sha2::sha512::x86::load_data_avx (x=0x7ffc9119e200, ms=0x7ffc9119e180,
//!     data=0x7ffc911a1658) at src/sha512/x86.rs:89
//! 89          unrolled_iterations!(0, 1, 2, 3, 4, 5, 6, 7);
//! (rr) c
//! Continuing.
//! [stack]: 139264 bytes
//! 7ffc9119dab0  40 40 40 40 40 40 40 40  40 40 40 40 40 40 40 40   !!!!!!!!!!!!!!!!
//! 7ffc9119dac0  40 40 40 40 40 40 40 40  40 40 40 40 40 40 40 40   !!!!!!!!!!!!!!!!
//! 7ffc9119ece0  40 40 40 40 40 40 40 40  40 40 40 40 40 40 40 40   !!!!!!!!!!!!!!!!
//! 7ffc9119ecf0  40 40 40 40 40 40 40 40  40 40 40 40 40 40 40 40   !!!!!!!!!!!!!!!!
//! 7ffc9119ed00  40 40 40 40 40 40 40 40  40 40 40 40 40 40 40 40   !!!!!!!!!!!!!!!!
//! 7ffc9119ed40  40 40 40 40 40 40 40 40  40 40 40 40 40 40 40 40   !!!!!!!!!!!!!!!!
//! 7ffc9119ed70  40 40 40 40 40 40 40 40  40 40 40 40 40 40 40 40   !!!!!!!!!!!!!!!!
//! 7ffc9119ed80  40 40 40 40 40 40 40 40  40 40 40 40 40 40 40 40   !!!!!!!!!!!!!!!!
//! 7ffc9119ed90  40 40 40 40 40 40 40 40  40 40 40 40 40 40 40 40   !!!!!!!!!!!!!!!!
//! 7ffc9119edd0  40 40 40 40 40 40 40 40  40 40 40 40 40 40 40 40   !!!!!!!!!!!!!!!!
//! test_ed25519: secret leaked
//!
//! Program received signal SIGKILL, Killed.
//! 0x0000000070000002 in syscall_traced ()
//! ```

#![allow(dead_code)]

use std::{
    env,
    io::{self, Write},
    path::{Path, PathBuf},
    process::Command,
    sync::OnceLock,
};
use anyhow::Result;

/// Locates the detector program.
///
/// The detector program is built as an example.  This has the
/// advantage that it is built using the same feature flags as the
/// test is invoked, and it is built with as little overhead as
/// possible.  The downside is that it may not have been built: if
/// cargo test --test secret-leak-detector is invoked to only run this
/// integration test, then the examples are not implicitly built
/// before running this test.
fn locate_detector() -> Option<&'static Path> {
    static NOFREE: OnceLock<Option<PathBuf>> = OnceLock::new();
    Some(NOFREE.get_or_init(|| -> Option<PathBuf> {
        let mut p = PathBuf::from(env::var_os("OUT_DIR")?);
        loop {
            let q = p.join("examples").join("secret-leak-detector");
            if q.exists() {
                break Some(q);
            }

            if let Some(parent) = p.parent() {
                p = parent.to_path_buf();
            } else {
                break None;
            }
        }
    }).as_ref()?.as_path())
}

/// Emits a message to stderr that is not captured by the test
/// framework, and returns success.
fn skip() -> Result<()> {
    // Write directly to stderr.  This way, we can emit the message
    // even though the test output is captured.
    writeln!(&mut io::stderr(),
             "Detector not built, skipping test: \
              run cargo build -p sequoia-openpgp \
              --example secret-leak-detector first")?;
    Ok(())
}

macro_rules! make_test {
    ($name: ident) => {
        #[cfg_attr(target_os = "linux", test)]
        fn $name() -> Result<()> {
            if let Some(d) = locate_detector() {
                let result = Command::new(d)
                    .arg(stringify!($name))
                    .output()?;

                if result.status.success() {
                    Ok(())
                } else {
                    io::stderr().write_all(&result.stderr)?;
                    Err(anyhow::anyhow!("leak detected"))
                }
            } else {
                skip()
            }
        }
    }
}

mod leak_tests {
    use super::*;

    /// Tests that we actually detect leaks.
    #[cfg_attr(target_os = "linux", test)]
    fn leak_basecase() -> Result<()> {
        if let Some(d) = locate_detector() {
            let result = Command::new(d)
                .arg("leak_basecase")
                .output()?;

            if ! result.status.success() {
                Ok(())
            } else {
                Err(anyhow::anyhow!("base case failed: no leak detected"))
            }
        } else {
            skip()
        }
    }

    // The tests.
    make_test!(clean_basecase);
    make_test!(test_memzero);
    make_test!(test_libc_memset);
    make_test!(test_protected);
    make_test!(test_protected_mpi);
    make_test!(test_session_key);
    make_test!(test_encrypted);
    make_test!(test_password);
    make_test!(test_ed25519);
    make_test!(test_aes_256_encryption);
    make_test!(test_aes_256_decryption);
}
