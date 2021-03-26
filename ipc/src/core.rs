//! Contexts and errors.
//!
//! Sequoia tries to be useful for a wide variety of applications.
//! Therefore, we need you to provide a little information about the
//! context you are using Sequoia in.
//!
//! # Examples
//!
//! A context with reasonable defaults can be created using
//! `Context::new`:
//!
//! ```no_run
//! # use sequoia_ipc::core::{Context, Result};
//! # fn main() -> Result<()> {
//! let c = Context::new();
//! # Ok(())
//! # }
//! ```

#![doc(html_favicon_url = "https://docs.sequoia-pgp.org/favicon.png")]
#![doc(html_logo_url = "https://docs.sequoia-pgp.org/logo.svg")]
#![warn(missing_docs)]

use dirs;
use tempfile;

use std::io;
use std::path::{Path, PathBuf};

/// A `Context` for Sequoia.
///
/// # Examples
///
/// A context with reasonable defaults can be created using
/// `Context::new`:
///
/// ```no_run
/// # use sequoia_ipc::core::{Context, Result};
/// # fn main() -> Result<()> {
/// let c = Context::new()?;
/// # Ok(())
/// # }
/// ```
///
/// A context can be configured using the builder pattern with
/// `Context::configure`:
///
/// ```
/// # use sequoia_ipc::core::{Context, IPCPolicy, Result};
/// # fn main() -> Result<()> {
/// let c = Context::configure()
/// #           .ephemeral()
///             .ipc_policy(IPCPolicy::Robust)
///             .build()?;
/// # Ok(())
/// # }
/// ```
pub struct Context {
    home: PathBuf,
    lib: PathBuf,
    ipc_policy: IPCPolicy,
    ephemeral: bool,
    cleanup: bool,
}

impl Clone for Context {
    fn clone(&self) -> Self {
        Context {
            home: self.home.clone(),
            lib: self.lib.clone(),
            ipc_policy: self.ipc_policy,
            ephemeral: self.ephemeral,
            cleanup: false, // Prevent cleanup.
        }
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        use std::fs::remove_dir_all;

        if self.ephemeral && self.cleanup {
            let _ = remove_dir_all(&self.home);
        }
    }
}

/// Returns $PREXIX at compile-time, or a reasonable default prefix.
fn prefix() -> PathBuf {
    /* XXX: Windows support.  */
    PathBuf::from(option_env!("PREFIX").unwrap_or("/usr/local"))
}

impl Context {
    /// Creates a Context with reasonable defaults.
    pub fn new() -> Result<Self> {
        Self::configure().build()
    }

    /// Creates a Context that can be configured.
    ///
    /// The configuration is seeded like in `Context::new`, but can be
    /// modified.  A configuration has to be finalized using
    /// `.build()` in order to turn it into a Context.
    pub fn configure() -> Config {
        Config(Context {
            home: PathBuf::from(""),  // Defer computation of default.
            lib: prefix().join("lib").join("sequoia"),
            ipc_policy: IPCPolicy::Robust,
            ephemeral: false,
            cleanup: false,
        })
    }

    /// Returns the directory containing shared state.
    pub fn home(&self) -> &Path {
        &self.home
    }

    /// Returns the directory containing backend servers.
    pub fn lib(&self) -> &Path {
        &self.lib
    }

    /// Returns the IPC policy.
    pub fn ipc_policy(&self) -> &IPCPolicy {
        &self.ipc_policy
    }

    /// Returns whether or not this is an ephemeral context.
    pub fn ephemeral(&self) -> bool {
        self.ephemeral
    }
}

/// Represents a `Context` configuration.
///
/// A context can be configured using the builder pattern with
/// `Context::configure`:
///
/// ```
/// # use sequoia_ipc::core::{Context, IPCPolicy, Result};
/// # fn main() -> Result<()> {
/// let c = Context::configure()
/// #           .ephemeral()
///             .ipc_policy(IPCPolicy::Robust)
///             .build()?;
/// # Ok(())
/// # }
/// ```
///
/// You can create ephemeral context that are useful for tests and
/// one-shot programs:
///
/// ```
/// # use sequoia_ipc::core::{Context, Result};
/// # use std::path::Path;
/// # fn main() -> Result<()> {
/// let c = Context::configure().ephemeral().build()?;
/// let ephemeral_home = c.home().to_path_buf();
/// // Do some tests.
/// drop(c);
/// assert!(! ephemeral_home.exists());
/// # Ok(())
/// # }
/// ```
pub struct Config(Context);

impl Config {
    /// Finalizes the configuration and returns a `Context`.
    pub fn build(self) -> Result<Context> {
        let mut c = self.0;

        // As a special case, we defer the computation of the default
        // home, because env::home_dir() may fail.
        let home_not_set = c.home == PathBuf::from("");

        // If we have an ephemeral home, and home is not explicitly
        // set, create a temporary directory.  Ephemeral contexts can
        // share home directories, e.g. client and server processes
        // share one home.
        if c.ephemeral && home_not_set {
            let tmp = tempfile::Builder::new().prefix("sequoia").tempdir()?;
            c.home = tmp.into_path();
            c.cleanup = true;
        } else {
            if home_not_set {
                c.home =
                    dirs::home_dir().ok_or(
                        anyhow::anyhow!("Failed to get users home directory"))?
                .join(".sequoia");
            }
        }
        Ok(c)
    }

    /// Sets the directory containing shared state.
    pub fn home<P: AsRef<Path>>(mut self, home: P) -> Self {
        self.set_home(home);
        self
    }

    /// Sets the directory containing shared state.
    pub fn set_home<P: AsRef<Path>>(&mut self, home: P) -> PathBuf {
        ::std::mem::replace(&mut self.0.home, PathBuf::new().join(home))
    }

    /// Sets the directory containing backend servers.
    pub fn lib<P: AsRef<Path>>(mut self, lib: P) -> Self {
        self.set_lib(lib);
        self
    }

    /// Sets the directory containing backend servers.
    pub fn set_lib<P: AsRef<Path>>(&mut self, lib: P) -> PathBuf {
        ::std::mem::replace(&mut self.0.lib, PathBuf::new().join(lib))
    }

    /// Sets the IPC policy.
    pub fn ipc_policy(mut self, policy: IPCPolicy) -> Self {
        self.set_ipc_policy(policy);
        self
    }

    /// Sets the IPC policy.
    pub fn set_ipc_policy(&mut self, policy: IPCPolicy) -> IPCPolicy {
        ::std::mem::replace(&mut self.0.ipc_policy, policy)
    }

    /// Makes this context ephemeral.
    pub fn ephemeral(mut self) -> Self {
        self.set_ephemeral();
        self
    }

    /// Makes this context ephemeral.
    pub fn set_ephemeral(&mut self) -> bool {
        ::std::mem::replace(&mut self.0.ephemeral, true)
    }
}

/* Error handling.  */

/// Result type for Sequoia.
pub type Result<T> = ::std::result::Result<T, anyhow::Error>;

#[derive(thiserror::Error, Debug)]
/// Errors for Sequoia.
pub enum Error {
    /// An `io::Error` occurred.
    #[error("{0}")]
    IoError(#[from] io::Error),
}


/* IPC policy.  */

/// IPC policy for Sequoia.
///
/// With this policy you can control how Sequoia starts background
/// servers.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum IPCPolicy {
    /// External background servers only.
    ///
    /// We will always use external background servers.  If starting
    /// one fails, the operation will fail.
    ///
    /// The advantage is that we never spawn a thread.
    ///
    /// The disadvantage is that we need to locate the background
    /// server to start.  If you are distribute Sequoia with your
    /// application, make sure to include the binaries, and to
    /// configure the Context so that `context.lib()` points to the
    /// directory containing the binaries.
    External,

    /// Internal background servers only.
    ///
    /// We will always use internal background servers.  It is very
    /// unlikely that this fails.
    ///
    /// The advantage is that this method is very robust.  If you
    /// distribute Sequoia with your application, you do not need to
    /// ship the binary, and it does not matter what `context.lib()`
    /// points to.  This is very robust and convenient.
    ///
    /// The disadvantage is that we spawn a thread in your
    /// application.  Threads may play badly with `fork(2)`, file
    /// handles, and locks.  If you are not doing anything fancy,
    /// however, and only use fork-then-exec, you should be okay.
    Internal,

    /// Prefer external, fall back to internal.
    ///
    /// We will first try to use an external background server, but
    /// fall back on an internal one should that fail.
    ///
    /// The advantage is that if Sequoia is properly set up to find
    /// the background servers, we will use these and get the
    /// advantages of that approach.  Because we fail back on using an
    /// internal server, we gain the robustness of that approach.
    ///
    /// The disadvantage is that we may or may not spawn a thread in
    /// your application.  If this is unacceptable in your
    /// environment, use the `External` policy.
    Robust,
}

impl<'a> From<&'a IPCPolicy> for u8 {
    fn from(policy: &IPCPolicy) -> Self {
        match policy {
            &IPCPolicy::External => 0,
            &IPCPolicy::Internal => 1,
            &IPCPolicy::Robust => 2,
        }
    }
}


// XXX: TryFrom would be nice.
impl From<u8> for IPCPolicy {
    fn from(policy: u8) -> Self {
        match policy {
            0 => IPCPolicy::External,
            1 => IPCPolicy::Internal,
            2 => IPCPolicy::Robust,
            n => panic!("Bad IPC policy: {}", n),
        }
    }
}
