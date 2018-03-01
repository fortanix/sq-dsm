//! Contexts and errors.
//!
//! Sequoia tries to be useful for a wide variety of applications.
//! Therefore, we need you to provide a little information about the
//! context you are using Sequoia in.
//!
/// # Example
///
/// A context with reasonable defaults can be created using
/// `Context::new`:
///
/// ```no_run
/// # use sequoia_core::{Context, Result};
/// # f().unwrap();
/// # fn f() -> Result<()> {
/// let c = Context::new("org.example.webmail")?;
/// # Ok(())
/// # }
/// ```

extern crate tempdir;
#[macro_use]
extern crate failure;

use std::env;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use tempdir::TempDir;

/// A `Context` for Sequoia.
///
/// # Example
///
/// A context with reasonable defaults can be created using
/// `Context::new`:
///
/// ```no_run
/// # use sequoia_core::{Context, Result};
/// # f().unwrap();
/// # fn f() -> Result<()> {
/// let c = Context::new("org.example.webmail")?;
/// # Ok(())
/// # }
/// ```
///
/// A context can be configured using the builder pattern with
/// `Context::configure`:
///
/// ```
/// # use sequoia_core::{Context, NetworkPolicy, Result};
/// # f().unwrap();
/// # fn f() -> Result<()> {
/// let c = Context::configure("org.example.webmail")
/// #           .ephemeral()
///             .network_policy(NetworkPolicy::Offline)
///             .build()?;
/// # Ok(())
/// # }
/// ```
pub struct Context {
    domain: String,
    home: PathBuf,
    lib: PathBuf,
    network_policy: NetworkPolicy,
    ipc_policy: IPCPolicy,
    ephemeral: bool,
    cleanup: bool,
}

impl Clone for Context {
    fn clone(&self) -> Self {
        Context {
            domain: self.domain.clone(),
            home: self.home.clone(),
            lib: self.lib.clone(),
            network_policy: self.network_policy,
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
    ///
    /// `domain` should uniquely identify your application, it is
    /// strongly suggested to use a reversed fully qualified domain
    /// name that is associated with your application.
    pub fn new(domain: &str) -> Result<Self> {
        Self::configure(domain).build()
    }

    /// Creates a Context that can be configured.
    ///
    /// `domain` should uniquely identify your application, it is
    /// strongly suggested to use a reversed fully qualified domain
    /// name that is associated with your application.
    ///
    /// The configuration is seeded like in `Context::new`, but can be
    /// modified.  A configuration has to be finalized using
    /// `.build()` in order to turn it into a Context.
    pub fn configure(domain: &str) -> Config {
        Config(Context {
            domain: String::from(domain),
            home: PathBuf::from(""),  // Defer computation of default.
            lib: prefix().join("lib").join("sequoia"),
            network_policy: NetworkPolicy::Encrypted,
            ipc_policy: IPCPolicy::Robust,
            ephemeral: false,
            cleanup: false,
        })
    }

    /// Returns the domain of the context.
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Returns the directory containing shared state.
    pub fn home(&self) -> &Path {
        &self.home
    }

    /// Returns the directory containing backend servers.
    pub fn lib(&self) -> &Path {
        &self.lib
    }

    /// Returns the network policy.
    pub fn network_policy(&self) -> &NetworkPolicy {
        &self.network_policy
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
/// # use sequoia_core::{Context, NetworkPolicy, Result};
/// # f().unwrap();
/// # fn f() -> Result<()> {
/// let c = Context::configure("org.example.webmail")
/// #           .ephemeral()
///             .network_policy(NetworkPolicy::Offline)
///             .build()?;
/// # Ok(())
/// # }
/// ```
///
/// You can create ephemeral context that are useful for tests and
/// one-shot programs:
///
/// ```
/// # use sequoia_core::{Context, Result};
/// # use std::path::Path;
/// # f().unwrap();
/// # fn f() -> Result<()> {
/// let c = Context::configure("org.example.my.test")
///             .ephemeral().build()?;
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
            let tmp = TempDir::new("sequoia")?;
            c.home = tmp.into_path();
            c.cleanup = true;
        } else {
            if home_not_set {
                c.home =
                    env::home_dir().ok_or(
                        format_err!("Failed to get users home directory"))?
                .join(".sequoia");
            }
            fs::create_dir_all(c.home())?;
        }
        Ok(c)
    }

    /// Sets the directory containing shared state.
    pub fn home<P: AsRef<Path>>(mut self, home: P) -> Self {
        self.set_home(home);
        self
    }

    /// Sets the directory containing shared state.
    pub fn set_home<P: AsRef<Path>>(&mut self, home: P) {
        self.0.home = PathBuf::new().join(home);
    }

    /// Sets the directory containing backend servers.
    pub fn lib<P: AsRef<Path>>(mut self, lib: P) -> Self {
        self.set_lib(lib);
        self
    }

    /// Sets the directory containing shared state.
    pub fn set_lib<P: AsRef<Path>>(&mut self, lib: P) {
        self.0.lib = PathBuf::new().join(lib);
    }

    /// Sets the network policy.
    pub fn network_policy(mut self, policy: NetworkPolicy) -> Self {
        self.set_network_policy(policy);
        self
    }

    /// Sets the network policy.
    pub fn set_network_policy(&mut self, policy: NetworkPolicy) {
        self.0.network_policy = policy;
    }

    /// Sets the IPC policy.
    pub fn ipc_policy(mut self, policy: IPCPolicy) -> Self {
        self.set_ipc_policy(policy);
        self
    }

    /// Sets the IPC policy.
    pub fn set_ipc_policy(&mut self, policy: IPCPolicy) {
        self.0.ipc_policy = policy;
    }

    /// Makes this context ephemeral.
    pub fn ephemeral(mut self) -> Self {
        self.set_ephemeral();
        self
    }

    /// Makes this context ephemeral.
    pub fn set_ephemeral(&mut self) {
        self.0.ephemeral = true;
    }
}

/* Error handling.  */

/// Result type for Sequoia.
pub type Result<T> = ::std::result::Result<T, failure::Error>;

#[derive(Fail, Debug)]
/// Errors for Sequoia.
pub enum Error {
    /// The network policy was violated by the given action.
    #[fail(display = "Unmet network policy requirement: {}", _0)]
    NetworkPolicyViolation(NetworkPolicy),

    /// An `io::Error` occurred.
    #[fail(display = "{}", _0)]
    IoError(#[cause] io::Error),
}

/* Network policy.  */

/// Network policy for Sequoia.
///
/// With this policy you can control how Sequoia accesses remote
/// systems.
#[derive(PartialEq, PartialOrd, Debug, Copy, Clone)]
pub enum NetworkPolicy {
    /// Do not contact remote systems.
    Offline,

    /// Only contact remote systems using anonymization techniques
    /// like TOR.
    Anonymized,

    /// Only contact remote systems using transports offering
    /// encryption and authentication like TLS.
    Encrypted,

    /// Contact remote systems even with insecure transports.
    Insecure,
}

impl fmt::Display for NetworkPolicy {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", match self {
            &NetworkPolicy::Offline    => "Offline",
            &NetworkPolicy::Anonymized => "Anonymized",
            &NetworkPolicy::Encrypted  => "Encrypted",
            &NetworkPolicy::Insecure   => "Insecure",
        })
    }
}

impl NetworkPolicy {
    pub fn assert(&self, action: NetworkPolicy) -> Result<()> {
        if action > *self {
            Err(Error::NetworkPolicyViolation(action).into())
        } else {
            Ok(())
        }
    }
}

impl<'a> From<&'a NetworkPolicy> for u8 {
    fn from(policy: &NetworkPolicy) -> Self {
        match policy {
            &NetworkPolicy::Offline    => 0,
            &NetworkPolicy::Anonymized => 1,
            &NetworkPolicy::Encrypted  => 2,
            &NetworkPolicy::Insecure   => 3,
        }
    }
}


// XXX: TryFrom would be nice.
impl From<u8> for NetworkPolicy {
    fn from(policy: u8) -> Self {
        match policy {
            0 => NetworkPolicy::Offline,
            1 => NetworkPolicy::Anonymized,
            2 => NetworkPolicy::Encrypted,
            3 => NetworkPolicy::Insecure,
            n => panic!("Bad network policy: {}", n),
        }
    }
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

#[macro_export]
macro_rules! assert_match {
    ( $error: pat = $expr:expr ) => {
        let x = $expr;
        if let $error = x {
            /* Pass.  */
        } else {
            panic!("Expected {}, got {:?}.", stringify!($error), x);
        }
    };
}

#[cfg(test)]
mod network_policy_test {
    use super::{Error, NetworkPolicy};

    fn ok(policy: NetworkPolicy, required: NetworkPolicy) {
        assert!(policy.assert(required).is_ok());
    }

    fn fail(policy: NetworkPolicy, required: NetworkPolicy) {
        assert_match!(Error::NetworkPolicyViolation(_)
                      = policy.assert(required)
                      .err().unwrap().downcast::<Error>().unwrap());
    }

    #[test]
    fn offline() {
        let p = NetworkPolicy::Offline;
        ok(p, NetworkPolicy::Offline);
        fail(p, NetworkPolicy::Anonymized);
        fail(p, NetworkPolicy::Encrypted);
        fail(p, NetworkPolicy::Insecure);
    }

    #[test]
    fn anonymized() {
        let p = NetworkPolicy::Anonymized;
        ok(p, NetworkPolicy::Offline);
        ok(p, NetworkPolicy::Anonymized);
        fail(p, NetworkPolicy::Encrypted);
        fail(p, NetworkPolicy::Insecure);
    }

    #[test]
    fn encrypted() {
        let p = NetworkPolicy::Encrypted;
        ok(p, NetworkPolicy::Offline);
        ok(p, NetworkPolicy::Anonymized);
        ok(p, NetworkPolicy::Encrypted);
        fail(p, NetworkPolicy::Insecure);
    }

    #[test]
    fn insecure() {
        let p = NetworkPolicy::Insecure;
        ok(p, NetworkPolicy::Offline);
        ok(p, NetworkPolicy::Anonymized);
        ok(p, NetworkPolicy::Encrypted);
        ok(p, NetworkPolicy::Insecure);
    }
}
