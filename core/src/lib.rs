//! Core functionality.

extern crate tempdir;

use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use tempdir::TempDir;

/// A `&Context` for Sequoia.
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
    ephemeral: bool,
    temp_dir: Option<TempDir>,
}

/// Returns $PREXIX, or a reasonable default prefix.
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
            home: env::home_dir().unwrap_or(env::temp_dir())
                .join(".sequoia"),
            lib: prefix().join("lib").join("sequoia"),
            network_policy: NetworkPolicy::Encrypted,
            ephemeral: false,
            temp_dir: None,
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
        if c.ephemeral {
            let tmp = TempDir::new("sequoia")?;
            c.home = tmp.path().clone().to_path_buf();
            c.temp_dir = Some(tmp);
        } else {
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
pub type Result<T> = ::std::result::Result<T, Error>;

/// Errors for Sequoia.
#[derive(Debug)]
pub enum Error {
    /// The network policy was violated by the given action.
    NetworkPolicyViolation(NetworkPolicy),
    /// An `io::Error` occured.
    IoError(io::Error),
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::IoError(error)
    }
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

impl NetworkPolicy {
    pub fn assert(&self, action: NetworkPolicy) -> Result<()> {
        if action > *self {
            Err(Error::NetworkPolicyViolation(action))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod network_policy_test {
    use super::{Error, NetworkPolicy};

    macro_rules! assert_match {
        (  $result:expr, $error: pat ) => {
            if let $error = $result {
                /* Pass.  */
            } else {
                panic!("Expected {}, got {:?}.", stringify!($error), $result);
            }
        };
    }


    #[test]
    fn offline() {
        let p = NetworkPolicy::Offline;
        assert_match!(p.assert(NetworkPolicy::Anonymized),
                      Err(Error::NetworkPolicyViolation(_)));
        assert_match!(p.assert(NetworkPolicy::Encrypted),
                      Err(Error::NetworkPolicyViolation(_)));
        assert_match!(p.assert(NetworkPolicy::Insecure),
                      Err(Error::NetworkPolicyViolation(_)));
    }

    #[test]
    fn anonymized() {
        let p = NetworkPolicy::Anonymized;
        assert_match!(p.assert(NetworkPolicy::Anonymized),
                      Ok(()));
        assert_match!(p.assert(NetworkPolicy::Encrypted),
                      Err(Error::NetworkPolicyViolation(_)));
        assert_match!(p.assert(NetworkPolicy::Insecure),
                      Err(Error::NetworkPolicyViolation(_)));
    }

    #[test]
    fn encrypted() {
        let p = NetworkPolicy::Encrypted;
        assert_match!(p.assert(NetworkPolicy::Anonymized),
                      Ok(()));
        assert_match!(p.assert(NetworkPolicy::Encrypted),
                      Ok(()));
        assert_match!(p.assert(NetworkPolicy::Insecure),
                      Err(Error::NetworkPolicyViolation(_)));
    }

    #[test]
    fn insecure() {
        let p = NetworkPolicy::Insecure;
        assert_match!(p.assert(NetworkPolicy::Anonymized),
                      Ok(()));
        assert_match!(p.assert(NetworkPolicy::Encrypted),
                      Ok(()));
        assert_match!(p.assert(NetworkPolicy::Insecure),
                      Ok(()));
    }
}
