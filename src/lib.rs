// For #[derive(FromPrimitive)]
extern crate num;

#[macro_use]
extern crate num_derive;

#[macro_use]
extern crate nom;

extern crate flate2;
extern crate bzip2;

pub mod openpgp;
pub mod keys;
pub mod store;
pub mod net;
pub mod ffi;
pub mod armor;

mod buffered_reader;

use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// A `&Context` is required for many operations.
///
/// # Example
///
/// ```
/// # use sequoia::Context;
/// let c = Context::new("org.example.webmail").unwrap();
/// ```
pub struct Context {
    domain: String,
    home: PathBuf,
    lib: PathBuf,
}

fn prefix() -> PathBuf {
    /* XXX: Windows support.  */
    PathBuf::from(option_env!("PREFIX").or(Some("/usr/local")).unwrap())
}

impl Context {
    /// Creates a Context with reasonable defaults.
    ///
    /// `domain` should uniquely identify your application, it is
    /// strongly suggested to use a reversed fully qualified domain
    /// name that is associated with your application.
    pub fn new(domain: &str) -> io::Result<Self> {
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
}

/// Represents a `Context` configuration.
pub struct Config(Context);

impl Config {
    /// Finalizes the configuration and return a `Context`.
    pub fn build(self) -> io::Result<Context> {
        let c = self.0;
        fs::create_dir_all(c.home())?;
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

    /// Set the directory containing backend servers.
    pub fn lib<P: AsRef<Path>>(mut self, lib: P) -> Self {
        self.set_lib(lib);
        self
    }

    /// Sets the directory containing shared state.
    pub fn set_lib<P: AsRef<Path>>(&mut self, lib: P) {
        self.0.lib = PathBuf::new().join(lib);
    }
}
