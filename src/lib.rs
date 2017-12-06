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

use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// A `&Context` is required for many operations.
///
/// # Example
///
/// ```
/// let c = Context::new("org.example.webmail").finalize().unwrap();
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
    /// Creates a `Pre(Context)` with reasonable defaults.
    ///
    /// `domain` should uniquely identify your application, it is
    /// strongly suggested to use a reversed fully qualified domain
    /// name that is associated with your application.
    ///
    /// `Pre(Context)`s can be modified, and have to be finalized in
    /// order to turn them into a Context.
    pub fn new(domain: &str) -> Pre {
        Pre(Context {
            domain: String::from(domain),
            home: env::home_dir().unwrap_or(env::temp_dir())
                .join(".sequoia"),
            lib: prefix().join("lib").join("sequoia"),
        })
    }

    /// Return the directory containing backend servers.
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Return the directory containing shared state and rendezvous
    /// nodes.
    pub fn home(&self) -> &Path {
        &self.home
    }

    /// Return the directory containing backend servers.
    pub fn lib(&self) -> &Path {
        &self.lib
    }
}

/// A `Pre(Context)` is a context object that can be modified.
pub struct Pre(Context);

impl Pre {
    /// Finalize the configuration and return a `Context`.
    pub fn finalize(self) -> io::Result<Context> {
        let c = self.0;
        fs::create_dir_all(c.home())?;
        Ok(c)
    }

    /// Set the directory containing shared state and rendezvous
    /// nodes.
    pub fn home<P: AsRef<Path>>(mut self, new: P) -> Self {
        self.0.home = PathBuf::new().join(new);
        self
    }

    /// Set the directory containing backend servers.
    pub fn lib<P: AsRef<Path>>(mut self, new: P) -> Self {
        self.0.lib = PathBuf::new().join(new);
        self
    }
}
