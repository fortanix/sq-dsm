//! Cryptographic primitives.
//!
//! This module contains cryptographic primitives as defined and used
//! by OpenPGP.  It abstracts over the cryptographic library chosen at
//! compile time.  Most of the time, it will not be necessary to
//! explicitly use types from this module directly, but they are used
//! in the API (e.g. [`Password`]).  Advanced users may use these
//! primitives to provide custom extensions to OpenPGP.
//!
//!   [`Password`]: struct.Password.html
//!
//! # Common Operations
//!
//!  - *Converting a string to a [`Password`]*: Use [`Password::from`].
//!  - *Create a session key*: Use [`SessionKey::new`].
//!  - *Use secret keys*: See the [`KeyPair` example].
//!
//!   [`Password::from`]: https://doc.rust-lang.org/std/convert/trait.From.html
//!   [`SessionKey::new`]: struct.SessionKey.html#method.new
//!   [`KeyPair` example]: struct.KeyPair.html#examples

use std::ops::{Deref, DerefMut};
use std::fmt;

pub(crate) mod aead;
mod asymmetric;
pub use self::asymmetric::{Signer, Decryptor, KeyPair};
mod backend;
pub use backend::random;
pub mod ecdh;
pub mod hash;
mod keygrip;
pub use self::keygrip::Keygrip;
pub mod mem;
pub mod mpi;
mod s2k;
pub use s2k::S2K;
pub mod sexp;
pub(crate) mod symmetric;

/// Holds a session key.
///
/// The session key is cleared when dropped.  Sequoia uses this type
/// to ensure that session keys are not left in memory returned to the
/// allocator.
///
/// Session keys can be generated using [`SessionKey::new`], or
/// converted from various types using [`From`].
///
///   [`SessionKey::new`]: #method.new
///   [`From`]: https://doc.rust-lang.org/std/convert/trait.From.html
#[derive(Clone, PartialEq, Eq)]
pub struct SessionKey(mem::Protected);

impl SessionKey {
    /// Creates a new session key.
    ///
    /// Creates a new session key `size` bytes in length initialized
    /// using a strong cryptographic number generator.
    ///
    /// # Examples
    ///
    /// This creates a session key and encrypts it for a given
    /// recipient key producing a [`PKESK`] packet.
    ///
    ///   [`PKESK`]: ../packet/enum.PKESK.html
    ///
    /// ```
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::types::{Curve, SymmetricAlgorithm};
    /// use openpgp::crypto::SessionKey;
    /// use openpgp::packet::prelude::*;
    ///
    /// let cipher = SymmetricAlgorithm::AES256;
    /// let sk = SessionKey::new(cipher.key_size().unwrap());
    ///
    /// let key: Key<key::SecretParts, key::UnspecifiedRole> =
    ///     Key4::generate_ecc(false, Curve::Cv25519)?.into();
    ///
    /// let pkesk: PKESK =
    ///     PKESK3::for_recipient(cipher, &sk, &key)?.into();
    /// # Ok(()) }
    /// ```
    pub fn new(size: usize) -> Self {
        let mut sk: mem::Protected = vec![0; size].into();
        random(&mut sk);
        Self(sk)
    }
}

impl Deref for SessionKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for SessionKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl DerefMut for SessionKey {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl AsMut<[u8]> for SessionKey {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl From<mem::Protected> for SessionKey {
    fn from(v: mem::Protected) -> Self {
        SessionKey(v)
    }
}

impl From<Vec<u8>> for SessionKey {
    fn from(v: Vec<u8>) -> Self {
        SessionKey(v.into())
    }
}

impl From<Box<[u8]>> for SessionKey {
    fn from(v: Box<[u8]>) -> Self {
        SessionKey(v.into())
    }
}

impl From<&[u8]> for SessionKey {
    fn from(v: &[u8]) -> Self {
        Vec::from(v).into()
    }
}

impl fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SessionKey ({:?})", self.0)
    }
}

/// Holds a password.
///
/// `Password`s can be converted from various types using [`From`].
/// The password is encrypted in memory and only decrypted on demand.
/// See [`mem::Encrypted`] for details.
///
///   [`From`]: https://doc.rust-lang.org/std/convert/trait.From.html
///   [`mem::Encrypted`]: mem/struct.Encrypted.html
///
/// # Examples
///
/// ```
/// use sequoia_openpgp as openpgp;
/// use openpgp::crypto::Password;
///
/// // Convert from a &str.
/// let p: Password = "hunter2".into();
///
/// // Convert from a &[u8].
/// let p: Password = b"hunter2"[..].into();
///
/// // Convert from a String.
/// let p: Password = String::from("hunter2").into();
///
/// // ...
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Password(mem::Encrypted);

impl From<Vec<u8>> for Password {
    fn from(v: Vec<u8>) -> Self {
        Password(mem::Encrypted::new(v.into()))
    }
}

impl From<Box<[u8]>> for Password {
    fn from(v: Box<[u8]>) -> Self {
        Password(mem::Encrypted::new(v.into()))
    }
}

impl From<String> for Password {
    fn from(v: String) -> Self {
        v.into_bytes().into()
    }
}

impl<'a> From<&'a str> for Password {
    fn from(v: &'a str) -> Self {
        v.to_owned().into()
    }
}

impl From<&[u8]> for Password {
    fn from(v: &[u8]) -> Self {
        Vec::from(v).into()
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if cfg!(debug_assertions) {
            self.map(|p| write!(f, "Password({:?})", p))
        } else {
            f.write_str("Password(<Encrypted>)")
        }
    }
}

impl Password {
    /// Maps the given function over the password.
    ///
    /// The password is stored encrypted in memory.  This function
    /// temporarily decrypts it for the given function to use.
    ///
    /// # Examples
    ///
    /// ```
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::crypto::Password;
    ///
    /// let p: Password = "hunter2".into();
    /// p.map(|p| assert_eq!(p.as_ref(), &b"hunter2"[..]));
    /// ```
    pub fn map<F, T>(&self, fun: F) -> T
        where F: FnMut(&mem::Protected) -> T
    {
        self.0.map(fun)
    }
}
