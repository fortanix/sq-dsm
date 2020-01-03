//! Cryptographic primitives.

use std::io::Read;
use std::ops::{Deref, DerefMut};
use std::fmt;

use nettle::{Random, Yarrow};

use crate::types::HashAlgorithm;
use crate::Result;

pub(crate) mod aead;
mod asymmetric;
pub(crate) mod ecdh;
pub mod hash;
mod keygrip;
pub use self::keygrip::Keygrip;
pub mod mem;
pub mod mpis;
mod s2k;
pub use s2k::S2K;
pub mod sexp;
pub(crate) mod symmetric;

pub use self::asymmetric::{
    Signer,
    Decryptor,
    KeyPair,
};

/// Fills the given buffer with random data.
pub fn random<B: AsMut<[u8]>>(mut buf: B) {
    use std::cell::RefCell;
    thread_local!(static RNG: RefCell<Yarrow> = Default::default());
    RNG.with(|rng| rng.borrow_mut().random(buf.as_mut()));
}

/// Holds a session key.
///
/// The session key is cleared when dropped.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionKey(mem::Protected);

impl SessionKey {
    /// Creates a new session key.
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
/// The password is encrypted in memory and only decrypted on demand.
/// See [`mem::Encrypted`] for details.
///
///  [`mem::Encrypted`]: mem/struct.Encrypted.html
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
    pub fn map<F, T>(&self, fun: F) -> T
        where F: FnMut(&mem::Protected) -> T
    {
        self.0.map(fun)
    }
}


/// Hash the specified file.
///
/// This is useful when verifying detached signatures.
pub fn hash_file<R: Read>(reader: R, algos: &[HashAlgorithm])
    -> Result<Vec<hash::Context>>
{
    use std::mem;

    use crate::parse::HashedReader;
    use crate::parse::HashesFor;

    use buffered_reader::BufferedReader;

    let reader
        = buffered_reader::Generic::with_cookie(
            reader, None, Default::default());

    let mut reader
        = HashedReader::new(reader, HashesFor::Signature, algos.to_vec());

    // Hash all of the data.
    reader.drop_eof()?;

    let hashes =
        mem::replace(&mut reader.cookie_mut().sig_group_mut().hashes,
                     Default::default());
    let hashes = hashes.into_iter().map(|(_, ctx)| ctx).collect();
    Ok(hashes)
}


#[test]
fn hash_file_test() {
    use std::collections::HashMap;

    let expected: HashMap<HashAlgorithm, &str> = [
        (HashAlgorithm::SHA1, "7945E3DA269C25C04F9EF435A5C0F25D9662C771"),
        (HashAlgorithm::SHA512, "DDE60DB05C3958AF1E576CD006A7F3D2C343DD8C8DECE789A15D148DF90E6E0D1454DE734F8343502CA93759F22C8F6221BE35B6BDE9728BD12D289122437CB1"),
    ].iter().cloned().collect();

    let result =
        hash_file(::std::io::Cursor::new(crate::tests::manifesto()),
                  &expected.keys().cloned().collect::<Vec<HashAlgorithm>>())
        .unwrap();

    for mut hash in result.into_iter() {
        let algo = hash.algo();
        let mut digest = vec![0u8; hash.digest_size()];
        hash.digest(&mut digest);

        assert_eq!(*expected.get(&algo).unwrap(),
                   &crate::fmt::to_hex(&digest[..], false));
    }
}
