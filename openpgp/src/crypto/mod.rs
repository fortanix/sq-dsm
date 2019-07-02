//! Cryptographic primitives.

use std::io::Read;
use std::ops::{Deref, DerefMut};
use std::fmt;

use nettle::{self, Random, Yarrow};

use constants::HashAlgorithm;
use Result;

pub(crate) mod aead;
mod asymmetric;
pub(crate) mod ecdh;
pub mod hash;
mod keygrip;
pub use self::keygrip::Keygrip;
pub(crate) mod mem;
pub mod mpis;
pub mod s2k;
pub mod sexp;
pub(crate) mod symmetric;

pub use self::asymmetric::{
    Signer,
    Decryptor,
    KeyPair,
};

/// Holds a session key.
///
/// The session key is cleared when dropped.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionKey(mem::Protected);

impl SessionKey {
    /// Creates a new session key.
    pub fn new(rng: &mut Yarrow, size: usize) -> Self {
        let mut sk: mem::Protected = vec![0; size].into();
        rng.random(&mut sk);
        Self(sk)
    }

    /// Converts to a buffer for modification.
    pub unsafe fn into_vec(self) -> Vec<u8> {
        self.0.into_vec()
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
/// The password is cleared when dropped.
#[derive(Clone, PartialEq, Eq)]
pub struct Password(mem::Protected);

impl AsRef<[u8]> for Password {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for Password {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Vec<u8>> for Password {
    fn from(v: Vec<u8>) -> Self {
        Password(v.into())
    }
}

impl From<Box<[u8]>> for Password {
    fn from(v: Box<[u8]>) -> Self {
        Password(v.into())
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
        write!(f, "Password ({:?})", self.0)
    }
}


/// Hash the specified file.
///
/// This is useful when verifying detached signatures.
pub fn hash_file<R: Read>(reader: R, algos: &[HashAlgorithm])
    -> Result<Vec<(HashAlgorithm, Box<nettle::Hash>)>>
{
    use std::mem;

    use ::parse::HashedReader;
    use ::parse::HashesFor;

    use buffered_reader::BufferedReader;

    let reader
        = buffered_reader::Generic::with_cookie(
            reader, None, Default::default());

    let mut reader
        = HashedReader::new(reader, HashesFor::Signature, algos.to_vec());

    // Hash all of the data.
    reader.drop_eof()?;

    let mut hashes =
        mem::replace(&mut reader.cookie_mut().sig_group_mut().hashes,
                     Default::default());
    let hashes = hashes.drain().collect();
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
        hash_file(::std::io::Cursor::new(::tests::manifesto()),
                  &expected.keys().cloned().collect::<Vec<HashAlgorithm>>())
        .unwrap();

    for (algo, mut hash) in result.into_iter() {
        let mut digest = vec![0u8; hash.digest_size()];
        hash.digest(&mut digest);

        assert_eq!(*expected.get(&algo).unwrap(),
                   &::conversions::to_hex(&digest[..], false));
    }
}
