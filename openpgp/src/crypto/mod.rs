//! Cryptographic primitives.

use std::io::Read;
use std::ops::Deref;
use std::fmt;
use std::cmp::Ordering;

use memsec;
use nettle::Hash;
use nettle::random::Yarrow;

use constants::HashAlgorithm;
use Result;

pub(crate) mod aead;
mod asymmetric;
pub(crate) mod ecdh;
mod hash;
pub mod mpis;
pub mod s2k;
pub(crate) mod symmetric;

pub use self::asymmetric::{
    Signer,
    KeyPair,
};

/// Holds a session key.
///
/// The session key is cleared when dropped.
#[derive(Clone, Eq)]
pub struct SessionKey(Box<[u8]>);

impl PartialEq for SessionKey {
    fn eq(&self, other: &Self) -> bool {
        secure_cmp(&self.0, &other.0) == Ordering::Equal
    }
}

impl SessionKey {
    /// Creates a new session key.
    pub fn new(rng: &mut Yarrow, size: usize) -> Self {
        let mut sk = vec![0; size];
        rng.random(&mut sk);
        sk.into()
    }
}

impl Deref for SessionKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Vec<u8>> for SessionKey {
    fn from(v: Vec<u8>) -> Self {
        SessionKey(v.into_boxed_slice())
    }
}

impl From<Box<[u8]>> for SessionKey {
    fn from(v: Box<[u8]>) -> Self {
        SessionKey(v)
    }
}

impl Drop for SessionKey {
    fn drop(&mut self) {
        unsafe {
            memsec::memzero(self.0.as_mut_ptr(), self.0.len());
        }
    }
}

impl fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if cfg!(debug_assertions) {
            write!(f, "SessionKey ({:?})", self.0)
        } else {
            f.write_str("SessionKey ( <Redacted> )")
        }
    }
}

/// Holds a password.
///
/// The password is cleared when dropped.
#[derive(Clone, Eq)]
pub struct Password(Box<[u8]>);

impl PartialEq for Password {
    fn eq(&self, other: &Self) -> bool {
        secure_cmp(&self.0, &other.0) == Ordering::Equal
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
        Password(v.into_boxed_slice())
    }
}

impl From<Box<[u8]>> for Password {
    fn from(v: Box<[u8]>) -> Self {
        Password(v)
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

impl Drop for Password {
    fn drop(&mut self) {
        unsafe {
            memsec::memzero(self.0.as_mut_ptr(), self.0.len());
        }
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if cfg!(debug_assertions) {
            write!(f, "Password ({:?})", self.0)
        } else {
            f.write_str("Password ( <Redacted> )")
        }
    }
}


/// Hash the specified file.
///
/// This is useful when verifying detached signatures.
pub fn hash_file<R: Read>(reader: R, algos: &[HashAlgorithm])
    -> Result<Vec<(HashAlgorithm, Box<Hash>)>>
{
    use std::mem;

    use ::parse::HashedReader;
    use ::parse::HashesFor;

    use buffered_reader::BufferedReader;
    use buffered_reader::BufferedReaderGeneric;

    let reader
        = BufferedReaderGeneric::with_cookie(
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
    use std::fs::File;

    let expected: HashMap<HashAlgorithm, &str> = [
        (HashAlgorithm::SHA1, "7945E3DA269C25C04F9EF435A5C0F25D9662C771"),
        (HashAlgorithm::SHA512, "DDE60DB05C3958AF1E576CD006A7F3D2C343DD8C8DECE789A15D148DF90E6E0D1454DE734F8343502CA93759F22C8F6221BE35B6BDE9728BD12D289122437CB1"),
    ].iter().cloned().collect();

    let result =
        hash_file(File::open(::path_to("a-cypherpunks-manifesto.txt")).unwrap(),
                  &expected.keys().cloned().collect::<Vec<HashAlgorithm>>())
        .unwrap();

    for (algo, mut hash) in result.into_iter() {
        let mut digest = vec![0u8; hash.digest_size()];
        hash.digest(&mut digest);

        assert_eq!(*expected.get(&algo).unwrap(),
                   &::conversions::to_hex(&digest[..], false));
    }
}

/// Time-constant comparison.
fn secure_cmp(a: &[u8], b: &[u8]) -> Ordering {
    let ord1 = a.len().cmp(&b.len());
    let ord2 = unsafe { memsec::memcmp(a.as_ptr(), b.as_ptr(), a.len()) };
    let ord2 = match ord2 {
        0 => Ordering::Equal,
        a if a < 0 => Ordering::Less,
        a if a > 0 => Ordering::Greater,
        _ => unreachable!(),
    };

    if ord1 == Ordering::Equal { ord2 } else { ord1 }
}
