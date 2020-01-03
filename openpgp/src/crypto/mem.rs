//! Memory protection and encryption.

use std::cmp::{min, Ordering};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::ops::{Deref, DerefMut};
use std::pin::Pin;

use memsec;

/// Protected memory.
///
/// The memory is guaranteed not to be copied around, and is cleared
/// when the object is dropped.
#[derive(Clone)]
pub struct Protected(Pin<Box<[u8]>>);

impl PartialEq for Protected {
    fn eq(&self, other: &Self) -> bool {
        secure_cmp(&self.0, &other.0) == Ordering::Equal
    }
}

impl Eq for Protected {}

impl Hash for Protected {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl Protected {
    /// Converts to a buffer for modification.
    pub unsafe fn into_vec(self) -> Vec<u8> {
        self.iter().cloned().collect()
    }
}

impl Deref for Protected {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for Protected {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for Protected {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl DerefMut for Protected {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl From<Vec<u8>> for Protected {
    fn from(v: Vec<u8>) -> Self {
        Protected(Pin::new(v.into_boxed_slice()))
    }
}

impl From<Box<[u8]>> for Protected {
    fn from(v: Box<[u8]>) -> Self {
        Protected(Pin::new(v))
    }
}

impl From<&[u8]> for Protected {
    fn from(v: &[u8]) -> Self {
        Vec::from(v).into()
    }
}

impl Drop for Protected {
    fn drop(&mut self) {
        unsafe {
            memsec::memzero(self.0.as_mut_ptr(), self.0.len());
        }
    }
}

impl fmt::Debug for Protected {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if cfg!(debug_assertions) {
            write!(f, "{:?}", self.0)
        } else {
            f.write_str("[<Redacted>]")
        }
    }
}

/// Encrypted memory.
///
/// This type encrypts sensitive data, such as secret keys, in memory
/// while they are unused, and decrypts them on demand.  This protects
/// against cross-protection-boundary readout via microarchitectural
/// flaws like Spectre or Meltdown, via attacks on physical layout
/// like Rowbleed, and even via coldboot attacks.
///
/// The key insight is that these kinds of attacks are imperfect,
/// i.e. the recovered data contains bitflips, or the attack only
/// provides a probability for any given bit.  Applied to
/// cryptographic keys, these kind of imperfect attacks are enough to
/// recover the actual key.
///
/// This implementation on the other hand, derives a sealing key from
/// a large area of memory, the "pre-key", using a key derivation
/// function.  Now, any single bitflip in the readout of the pre-key
/// will avalanche through all the bits in the sealing key, rendering
/// it unusable with no indication of where the error occurred.
///
/// This kind of protection was pioneered by OpenSSH.  The commit
/// adding it can be found
/// [here](https://marc.info/?l=openbsd-cvs&m=156109087822676).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Encrypted {
    ciphertext: Protected,
    iv: Protected,
}

/// The number of pages containing random bytes to derive the prekey
/// from.
const ENCRYPTED_MEMORY_PREKEY_PAGES: usize = 4;

/// Page size.
const ENCRYPTED_MEMORY_PAGE_SIZE: usize = 4096;

/// This module contains the code that needs to access the prekey.
///
/// Code outside of it cannot access it, because `PREKEY` is private.
mod has_access_to_prekey {
    use std::io::{self, Cursor, Write};
    use lazy_static;
    use crate::types::{AEADAlgorithm, HashAlgorithm, SymmetricAlgorithm};
    use crate::crypto::{aead, SessionKey};
    use super::*;

    lazy_static::lazy_static! {
        static ref PREKEY: Box<[Box<[u8]>]> = {
            let mut pages = Vec::new();
            for _ in 0..ENCRYPTED_MEMORY_PREKEY_PAGES {
                let mut page = vec![0; ENCRYPTED_MEMORY_PAGE_SIZE];
                crate::crypto::random(&mut page);
                pages.push(page.into());
            }
            pages.into()
        };
    }

    // Algorithms used for the memory encryption.
    //
    // The digest of the hash algorithm must be at least as large as
    // the size of the key used by the symmetric algorithm.  All
    // algorithms MUST be supported by the cryptographic library.
    const HASH_ALGO: HashAlgorithm = HashAlgorithm::SHA256;
    const SYMMETRIC_ALGO: SymmetricAlgorithm = SymmetricAlgorithm::AES256;
    const AEAD_ALGO: AEADAlgorithm = AEADAlgorithm::EAX;

    impl Encrypted {
        /// Computes the sealing key used to encrypt the memory.
        fn sealing_key() -> SessionKey {
            let mut ctx = HASH_ALGO.context()
                .expect("Mandatory algorithm unsupported");
            PREKEY.iter().for_each(|page| ctx.update(page));
            let mut sk: SessionKey = vec![0; 256/8].into();
            ctx.digest(&mut sk);
            sk
        }

        /// Encrypts the given chunk of memory.
        pub fn new(p: Protected) -> Self {
            let mut iv =
                vec![0; AEAD_ALGO.iv_size()
                            .expect("Mandatory algorithm unsupported")];
            crate::crypto::random(&mut iv);

            let mut ciphertext = Vec::new();
            {
                let mut encryptor =
                    aead::Encryptor::new(1,
                                         SYMMETRIC_ALGO,
                                         AEAD_ALGO,
                                         4096,
                                         &iv,
                                         &Self::sealing_key(),
                                         &mut ciphertext)
                    .expect("Mandatory algorithm unsupported");
                encryptor.write_all(&p).unwrap();
                encryptor.finish().unwrap();
            }

            Encrypted {
                ciphertext: ciphertext.into(),
                iv: iv.into(),
            }
        }

        /// Maps the given function over the temporarily decrypted
        /// memory.
        pub fn map<F, T>(&self, mut fun: F) -> T
            where F: FnMut(&Protected) -> T
        {
            let mut plaintext = Vec::new();
            let mut decryptor =
                aead::Decryptor::new(1,
                                     SYMMETRIC_ALGO,
                                     AEAD_ALGO,
                                     4096,
                                     &self.iv,
                                     &Self::sealing_key(),
                                     Cursor::new(&self.ciphertext))
                .expect("Mandatory algorithm unsupported");
            io::copy(&mut decryptor, &mut plaintext)
                .expect("Encrypted memory modified or corrupted");
            let plaintext: Protected = plaintext.into();
            fun(&plaintext)
        }
    }
}

/// Time-constant comparison.
pub fn secure_cmp(a: &[u8], b: &[u8]) -> Ordering {
    let ord1 = a.len().cmp(&b.len());
    let ord2 = unsafe {
        memsec::memcmp(a.as_ptr(), b.as_ptr(), min(a.len(), b.len()))
    };
    let ord2 = match ord2 {
        0 => Ordering::Equal,
        a if a < 0 => Ordering::Less,
        a if a > 0 => Ordering::Greater,
        _ => unreachable!(),
    };

    if ord1 == Ordering::Equal { ord2 } else { ord1 }
}
