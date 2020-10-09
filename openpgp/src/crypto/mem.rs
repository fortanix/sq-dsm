//! Memory protection and encryption.
//!
//! Sequoia makes an effort to protect secrets stored in memory.  Even
//! though a process's memory should be protected from being read by an
//! adversary, there may be bugs in the program or the architecture
//! the program is running on that allow (partial) recovery of data.
//! Or, the process may be serialized to persistent storage, and its
//! memory may be inspected while it is not running.
//!
//! To reduce the window for these kind of exfiltrations, we use
//! [`Protected`] to clear the memory once it is no longer in use, and
//! [`Encrypted`] to protect long-term secrets like passwords and
//! secret keys.
//!
//!   [`Protected`]: struct.Protected.html
//!   [`Encrypted`]: struct.Encrypted.html
//!
//! Furthermore, operations involving secrets must be carried out in a
//! way that avoids leaking information.  For example, comparison
//! must be done in constant time with [`secure_cmp`].
//!
//!   [`secure_cmp`]: fn.secure_cmp.html

use std::cmp::{min, Ordering};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::ops::{Deref, DerefMut};

use memsec;

/// Protected memory.
///
/// The memory is guaranteed not to be copied around, and is cleared
/// when the object is dropped.
///
/// # Examples
///
/// ```rust
/// use sequoia_openpgp::crypto::mem::Protected;
///
/// {
///     let p: Protected = vec![0, 1, 2].into();
///     assert_eq!(p.as_ref(), &[0, 1, 2]);
/// }
///
/// // p is cleared once it goes out of scope.
/// ```
#[derive(Clone)]
pub struct Protected(Box<[u8]>);

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
    ///
    /// Don't expose `Protected` values unless you know what you're doing.
    pub(crate) fn expose_into_unprotected_vec(self) -> Vec<u8> {
        self.0.clone().into()
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
        // FIXME(xanewok): This can potentially realloc and leave a lingering
        // copy of the secret somewhere. It'd be great to explicitly move the
        // source data by copying it and zeroing it explicitly afterwards.
        Protected(v.into_boxed_slice())
    }
}

impl From<Box<[u8]>> for Protected {
    fn from(v: Box<[u8]>) -> Self {
        Protected(v)
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
///
/// # Examples
///
/// ```rust
/// use sequoia_openpgp::crypto::mem::Encrypted;
///
/// let e = Encrypted::new(vec![0, 1, 2].into());
/// e.map(|p| {
///     // e is temporarily decrypted and made available to the closure.
///     assert_eq!(p.as_ref(), &[0, 1, 2]);
///     // p is cleared once the function returns.
/// });
/// ```
#[derive(Clone, Debug)]
pub struct Encrypted {
    ciphertext: Protected,
    iv: Protected,
}

impl PartialEq for Encrypted {
    fn eq(&self, other: &Self) -> bool {
        // Protected::eq is time-constant.
        self.map(|a| other.map(|b| a == b))
    }
}

impl Eq for Encrypted {}

impl Hash for Encrypted {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.map(|k| Hash::hash(k, state));
    }
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
        1..=std::i32::MAX => Ordering::Greater,
        0 => Ordering::Equal,
        std::i32::MIN..=-1 => Ordering::Less,
    };

    if ord1 == Ordering::Equal { ord2 } else { ord1 }
}
