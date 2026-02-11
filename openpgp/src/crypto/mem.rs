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
//!
//! Furthermore, operations involving secrets must be carried out in a
//! way that avoids leaking information.  For example, comparison
//! must be done in constant time with [`secure_cmp`].
//!
//!   [`secure_cmp`]: secure_cmp()

use std::cmp::{min, Ordering};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::ops::{Deref, DerefMut};

/// Whether to trace execution by default (on stderr).
const TRACE: bool = false;

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
// # Note on the implementation
//
// We use a boxed slice, then Box::leak the Box.  This takes the
// knowledge about the shape of the heap allocation away from Rust,
// preventing any optimization based on that.
//
// For example, Rust could conceivably compact the heap: The borrow
// checker knows when no references exist, and this is an excellent
// opportunity to move the object on the heap because only one pointer
// needs to be updated.
pub struct Protected(*mut [u8]);

// Safety: Box<[u8]> is Send and Sync, we do not expose any
// functionality that was not possible before, hence Protected may
// still be Send and Sync.
unsafe impl Send for Protected {}
unsafe impl Sync for Protected {}

impl Clone for Protected {
    fn clone(&self) -> Self {
        // Make a vector with the correct size to avoid potential
        // reallocations when turning it into a `Protected`.
        let mut p = Vec::with_capacity(self.len());
        p.extend_from_slice(self);
        p.into_boxed_slice().into()
    }
}

impl PartialEq for Protected {
    fn eq(&self, other: &Self) -> bool {
        secure_cmp(self, other) == Ordering::Equal
    }
}

impl Eq for Protected {}

impl Hash for Protected {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state);
    }
}

impl Protected {
    /// Allocates a chunk of protected memory.
    ///
    /// Effective protection of sensitive values requires avoiding any
    /// copying and reallocations.  Therefore, it is required to
    /// provide the size upfront at allocation time, then copying the
    /// secrets into this protected memory region.
    pub fn new(size: usize) -> Protected {
        vec![0; size].into_boxed_slice().into()
    }

    /// Converts to a buffer for modification.
    ///
    /// Don't expose `Protected` values unless you know what you're doing.
    pub(crate) fn expose_into_unprotected_vec(self) -> Vec<u8> {
        let mut p = Vec::with_capacity(self.len());
        p.extend_from_slice(&self);
        p
    }
}

impl Deref for Protected {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl AsRef<[u8]> for Protected {
    fn as_ref(&self) -> &[u8] {
        unsafe { &*self.0 }
    }
}

impl AsMut<[u8]> for Protected {
    fn as_mut(&mut self) -> &mut [u8] {
        unsafe { &mut *self.0 }
    }
}

impl DerefMut for Protected {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.as_mut()
    }
}

impl From<Vec<u8>> for Protected {
    fn from(mut v: Vec<u8>) -> Self {
        // Make a careful copy of the data.  We do this instead of
        // reusing v's allocation so that our allocation has the exact
        // size.
        let p = Protected::from(&v[..]);

        // Now clear the previous allocation.  Just to be safe, we
        // clear the whole allocation.
        let capacity = v.capacity();
        unsafe {
            // Safety: New size is equal to the capacity, and we
            // initialize all elements.
            v.set_len(capacity);
            memsec::memzero(v.as_mut_ptr(), capacity);
        }

        p
    }
}

/// Zeros N bytes on the stack after running the given closure.
///
/// Note: In general, don't use this function directly, use the more
/// convenient and robust macro zero_stack! instead, like so:
///
/// ```ignore
/// zero_stack!(128 bytes after running {
///     let mut a = [0; 6];
///     a.copy_from_slice(b"secret");
/// })
/// ```
///
/// Or, if you need to specify the type of the expression:
///
/// ```ignore
/// zero_stack!(128 bytes after running || -> () {
///     let mut a = [0; 6];
///     a.copy_from_slice(b"secret");
/// })
/// ```
///
/// If you must use this function directly, make sure to declare `fun`
/// as `#[inline(never)]`.
#[allow(dead_code)]
#[inline(never)]
pub(crate) fn zero_stack_after<const N: usize, T>(fun: impl FnOnce() -> T) -> T
{
    zero_stack::<N, T>(fun())
}

/// Zeros N bytes on the stack, returning the given value.
///
/// Note: In general, don't use this function directly.  This is only
/// effective if `v` has been computed by a function that has been
/// marked as `#[inline(never)]`.  However, since the inline attribute
/// is only a hint that may be freely ignored by the compiler, it is
/// sometimes necessary to use this function directly.
#[allow(dead_code)]
#[inline(never)]
pub(crate) fn zero_stack<const N: usize, T>(v: T) -> T {
    tracer!(TRACE, "zero_stack");
    let mut a = [0xffu8; N];
    t!("zeroing {:?}..{:?}", a.as_ptr(), unsafe { a.as_ptr().offset(N as _) });
    unsafe {
        memsec::memzero(a.as_mut_ptr(), a.len());
    }
    std::hint::black_box(a);
    v
}

/// Very carefully copies the slice.
///
/// The obvious `to.copy_from_slice(from);` indeed leaks secrets.
pub(crate) fn careful_memcpy(from: &[u8], to: &mut [u8]) {
    from.iter().zip(to.iter_mut()).for_each(|(f, t)| *t = *f);
}

impl From<Box<[u8]>> for Protected {
    fn from(v: Box<[u8]>) -> Self {
        Protected(Box::leak(v))
    }
}

impl From<&[u8]> for Protected {
    fn from(v: &[u8]) -> Self {
        let mut p = Protected::new(v.len());
        careful_memcpy(v, &mut p);
        p
    }
}

impl<const N: usize> From<[u8; N]> for Protected {
    fn from(mut v: [u8; N]) -> Self {
        let mut p = Protected::new(v.len());
        careful_memcpy(&v, &mut p);
        unsafe {
            memsec::memzero(v.as_mut_ptr(), v.len());
        }
        p
    }
}

impl Drop for Protected {
    fn drop(&mut self) {
        unsafe {
            let len = self.len();
            memsec::memzero(self.as_mut().as_mut_ptr(), len);
            drop(Box::from_raw(self.0));
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
/// # fn main() -> sequoia_openpgp::Result<()> {
/// use sequoia_openpgp::crypto::mem::Encrypted;
///
/// let e = Encrypted::new(vec![0, 1, 2].into())?;
/// e.map(|p| {
///     // e is temporarily decrypted and made available to the closure.
///     assert_eq!(p.as_ref(), &[0, 1, 2]);
///     // p is cleared once the function returns.
/// });
/// # Ok(()) }
/// ```
#[derive(Clone, Debug)]
pub struct Encrypted {
    ciphertext: Protected,
    salt: [u8; 32],
    plaintext_len: usize,
}
assert_send_and_sync!(Encrypted);

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

/// Opt out of memory encryption.
const DANGER_DISABLE_ENCRYPTED_MEMORY: bool = false;

/// The number of pages containing random bytes to derive the prekey
/// from.
const ENCRYPTED_MEMORY_PREKEY_PAGES: usize = 4;

/// Page size.
const ENCRYPTED_MEMORY_PAGE_SIZE: usize = 4096;

/// This module contains the code that needs to access the prekey.
///
/// Code outside of it cannot access it, because `PREKEY` is private.
mod has_access_to_prekey {
    use crate::Result;
    use crate::types::{AEADAlgorithm, HashAlgorithm, SymmetricAlgorithm};
    use crate::crypto::{aead, SessionKey};
    use super::*;

    /// Returns the pre-key.
    ///
    /// Access to this function is restricted to this module and its
    /// descendants.
    fn prekey() -> Result<&'static Box<[Box<[u8]>]>> {
        use std::sync::OnceLock;

        static PREKEY: OnceLock<Result<Box<[Box<[u8]>]>>>
            = OnceLock::new();
        PREKEY.get_or_init(|| -> Result<Box<[Box<[u8]>]>> {
            let mut pages = Vec::new();
            for _ in 0..ENCRYPTED_MEMORY_PREKEY_PAGES {
                let mut page = vec![0; ENCRYPTED_MEMORY_PAGE_SIZE];
                crate::crypto::random(&mut page)?;
                pages.push(page.into());
            }
            Ok(pages.into())
        }).as_ref().map_err(|e| anyhow::anyhow!("{}", e))
    }

    // Algorithms used for the memory encryption.
    //
    // The digest of the hash algorithm must be at least as large as
    // the size of the key used by the symmetric algorithm.  All
    // algorithms MUST be supported by the cryptographic library.
    const HASH_ALGO: HashAlgorithm = HashAlgorithm::SHA256;
    const SYMMETRIC_ALGO: SymmetricAlgorithm = SymmetricAlgorithm::AES256;

    impl Encrypted {
        /// Computes the sealing key used to encrypt the memory.
        fn sealing_key(salt: &[u8; 32]) -> Result<SessionKey> {
            let mut ctx = HASH_ALGO.context()
                .expect("Mandatory algorithm unsupported")
                .for_digest();
            ctx.update(salt);
            prekey()?
                .iter().for_each(|page| ctx.update(page));
            let mut sk: SessionKey = Protected::new(256/8).into();
            let _ = ctx.digest(&mut sk);
            Ok(sk)
        }

        /// Returns a zero nonce.
        ///
        /// The key is unique to every memory object, and we don't do
        /// chunking.  The nonce is zero.
        fn nonce(aead_algo: AEADAlgorithm) -> &'static [u8] {
            const NONCE_STORE: [u8; aead::MAX_NONCE_LEN] =
                [0u8; aead::MAX_NONCE_LEN];
            let nonce_len = aead_algo.nonce_size()
                .expect("Mandatory algorithm unsupported");
            debug_assert!(nonce_len >= 8 && nonce_len <= aead::MAX_NONCE_LEN);
            &NONCE_STORE[..nonce_len]
        }

        /// Encrypts the given chunk of memory.
        pub fn new(p: Protected) -> Result<Self> {
            if DANGER_DISABLE_ENCRYPTED_MEMORY {
                return Ok(Encrypted {
                    plaintext_len: p.len(),
                    ciphertext: p,
                    salt: Default::default(),
                });
            }

            let aead_algo = AEADAlgorithm::default();
            let mut salt = [0; 32];
            crate::crypto::random(&mut salt)?;
            let mut ciphertext = Protected::new(
                p.len() + aead_algo.digest_size().expect("supported"));

            aead_algo.context(SYMMETRIC_ALGO,
                              &Self::sealing_key(&salt)?,
                              &[],
                              Self::nonce(aead_algo))?
                .for_encryption()?
                .encrypt_seal(&mut ciphertext, &p)?;

            Ok(Encrypted {
                plaintext_len: p.len(),
                ciphertext,
                salt,
            })
        }

        /// Maps the given function over the temporarily decrypted
        /// memory.
        pub fn map<F, T>(&self, mut fun: F) -> T
            where F: FnMut(&Protected) -> T
        {
            if DANGER_DISABLE_ENCRYPTED_MEMORY {
                return fun(&self.ciphertext);
            }

            let aead_algo = AEADAlgorithm::default();
            let mut plaintext = Protected::new(self.plaintext_len);

            let r = aead_algo.context(SYMMETRIC_ALGO,
                              &Self::sealing_key(&self.salt).unwrap(),
                              &[],
                              Self::nonce(aead_algo)).unwrap()
                .for_decryption().unwrap()
                .decrypt_verify(&mut plaintext, &self.ciphertext);

            // Be careful not to leak partially decrypted plain text.
            if r.is_err() {
                drop(plaintext); // Securely erase partial plaintext.
                panic!("Encrypted memory modified or corrupted");
            }
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
