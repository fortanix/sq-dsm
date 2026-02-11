//! Authenticated encryption with additional data.
//!
//! This module provides both a uniform streaming (chunked) and a
//! non-streaming (non-chunked) interface to authenticated symmetric
//! encryption and decryption using different block ciphers and AEAD
//! modes.
//!
//! Note: this is a very low-level interface.  It is not about OpenPGP
//! encryption or decryption.  If you are looking for that, see
//! [`crate::serialize::stream::Encryptor`] and
//! [`crate::parse::stream::Decryptor`] instead.
//!
//! # Examples
//!
//! This example demonstrates streaming (chunked) encryption and
//! decryption.
//!
//! ```rust
//! # use std::io::{Read, Write};
//! # use sequoia_openpgp::crypto::SessionKey;
//! # use sequoia_openpgp::crypto::{AEADAlgorithm, SymmetricAlgorithm};
//! # use sequoia_openpgp::crypto::aead::*;
//! # use sequoia_openpgp::parse::buffered_reader::{self, BufferedReader};
//! # fn main() -> sequoia_openpgp::Result<()> {
//! let text = b"Hello World :)";
//! let algo = SymmetricAlgorithm::default();
//! let aead = AEADAlgorithm::default();
//! let key = SessionKey::new(algo.key_size()?)?;
//! let chunk_size = 4096;
//! let schedule = SEIPv2Schedule::new(&key, algo, aead, chunk_size, b"salt")?;
//!
//! // Encrypt the `text`.
//! let mut ciphertext = Vec::new();
//! let mut encryptor = Encryptor::new(
//!     algo, aead, chunk_size, schedule.clone(), &mut ciphertext)?;
//! encryptor.write_all(text)?;
//! encryptor.finalize()?;
//!
//! // Decrypt the `ciphertext`.
//! let mut plaintext = Vec::new();
//! let reader = buffered_reader::Memory::with_cookie(
//!     &ciphertext, Default::default());
//!
//! let mut decryptor = Decryptor::new(
//!     algo, aead, chunk_size, schedule.clone(), reader.into_boxed())?;
//!
//! decryptor.read_to_end(&mut plaintext)?;
//!
//! // Check that we recovered it.
//! assert_eq!(&plaintext[..], text);
//! # Ok(()) }
//! ```
//!
//! This example demonstrates non-streaming (non-chunked) encryption
//! and decryption.
//!
//! ```rust
//! # use std::io::{Read, Write};
//! # use sequoia_openpgp::crypto::{self, SessionKey};
//! # use sequoia_openpgp::crypto::{AEADAlgorithm, SymmetricAlgorithm};
//! # use sequoia_openpgp::crypto::aead::*;
//! # fn main() -> sequoia_openpgp::Result<()> {
//! let text = b"Hello World :)";
//! let aad = b"Not secret, but authenticated";
//! let algo = SymmetricAlgorithm::default();
//! let aead = AEADAlgorithm::default();
//! let key = SessionKey::new(algo.key_size()?)?;
//! let mut nonce = vec![0; aead.nonce_size()?];
//! crypto::random(&mut nonce)?;
//!
//! // Encrypt the `text`.
//! let mut ciphertext = vec![0; text.len() + aead.digest_size()?];
//! aead.context(algo, &key, aad, &nonce)?
//!     .for_encryption()?
//!     .encrypt_seal(&mut ciphertext, text)?;
//!
//! // Decrypt the `ciphertext`.
//! let mut plaintext = vec![0; ciphertext.len() - aead.digest_size()?];
//! aead.context(algo, &key, aad, &nonce)?
//!     .for_decryption()?
//!     .decrypt_verify(&mut plaintext, &ciphertext)?;
//!
//! // Check that we recovered it.
//! assert_eq!(&plaintext[..], text);
//! # Ok(()) }
//! ```

use std::cmp;
use std::convert::TryInto;
use std::fmt;
use std::io;

use buffered_reader::BufferedReader;

use crate::types::{
    AEADAlgorithm,
    SymmetricAlgorithm,
};
use crate::utils::{
    write_be_u64,
};
use crate::Error;
use crate::Result;
use crate::crypto::SessionKey;
use crate::seal;
use crate::parse::Cookie;
use crate::crypto::backend::{Backend, interface::Kdf};

/// Maximum size of any Nonce used by an AEAD mode.
pub const MAX_NONCE_LEN: usize = 16;

/// Converts a chunk size to a usize.
pub(crate) fn chunk_size_usize(chunk_size: u64) -> Result<usize> {
    chunk_size.try_into()
        .map_err(|_| Error::InvalidOperation(
            format!("AEAD chunk size exceeds size of \
                     virtual memory: {}", chunk_size)).into())
}

/// Builds AEAD contexts.
pub struct Builder<'a> {
    symm: SymmetricAlgorithm,
    aead: AEADAlgorithm,
    key: &'a SessionKey,
    aad: &'a [u8],
    nonce: &'a [u8],
}

impl AEADAlgorithm {
    /// Creates a new AEAD context builder for this algorithm.
    ///
    /// # Errors
    ///
    /// Fails with [`Error::UnsupportedSymmetricAlgorithm`] if Sequoia
    /// does not support the given symmetric algorithm, and
    /// [`Error::UnsupportedAEADAlgorithm`] if Sequoia does not
    /// support the given AEAD algorithm, or combination of symmetric
    /// algorithm and AEAD algorithm.
    pub fn context<'s>(self,
                       symm: SymmetricAlgorithm,
                       key: &'s SessionKey,
                       aad: &'s [u8],
                       nonce: &'s [u8])
                       -> Result<Builder<'s>>
    {
        if ! symm.is_supported() {
            return Err(Error::UnsupportedSymmetricAlgorithm(symm).into());
        }

        use crate::crypto::backend::{Backend, interface::Aead};
        if ! Backend::supports_algo_with_symmetric(self, symm) {
            return Err(Error::UnsupportedAEADAlgorithm(self).into());
        }

        Ok(Builder {
            symm,
            aead: self,
            key,
            aad,
            nonce,
        })
    }
}

impl Builder<'_> {
    /// Returns an AEAD context for encryption.
    pub fn for_encryption(self) -> Result<EncryptionContext> {
        use crate::crypto::backend::{Backend, interface::Aead};
        Ok(EncryptionContext(
            Backend::context(self.aead, self.symm, self.key.as_protected(),
                             self.aad, self.nonce, CipherOp::Encrypt)?))
    }

    /// Returns an AEAD context for decryption.
    pub fn for_decryption(self) -> Result<DecryptionContext> {
        use crate::crypto::backend::{Backend, interface::Aead};
        Ok(DecryptionContext(
            Backend::context(self.aead, self.symm, self.key.as_protected(),
                             self.aad, self.nonce, CipherOp::Decrypt)?))
    }
}

/// A block cipher state and AEAD mode for encryption.
pub struct EncryptionContext(Box<dyn Context>);

impl EncryptionContext {
    /// Encrypts `src` to `dst`.
    ///
    /// Encrypts the given plaintext, and adds an authentication tag.
    ///
    /// `dst` must be exactly large enough to accommodate both the
    /// ciphertext and the digest, i.e. its length must be exactly
    /// `src.len() + self.digest_size()`.
    pub fn encrypt_seal(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()> {
        if dst.len() != src.len() + self.digest_size() {
            return Err(Error::InvalidOperation(
                "invalid buffer length".into()).into());
        }

        self.0.encrypt_seal(dst, src)
    }

    /// Length of the digest in bytes.
    pub fn digest_size(&self) -> usize {
        self.0.digest_size()
    }
}

/// A block cipher state and AEAD mode for decryption.
pub struct DecryptionContext(Box<dyn Context>);

impl DecryptionContext {
    /// Decrypts `src` to `dst`.
    ///
    /// Decrypts the given plaintext, and checks the authentication
    /// tag.  If the authentication tag is not correct, an error is
    /// returned.
    ///
    /// `src` contains both the ciphertext and the digest, i.e. its
    /// length must be exactly `dst.len() + self.digest_size()`.
    pub fn decrypt_verify(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()> {
        if dst.len() + self.digest_size() != src.len() {
            return Err(Error::InvalidOperation(
                "invalid buffer length".into()).into());
        }

        self.0.decrypt_verify(dst, src)
    }

    /// Length of the digest in bytes.
    pub fn digest_size(&self) -> usize {
        self.0.digest_size()
    }
}

/// A block cipher state and AEAD mode of operation.
///
/// # Sealed trait
///
/// This trait is [sealed] and cannot be implemented for types outside this crate.
/// Therefore it can be extended in a non-breaking way.
/// If you want to implement the trait inside the crate
/// you also need to implement the `seal::Sealed` marker trait.
///
/// [sealed]: https://rust-lang.github.io/api-guidelines/future-proofing.html#sealed-traits-protect-against-downstream-implementations-c-sealed
pub(crate) trait Context: seal::Sealed {
    /// Encrypts one chunk `src` to `dst` adding a digest.
    ///
    /// Note: `dst` must be exactly large enough to accommodate both
    /// the ciphertext and the digest!
    fn encrypt_seal(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()>;

    /// Length of the digest in bytes.
    #[allow(dead_code)] // Used in debug assertions.
    fn digest_size(&self) -> usize;

    /// Decrypt one chunk `src` to `dst` and verify that the digest is
    /// correct.
    fn decrypt_verify(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()>;
}

/// Whether AEAD cipher is used for data encryption or decryption.
pub(crate) enum CipherOp {
    /// Cipher is used for data encryption.
    Encrypt,
    /// Cipher is used for data decryption.
    Decrypt,
}

impl AEADAlgorithm {
    /// Returns the digest size of the AEAD algorithm.
    pub fn digest_size(&self) -> Result<usize> {
        use self::AEADAlgorithm::*;
        match self {
            // See https://www.rfc-editor.org/rfc/rfc9580.html#name-eax-mode
            EAX => Ok(16),
            // See https://www.rfc-editor.org/rfc/rfc9580.html#name-ocb-mode
            OCB => Ok(16),
            // See https://www.rfc-editor.org/rfc/rfc9580.html#name-gcm-mode
            GCM => Ok(16),
            _ => Err(Error::UnsupportedAEADAlgorithm(*self).into()),
        }
    }

    /// Returns the nonce size of the AEAD algorithm.
    pub fn nonce_size(&self) -> Result<usize> {
        use self::AEADAlgorithm::*;
        match self {
            // See https://www.rfc-editor.org/rfc/rfc9580.html#name-eax-mode
            EAX => Ok(16),
            // See https://www.rfc-editor.org/rfc/rfc9580.html#name-ocb-mode
            OCB => Ok(15),
            // See https://www.rfc-editor.org/rfc/rfc9580.html#name-gcm-mode
            GCM => Ok(12),
            _ => Err(Error::UnsupportedAEADAlgorithm(*self).into()),
        }
    }
}

/// Schedules key, nonce, and additional authenticated data (AAD) for
/// use with chunked AEAD encryption.
pub trait Schedule<T>: Send + Sync {
    /// Computes key, nonce, and AAD for a chunk.
    ///
    /// For every chunk, implementations must produce a key, a nonce,
    /// and the additional authenticated data (AAD), then invoke `fun`
    /// with key, nonce, and AAD.
    ///
    /// `index` is the current chunk index.
    fn chunk(&self,
             index: u64,
             fun: &mut dyn FnMut(&SessionKey, &[u8], &[u8]) -> Result<T>)
             -> Result<T>;

    /// Computes key, nonce, and AAD for the final authentication tag.
    ///
    /// When doing chunked AEAD, we need to protect against truncation
    /// of the chunked stream.  In OpenPGP this is done by adding a
    /// final empty chunk that includes the length of the stream in
    /// the additional authenticated data (AAD).
    ///
    /// Implementations must produce a key, a nonce, and the AAD
    /// (which SHOULD include the length of the stream), then invoke
    /// `fun` with key, nonce, and AAD.
    ///
    /// `index` is the current chunk index. `length` is the total
    /// length of the stream.
    fn finalizer(&self,
                 index: u64,
                 length: u64,
                 fun: &mut dyn FnMut(&SessionKey, &[u8], &[u8]) -> Result<T>)
                 -> Result<T>;
}

/// The key, nonce, and AAD schedule for the version 2 SEIPD packet.
///
/// See [Section 5.13.2 of RFC 9580].
///
///   [Section 5.13.2 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.13.2
#[derive(Clone)]
pub struct SEIPv2Schedule {
    key: SessionKey,
    nonce: Box<[u8]>,
    ad: [u8; Self::AD_PREFIX_LEN],
    nonce_len: usize,
}

impl SEIPv2Schedule {
    /// Minimum AEAD chunk size.
    ///
    /// Implementations MUST support chunk sizes down to 64B.
    const MIN_CHUNK_SIZE: usize = 1 << 6; // 64B

    /// Maximum AEAD chunk size.
    ///
    /// Implementations MUST support chunk sizes up to 4MiB.
    const MAX_CHUNK_SIZE: usize = 1 << 22; // 4MiB

    /// The length of the additional authenticated data.
    ///
    /// For the final tag, the stream length as big-endian u64 is
    /// appended to this prefix.
    const AD_PREFIX_LEN: usize = 5;

    /// Creates a new schedule to encrypt or decrypt version 2 SEIPD
    /// packets.
    pub fn new(session_key: &SessionKey,
               sym_algo: SymmetricAlgorithm,
               aead: AEADAlgorithm,
               chunk_size: usize,
               salt: &[u8]) -> Result<Self>
    {
        if !(Self::MIN_CHUNK_SIZE..=Self::MAX_CHUNK_SIZE).contains(&chunk_size)
        {
            return Err(Error::InvalidArgument(
                format!("Invalid AEAD chunk size: {}", chunk_size)).into());
        }

        // Derive the message key and initialization vector.
        let key_size = sym_algo.key_size()?;
        // The NONCE size is NONCE_LEN - 8 bytes taken from the KDF.
        let nonce_size = aead.nonce_size()? - 8;
        let mut key_nonce: SessionKey =
            vec![0; key_size + nonce_size].into();
        let ad = [
            0xd2, // Tag.
            2,    // Version.
            sym_algo.into(),
            aead.into(),
            chunk_size.trailing_zeros() as u8 - 6,
        ];
        Backend::hkdf_sha256(session_key, Some(salt), &ad, &mut key_nonce)?;
        let key = Vec::from(&key_nonce[..key_size]).into();
        let nonce = Vec::from(&key_nonce[key_size..]).into();

        Ok(Self {
            key,
            nonce,
            ad,
            nonce_len: aead.nonce_size()?,
        })
    }
}

impl<T> Schedule<T> for SEIPv2Schedule {
    fn chunk(&self,
             index: u64,
             fun: &mut dyn FnMut(&SessionKey, &[u8], &[u8]) -> Result<T>)
             -> Result<T>
    {
        // The nonce is the NONCE (NONCE_LEN - 8 bytes taken from the
        // KDF) concatenated with the chunk index.
        let index_be: [u8; 8] = index.to_be_bytes();
        let mut nonce_store = [0u8; MAX_NONCE_LEN];
        let nonce = &mut nonce_store[..self.nonce_len];
        nonce[..self.nonce.len()].copy_from_slice(&self.nonce);
        nonce[self.nonce.len()..].copy_from_slice(&index_be);

        fun(&self.key, nonce, &self.ad)
    }

    fn finalizer(&self,
                 index: u64,
                 length: u64,
                 fun: &mut dyn FnMut(&SessionKey, &[u8], &[u8]) -> Result<T>)
                 -> Result<T>
    {
        // Prepare the associated data.
        let mut ad = [0u8; Self::AD_PREFIX_LEN + 8];
        ad[..Self::AD_PREFIX_LEN].copy_from_slice(&self.ad);
        write_be_u64(&mut ad[Self::AD_PREFIX_LEN..], length);

        // The nonce is the NONCE (NONCE_LEN - 8 bytes taken from the
        // KDF) concatenated with the chunk index.
        let index_be: [u8; 8] = index.to_be_bytes();
        let mut nonce_store = [0u8; MAX_NONCE_LEN];
        let nonce = &mut nonce_store[..self.nonce_len];
        nonce[..self.nonce.len()].copy_from_slice(&self.nonce);
        nonce[self.nonce.len()..].copy_from_slice(&index_be);

        fun(&self.key, nonce, &ad)
    }
}

/// A `Read`er for decrypting AEAD-encrypted data.
pub(crate) struct InternalDecryptor<'a, 's> {
    // The encrypted data.
    source: Box<dyn BufferedReader<Cookie> + 'a>,

    sym_algo: SymmetricAlgorithm,
    aead: AEADAlgorithm,
    schedule: Box<dyn Schedule<DecryptionContext> + 's>,

    digest_size: usize,
    chunk_size: usize,
    chunk_index: u64,
    bytes_decrypted: u64,
    // Up to a chunk of unread data.
    buffer: Vec<u8>,
}
assert_send_and_sync!(InternalDecryptor<'_, '_>);


impl<'a, 's> InternalDecryptor<'a, 's> {
    /// Instantiate a new AEAD decryptor.
    ///
    /// `source` is the source to wrap.
    pub fn new<R, S>(sym_algo: SymmetricAlgorithm,
                     aead: AEADAlgorithm, chunk_size: usize,
                     schedule: S, source: R)
        -> Result<Self>
    where
        R: BufferedReader<Cookie> + 'a,
        S: Schedule<DecryptionContext> + 's,
    {
        Ok(InternalDecryptor {
            source: source.into_boxed(),
            sym_algo,
            aead,
            schedule: Box::new(schedule),
            digest_size: aead.digest_size()?,
            chunk_size,
            chunk_index: 0,
            bytes_decrypted: 0,
            buffer: Vec::with_capacity(chunk_size),
        })
    }

    // Note: this implementation tries *very* hard to make sure we don't
    // gratuitiously do a short read.  Specifically, if the return value
    // is less than `plaintext.len()`, then it is either because we
    // reached the end of the input or an error occurred.
    fn read_helper(&mut self, plaintext: &mut [u8]) -> Result<usize> {
        let mut pos = 0;

        // 1. Copy any buffered data.
        if !self.buffer.is_empty() {
            let to_copy = cmp::min(self.buffer.len(), plaintext.len());
            plaintext[..to_copy].copy_from_slice(&self.buffer[..to_copy]);
            crate::vec_drain_prefix(&mut self.buffer, to_copy);

            pos = to_copy;
            if pos == plaintext.len() {
                return Ok(pos);
            }
        }

        // 2. Decrypt the data a chunk at a time until we've filled
        // `plaintext`.
        //
        // Unfortunately, framing is hard.
        //
        // Recall: AEAD data is of the form:
        //
        //   [ chunk1 ][ tag1 ] ... [ chunkN ][ tagN ][ tagF ]
        //
        // And, all chunks are the same size except for the last
        // chunk, which may be shorter.
        //
        // The naive approach to decryption is to read a chunk and a
        // tag at a time.  Unfortunately, this may not work if the
        // last chunk is a partial chunk.
        //
        // Assume that the chunk size is 32 bytes and the digest size
        // is 16 bytes, and consider a message with 17 bytes of data.
        // That message will be encrypted as follows:
        //
        //   [ chunk1 ][ tag1 ][ tagF ]
        //       17B     16B     16B
        //
        // If we read a chunk and a digest, we'll successfully read 48
        // bytes of data.  Unfortunately, we'll have over read: the
        // last 15 bytes are from the final tag.
        //
        // To correctly handle this case, we have to make sure that
        // there are at least a tag worth of bytes left over when we
        // read a chunk and a tag.

        let n_chunks
            = (plaintext.len() - pos + self.chunk_size - 1) / self.chunk_size;
        let chunk_digest_size = self.chunk_size + self.digest_size;
        let final_digest_size = self.digest_size;

        for _ in 0..n_chunks {
            // Do a little dance to avoid exclusively locking
            // `self.source`.
            let to_read = chunk_digest_size + final_digest_size;
            let result = {
                match self.source.data(to_read) {
                    Ok(_) => Ok(self.source.buffer()),
                    Err(err) => Err(err),
                }
            };

            let check_final_tag;
            let chunk = match result {
                Ok(chunk) => {
                    if chunk.is_empty() {
                        // Exhausted source.
                        return Ok(pos);
                    }

                    if chunk.len() < final_digest_size {
                        return Err(Error::ManipulatedMessage.into());
                    }

                    check_final_tag = chunk.len() < to_read;

                    // Return the chunk.
                    &chunk[..cmp::min(chunk.len(), to_read) - final_digest_size]
                },
                Err(e) => return Err(e.into()),
            };

            assert!(chunk.len() <= chunk_digest_size);

            if chunk.is_empty() {
                // There is nothing to decrypt: all that is left is
                // the final tag.
            } else if chunk.len() <= self.digest_size {
                // A chunk has to include at least one byte and a tag.
                return Err(Error::ManipulatedMessage.into());
            } else {
                let mut aead = self.schedule.chunk(
                    self.chunk_index,
                    &mut |key, iv, ad| {
                        self.aead.context(self.sym_algo, key, ad, iv)?
                            .for_decryption()
                    })?;

                // Decrypt the chunk and check the tag.
                let to_decrypt = chunk.len() - self.digest_size;

                // If plaintext doesn't have enough room for the whole
                // chunk, then we have to double buffer.
                let double_buffer = to_decrypt > plaintext.len() - pos;
                let buffer = if double_buffer {
                    self.buffer.resize(to_decrypt, 0);
                    &mut self.buffer[..]
                } else {
                    &mut plaintext[pos..pos + to_decrypt]
                };

                aead.decrypt_verify(buffer, chunk)?;

                if double_buffer {
                    let to_copy = plaintext.len() - pos;
                    assert!(0 < to_copy);
                    assert!(to_copy < self.chunk_size);

                    plaintext[pos..pos + to_copy]
                        .copy_from_slice(&self.buffer[..to_copy]);
                    crate::vec_drain_prefix(&mut self.buffer, to_copy);
                    pos += to_copy;
                } else {
                    pos += to_decrypt;
                }

                // Increase index, update position in plaintext.
                self.chunk_index += 1;
                self.bytes_decrypted += to_decrypt as u64;

                // Consume the data only on success so that we keep
                // returning the error.
                let chunk_len = chunk.len();
                self.source.consume(chunk_len);
            }

            if check_final_tag {
                // We read the whole ciphertext, now check the final digest.
                let mut aead = self.schedule.finalizer(
                    self.chunk_index, self.bytes_decrypted,
                    &mut |key, iv, ad| {
                        self.aead.context(self.sym_algo, key, ad, iv)?
                            .for_decryption()
                    })?;

                let final_digest = self.source.data(final_digest_size)?;

                aead.decrypt_verify(&mut [], final_digest)?;

                // Consume the data only on success so that we keep
                // returning the error.
                self.source.consume(final_digest_size);
                break;
            }
        }

        Ok(pos)
    }
}

// Note: this implementation tries *very* hard to make sure we don't
// gratuitiously do a short read.  Specifically, if the return value
// is less than `plaintext.len()`, then it is either because we
// reached the end of the input or an error occurred.
impl io::Read for InternalDecryptor<'_, '_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.read_helper(buf) {
            Ok(n) => Ok(n),
            Err(e) => match e.downcast::<io::Error>() {
                // An io::Error.  Pass as-is.
                Ok(e) => Err(e),
                // A failure.  Wrap it.
                Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
            },
        }
    }
}

/// A `BufferedReader` that decrypts AEAD-encrypted data as it is
/// read.
pub struct Decryptor<'a, 's> {
    reader: buffered_reader::Generic<InternalDecryptor<'a, 's>, Cookie>,
}

impl<'a, 's> Decryptor<'a, 's> {
    /// Instantiate a new AEAD decryptor.
    ///
    /// `source` is the ciphertext to decrypt.
    pub fn new<S>(symm: SymmetricAlgorithm,
                  aead: AEADAlgorithm,
                  chunk_size: usize,
                  schedule: S,
                  source: Box<dyn BufferedReader<Cookie> + 'a>)
                  -> Result<Self>
    where
        S: Schedule<DecryptionContext> + 's,
    {
        Self::with_cookie(symm, aead, chunk_size, schedule, source,
                          Default::default())
    }

    /// Like [`Decryptor::new`], but sets a cookie.
    pub fn with_cookie<S>(symm: SymmetricAlgorithm,
                          aead: AEADAlgorithm,
                          chunk_size: usize,
                          schedule: S,
                          source: Box<dyn BufferedReader<Cookie> + 'a>,
                          cookie: Cookie)
                          -> Result<Self>
    where
        S: Schedule<DecryptionContext> + 's,
    {
        Ok(Decryptor {
            reader: buffered_reader::Generic::with_cookie(
                InternalDecryptor::new(
                    symm, aead, chunk_size, schedule, source)?,
                None, cookie),
        })
    }
}

impl io::Read for Decryptor<'_, '_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buf)
    }
}

impl fmt::Display for Decryptor<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Decryptor")
    }
}

impl fmt::Debug for Decryptor<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Decryptor")
            .field("reader", &self.get_ref().unwrap())
            .finish()
    }
}

impl BufferedReader<Cookie> for Decryptor<'_, '_> {
    fn buffer(&self) -> &[u8] {
        self.reader.buffer()
    }

    fn data(&mut self, amount: usize) -> io::Result<&[u8]> {
        self.reader.data(amount)
    }

    fn data_hard(&mut self, amount: usize) -> io::Result<&[u8]> {
        self.reader.data_hard(amount)
    }

    fn data_eof(&mut self) -> io::Result<&[u8]> {
        self.reader.data_eof()
    }

    fn consume(&mut self, amount: usize) -> &[u8] {
        self.reader.consume(amount)
    }

    fn data_consume(&mut self, amount: usize)
                    -> io::Result<&[u8]> {
        self.reader.data_consume(amount)
    }

    fn data_consume_hard(&mut self, amount: usize) -> io::Result<&[u8]> {
        self.reader.data_consume_hard(amount)
    }

    fn read_be_u16(&mut self) -> io::Result<u16> {
        self.reader.read_be_u16()
    }

    fn read_be_u32(&mut self) -> io::Result<u32> {
        self.reader.read_be_u32()
    }

    fn steal(&mut self, amount: usize) -> io::Result<Vec<u8>> {
        self.reader.steal(amount)
    }

    fn steal_eof(&mut self) -> io::Result<Vec<u8>> {
        self.reader.steal_eof()
    }

    fn get_mut(&mut self) -> Option<&mut dyn BufferedReader<Cookie>> {
        Some(&mut self.reader.reader_mut().source)
    }

    fn get_ref(&self) -> Option<&dyn BufferedReader<Cookie>> {
        Some(&self.reader.reader_ref().source)
    }

    fn into_inner<'b>(self: Box<Self>)
            -> Option<Box<dyn BufferedReader<Cookie> + 'b>> where Self: 'b {
        Some(self.reader.into_reader().source.into_boxed())
    }

    fn cookie_set(&mut self, cookie: Cookie) -> Cookie {
        self.reader.cookie_set(cookie)
    }

    fn cookie_ref(&self) -> &Cookie {
        self.reader.cookie_ref()
    }

    fn cookie_mut(&mut self) -> &mut Cookie {
        self.reader.cookie_mut()
    }
}

/// A `Write`r for AEAD encrypting data.
pub struct Encryptor<'s, W: io::Write> {
    inner: Option<W>,

    sym_algo: SymmetricAlgorithm,
    aead: AEADAlgorithm,
    schedule: Box<dyn Schedule<EncryptionContext> + 's>,

    digest_size: usize,
    chunk_size: usize,
    chunk_index: u64,
    bytes_encrypted: u64,
    // Up to a chunk of unencrypted data.
    buffer: Vec<u8>,

    // A place to write encrypted data into.
    scratch: Vec<u8>,
}
assert_send_and_sync!(Encryptor<'_, W> where W: io::Write);

impl<'s, W: io::Write> Encryptor<'s, W> {
    /// Instantiate a new AEAD encryptor.
    pub fn new<S>(sym_algo: SymmetricAlgorithm, aead: AEADAlgorithm,
                  chunk_size: usize, schedule: S, sink: W)
                  -> Result<Self>
    where
        S: Schedule<EncryptionContext> + 's,
    {
        Ok(Encryptor {
            inner: Some(sink),
            sym_algo,
            aead,
            schedule: Box::new(schedule),
            digest_size: aead.digest_size()?,
            chunk_size,
            chunk_index: 0,
            bytes_encrypted: 0,
            buffer: Vec::with_capacity(chunk_size),
            scratch: vec![0; chunk_size + aead.digest_size()?],
        })
    }

    // Like io::Write, but returns our Result.
    fn write_helper(&mut self, mut buf: &[u8]) -> Result<usize> {
        if self.inner.is_none() {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe,
                                      "Inner writer was taken").into());
        }
        let amount = buf.len();

        // First, fill the buffer if there is something in it.
        if !self.buffer.is_empty() {
            let n = cmp::min(buf.len(), self.chunk_size - self.buffer.len());
            self.buffer.extend_from_slice(&buf[..n]);
            assert!(self.buffer.len() <= self.chunk_size);
            buf = &buf[n..];

            // And possibly encrypt the chunk.
            if self.buffer.len() == self.chunk_size {
                let mut aead =
                    self.schedule.chunk(self.chunk_index, &mut |key, iv, ad| {
                        self.aead.context(self.sym_algo, key, ad, iv)?
                            .for_encryption()
                    })?;

                let inner = self.inner.as_mut().unwrap();

                // Encrypt the chunk.
                aead.encrypt_seal(&mut self.scratch, &self.buffer)?;
                self.bytes_encrypted += self.chunk_size as u64;
                self.chunk_index += 1;
                // XXX: clear plaintext buffer.
                crate::vec_truncate(&mut self.buffer, 0);
                inner.write_all(&self.scratch)?;
            }
        }

        // Then, encrypt all whole chunks.
        for chunk in buf.chunks(self.chunk_size) {
            if chunk.len() == self.chunk_size {
                // Complete chunk.
                let mut aead =
                    self.schedule.chunk(self.chunk_index, &mut |key, iv, ad| {
                        self.aead.context(self.sym_algo, key, ad, iv)?
                            .for_encryption()
                    })?;

                let inner = self.inner.as_mut().unwrap();

                // Encrypt the chunk.
                aead.encrypt_seal(&mut self.scratch, chunk)?;
                self.bytes_encrypted += self.chunk_size as u64;
                self.chunk_index += 1;
                inner.write_all(&self.scratch)?;
            } else {
                // Stash for later.
                assert!(self.buffer.is_empty());
                self.buffer.extend_from_slice(chunk);
            }
        }

        Ok(amount)
    }

    /// Finish encryption and write last partial block.
    pub fn finalize(mut self) -> Result<W> {
        self.finalize_intern()
    }

    /// Like [`Self::finalize`], but with a mutable reference.
    ///
    /// This can be used in [`Self::drop`], whereas [`Self::finalize`]
    /// consumes self, and is convenient for callers because consuming
    /// self makes Rust understand that any borrow on the writer
    /// terminates.
    fn finalize_intern(&mut self) -> Result<W> {
        if let Some(mut inner) = self.inner.take() {
            if !self.buffer.is_empty() {
                let mut aead =
                    self.schedule.chunk(self.chunk_index, &mut |key, iv, ad| {
                        self.aead.context(self.sym_algo, key, ad, iv)?
                            .for_encryption()
                    })?;

                // Encrypt the chunk.
                unsafe {
                    // Safety: remaining data is less than the chunk
                    // size.  The vector has capacity chunk size plus
                    // digest size.
                    debug_assert!(self.buffer.len() < self.chunk_size);
                    self.scratch.set_len(self.buffer.len() + self.digest_size)
                }
                aead.encrypt_seal(&mut self.scratch, &self.buffer)?;
                self.bytes_encrypted += self.buffer.len() as u64;
                self.chunk_index += 1;
                // XXX: clear plaintext buffer
                crate::vec_truncate(&mut self.buffer, 0);
                inner.write_all(&self.scratch)?;
            }

            // Write final digest.
            let mut aead = self.schedule.finalizer(
                self.chunk_index, self.bytes_encrypted,
                &mut |key, iv, ad| {
                    self.aead.context(self.sym_algo, key, ad, iv)?
                        .for_encryption()
                })?;
            debug_assert!(self.digest_size <= self.scratch.len());
            aead.encrypt_seal(&mut self.scratch[..self.digest_size], b"")?;
            inner.write_all(&self.scratch[..self.digest_size])?;

            Ok(inner)
        } else {
            Err(io::Error::new(io::ErrorKind::BrokenPipe,
                               "Inner writer was taken").into())
        }
    }

    /// Acquires a reference to the underlying writer.
    pub(crate) fn get_ref(&self) -> Option<&W> {
        self.inner.as_ref()
    }

    /// Acquires a mutable reference to the underlying writer.
    #[allow(dead_code)]
    pub(crate) fn get_mut(&mut self) -> Option<&mut W> {
        self.inner.as_mut()
    }
}

impl<W: io::Write> io::Write for Encryptor<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.write_helper(buf) {
            Ok(n) => Ok(n),
            Err(e) => match e.downcast::<io::Error>() {
                // An io::Error.  Pass as-is.
                Ok(e) => Err(e),
                // A failure.  Wrap it.
                Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
            },
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        // It is not clear how we can implement this, because we can
        // only operate on chunk sizes.  We will, however, ask our
        // inner writer to flush.
        if let Some(ref mut inner) = self.inner {
            inner.flush()
        } else {
            Err(io::Error::new(io::ErrorKind::BrokenPipe,
                               "Inner writer was taken"))
        }
    }
}

impl<W: io::Write> Drop for Encryptor<'_, W> {
    fn drop(&mut self) {
        // Unfortunately, we cannot handle errors here.  If error
        // handling is a concern, call finalize() and properly handle
        // errors there.
        let _ = self.finalize_intern();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    /// This test tries to encrypt, then decrypt some data.
    #[test]
    fn roundtrip() {
        // EAX and OCB can be used with all symmetric algorithms using
        // a 16-byte block size.
        for sym_algo in [SymmetricAlgorithm::AES128,
                         SymmetricAlgorithm::AES192,
                         SymmetricAlgorithm::AES256,
                         SymmetricAlgorithm::Twofish,
                         SymmetricAlgorithm::Camellia128,
                         SymmetricAlgorithm::Camellia192,
                         SymmetricAlgorithm::Camellia256]
                         .iter()
                         .filter(|algo| algo.is_supported()) {

            for aead in [
                AEADAlgorithm::EAX,
                AEADAlgorithm::OCB,
                AEADAlgorithm::GCM,
            ].iter().filter(|algo| {
                use crate::crypto::backend::{Backend, interface::Aead};
                Backend::supports_algo_with_symmetric(**algo, *sym_algo)
            }) {
                let chunk_size = 64;
                let mut key = vec![0; sym_algo.key_size().unwrap()];
                crate::crypto::random(&mut key).unwrap();
                let key: SessionKey = key.into();
                let mut iv = vec![0; aead.nonce_size().unwrap()];
                crate::crypto::random(&mut iv).unwrap();

                let mut ciphertext = Vec::new();
                {
                    let schedule = SEIPv2Schedule::new(
                        &key,
                        *sym_algo,
                        *aead,
                        chunk_size,
                        &iv).expect("valid parameters");
                    let mut encryptor = Encryptor::new(*sym_algo,
                                                       *aead,
                                                       chunk_size,
                                                       schedule,
                                                       &mut ciphertext)
                        .unwrap();

                    encryptor.write_all(crate::tests::manifesto()).unwrap();
                }

                let mut plaintext = Vec::new();
                {
                    let cur = buffered_reader::Memory::with_cookie(
                        &ciphertext, Default::default());
                    let schedule = SEIPv2Schedule::new(
                        &key,
                        *sym_algo,
                        *aead,
                        chunk_size,
                        &iv).expect("valid parameters");
                    let mut decryptor = Decryptor::new(*sym_algo,
                                                       *aead,
                                                       chunk_size,
                                                       schedule,
                                                       cur.into_boxed())
                        .unwrap();

                    decryptor.read_to_end(&mut plaintext).unwrap();
                }

                assert_eq!(&plaintext[..], crate::tests::manifesto());
            }
        }
    }
}
