//! Unauthenticated symmetric encryption and decryption.
//!
//! This module provides a uniform streaming interface to
//! unauthenticated symmetric encryption and decryption using
//! different block ciphers and padding modes.
//!
//! Note: this is a very low-level interface.  It is not about OpenPGP
//! encryption or decryption.  If you are looking for that, see
//! [`crate::serialize::stream::Encryptor`] and
//! [`crate::parse::stream::Decryptor`] instead.
//!
//! # Examples
//!
//! ```rust
//! # use std::io::{Read, Write};
//! # use sequoia_openpgp::crypto::SessionKey;
//! # use sequoia_openpgp::crypto::SymmetricAlgorithm;
//! # use sequoia_openpgp::crypto::symmetric::*;
//! # use sequoia_openpgp::parse::buffered_reader;
//! # fn main() -> sequoia_openpgp::Result<()> {
//! let text = b"Hello World :)";
//! let algo = SymmetricAlgorithm::AES128;
//! let key = SessionKey::new(algo.key_size()?)?;
//!
//! // Encrypt the `text`.
//! let mut ciphertext = Vec::new();
//! let mut encryptor = Encryptor::new(
//!     algo, BlockCipherMode::CFB, PaddingMode::None,
//!     &key, None, &mut ciphertext)?;
//! encryptor.write_all(text)?;
//! encryptor.finalize()?;
//!
//! // Decrypt the `ciphertext`.
//! let mut plaintext = Vec::new();
//! let reader = buffered_reader::Memory::with_cookie(
//!     &ciphertext, Default::default());
//!
//! let mut decryptor = Decryptor::new(
//!     algo, BlockCipherMode::CFB, UnpaddingMode::None,
//!     &key, None, reader)?;
//!
//! decryptor.read_to_end(&mut plaintext)?;
//!
//! // Check that we recovered it.
//! assert_eq!(&plaintext[..], text);
//! # Ok(()) }
//! ```

use std::io;
use std::cmp;
use std::fmt;

use crate::{Error, Result};
use crate::SymmetricAlgorithm;
use crate::vec_resize;
use crate::{
    crypto::SessionKey,
    parse::Cookie,
};

use buffered_reader::BufferedReader;

/// Block cipher mode of operation.
///
/// Block modes govern how a block cipher processes data spanning
/// multiple blocks.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BlockCipherMode {
    /// Full-block cipher feedback mode.
    CFB,

    /// Cipher block chaining.
    CBC,

    /// Electronic codebook mode.
    ///
    /// Note: do not use as-is.  Patterns in the plaintext will be
    /// visible as patterns in the ciphertext.  Mind the penguin!
    ECB,
}

impl BlockCipherMode {
    /// Returns whether the mode requires padding.
    ///
    /// Some modes only operate on complete blocks, so if the
    /// plaintext's length is not a multiple of the symmetric
    /// algorithm's block size, padding is required.
    pub fn requires_padding(&self) -> bool {
        match self {
            BlockCipherMode::CFB => false,
            BlockCipherMode::CBC => true,
            BlockCipherMode::ECB => true,
        }
    }
}

/// Padding mode for encryption.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PaddingMode {
    /// No padding.
    ///
    /// If the [`BlockCipherMode`] requires padding of incomplete
    /// final blocks (see [`BlockCipherMode::requires_padding`]), and
    /// you chose no padding, you need to ensure that the plaintext's
    /// length is a multiple of the symmetric algorithm's block size.
    /// Otherwise, an error is returned.
    None,
}

/// Padding mode for decryption.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum UnpaddingMode {
    /// No padding.
    ///
    /// If the [`BlockCipherMode`] requires padding of incomplete
    /// final blocks (see [`BlockCipherMode::requires_padding`]),
    /// padding is required unless the plaintext's length is a
    /// multiple of the symmetric algorithm's block size.  Otherwise,
    /// an error is returned.
    None,
}

/// A context representing symmetric algorithm state and block cipher
/// mode.
pub(crate) trait Context: Send + Sync {
    /// Encrypt a single block `src` to a ciphertext block `dst`.
    /// The `dst` and `src` buffers are expected to be at least as large as
    /// the block size of the underlying cipher.
    fn encrypt(
        &mut self,
        dst: &mut [u8],
        src: &[u8],
    ) -> Result<()>;

    /// Decrypt a single ciphertext block `src` to a plaintext block `dst`.
    /// The `dst` and `src` buffers are expected to be at least as large as
    /// the block size of the underlying cipher.
    fn decrypt(
        &mut self,
        dst: &mut [u8],
        src: &[u8],
    ) -> Result<()>;
}

/// A `Read`er for decrypting symmetrically encrypted data.
pub(crate) struct InternalDecryptor<'a> {
    // The encrypted data.
    source: Box<dyn BufferedReader<Cookie> + 'a>,

    mode: BlockCipherMode,
    padding: UnpaddingMode,
    dec: Box<dyn Context>,
    block_size: usize,
    // Up to a block of unread data.
    buffer: Vec<u8>,
}
assert_send_and_sync!(InternalDecryptor<'_>);

impl<'a> InternalDecryptor<'a> {
    /// Instantiate a new symmetric decryptor.
    pub fn new<R>(algo: SymmetricAlgorithm,
                  mode: BlockCipherMode,
                  padding: UnpaddingMode,
                  key: &SessionKey,
                  iv: Option<&[u8]>,
                  source: R)
                  -> Result<Self>
    where
        R: BufferedReader<Cookie> + 'a,
    {
        use crate::crypto::backend::{Backend, interface::Symmetric};
        let block_size = algo.block_size()?;
        let dec = Backend::decryptor(algo, mode, key.as_protected(), iv)?;

        Ok(InternalDecryptor {
            source: source.into_boxed(),
            mode,
            padding,
            dec,
            block_size,
            buffer: Vec::with_capacity(block_size),
        })
    }
}

// Note: this implementation tries *very* hard to make sure we don't
// gratuitiously do a short read.  Specifically, if the return value
// is less than `plaintext.len()`, then it is either because we
// reached the end of the input or an error occurred.
impl<'a> io::Read for InternalDecryptor<'a> {
    fn read(&mut self, plaintext: &mut [u8]) -> io::Result<usize> {
        let mut pos = 0;

        // 1. Copy any buffered data.
        if !self.buffer.is_empty() {
            let to_copy = cmp::min(self.buffer.len(), plaintext.len());
            plaintext[..to_copy].copy_from_slice(&self.buffer[..to_copy]);
            crate::vec_drain_prefix(&mut self.buffer, to_copy);
            pos = to_copy;
        }

        if pos == plaintext.len() {
            return Ok(pos);
        }

        // 2. Decrypt as many whole blocks as `plaintext` can hold.
        let mut to_copy
            = ((plaintext.len() - pos) / self.block_size) *  self.block_size;
        let result = self.source.data_consume(to_copy);
        let short_read;
        let ciphertext = match result {
            Ok(data) => {
                short_read = data.len() < to_copy;
                to_copy = data.len().min(to_copy);
                &data[..to_copy]
            },
            // We encountered an error, but we did read some.
            Err(_) if pos > 0 => return Ok(pos),
            Err(e) => return Err(e),
        };

        // Avoid trying to decrypt empty ciphertexts.  Some backends
        // might not like that, for example Botan's CBC mode.
        if ! ciphertext.is_empty() {
            // Possibly deal with padding.
            match self.padding {
                UnpaddingMode::None => if self.mode.requires_padding()
                    && ciphertext.len() % self.block_size > 0
                {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        Error::InvalidOperation(
                            "incomplete last block".into())));
                },
            }

            self.dec.decrypt(&mut plaintext[pos..pos + to_copy],
                             ciphertext)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput,
                                            format!("{}", e)))?;

            // Possibly deal with padding.
            match self.padding {
                UnpaddingMode::None => (),
            }

            pos += to_copy;
        }

        if short_read || pos == plaintext.len() {
            return Ok(pos);
        }

        // 3. The last bit is a partial block.  Buffer it.
        let mut to_copy = plaintext.len() - pos;
        assert!(0 < to_copy);
        assert!(to_copy < self.block_size);

        let to_read = self.block_size;
        let result = self.source.data_consume(to_read);
        let ciphertext = match result {
            Ok(data) => {
                // Make sure we don't read more than is available.
                to_copy = cmp::min(to_copy, data.len());
                &data[..data.len().min(to_read)]
            },
            // We encountered an error, but we did read some.
            Err(_) if pos > 0 => return Ok(pos),
            Err(e) => return Err(e),
        };
        assert!(ciphertext.len() <= self.block_size);

        // Avoid trying to decrypt empty ciphertexts.  Some backends
        // might not like that, for example Botan's CBC mode.
        if ciphertext.is_empty() {
            return Ok(pos);
        }

        vec_resize(&mut self.buffer, ciphertext.len());

        // Possibly deal with padding.
        match self.padding {
            UnpaddingMode::None => if self.mode.requires_padding()
                && ciphertext.len() % self.block_size > 0
            {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    Error::InvalidOperation(
                        "incomplete last block".into())));
            },
        }

        self.dec.decrypt(&mut self.buffer, ciphertext)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput,
                                        format!("{}", e)))?;

        // Possibly deal with padding.
        match self.padding {
            UnpaddingMode::None => (),
        }

        plaintext[pos..pos + to_copy].copy_from_slice(&self.buffer[..to_copy]);
        crate::vec_drain_prefix(&mut self.buffer, to_copy);

        pos += to_copy;

        Ok(pos)
    }
}

/// A `BufferedReader` that decrypts symmetrically-encrypted data as
/// it is read.
pub struct Decryptor<'a> {
    reader: buffered_reader::Generic<InternalDecryptor<'a>, Cookie>,
}

impl<'a> Decryptor<'a> {
    /// Instantiate a new symmetric decryptor.
    ///
    /// If `iv` is `None`, and the given `mode` requires an IV, an
    /// all-zero IV is used.
    pub fn new<R>(algo: SymmetricAlgorithm,
                  mode: BlockCipherMode,
                  padding: UnpaddingMode,
                  key: &SessionKey,
                  iv: Option<&[u8]>,
                  source: R)
                  -> Result<Self>
    where
        R: BufferedReader<Cookie> + 'a,
    {
        Self::with_cookie(
            algo, mode, padding, key, iv, source, Default::default())
    }

    /// Like [`Decryptor::new`], but sets a cookie.
    pub fn with_cookie<R>(algo: SymmetricAlgorithm,
                          mode: BlockCipherMode,
                          padding: UnpaddingMode,
                          key: &SessionKey,
                          iv: Option<&[u8]>,
                          reader: R,
                          cookie: Cookie)
                          -> Result<Self>
    where
        R: BufferedReader<Cookie> + 'a,
    {
        Ok(Decryptor {
            reader: buffered_reader::Generic::with_cookie(
                InternalDecryptor::new(algo, mode, padding, key, iv, reader)?,
                None, cookie),
        })
    }
}

impl<'a> io::Read for Decryptor<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buf)
    }
}

impl<'a> fmt::Display for Decryptor<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Decryptor")
    }
}

impl<'a> fmt::Debug for Decryptor<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Decryptor")
            .field("reader", &self.get_ref().unwrap())
            .finish()
    }
}

impl<'a> BufferedReader<Cookie> for Decryptor<'a> {
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

/// A `Write`r that symmetrically encrypts data as it is written.
pub struct Encryptor<W: io::Write> {
    inner: Option<W>,

    mode: BlockCipherMode,
    padding: PaddingMode,
    cipher: Box<dyn Context>,
    block_size: usize,
    // Up to a block of unencrypted data.
    buffer: Vec<u8>,
    // A place to write encrypted data into.
    scratch: Vec<u8>,
}
assert_send_and_sync!(Encryptor<W> where W: io::Write);

impl<W: io::Write> Encryptor<W> {
    /// Instantiate a new symmetric encryptor.
    ///
    /// If `iv` is `None`, and the given `mode` requires an IV, an
    /// all-zero IV is used.
    pub fn new(algo: SymmetricAlgorithm,
               mode: BlockCipherMode,
               padding: PaddingMode,
               key: &SessionKey,
               iv: Option<&[u8]>,
               sink: W) -> Result<Self> {
        use crate::crypto::backend::{Backend, interface::Symmetric};
        let block_size = algo.block_size()?;
        let cipher =
            Backend::encryptor(algo, mode, key.as_protected(), iv)?;

        Ok(Encryptor {
            inner: Some(sink),
            mode,
            padding,
            cipher,
            block_size,
            buffer: Vec::with_capacity(block_size),
            scratch: vec![0; 4096],
        })
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
                let n = self.buffer.len();
                assert!(n < self.block_size);

                // Possibly deal with padding.
                match self.padding {
                    PaddingMode::None => if self.mode.requires_padding()
                    {
                        return Err(Error::InvalidOperation(
                            "incomplete last block".into())
                                   .into());
                    },
                }

                self.cipher.encrypt(&mut self.scratch[..n], &self.buffer)?;

                // Possibly deal with padding.
                match self.padding {
                    PaddingMode::None => (),
                }

                crate::vec_truncate(&mut self.buffer, 0);
                inner.write_all(&self.scratch[..n])?;
                crate::vec_truncate(&mut self.scratch, 0);
            }
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

impl<W: io::Write> io::Write for Encryptor<W> {
    fn write(&mut self, mut buf: &[u8]) -> io::Result<usize> {
        if self.inner.is_none() {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe,
                                      "Inner writer was taken"));
        }
        let inner = self.inner.as_mut().unwrap();
        let amount = buf.len();

        // First, fill the buffer if there is something in it.
        if !self.buffer.is_empty() {
            let n = cmp::min(buf.len(), self.block_size - self.buffer.len());
            self.buffer.extend_from_slice(&buf[..n]);
            assert!(self.buffer.len() <= self.block_size);
            buf = &buf[n..];

            // And possibly encrypt the block.
            if self.buffer.len() == self.block_size {
                self.cipher.encrypt(&mut self.scratch[..self.block_size],
                                    &self.buffer)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput,
                                                format!("{}", e)))?;
                crate::vec_truncate(&mut self.buffer, 0);
                inner.write_all(&self.scratch[..self.block_size])?;
            }
        }

        // Then, encrypt all whole blocks.
        let whole_blocks = (buf.len() / self.block_size) * self.block_size;
        if whole_blocks > 0 {
            // Encrypt whole blocks.
            if self.scratch.len() < whole_blocks {
                vec_resize(&mut self.scratch, whole_blocks);
            }

            self.cipher.encrypt(&mut self.scratch[..whole_blocks],
                                &buf[..whole_blocks])
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput,
                                            format!("{}", e)))?;
            inner.write_all(&self.scratch[..whole_blocks])?;
        }

        // Stash rest for later.
        assert!(buf.is_empty() || self.buffer.is_empty());
        self.buffer.extend_from_slice(&buf[whole_blocks..]);
        assert!(self.buffer.len() < self.block_size);

        Ok(amount)
    }

    fn flush(&mut self) -> io::Result<()> {
        // It is not clear how we can implement this, because we can
        // only operate on block sizes.  We will, however, ask our
        // inner writer to flush.
        if let Some(ref mut inner) = self.inner {
            inner.flush()
        } else {
            Err(io::Error::new(io::ErrorKind::BrokenPipe,
                               "Inner writer was taken"))
        }
    }
}

impl<W: io::Write> Drop for Encryptor<W> {
    fn drop(&mut self) {
        // Unfortunately, we cannot handle errors here.  If error
        // handling is a concern, call finish() and properly handle
        // errors there.
        let _ = self.finalize_intern();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Read, Write};

    #[test]
    fn smoke_test() {
        use crate::crypto::mem::Protected;
        use crate::crypto::symmetric::BlockCipherMode;
        use crate::crypto::backend::{Backend, interface::Symmetric};

        use crate::fmt::hex;

        let algo = SymmetricAlgorithm::AES128;
        let key: Protected =
            hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap().into();
        assert_eq!(key.len(), 16);

        // Ensure we use CFB128 by default
        let iv = hex::decode("000102030405060708090A0B0C0D0E0F").unwrap();
        let mut cfb =
            Backend::encryptor(algo, BlockCipherMode::CFB, &key, Some(&iv)).unwrap();
        let msg = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
        let mut dst = vec![0; msg.len()];
        cfb.encrypt(&mut dst, &*msg).unwrap();
        assert_eq!(&dst[..16], &*hex::decode("3b3fd92eb72dad20333449f8e83cfb4a").unwrap());

        // 32-byte long message
        let iv = hex::decode("000102030405060708090A0B0C0D0E0F").unwrap();
        let mut cfb =
            Backend::encryptor(algo, BlockCipherMode::CFB, &key, Some(&iv)).unwrap();
        let msg = b"This is a very important message";
        let mut dst = vec![0; msg.len()];
        cfb.encrypt(&mut dst, &*msg).unwrap();
        assert_eq!(&dst, &hex::decode(
            "04960ebfb9044196bb29418ce9d6cc0939d5ccb1d0712fa8e45fe5673456fded"
        ).unwrap());

        // 33-byte (uneven) long message
        let iv = hex::decode("000102030405060708090A0B0C0D0E0F").unwrap();
        let mut cfb =
            Backend::encryptor(algo, BlockCipherMode::CFB, &key, Some(&iv)).unwrap();
        let msg = b"This is a very important message!";
        let mut dst = vec![0; msg.len()];
        cfb.encrypt(&mut dst, &*msg).unwrap();
        assert_eq!(&dst, &hex::decode(
            "04960ebfb9044196bb29418ce9d6cc0939d5ccb1d0712fa8e45fe5673456fded0b"
        ).unwrap());

        // 33-byte (uneven) long message, chunked
        let iv = hex::decode("000102030405060708090A0B0C0D0E0F").unwrap();
        let mut cfb =
            Backend::encryptor(algo, BlockCipherMode::CFB, &key, Some(&iv)).unwrap();
        let mut dst = vec![0; msg.len()];
        for (mut dst, msg) in dst.chunks_mut(16).zip(msg.chunks(16)) {
            cfb.encrypt(&mut dst, msg).unwrap();
        }
        assert_eq!(&dst, &hex::decode(
            "04960ebfb9044196bb29418ce9d6cc0939d5ccb1d0712fa8e45fe5673456fded0b"
        ).unwrap());
    }

    /// This test is designed to test the buffering logic in Decryptor
    /// by reading directly from it (i.e. without any buffering
    /// introduced by the Decryptor or any other source
    /// of buffering).
    #[test]
    fn decryptor() {
        for algo in [SymmetricAlgorithm::AES128,
                     SymmetricAlgorithm::AES192,
                     SymmetricAlgorithm::AES256].iter() {
            // The keys are [key.len() - 1, 0, 0, 0, ...].
            let mut key = vec![0u8; algo.key_size().unwrap()];
            key[0] = key.len() as u8 - 1;
            let key = key.into();

            let filename = &format!(
                    "raw/a-cypherpunks-manifesto.aes{}.key_is_key_len_dec1_as_le",
                algo.key_size().unwrap() * 8);
            let ciphertext = buffered_reader::Memory::with_cookie(
                crate::tests::file(filename), Default::default());
            let decryptor = InternalDecryptor::new(
                *algo, BlockCipherMode::CFB, UnpaddingMode::None,
                &key, None, ciphertext).unwrap();

            // Read bytewise to test the buffer logic.
            let mut plaintext = Vec::new();
            for b in decryptor.bytes() {
                plaintext.push(b.unwrap());
            }

            assert_eq!(crate::tests::manifesto(), &plaintext[..]);
        }
    }

    /// This test is designed to test the buffering logic in Encryptor
    /// by writing directly to it.
    #[test]
    fn encryptor() {
        for algo in [SymmetricAlgorithm::AES128,
                     SymmetricAlgorithm::AES192,
                     SymmetricAlgorithm::AES256].iter() {
            // The keys are [key.len() - 1, 0, 0, 0, ...].
            let mut key = vec![0u8; algo.key_size().unwrap()];
            key[0] = key.len() as u8 - 1;
            let key = key.into();

            let mut ciphertext = Vec::new();
            {
                let mut encryptor = Encryptor::new(
                    *algo, BlockCipherMode::CFB, PaddingMode::None,
                    &key, None, &mut ciphertext).unwrap();

                // Write bytewise to test the buffer logic.
                for b in crate::tests::manifesto().chunks(1) {
                    encryptor.write_all(b).unwrap();
                }
            }

            let filename = format!(
                "raw/a-cypherpunks-manifesto.aes{}.key_is_key_len_dec1_as_le",
                algo.key_size().unwrap() * 8);
            let mut cipherfile = Cursor::new(crate::tests::file(&filename));
            let mut reference = Vec::new();
            cipherfile.read_to_end(&mut reference).unwrap();
            assert_eq!(&reference[..], &ciphertext[..]);
        }
    }

    /// This test tries to encrypt, then decrypt some data.
    #[test]
    fn roundtrip() {
        for algo in SymmetricAlgorithm::variants()
                     .filter(|x| x.is_supported()) {
          for mode in [BlockCipherMode::CFB,
                       BlockCipherMode::CBC,
                       BlockCipherMode::ECB] {
            eprintln!("Testing {:?}/{:?}", algo, mode);

            let bs = algo.block_size().unwrap();
            let text = if mode.requires_padding() {
                // For modes requiring padding, make sure the payload
                // is a multiple of the block size, so that we don't
                // in fact require padding.
                let l = (crate::tests::manifesto().len() / bs) * bs;
                &crate::tests::manifesto()[..l]
            } else {
                crate::tests::manifesto()
            };

            let key = SessionKey::new(algo.key_size().unwrap()).unwrap();

            let mut ciphertext = Vec::new();
            let mut encryptor = Encryptor::new(
                algo, mode, PaddingMode::None,
                &key, None, &mut ciphertext).unwrap();

            encryptor.write_all(text).unwrap();
            encryptor.finalize().unwrap();

            let mut plaintext = Vec::new();
            let reader = buffered_reader::Memory::with_cookie(
                &ciphertext, Default::default());

            let mut decryptor = InternalDecryptor::new(
                algo, mode, UnpaddingMode::None,
                &key, None, reader).unwrap();

            decryptor.read_to_end(&mut plaintext).unwrap();

            assert_eq!(&plaintext[..], text);
          }
        }
    }
}
