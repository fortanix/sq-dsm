//! Symmetric encryption.

use std::io;
use std::cmp;
use std::fmt;

use crate::Result;
use crate::Error;
use crate::SymmetricAlgorithm;
use crate::vec_truncate;

use buffered_reader::BufferedReader;

use nettle::Cipher;
use nettle::Mode;

impl SymmetricAlgorithm {
    /// Length of a key for this algorithm in bytes.  Fails if Sequoia
    /// does not support this algorithm.
    pub fn key_size(self) -> Result<usize> {
        use nettle::cipher;
        match self {
            SymmetricAlgorithm::TripleDES => Ok(cipher::Des3::KEY_SIZE),
            SymmetricAlgorithm::CAST5 => Ok(cipher::Cast128::KEY_SIZE),
            // RFC4880, Section 9.2: Blowfish (128 bit key, 16 rounds)
            SymmetricAlgorithm::Blowfish => Ok(16),
            SymmetricAlgorithm::AES128 => Ok(cipher::Aes128::KEY_SIZE),
            SymmetricAlgorithm::AES192 => Ok(cipher::Aes192::KEY_SIZE),
            SymmetricAlgorithm::AES256 => Ok(cipher::Aes256::KEY_SIZE),
            SymmetricAlgorithm::Twofish => Ok(cipher::Twofish::KEY_SIZE),
            SymmetricAlgorithm::Camellia128 => Ok(cipher::Camellia128::KEY_SIZE),
            SymmetricAlgorithm::Camellia192 => Ok(cipher::Camellia192::KEY_SIZE),
            SymmetricAlgorithm::Camellia256 => Ok(cipher::Camellia256::KEY_SIZE),
            _ => Err(Error::UnsupportedSymmetricAlgorithm(self).into()),
        }
    }

    /// Length of a block for this algorithm in bytes.  Fails if
    /// Sequoia does not support this algorithm.
    pub fn block_size(self) -> Result<usize> {
        use nettle::cipher;
        match self {
            SymmetricAlgorithm::TripleDES => Ok(cipher::Des3::BLOCK_SIZE),
            SymmetricAlgorithm::CAST5 => Ok(cipher::Cast128::BLOCK_SIZE),
            SymmetricAlgorithm::Blowfish => Ok(cipher::Blowfish::BLOCK_SIZE),
            SymmetricAlgorithm::AES128 => Ok(cipher::Aes128::BLOCK_SIZE),
            SymmetricAlgorithm::AES192 => Ok(cipher::Aes192::BLOCK_SIZE),
            SymmetricAlgorithm::AES256 => Ok(cipher::Aes256::BLOCK_SIZE),
            SymmetricAlgorithm::Twofish => Ok(cipher::Twofish::BLOCK_SIZE),
            SymmetricAlgorithm::Camellia128 => Ok(cipher::Camellia128::BLOCK_SIZE),
            SymmetricAlgorithm::Camellia192 => Ok(cipher::Camellia192::BLOCK_SIZE),
            SymmetricAlgorithm::Camellia256 => Ok(cipher::Camellia256::BLOCK_SIZE),
            _ => Err(Error::UnsupportedSymmetricAlgorithm(self).into()),
        }
    }

    /// Creates a Nettle context for encrypting in CFB mode.
    pub fn make_encrypt_cfb(self, key: &[u8]) -> Result<Box<dyn Mode>> {
        use nettle::{mode, cipher};
        match self {
            SymmetricAlgorithm::TripleDES =>
                Ok(Box::new(
                    mode::Cfb::<cipher::Des3>::with_encrypt_key(&key[..])?)),
            SymmetricAlgorithm::CAST5 =>
                Ok(Box::new(
                    mode::Cfb::<cipher::Cast128>::with_encrypt_key(&key[..])?)),
            SymmetricAlgorithm::Blowfish =>
                Ok(Box::new(
                    mode::Cfb::<cipher::Blowfish>::with_encrypt_key(&key[..])?)),
            SymmetricAlgorithm::AES128 =>
                Ok(Box::new(
                    mode::Cfb::<cipher::Aes128>::with_encrypt_key(&key[..])?)),
            SymmetricAlgorithm::AES192 =>
                Ok(Box::new(
                    mode::Cfb::<cipher::Aes192>::with_encrypt_key(&key[..])?)),
            SymmetricAlgorithm::AES256 =>
                Ok(Box::new(
                    mode::Cfb::<cipher::Aes256>::with_encrypt_key(&key[..])?)),
            SymmetricAlgorithm::Twofish =>
                Ok(Box::new(
                    mode::Cfb::<cipher::Twofish>::with_encrypt_key(&key[..])?)),
            SymmetricAlgorithm::Camellia128 =>
                Ok(Box::new(
                    mode::Cfb::<cipher::Camellia128>::with_encrypt_key(&key[..])?)),
            SymmetricAlgorithm::Camellia192 =>
                Ok(Box::new(
                    mode::Cfb::<cipher::Camellia192>::with_encrypt_key(&key[..])?)),
            SymmetricAlgorithm::Camellia256 =>
                Ok(Box::new(
                    mode::Cfb::<cipher::Camellia256>::with_encrypt_key(&key[..])?)),
            _ => Err(Error::UnsupportedSymmetricAlgorithm(self).into()),
        }
    }

    /// Creates a Nettle context for decrypting in CFB mode.
    pub fn make_decrypt_cfb(self, key: &[u8]) -> Result<Box<dyn Mode>> {
        use nettle::{mode, cipher};
        match self {
            SymmetricAlgorithm::TripleDES =>
                Ok(Box::new(
                    mode::Cfb::<cipher::Des3>::with_decrypt_key(&key[..])?)),
            SymmetricAlgorithm::CAST5 =>
                Ok(Box::new(
                    mode::Cfb::<cipher::Cast128>::with_decrypt_key(&key[..])?)),
            SymmetricAlgorithm::Blowfish =>
                Ok(Box::new(
                    mode::Cfb::<cipher::Blowfish>::with_decrypt_key(&key[..])?)),
            SymmetricAlgorithm::AES128 =>
                Ok(Box::new(
                    mode::Cfb::<cipher::Aes128>::with_decrypt_key(&key[..])?)),
            SymmetricAlgorithm::AES192 =>
                Ok(Box::new(
                    mode::Cfb::<cipher::Aes192>::with_decrypt_key(&key[..])?)),
            SymmetricAlgorithm::AES256 =>
                Ok(Box::new(
                    mode::Cfb::<cipher::Aes256>::with_decrypt_key(&key[..])?)),
            SymmetricAlgorithm::Twofish =>
                Ok(Box::new(
                    mode::Cfb::<cipher::Twofish>::with_decrypt_key(&key[..])?)),
            SymmetricAlgorithm::Camellia128 =>
                Ok(Box::new(
                    mode::Cfb::<cipher::Camellia128>::with_decrypt_key(&key[..])?)),
            SymmetricAlgorithm::Camellia192 =>
                Ok(Box::new(
                    mode::Cfb::<cipher::Camellia192>::with_decrypt_key(&key[..])?)),
            SymmetricAlgorithm::Camellia256 =>
                Ok(Box::new(
                    mode::Cfb::<cipher::Camellia256>::with_decrypt_key(&key[..])?)),
            _ => Err(Error::UnsupportedSymmetricAlgorithm(self).into())
        }
    }
}

/// A `Read`er for decrypting symmetrically encrypted data.
pub struct Decryptor<R: io::Read> {
    // The encrypted data.
    source: R,

    dec: Box<dyn Mode>,
    block_size: usize,
    iv: Vec<u8>,
    // Up to a block of unread data.
    buffer: Vec<u8>,
}

impl<R: io::Read> Decryptor<R> {
    /// Instantiate a new symmetric decryptor.  `reader` is the source
    /// to wrap.
    pub fn new(algo: SymmetricAlgorithm, key: &[u8], source: R) -> Result<Self> {
        let dec = algo.make_decrypt_cfb(key)?;
        let block_size = algo.block_size()?;

        Ok(Decryptor {
            source: source,
            dec: dec,
            block_size: block_size,
            iv: vec![0u8; block_size],
            buffer: Vec::with_capacity(block_size),
        })
    }
}

// Fills `buffer` with data from `R` and returns the number of bytes
// actually read.  This will only return less than `buffer.len()`
// bytes if the end of the file is reached or an error is encountered.
fn read_exact<R: io::Read>(reader: &mut R, mut buffer: &mut [u8])
    -> io::Result<usize>
{
    let mut read = 0;

    while !buffer.is_empty() {
        match reader.read(buffer) {
            Ok(0) => break,
            Ok(n) => {
                read += n;
                let tmp = buffer;
                buffer = &mut tmp[n..];
            },
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => {
                // We don't buffer the error.  Instead, we assume that
                // the same error will be encountered if the user
                // tries to read from source again.
                if read > 0 {
                    return Ok(read);
                } else {
                    return Err(e);
                }
            },
        }
    }

    Ok(read)
}

// Note: this implementation tries *very* hard to make sure we don't
// gratuitiously do a short read.  Specifically, if the return value
// is less than `plaintext.len()`, then it is either because we
// reached the end of the input or an error occurred.
impl<R: io::Read> io::Read for Decryptor<R> {
    fn read(&mut self, plaintext: &mut [u8]) -> io::Result<usize> {
        let mut pos = 0;

        // 1. Copy any buffered data.
        if self.buffer.len() > 0 {
            let to_copy = cmp::min(self.buffer.len(), plaintext.len());
            &plaintext[..to_copy].copy_from_slice(&self.buffer[..to_copy]);
            crate::vec_drain_prefix(&mut self.buffer, to_copy);
            pos = to_copy;
        }

        if pos == plaintext.len() {
            return Ok(pos);
        }

        // 2. Decrypt as many whole blocks as `plaintext` can hold.
        let mut to_copy
            = ((plaintext.len() - pos) / self.block_size) *  self.block_size;
        let mut ciphertext = vec![0u8; to_copy];
        let result = read_exact(&mut self.source, &mut ciphertext[..]);
        let short_read;
        match result {
            Ok(amount) => {
                short_read = amount < to_copy;
                to_copy = amount;
                vec_truncate(&mut ciphertext, to_copy);
            },
            // We encountered an error, but we did read some.
            Err(_) if pos > 0 => return Ok(pos),
            Err(e) => return Err(e),
        }

        self.dec.decrypt(&mut self.iv,
                         &mut plaintext[pos..pos + to_copy],
                         &ciphertext[..])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput,
                                        format!("{}", e)))?;

        pos += to_copy;

        if short_read || pos == plaintext.len() {
            return Ok(pos);
        }

        // 3. The last bit is a partial block.  Buffer it.
        let mut to_copy = plaintext.len() - pos;
        assert!(0 < to_copy);
        assert!(to_copy < self.block_size);

        let mut ciphertext = vec![0u8; self.block_size];
        let result = read_exact(&mut self.source, &mut ciphertext[..]);
        match result {
            Ok(amount) => {
                // Make sure `ciphertext` is not larger than the
                // amount of data that was actually read.
                vec_truncate(&mut ciphertext, amount);

                // Make sure we don't read more than is available.
                to_copy = cmp::min(to_copy, ciphertext.len());
            },
            // We encountered an error, but we did read some.
            Err(_) if pos > 0 => return Ok(pos),
            Err(e) => return Err(e),
        }
        assert!(ciphertext.len() <= self.block_size);

        while self.buffer.len() < ciphertext.len() {
            self.buffer.push(0u8);
        }
        vec_truncate(&mut self.buffer, ciphertext.len());

        self.dec.decrypt(&mut self.iv, &mut self.buffer, &ciphertext[..])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput,
                                        format!("{}", e)))?;

        &plaintext[pos..pos + to_copy].copy_from_slice(&self.buffer[..to_copy]);
        crate::vec_drain_prefix(&mut self.buffer, to_copy);

        pos += to_copy;

        Ok(pos)
    }
}

/// A `BufferedReader` that decrypts symmetrically-encrypted data as
/// it is read.
pub(crate) struct BufferedReaderDecryptor<R: BufferedReader<C>, C> {
    reader: buffered_reader::Generic<Decryptor<R>, C>,
}

impl <R: BufferedReader<C>, C> BufferedReaderDecryptor<R, C> {
    /// Like `new()`, but sets a cookie, which can be retrieved using
    /// the `cookie_ref` and `cookie_mut` methods, and set using
    /// the `cookie_set` method.
    pub fn with_cookie(algo: SymmetricAlgorithm, key: &[u8], reader: R,
                       cookie: C)
        -> Result<Self>
    {
        Ok(BufferedReaderDecryptor {
            reader: buffered_reader::Generic::with_cookie(
                Decryptor::new(algo, key, reader)?, None, cookie),
        })
    }
}

impl<R: BufferedReader<C>, C> io::Read for BufferedReaderDecryptor<R, C> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buf)
    }
}

impl<R: BufferedReader<C>, C> fmt::Display for BufferedReaderDecryptor<R, C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "BufferedReaderDecryptor")
    }
}

impl<R: BufferedReader<C>, C> fmt::Debug for BufferedReaderDecryptor<R, C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("BufferedReaderDecryptor")
            .field("reader", &self.get_ref().unwrap())
            .finish()
    }
}

impl<R: BufferedReader<C>, C> BufferedReader<C>
        for BufferedReaderDecryptor<R, C> {
    fn buffer(&self) -> &[u8] {
        return self.reader.buffer();
    }

    fn data(&mut self, amount: usize) -> io::Result<&[u8]> {
        return self.reader.data(amount);
    }

    fn data_hard(&mut self, amount: usize) -> io::Result<&[u8]> {
        return self.reader.data_hard(amount);
    }

    fn data_eof(&mut self) -> io::Result<&[u8]> {
        return self.reader.data_eof();
    }

    fn consume(&mut self, amount: usize) -> &[u8] {
        return self.reader.consume(amount);
    }

    fn data_consume(&mut self, amount: usize)
                    -> io::Result<&[u8]> {
        return self.reader.data_consume(amount);
    }

    fn data_consume_hard(&mut self, amount: usize) -> io::Result<&[u8]> {
        return self.reader.data_consume_hard(amount);
    }

    fn read_be_u16(&mut self) -> io::Result<u16> {
        return self.reader.read_be_u16();
    }

    fn read_be_u32(&mut self) -> io::Result<u32> {
        return self.reader.read_be_u32();
    }

    fn steal(&mut self, amount: usize) -> io::Result<Vec<u8>> {
        return self.reader.steal(amount);
    }

    fn steal_eof(&mut self) -> io::Result<Vec<u8>> {
        return self.reader.steal_eof();
    }

    fn get_mut(&mut self) -> Option<&mut dyn BufferedReader<C>> {
        Some(&mut self.reader.reader.source)
    }

    fn get_ref(&self) -> Option<&dyn BufferedReader<C>> {
        Some(&self.reader.reader.source)
    }

    fn into_inner<'b>(self: Box<Self>)
            -> Option<Box<dyn BufferedReader<C> + 'b>> where Self: 'b {
        Some(Box::new(self.reader.reader.source))
    }

    fn cookie_set(&mut self, cookie: C) -> C {
        self.reader.cookie_set(cookie)
    }

    fn cookie_ref(&self) -> &C {
        self.reader.cookie_ref()
    }

    fn cookie_mut(&mut self) -> &mut C {
        self.reader.cookie_mut()
    }
}

/// A `Write`r for symmetrically encrypting data.
pub struct Encryptor<W: io::Write> {
    inner: Option<W>,

    cipher: Box<dyn Mode>,
    block_size: usize,
    iv: Vec<u8>,
    // Up to a block of unencrypted data.
    buffer: Vec<u8>,
    // A place to write encrypted data into.
    scratch: Vec<u8>,
}

impl<W: io::Write> Encryptor<W> {
    /// Instantiate a new symmetric encryptor.
    pub fn new(algo: SymmetricAlgorithm, key: &[u8], sink: W) -> Result<Self> {
        let cipher = algo.make_encrypt_cfb(key)?;
        let block_size = algo.block_size()?;
        let mut scratch = Vec::with_capacity(block_size);
        unsafe { scratch.set_len(block_size); }

        Ok(Encryptor {
            inner: Some(sink),
            cipher: cipher,
            block_size: block_size,
            iv: vec![0u8; block_size],
            buffer: Vec::with_capacity(block_size),
            scratch: scratch,
        })
    }

    /// Finish encryption and write last partial block.
    pub fn finish(&mut self) -> Result<W> {
        if let Some(mut inner) = self.inner.take() {
            if self.buffer.len() > 0 {
                unsafe { self.scratch.set_len(self.buffer.len()) }
                self.cipher.encrypt(&mut self.iv, &mut self.scratch, &self.buffer)?;
                crate::vec_truncate(&mut self.buffer, 0);
                inner.write_all(&self.scratch)?;
            }
            Ok(inner)
        } else {
            Err(io::Error::new(io::ErrorKind::BrokenPipe,
                               "Inner writer was taken").into())
        }
    }

    /// Acquires a reference to the underlying writer.
    pub fn get_ref(&self) -> Option<&W> {
        self.inner.as_ref()
    }

    /// Acquires a mutable reference to the underlying writer.
    #[allow(dead_code)]
    pub fn get_mut(&mut self) -> Option<&mut W> {
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
        if self.buffer.len() > 0 {
            let n = cmp::min(buf.len(), self.block_size - self.buffer.len());
            self.buffer.extend_from_slice(&buf[..n]);
            assert!(self.buffer.len() <= self.block_size);
            buf = &buf[n..];

            // And possibly encrypt the block.
            if self.buffer.len() == self.block_size {
                self.cipher.encrypt(&mut self.iv, &mut self.scratch, &self.buffer)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput,
                                                format!("{}", e)))?;
                crate::vec_truncate(&mut self.buffer, 0);
                inner.write_all(&self.scratch)?;
            }
        }

        // Then, encrypt all whole blocks.
        // XXX: If this turns out to be too slow, encrypt larger chunks.
        for block in buf.chunks(self.block_size) {
            if block.len() == self.block_size {
                // Complete block.
                self.cipher.encrypt(&mut self.iv, &mut self.scratch, block)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput,
                                                format!("{}", e)))?;
                inner.write_all(&self.scratch)?;
            } else {
                // Stash for later.
                assert!(self.buffer.is_empty());
                self.buffer.extend_from_slice(block);
            }
        }

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
        let _ = self.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Read, Write};

    /// This test is designed to test the buffering logic in Decryptor
    /// by reading directly from it (i.e. without any buffering
    /// introduced by the BufferedReaderDecryptor or any other source
    /// of buffering).
    #[test]
    fn decryptor() {
        for algo in [SymmetricAlgorithm::AES128,
                     SymmetricAlgorithm::AES192,
                     SymmetricAlgorithm::AES256].iter() {
            // The keys are [0, 1, 2, ...].
            let mut key = vec![0u8; algo.key_size().unwrap()];
            for i in 0..key.len() {
                key[0] = i as u8;
            }

            let filename = &format!(
                    "raw/a-cypherpunks-manifesto.aes{}.key_ascending_from_0",
                algo.key_size().unwrap() * 8);
            let ciphertext = Cursor::new(crate::tests::file(filename));
            let decryptor = Decryptor::new(*algo, &key, ciphertext).unwrap();

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
            // The keys are [0, 1, 2, ...].
            let mut key = vec![0u8; algo.key_size().unwrap()];
            for i in 0..key.len() {
                key[0] = i as u8;
            }

            let mut ciphertext = Vec::new();
            {
                let mut encryptor = Encryptor::new(*algo, &key, &mut ciphertext)
                    .unwrap();

                // Write bytewise to test the buffer logic.
                for b in crate::tests::manifesto().chunks(1) {
                    encryptor.write_all(b).unwrap();
                }
            }

            let filename = format!(
                "raw/a-cypherpunks-manifesto.aes{}.key_ascending_from_0",
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
        use std::io::Cursor;

        for algo in [SymmetricAlgorithm::TripleDES,
                     SymmetricAlgorithm::CAST5,
                     SymmetricAlgorithm::Blowfish,
                     SymmetricAlgorithm::AES128,
                     SymmetricAlgorithm::AES192,
                     SymmetricAlgorithm::AES256,
                     SymmetricAlgorithm::Twofish,
                     SymmetricAlgorithm::Camellia128,
                     SymmetricAlgorithm::Camellia192,
                     SymmetricAlgorithm::Camellia256].iter() {
            let mut key = vec![0; algo.key_size().unwrap()];
            crate::crypto::random(&mut key);

            let mut ciphertext = Vec::new();
            {
                let mut encryptor = Encryptor::new(*algo, &key, &mut ciphertext)
                    .unwrap();

                encryptor.write_all(crate::tests::manifesto()).unwrap();
            }

            let mut plaintext = Vec::new();
            {
                let mut decryptor = Decryptor::new(*algo, &key,
                                                   Cursor::new(&mut ciphertext))
                    .unwrap();

                decryptor.read_to_end(&mut plaintext).unwrap();
            }

            assert_eq!(&plaintext[..], &crate::tests::manifesto()[..]);
        }
    }
}
