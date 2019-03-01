use std::cmp;
use std::fmt;
use std::io::{self, Read};

use nettle::{aead, cipher};
use buffered_reader::BufferedReader;

use constants::{
    AEADAlgorithm,
    SymmetricAlgorithm,
};
use conversions::{
    write_be_u64,
};
use Error;
use Result;
use crypto::SessionKey;
use super::secure_cmp;

impl AEADAlgorithm {
    /// Returns the digest size of the AEAD algorithm.
    pub fn digest_size(&self) -> Result<usize> {
        use self::AEADAlgorithm::*;
        match self {
            &EAX =>
            // Digest size is independent of the cipher.
                Ok(aead::Eax::<cipher::Aes128>::DIGEST_SIZE),
            _ => Err(Error::UnsupportedAEADAlgorithm(self.clone()).into()),
        }
    }

    /// Returns the initialization vector size of the AEAD algorithm.
    pub fn iv_size(&self) -> Result<usize> {
        use self::AEADAlgorithm::*;
        match self {
            &EAX =>
                Ok(16), // According to RFC4880bis, Section 5.16.1.
            _ => Err(Error::UnsupportedAEADAlgorithm(self.clone()).into()),
        }
    }

    /// Creates a nettle context.
    pub fn context(&self, cipher: SymmetricAlgorithm, key: &[u8], nonce: &[u8])
                   -> Result<Box<aead::Aead>> {
        match self {
            AEADAlgorithm::EAX => match cipher {
                SymmetricAlgorithm::AES128 =>
                    Ok(Box::new(aead::Eax::<cipher::Aes128>
                                ::with_key_and_nonce(key, nonce)?)),
                SymmetricAlgorithm::AES192 =>
                    Ok(Box::new(aead::Eax::<cipher::Aes192>
                                ::with_key_and_nonce(key, nonce)?)),
                SymmetricAlgorithm::AES256 =>
                    Ok(Box::new(aead::Eax::<cipher::Aes256>
                                ::with_key_and_nonce(key, nonce)?)),
                SymmetricAlgorithm::Twofish =>
                    Ok(Box::new(aead::Eax::<cipher::Twofish>
                                ::with_key_and_nonce(key, nonce)?)),
                SymmetricAlgorithm::Camellia128 =>
                    Ok(Box::new(aead::Eax::<cipher::Camellia128>
                                ::with_key_and_nonce(key, nonce)?)),
                SymmetricAlgorithm::Camellia192 =>
                    Ok(Box::new(aead::Eax::<cipher::Camellia192>
                                ::with_key_and_nonce(key, nonce)?)),
                SymmetricAlgorithm::Camellia256 =>
                    Ok(Box::new(aead::Eax::<cipher::Camellia256>
                                ::with_key_and_nonce(key, nonce)?)),
                _ =>
                    Err(Error::UnsupportedSymmetricAlgorithm(cipher).into()),
            },
            _ =>
                Err(Error::UnsupportedAEADAlgorithm(self.clone()).into()),
        }
    }
}

const AD_PREFIX_LEN: usize = 5;

/// A `Read`er for decrypting AEAD-encrypted data.
pub struct Decryptor<R: io::Read> {
    // The encrypted data.
    source: R,

    cipher: SymmetricAlgorithm,
    aead: AEADAlgorithm,
    key: SessionKey,
    iv: Box<[u8]>,
    ad: [u8; AD_PREFIX_LEN + 8 + 8],

    digest_size: usize,
    chunk_size: usize,
    chunk_index: u64,
    bytes_decrypted: u64,
    // Up to a chunk of unread data.
    buffer: Vec<u8>,
}

impl<R: io::Read> Decryptor<R> {
    /// Instantiate a new AEAD decryptor.
    ///
    /// `source` is the source to wrap.
    pub fn new(version: u8, cipher: SymmetricAlgorithm, aead: AEADAlgorithm,
               chunk_size: usize, iv: &[u8], key: &SessionKey, source: R)
               -> Result<Self> {
        Ok(Decryptor {
            source: source,
            cipher: cipher,
            aead: aead,
            key: key.clone(),
            iv: Vec::from(iv).into_boxed_slice(),
            ad: [
                // Prefix.
                0xd4, version, cipher.into(), aead.into(),
                chunk_size.trailing_zeros() as u8 - 6,
                // Chunk index.
                0, 0, 0, 0, 0, 0, 0, 0,
                // Message size.
                0, 0, 0, 0, 0, 0, 0, 0,
            ],
            digest_size: aead.digest_size()?,
            chunk_size: chunk_size,
            chunk_index: 0,
            bytes_decrypted: 0,
            buffer: Vec::with_capacity(chunk_size),
        })
    }

    fn hash_associated_data(&mut self, aead: &mut Box<aead::Aead>,
                            final_digest: bool) {
        // Prepare the associated data.
        write_be_u64(&mut self.ad[AD_PREFIX_LEN..AD_PREFIX_LEN + 8],
                     self.chunk_index);

        if final_digest {
            write_be_u64(&mut self.ad[AD_PREFIX_LEN + 8..],
                         self.bytes_decrypted);
            aead.update(&self.ad);
        } else {
            aead.update(&self.ad[..AD_PREFIX_LEN + 8]);
        }
    }

    fn make_aead(&mut self) -> Result<Box<aead::Aead>> {
        // The chunk index is XORed into the IV.
        let mut chunk_index_be64 = vec![0u8; 8];
        write_be_u64(&mut chunk_index_be64, self.chunk_index);

        match self.aead {
            AEADAlgorithm::EAX => {
                // The nonce for EAX mode is computed by treating the
                // starting initialization vector as a 16-octet,
                // big-endian value and exclusive-oring the low eight
                // octets of it with the chunk index.
                let iv_len = self.iv.len();
                for (i, o) in &mut self.iv[iv_len - 8..].iter_mut()
                    .enumerate()
                {
                    // The lower eight octets of the associated data
                    // are the big endian representation of the chunk
                    // index.
                    *o ^= chunk_index_be64[i];
                }

                // Instantiate the AEAD cipher.
                let aead = self.aead.context(self.cipher, &self.key, &self.iv)?;

                // Restore the IV.
                for (i, o) in &mut self.iv[iv_len - 8..].iter_mut()
                    .enumerate()
                {
                    *o ^= chunk_index_be64[i];
                }

                Ok(aead)
            }
            _ => Err(Error::UnsupportedAEADAlgorithm(self.aead).into()),
        }
    }

    fn read_helper(&mut self, plaintext: &mut [u8]) -> Result<usize> {
        use std::cmp::Ordering;

        let mut pos = 0;

        // 1. Copy any buffered data.
        if self.buffer.len() > 0 {
            let to_copy = cmp::min(self.buffer.len(), plaintext.len());
            &plaintext[..to_copy].copy_from_slice(&self.buffer[..to_copy]);
            self.buffer.drain(..to_copy);
            pos = to_copy;
        }

        if pos == plaintext.len() {
            return Ok(pos);
        }

        // 2. Decrypt as many whole chunks as `plaintext` can hold.
        let n_chunks = (plaintext.len() - pos) / self.chunk_size;
        let chunk_digest_size = self.chunk_size + self.digest_size;
        let mut to_copy = n_chunks * self.chunk_size;
        let to_read =     n_chunks * chunk_digest_size;

        let mut ciphertext = Vec::new();
        let result = (&mut self.source).take(to_read as u64)
            .read_to_end(&mut ciphertext);
        let short_read;
        match result {
            Ok(amount) => {
                if to_read != 0 && amount == 0 {
                    // Exhausted source.
                    return Ok(pos);
                }

                short_read = amount < to_copy;
                to_copy = amount;
                ciphertext.truncate(to_copy);
            },
            // We encountered an error, but we did read some.
            Err(_) if pos > 0 => return Ok(pos),
            Err(e) => return Err(e.into()),
        }

        // Buffer to hold digests.
        let mut digest = vec![0u8; self.digest_size];

        // At the end of the stream, there is an additional tag.  Be
        // careful not to consume this tag.
        let ciphertext_end = if short_read {
            ciphertext.len() - self.digest_size
        } else {
            ciphertext.len()
        };

        for chunk in (&ciphertext[..ciphertext_end]).chunks(chunk_digest_size) {
            let mut aead = self.make_aead()?;

            // Digest the associated data.
            self.hash_associated_data(&mut aead, false);

            // Decrypt the chunk.
            aead.decrypt(
                &mut plaintext[pos..pos + chunk.len() - self.digest_size],
                &chunk[..chunk.len() - self.digest_size]);
            self.bytes_decrypted += (chunk.len() - self.digest_size) as u64;

            // Check digest.
            aead.digest(&mut digest);
            let dig_ord = secure_cmp(&digest[..],
                                     &chunk[chunk.len() - self.digest_size..]);
            if dig_ord != Ordering::Equal {
                return Err(Error::ManipulatedMessage.into());
            }

            // Increase index, update position in plaintext.
            self.chunk_index += 1;
            pos += chunk.len() - self.digest_size;
        }

        if short_read {
            // We read the whole ciphertext, now check the final digest.
            let mut aead = self.make_aead()?;
            self.hash_associated_data(&mut aead, true);

            let mut nada = [0; 0];
            aead.decrypt(&mut nada, b"");
            aead.digest(&mut digest);

            let dig_ord = secure_cmp(&digest[..], &ciphertext[ciphertext_end..]);
            if dig_ord != Ordering::Equal {
                return Err(Error::ManipulatedMessage.into());
            }
        }

        if short_read || pos == plaintext.len() {
            return Ok(pos);
        }

        // 3. The last bit is a partial chunk.  Buffer it.
        let mut to_copy = plaintext.len() - pos;
        assert!(0 < to_copy);
        assert!(to_copy < self.chunk_size);

        let mut ciphertext = Vec::new();
        let result = (&mut self.source).take(chunk_digest_size as u64)
            .read_to_end(&mut ciphertext);
        let short_read;
        match result {
            Ok(amount) => {
                if amount == 0 {
                    return Ok(pos);
                }

                short_read = amount < chunk_digest_size;

                // Make sure `ciphertext` is not larger than the
                // amount of data that was actually read.
                ciphertext.truncate(amount);

                // Make sure we don't read more than is available.
                to_copy = cmp::min(to_copy,
                                   ciphertext.len() - self.digest_size
                                   - if short_read {
                                       self.digest_size
                                   } else {
                                       0
                                   });
            },
            // We encountered an error, but we did read some.
            Err(_) if pos > 0 => return Ok(pos),
            Err(e) => return Err(e.into()),
        }
        assert!(ciphertext.len() <= self.chunk_size + self.digest_size);

        let mut aead = self.make_aead()?;

        // Digest the associated data.
        self.hash_associated_data(&mut aead, false);

        // At the end of the stream, there is an additional tag.  Be
        // careful not to consume this tag.
        let ciphertext_end = if short_read {
            ciphertext.len() - self.digest_size
        } else {
            ciphertext.len()
        };

        while self.buffer.len() < ciphertext_end - self.digest_size {
            self.buffer.push(0u8);
        }
        self.buffer.truncate(ciphertext_end - self.digest_size);

        // Decrypt the chunk.
        aead.decrypt(&mut self.buffer,
                     &ciphertext[..ciphertext_end - self.digest_size]);
        self.bytes_decrypted += (ciphertext_end - self.digest_size) as u64;

        // Check digest.
        aead.digest(&mut digest);
        let mac_ord = secure_cmp(
            &digest[..],
            &ciphertext[ciphertext_end - self.digest_size..ciphertext_end]);
        if mac_ord != Ordering::Equal {
            return Err(Error::ManipulatedMessage.into());
        }

        // Increase index.
        self.chunk_index += 1;

        &plaintext[pos..pos + to_copy].copy_from_slice(&self.buffer[..to_copy]);
        self.buffer.drain(..to_copy);
        pos += to_copy;

        if short_read {
            // We read the whole ciphertext, now check the final digest.
            let mut aead = self.make_aead()?;
            self.hash_associated_data(&mut aead, true);

            let mut nada = [0; 0];
            aead.decrypt(&mut nada, b"");
            aead.digest(&mut digest);

            let dig_ord = secure_cmp(&digest[..], &ciphertext[ciphertext_end..]);
            if dig_ord != Ordering::Equal {
                return Err(Error::ManipulatedMessage.into());
            }
        }

        Ok(pos)
    }
}

// Note: this implementation tries *very* hard to make sure we don't
// gratuitiously do a short read.  Specifically, if the return value
// is less than `plaintext.len()`, then it is either because we
// reached the end of the input or an error occured.
impl<R: io::Read> io::Read for Decryptor<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.read_helper(buf) {
            Ok(n) => Ok(n),
            Err(e) => match e.downcast::<io::Error>() {
                // An io::Error.  Pass as-is.
                Ok(e) => Err(e),
                // A failure.  Create a compat object and wrap it.
                Err(e) => Err(io::Error::new(io::ErrorKind::Other,
                                             e.compat())),
            },
        }
    }
}

/// A `BufferedReader` that decrypts AEAD-encrypted data as it is
/// read.
pub(crate) struct BufferedReaderDecryptor<R: BufferedReader<C>, C> {
    reader: buffered_reader::Generic<Decryptor<R>, C>,
}

impl <R: BufferedReader<C>, C> BufferedReaderDecryptor<R, C> {
    /// Like `new()`, but sets a cookie, which can be retrieved using
    /// the `cookie_ref` and `cookie_mut` methods, and set using
    /// the `cookie_set` method.
    pub fn with_cookie(version: u8, cipher: SymmetricAlgorithm,
                       aead: AEADAlgorithm, chunk_size: usize, iv: &[u8],
                       key: &SessionKey, source: R, cookie: C)
        -> Result<Self>
    {
        Ok(BufferedReaderDecryptor {
            reader: buffered_reader::Generic::with_cookie(
                Decryptor::new(version, cipher, aead, chunk_size, iv, key,
                               source)?,
                None, cookie),
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

    fn get_mut(&mut self) -> Option<&mut BufferedReader<C>> {
        Some(&mut self.reader.reader.source)
    }

    fn get_ref(&self) -> Option<&BufferedReader<C>> {
        Some(&self.reader.reader.source)
    }

    fn into_inner<'b>(self: Box<Self>)
            -> Option<Box<BufferedReader<C> + 'b>> where Self: 'b {
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

/// A `Write`r for AEAD encrypting data.
pub struct Encryptor<W: io::Write> {
    inner: Option<W>,

    cipher: SymmetricAlgorithm,
    aead: AEADAlgorithm,
    key: SessionKey,
    iv: Box<[u8]>,
    ad: [u8; AD_PREFIX_LEN + 8 + 8],

    digest_size: usize,
    chunk_size: usize,
    chunk_index: u64,
    bytes_encrypted: u64,
    // Up to a chunk of unencrypted data.
    buffer: Vec<u8>,

    // A place to write encrypted data into.
    scratch: Vec<u8>,
}

impl<W: io::Write> Encryptor<W> {
    /// Instantiate a new AEAD encryptor.
    pub fn new(version: u8, cipher: SymmetricAlgorithm, aead: AEADAlgorithm,
               chunk_size: usize, iv: &[u8], key: &SessionKey, sink: W)
               -> Result<Self> {
        let mut scratch = Vec::with_capacity(chunk_size);
        unsafe { scratch.set_len(chunk_size); }

        Ok(Encryptor {
            inner: Some(sink),
            cipher: cipher,
            aead: aead,
            key: key.clone(),
            iv: Vec::from(iv).into_boxed_slice(),
            ad: [
                // Prefix.
                0xd4, version, cipher.into(), aead.into(),
                chunk_size.trailing_zeros() as u8 - 6,
                // Chunk index.
                0, 0, 0, 0, 0, 0, 0, 0,
                // Message size.
                0, 0, 0, 0, 0, 0, 0, 0,
            ],
            digest_size: aead.digest_size()?,
            chunk_size: chunk_size,
            chunk_index: 0,
            bytes_encrypted: 0,
            buffer: Vec::with_capacity(chunk_size),
            scratch: scratch,
        })
    }

    fn hash_associated_data(&mut self, aead: &mut Box<aead::Aead>,
                            final_digest: bool) {
        // Prepare the associated data.
        write_be_u64(&mut self.ad[AD_PREFIX_LEN..AD_PREFIX_LEN + 8],
                     self.chunk_index);

        if final_digest {
            write_be_u64(&mut self.ad[AD_PREFIX_LEN + 8..],
                         self.bytes_encrypted);
            aead.update(&self.ad);
        } else {
            aead.update(&self.ad[..AD_PREFIX_LEN + 8]);
        }
    }

    fn make_aead(&mut self) -> Result<Box<aead::Aead>> {
        // The chunk index is XORed into the IV.
        let mut chunk_index_be64 = vec![0u8; 8];
        write_be_u64(&mut chunk_index_be64, self.chunk_index);

        match self.aead {
            AEADAlgorithm::EAX => {
                // The nonce for EAX mode is computed by treating the
                // starting initialization vector as a 16-octet,
                // big-endian value and exclusive-oring the low eight
                // octets of it with the chunk index.
                let iv_len = self.iv.len();
                for (i, o) in &mut self.iv[iv_len - 8..].iter_mut()
                    .enumerate()
                {
                    // The lower eight octets of the associated data
                    // are the big endian representation of the chunk
                    // index.
                    *o ^= chunk_index_be64[i];
                }

                // Instantiate the AEAD cipher.
                let aead = self.aead.context(self.cipher, &self.key, &self.iv)?;

                // Restore the IV.
                for (i, o) in &mut self.iv[iv_len - 8..].iter_mut()
                    .enumerate()
                {
                    *o ^= chunk_index_be64[i];
                }

                Ok(aead)
            }
            _ => Err(Error::UnsupportedAEADAlgorithm(self.aead).into()),
        }
    }

    // Like io::Write, but returns our Result.
    fn write_helper(&mut self, mut buf: &[u8]) -> Result<usize> {
        if self.inner.is_none() {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe,
                                      "Inner writer was taken").into());
        }
        let amount = buf.len();

        // First, fill the buffer if there is something in it.
        if self.buffer.len() > 0 {
            let n = cmp::min(buf.len(), self.chunk_size - self.buffer.len());
            self.buffer.extend_from_slice(&buf[..n]);
            assert!(self.buffer.len() <= self.chunk_size);
            buf = &buf[n..];

            // And possibly encrypt the chunk.
            if self.buffer.len() == self.chunk_size {
                let mut aead = self.make_aead()?;
                self.hash_associated_data(&mut aead, false);

                let inner = self.inner.as_mut().unwrap();

                // Encrypt the chunk.
                aead.encrypt(&mut self.scratch, &self.buffer);
                self.bytes_encrypted += self.scratch.len() as u64;
                self.chunk_index += 1;
                self.buffer.clear();
                inner.write_all(&self.scratch)?;

                // Write digest.
                aead.digest(&mut self.scratch[..self.digest_size]);
                inner.write_all(&self.scratch[..self.digest_size])?;
            }
        }

        // Then, encrypt all whole chunks.
        for chunk in buf.chunks(self.chunk_size) {
            if chunk.len() == self.chunk_size {
                // Complete chunk.
                let mut aead = self.make_aead()?;
                self.hash_associated_data(&mut aead, false);

                let inner = self.inner.as_mut().unwrap();

                // Encrypt the chunk.
                aead.encrypt(&mut self.scratch, chunk);
                self.bytes_encrypted += self.scratch.len() as u64;
                self.chunk_index += 1;
                inner.write_all(&self.scratch)?;

                // Write digest.
                aead.digest(&mut self.scratch[..self.digest_size]);
                inner.write_all(&self.scratch[..self.digest_size])?;
            } else {
                // Stash for later.
                assert!(self.buffer.is_empty());
                self.buffer.extend_from_slice(chunk);
            }
        }

        Ok(amount)
    }

    /// Finish encryption and write last partial chunk.
    pub fn finish(&mut self) -> Result<W> {
        if let Some(mut inner) = self.inner.take() {
            if self.buffer.len() > 0 {
                let mut aead = self.make_aead()?;
                self.hash_associated_data(&mut aead, false);

                // Encrypt the chunk.
                unsafe { self.scratch.set_len(self.buffer.len()) }
                aead.encrypt(&mut self.scratch, &self.buffer);
                self.bytes_encrypted += self.scratch.len() as u64;
                self.chunk_index += 1;
                self.buffer.clear();
                inner.write_all(&self.scratch)?;

                // Write digest.
                unsafe { self.scratch.set_len(self.digest_size) }
                aead.digest(&mut self.scratch[..self.digest_size]);
                inner.write_all(&self.scratch[..self.digest_size])?;

                // Write final digest.
                let mut aead = self.make_aead()?;
                self.hash_associated_data(&mut aead, true);
                let mut nada = [0; 0];
                aead.encrypt(&mut nada, b"");
                aead.digest(&mut self.scratch[..self.digest_size]);
                inner.write_all(&self.scratch[..self.digest_size])?;
            }
            Ok(inner)
        } else {
            Err(io::Error::new(io::ErrorKind::BrokenPipe,
                               "Inner writer was taken").into())
        }
    }
}

impl<W: io::Write> io::Write for Encryptor<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.write_helper(buf) {
            Ok(n) => Ok(n),
            Err(e) => match e.downcast::<io::Error>() {
                // An io::Error.  Pass as-is.
                Ok(e) => Err(e),
                // A failure.  Create a compat object and wrap it.
                Err(e) => Err(io::Error::new(io::ErrorKind::Other,
                                             e.compat())),
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
    use std::io::{Read, Write};

    const PLAINTEXT: &[u8]
        = include_bytes!("../../tests/data/messages/a-cypherpunks-manifesto.txt");

    /// This test tries to encrypt, then decrypt some data.
    #[test]
    fn roundtrip() {
        use std::io::Cursor;
        use nettle::{Random, Yarrow};
        let mut rng = Yarrow::default();

        for cipher in [SymmetricAlgorithm::AES128,
                       SymmetricAlgorithm::AES192,
                       SymmetricAlgorithm::AES256,
                       SymmetricAlgorithm::Twofish,
                       SymmetricAlgorithm::Camellia128,
                       SymmetricAlgorithm::Camellia192,
                       SymmetricAlgorithm::Camellia256].iter() {
            for aead in [AEADAlgorithm::EAX].iter() {
                let version = 1;
                let chunk_size = 64;
                let mut key = vec![0; cipher.key_size().unwrap()];
                rng.random(&mut key);
                let key: SessionKey = key.into();
                let mut iv = vec![0; aead.iv_size().unwrap()];
                rng.random(&mut iv);

                let mut ciphertext = Vec::new();
                {
                    let mut encryptor = Encryptor::new(version, *cipher, *aead,
                                                       chunk_size, &iv, &key,
                                                       &mut ciphertext)
                        .unwrap();

                    encryptor.write_all(PLAINTEXT).unwrap();
                }

                let mut plaintext = Vec::new();
                {
                    let mut decryptor = Decryptor::new(version, *cipher, *aead,
                                                       chunk_size, &iv, &key,
                                                       Cursor::new(&ciphertext))
                        .unwrap();

                    decryptor.read_to_end(&mut plaintext).unwrap();
                }

                assert_eq!(&plaintext[..], &PLAINTEXT[..]);
            }
        }
    }
}
