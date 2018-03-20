use std::io;
use std::cmp;
use std::fmt;

use Result;
use Error;
use SymmetricAlgo;

use buffered_reader::BufferedReader;
use buffered_reader::BufferedReaderGeneric;

use nettle::Cipher;
use nettle::cipher::{Aes128, Aes192, Aes256, Twofish};
use nettle::Mode;
use nettle::mode::Cfb;

pub fn symmetric_key_size(algo: u8) -> Result<usize> {
    match SymmetricAlgo::from_numeric(algo)? {
        // SymmetricAlgo::IDEA =>
        // SymmetricAlgo::TripleDES =>
        // SymmetricAlgo::CAST5 =>
        // SymmetricAlgo::Blowfish =>
        SymmetricAlgo::AES128 => Ok(Aes128::KEY_SIZE),
        SymmetricAlgo::AES192 => Ok(Aes192::KEY_SIZE),
        SymmetricAlgo::AES256 => Ok(Aes256::KEY_SIZE),
        SymmetricAlgo::Twofish => Ok(Twofish::KEY_SIZE),
        _ => Err(Error::UnsupportedSymmetricAlgorithm(algo).into()),
    }
}
pub fn symmetric_block_size(algo: u8) -> Result<usize> {
    match SymmetricAlgo::from_numeric(algo)? {
        SymmetricAlgo::AES128 => Ok(Aes128::BLOCK_SIZE),
        SymmetricAlgo::AES192 => Ok(Aes192::BLOCK_SIZE),
        SymmetricAlgo::AES256 => Ok(Aes256::BLOCK_SIZE),
        SymmetricAlgo::Twofish => Ok(Twofish::BLOCK_SIZE),
        // SymmetricAlgo::IDEA =>
        // SymmetricAlgo::TripleDES =>
        // SymmetricAlgo::CAST5 =>
        // SymmetricAlgo::Blowfish =>
        _ => Err(Error::UnsupportedSymmetricAlgorithm(algo).into()),
    }
}

pub fn symmetric_init(algo: u8, key: &[u8])
        -> Result<Box<Mode>> {
    match SymmetricAlgo::from_numeric(algo)? {
        SymmetricAlgo::AES128 =>
            Ok(Box::new(Cfb::<Aes128>::with_encrypt_key(&key[..]))),
        SymmetricAlgo::AES192 =>
            Ok(Box::new(Cfb::<Aes192>::with_encrypt_key(&key[..]))),
        SymmetricAlgo::AES256 =>
            Ok(Box::new(Cfb::<Aes256>::with_encrypt_key(&key[..]))),
        SymmetricAlgo::Twofish =>
            Ok(Box::new(Cfb::<Twofish>::with_encrypt_key(&key[..]))),
        _ => Err(Error::UnsupportedSymmetricAlgorithm(algo).into()),
    }
}

/// A `Read`er for decrypting symmetrically encrypted data.
pub struct Decryptor<R: io::Read> {
    // The encrypted data.
    source: R,

    dec: Box<Mode>,
    block_size: usize,
    iv: Vec<u8>,
    // Up to a block of unread data.
    buffer: Vec<u8>,
}

impl<R: io::Read> Decryptor<R> {
    /// Instantiate a new symmetric decryptor.  `reader` is the source
    /// to wrap.
    pub fn new(algo: u8, key: &[u8], source: R) -> Result<Self> {
        let dec = symmetric_init(algo, key)?;
        let block_size = symmetric_key_size(algo)?;

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
// reached the end of the input or an error occured.
impl<R: io::Read> io::Read for Decryptor<R> {
    fn read(&mut self, plaintext: &mut [u8]) -> io::Result<usize> {
        let mut pos = 0;

        // 1. Copy any buffered data.
        if self.buffer.len() > 0 {
            let to_copy = cmp::min(self.buffer.len(), plaintext.len());
            for (i, b) in self.buffer.drain(..to_copy).enumerate() {
                plaintext[i] = b;
            }
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
                ciphertext.truncate(to_copy);
            },
            // We encountered an error, but we did read some.
            Err(_) if pos > 0 => return Ok(pos),
            Err(e) => return Err(e),
        }

        self.dec.decrypt(&mut self.iv,
                         &mut plaintext[pos..pos + to_copy],
                         &ciphertext[..]);
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
                ciphertext.truncate(amount);

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
        self.buffer.truncate(ciphertext.len());

        self.dec.decrypt(&mut self.iv, &mut self.buffer, &ciphertext[..]);

        for (i, b) in self.buffer.drain(..to_copy).enumerate() {
            plaintext[pos + i] = b;
        }

        pos += to_copy;

        Ok(pos)
    }
}

/// A `BufferedReader` that decrypts symmetrically-encrypted data as
/// it is read.
pub struct BufferedReaderDecryptor<R: BufferedReader<C>, C> {
    reader: BufferedReaderGeneric<Decryptor<R>, C>,
}

impl <R: BufferedReader<()>> BufferedReaderDecryptor<R, ()> {
    /// Instantiate a new symmetric decryptor.  `reader` is the source
    /// to wrap.
    pub fn new(algo: u8, key: &[u8], reader: R) -> Result<Self> {
        Self::with_cookie(algo, key, reader, ())
    }
}

impl <R: BufferedReader<C>, C> BufferedReaderDecryptor<R, C> {
    /// Like `new()`, but sets a cookie, which can be retrieved using
    /// the `cookie_ref` and `cookie_mut` methods, and set using
    /// the `cookie_set` method.
    pub fn with_cookie(algo: u8, key: &[u8], reader: R, cookie: C)
        -> Result<Self>
    {
        Ok(BufferedReaderDecryptor {
            reader: BufferedReaderGeneric::with_cookie(
                Decryptor::new(algo, key, reader)?, None, cookie),
        })
    }
}

impl<R: BufferedReader<C>, C> io::Read for BufferedReaderDecryptor<R, C> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buf)
    }
}

impl <R: BufferedReader<C>, C> fmt::Debug for BufferedReaderDecryptor<R, C> {
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
