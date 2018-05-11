//! Symmetric encryption.

use std::io;
use std::cmp;
use std::fmt;

use Result;
use Error;

use buffered_reader::BufferedReader;
use buffered_reader::BufferedReaderGeneric;

use nettle::Cipher;
use nettle::Mode;

use quickcheck::{Arbitrary,Gen};

/// The symmetric-key algorithms as defined in [Section 9.2 of RFC 4880].
///
///   [Section 9.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-9.2
///
/// The values can be converted into and from their corresponding values of the serialized format.
///
/// Use [`SymmetricAlgo::into`] to translate a numeric value
/// to a symbolic one.
///
///   [`SymmetricAlgo::from`]: enum.SymmetricAlgo.html#method.from
#[derive(Clone,Copy,PartialEq,Eq,Debug)]
pub enum SymmetricAlgo {
    Unencrypted,
    IDEA,
    TripleDES,
    CAST5,
    Blowfish,
    AES128,
    AES192,
    AES256,
    Twofish,
    Private(u8),
    Unknown(u8),
}

impl From<u8> for SymmetricAlgo {
    fn from(u: u8) -> Self {
        match u {
            0 => SymmetricAlgo::Unencrypted,
            1 => SymmetricAlgo::IDEA,
            2 => SymmetricAlgo::TripleDES,
            3 => SymmetricAlgo::CAST5,
            4 => SymmetricAlgo::Blowfish,
            7 => SymmetricAlgo::AES128,
            8 => SymmetricAlgo::AES192,
            9 => SymmetricAlgo::AES256,
            10 => SymmetricAlgo::Twofish,
            100...110 => SymmetricAlgo::Private(u),
            u => SymmetricAlgo::Unknown(u),
        }
    }
}

impl From<SymmetricAlgo> for u8 {
    fn from(s: SymmetricAlgo) -> u8 {
        match s {
            SymmetricAlgo::Unencrypted => 0,
            SymmetricAlgo::IDEA => 1,
            SymmetricAlgo::TripleDES => 2,
            SymmetricAlgo::CAST5 => 3,
            SymmetricAlgo::Blowfish => 4,
            SymmetricAlgo::AES128 => 7,
            SymmetricAlgo::AES192 => 8,
            SymmetricAlgo::AES256 => 9,
            SymmetricAlgo::Twofish => 10,
            SymmetricAlgo::Private(u) => u,
            SymmetricAlgo::Unknown(u) => u,
        }
    }
}

impl fmt::Display for SymmetricAlgo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SymmetricAlgo::Unencrypted =>
                f.write_str("Unencrypted"),
            SymmetricAlgo::IDEA =>
                f.write_str("IDEA"),
            SymmetricAlgo::TripleDES =>
                f.write_str("TipleDES (EDE-DES, 168 bit key derived from 192))"),
            SymmetricAlgo::CAST5 =>
                f.write_str("CAST5 (128 bit key, 16 rounds)"),
            SymmetricAlgo::Blowfish =>
                f.write_str("Blowfish (128 bit key, 16 rounds)"),
            SymmetricAlgo::AES128 =>
                f.write_str("AES with 128-bit key"),
            SymmetricAlgo::AES192 =>
                f.write_str("AES with 192-bit key"),
            SymmetricAlgo::AES256 =>
                f.write_str("AES with 256-bit key"),
            SymmetricAlgo::Twofish =>
                f.write_str("Twofish with 256-bit key"),
            SymmetricAlgo::Private(u) =>
                f.write_fmt(format_args!("Private/Experimental symmetric key algorithm {}",u)),
            SymmetricAlgo::Unknown(u) =>
                f.write_fmt(format_args!("Unknown symmetric key algorithm {}",u)),
        }
    }
}

impl Arbitrary for SymmetricAlgo {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        u8::arbitrary(g).into()
    }
}

impl SymmetricAlgo {
    pub fn key_size(self) -> Result<usize> {
        use nettle::cipher;
        match self {
            SymmetricAlgo::AES128 => Ok(cipher::Aes128::KEY_SIZE),
            SymmetricAlgo::AES192 => Ok(cipher::Aes192::KEY_SIZE),
            SymmetricAlgo::AES256 => Ok(cipher::Aes256::KEY_SIZE),
            SymmetricAlgo::Twofish => Ok(cipher::Twofish::KEY_SIZE),
            _ => Err(Error::UnsupportedSymmetricAlgorithm(self.into()).into()),
        }
    }
    pub fn block_size(self) -> Result<usize> {
        use nettle::cipher;
        match self {
            SymmetricAlgo::AES128 => Ok(cipher::Aes128::BLOCK_SIZE),
            SymmetricAlgo::AES192 => Ok(cipher::Aes192::BLOCK_SIZE),
            SymmetricAlgo::AES256 => Ok(cipher::Aes256::BLOCK_SIZE),
            SymmetricAlgo::Twofish => Ok(cipher::Twofish::BLOCK_SIZE),
            _ => Err(Error::UnsupportedSymmetricAlgorithm(self.into()).into()),
        }
    }

    pub fn make_encrypt_cfb(self, key: &[u8]) -> Result<Box<Mode>> {
        use nettle::{mode,cipher};
        match self {
            SymmetricAlgo::AES128 =>
                Ok(Box::new(mode::Cfb::<cipher::Aes128>::with_encrypt_key(&key[..]))),
            SymmetricAlgo::AES192 =>
                Ok(Box::new(mode::Cfb::<cipher::Aes192>::with_encrypt_key(&key[..]))),
            SymmetricAlgo::AES256 =>
                Ok(Box::new(mode::Cfb::<cipher::Aes256>::with_encrypt_key(&key[..]))),
            SymmetricAlgo::Twofish =>
                Ok(Box::new(mode::Cfb::<cipher::Twofish>::with_encrypt_key(&key[..]))),
            _ => Err(Error::UnsupportedSymmetricAlgorithm(self.into()).into()),
        }
    }

    pub fn make_decrypt_cfb(self, key: &[u8]) -> Result<Box<Mode>> {
        use nettle::{mode,cipher};
        match self {
            SymmetricAlgo::AES128 =>
                Ok(Box::new(mode::Cfb::<cipher::Aes128>::with_decrypt_key(&key[..]))),
            SymmetricAlgo::AES192 =>
                Ok(Box::new(mode::Cfb::<cipher::Aes192>::with_decrypt_key(&key[..]))),
            SymmetricAlgo::AES256 =>
                Ok(Box::new(mode::Cfb::<cipher::Aes256>::with_decrypt_key(&key[..]))),
            SymmetricAlgo::Twofish =>
                Ok(Box::new(mode::Cfb::<cipher::Twofish>::with_decrypt_key(&key[..]))),
            _ => Err(Error::UnsupportedSymmetricAlgorithm(self.into()).into())
        }
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
    pub fn new(algo: SymmetricAlgo, key: &[u8], source: R) -> Result<Self> {
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
// reached the end of the input or an error occured.
impl<R: io::Read> io::Read for Decryptor<R> {
    fn read(&mut self, plaintext: &mut [u8]) -> io::Result<usize> {
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

        &plaintext[pos..pos + to_copy].copy_from_slice(&self.buffer[..to_copy]);
        self.buffer.drain(..to_copy);

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
    pub fn new(algo: SymmetricAlgo, key: &[u8], reader: R) -> Result<Self> {
        Self::with_cookie(algo, key, reader, ())
    }
}

impl <R: BufferedReader<C>, C> BufferedReaderDecryptor<R, C> {
    /// Like `new()`, but sets a cookie, which can be retrieved using
    /// the `cookie_ref` and `cookie_mut` methods, and set using
    /// the `cookie_set` method.
    pub fn with_cookie(algo: SymmetricAlgo, key: &[u8], reader: R, cookie: C)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Read;

    quickcheck! {
        fn sym_roundtrip(sym: SymmetricAlgo) -> bool {
            let val: u8 = sym.clone().into();
            sym == SymmetricAlgo::from(val)
        }
    }

    quickcheck! {
        fn sym_display(sym: SymmetricAlgo) -> bool {
            let s = format!("{}",sym);
            !s.is_empty()
        }
    }

    quickcheck! {
        fn sym_parse(sym: SymmetricAlgo) -> bool {
            match sym {
                SymmetricAlgo::Unknown(u) => u == 5 || u == 6 || u > 110 || (u > 10 && u < 100),
                SymmetricAlgo::Private(u) => u >= 100 && u <= 110,
                _ => true
            }
        }
    }

    const PLAINTEXT: &[u8]
        = include_bytes!("../tests/data/messages/a-cypherpunks-manifesto.txt");

    /// This test is designed to test the buffering logic in Decryptor
    /// by reading directly from it (i.e. without any buffering
    /// introduced by the BufferedReaderDecryptor or any other source
    /// of buffering).
    #[test]
    fn decryptor() {
        let basedir = ::std::env::current_exe().unwrap()
            .parent().unwrap().parent().unwrap()
            .parent().unwrap().parent().unwrap()
            .join("openpgp/tests/data/raw");

        for algo in [SymmetricAlgo::AES128,
                     SymmetricAlgo::AES192,
                     SymmetricAlgo::AES256].iter() {
            // The keys are [0, 1, 2, ...].
            let mut key = vec![0u8; algo.key_size().unwrap()];
            for i in 0..key.len() {
                key[0] = i as u8;
            }

            let ciphertext
                = File::open(basedir.join(
                    format!("a-cypherpunks-manifesto.aes{}.key_ascending_from_0",
                            algo.key_size().unwrap() * 8))).unwrap();
            let decryptor = Decryptor::new(*algo, &key, ciphertext).unwrap();

            // Read bytewise to test the buffer logic.
            let mut plaintext = Vec::new();
            for b in decryptor.bytes() {
                plaintext.push(b.unwrap());
            }

            assert_eq!(&PLAINTEXT[..], &plaintext[..]);
        }
    }
}
