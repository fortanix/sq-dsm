use std::io;
use std::cmp;
use std::mem;

use nettle::Hash;

use buffered_reader::BufferedReader;
use buffered_reader::buffered_reader_generic_read_impl;

use HashAlgorithm;
use parse::{Cookie, HashesFor};

use super::indent;

const TRACE : bool = false;

#[derive(Debug)]
pub(crate) struct HashedReader<R: BufferedReader<Cookie>> {
    reader: R,
    cookie: Cookie,
}

impl<R: BufferedReader<Cookie>> HashedReader<R> {
    /// Instantiates a new hashed reader.  `hashes_for` is the hash's
    /// purpose.  `algos` is a list of algorithms for which we should
    /// compute the hash.
    pub fn new(reader: R, hashes_for: HashesFor, algos: Vec<HashAlgorithm>)
            -> Self {
        let mut cookie = Cookie::default();
        for &algo in &algos {
            cookie.hashes.insert(algo, algo.context().unwrap());
        }
        cookie.hashes_for = hashes_for;

        HashedReader {
            reader: reader,
            cookie: cookie,
        }
    }
}

impl Cookie {
    fn hash_update(&mut self, data: &[u8]) {
        if TRACE {
            eprintln!("{}hash_update({} bytes, {} hashes, enabled: {})",
                      indent(cmp::max(0, self.level.unwrap_or(0)) as u8),
                      data.len(), self.hashes.len(), self.hashing);
        }

        if ! self.hashing {
            if TRACE {
                eprintln!("{}  hash_update: NOT hashing {} bytes: {}.",
                          indent(cmp::max(0, self.level.unwrap_or(0)) as u8),
                          data.len(), ::conversions::to_hex(data, true));
            }

            return;
        }

        for (algo, ref mut h) in self.hashes.iter_mut() {
            if TRACE {
                eprintln!("{}  hash_update({:?}): {:?} hashing {} bytes.",
                          indent(cmp::max(0, self.level.unwrap_or(0)) as u8),
                          self.hashes_for, algo, data.len());
                if false {
                    eprintln!("{}", ::conversions::to_hex(data, true));
                }
            }
            h.update(data);
        }
    }
}

impl<T: BufferedReader<Cookie>> io::Read for HashedReader<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        return buffered_reader_generic_read_impl(self, buf);
    }
}

// Wrap a BufferedReader so that any data that is consumed is added to
// the hash.
impl<R: BufferedReader<Cookie>>
        BufferedReader<Cookie> for HashedReader<R> {
    fn buffer(&self) -> &[u8] {
        self.reader.buffer()
    }

    fn data(&mut self, amount: usize) -> io::Result<&[u8]> {
        self.reader.data(amount)
    }

    fn data_hard(&mut self, amount: usize) -> io::Result<&[u8]> {
        self.reader.data_hard(amount)
    }

    fn consume(&mut self, amount: usize) -> &[u8] {
        // We need to take the state rather than get a mutable
        // reference to it, because self.reader.buffer() requires a
        // reference as well.
        let mut state = self.cookie_set(Cookie::default());

        {
            // The inner buffered reader must return at least `amount`
            // bytes, because the caller can't `consume(amount)` if
            // the internal buffer doesn't have at least that many
            // bytes.
            let data = self.reader.buffer();
            assert!(data.len() >= amount);
            state.hash_update(&data[..amount]);
        }

        self.cookie_set(state);

        self.reader.consume(amount)
    }

    fn data_consume(&mut self, amount: usize) -> io::Result<&[u8]> {
        // See consume() for an explanation of the following
        // acrobatics.

        let mut state = self.cookie_set(Cookie::default());

        let got = {
            let data = self.reader.data(amount)?;
            let data = &data[..cmp::min(data.len(), amount)];
            state.hash_update(data);
            data.len()
        };

        self.cookie_set(state);

        if let Ok(data) = self.reader.data_consume(amount) {
            assert!(data.len() >= got);
            Ok(data)
        } else {
            panic!("reader.data_consume() returned less than reader.data()!");
        }
    }

    fn data_consume_hard(&mut self, amount: usize) -> io::Result<&[u8]> {
        // See consume() for an explanation of the following
        // acrobatics.

        let mut state = self.cookie_set(Cookie::default());

        {
            let data = self.reader.data_hard(amount)?;
            assert!(data.len() >= amount);
            state.hash_update(&data[..amount]);
        }

        self.cookie_set(state);

        let result = self.reader.data_consume(amount);
        assert!(result.is_ok());
        result
    }

    fn get_mut(&mut self) -> Option<&mut BufferedReader<Cookie>> {
        Some(&mut self.reader)
    }

    fn get_ref(&self) -> Option<&BufferedReader<Cookie>> {
        Some(&self.reader)
    }

    fn into_inner<'b>(self: Box<Self>)
            -> Option<Box<BufferedReader<Cookie> + 'b>>
            where Self: 'b {
        Some(Box::new(self.reader))
    }

    fn cookie_set(&mut self, cookie: Cookie) -> Cookie {
        mem::replace(&mut self.cookie, cookie)
    }

    fn cookie_ref(&self) -> &Cookie {
        &self.cookie
    }

    fn cookie_mut(&mut self) -> &mut Cookie {
        &mut self.cookie
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use buffered_reader::BufferedReader;
    use buffered_reader::BufferedReaderGeneric;

    #[test]
    fn hash_test_1() {
        use std::collections::HashMap;
        struct Test<'a> {
            data: &'a [u8],
            expected: HashMap<HashAlgorithm, &'a str>,
        };

        let tests = [
            Test {
                data: &b"foobar\n"[..],
                expected: [
                    (HashAlgorithm::SHA1,
                     "988881adc9fc3655077dc2d4d757d480b5ea0e11"),
                ].iter().cloned().collect(),
            },
            Test {
                data: &b"0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789\n"[..],
                expected: [
                    (HashAlgorithm::SHA1,
                     "1d12c55b3a85daab4776a1df41a8f30ada099e11"),
                    (HashAlgorithm::SHA224,
                     "a4c1bde77c682a0e9e30c6afdd1ece2397ffeec61dde2a0eaa23191e"),
                    (HashAlgorithm::SHA256,
                    "151a1d51a1870dc244f07f4844f46ee65fae19a8efeb60b203a074aff899e27d"),
                    (HashAlgorithm::SHA384,
                    "5bea68c8c696bbed95e152d61c446ad0e05bf68f7df39cbfeae568bee6f6691c840fb1d5dd2599737b08dbb33eed344b"),
                    (HashAlgorithm::SHA512,
                     "5fa032487774082af5cc833c2db5f943e31cc75cd2bfaa7d9bbd0ccabf5403b6dbcb484254727a524588f20e9ef336d8ce8533332c5ac1b9d50af3003a0da8d8"),
                ].iter().cloned().collect(),
            },
        ];

        for test in tests.iter() {
            let reader
                = BufferedReaderGeneric::with_cookie(
                    test.data, None, Default::default());
            let mut reader
                = HashedReader::new(reader, HashesFor::MDC,
                                    test.expected.keys().cloned().collect());

            assert_eq!(reader.steal_eof().unwrap(), test.data);

            let cookie = reader.cookie_mut();

            let mut hashes = mem::replace(&mut cookie.hashes,
                                          Default::default());
            for (algo, ref mut hash) in hashes.iter_mut() {
                let mut digest = vec![0u8; hash.digest_size()];
                hash.digest(&mut digest);

                assert_eq!(digest,
                           &::conversions::from_hex(test.expected.get(algo)
                                                    .unwrap(), true)
                           .unwrap()[..],
                           "Algo: {:?}", algo);
            }
        }
    }
}
