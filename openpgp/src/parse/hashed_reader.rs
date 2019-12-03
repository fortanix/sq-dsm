use std::io;
use std::cmp;
use std::mem;
use std::fmt;

use buffered_reader::BufferedReader;
use buffered_reader::buffered_reader_generic_read_impl;

use crate::HashAlgorithm;
use crate::parse::{Cookie, HashesFor, Hashing};

const TRACE : bool = false;

pub(crate) struct HashedReader<R: BufferedReader<Cookie>> {
    reader: R,
    cookie: Cookie,
}

impl<R: BufferedReader<Cookie>> fmt::Display for HashedReader<R> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "HashedReader")
    }
}

impl<R: BufferedReader<Cookie>> fmt::Debug for HashedReader<R> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("HashedReader")
            .field("cookie", &self.cookie)
            .field("reader", &self.reader)
            .finish()
    }
}

impl<R: BufferedReader<Cookie>> HashedReader<R> {
    /// Instantiates a new hashed reader.  `hashes_for` is the hash's
    /// purpose.  `algos` is a list of algorithms for which we should
    /// compute the hash.
    pub fn new(reader: R, hashes_for: HashesFor, algos: Vec<HashAlgorithm>)
            -> Self {
        let mut cookie = Cookie::default();
        for &algo in &algos {
            cookie.sig_group_mut().hashes
                .push((algo, algo.context().unwrap()));
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
        let level = self.level.unwrap_or(0);
        let hashes_for = self.hashes_for;
        let ngroups = self.sig_groups.len();

        tracer!(TRACE, "Cookie::hash_update", level);

        // Hash stashed data first.
        if let Some(stashed_data) = self.hash_stash.take() {
            // The stashed data was supposed to be hashed into the
            // then-topmost signature-group's hash, but wasn't,
            // because framing isn't hashed into the topmost signature
            // group.  By the time the parser encountered a new
            // signature group, the data has already been consumed.
            // We fix that here by hashing the stashed data into the
            // former topmost signature-group's hash.
            assert!(ngroups > 1);
            for (algo, ref mut h) in
                self.sig_groups[ngroups-2].hashes.iter_mut()
            {
                t!("({:?}): group {} {:?} hashing {} stashed bytes.",
                   hashes_for, ngroups-2, algo, data.len());

                h.update(&stashed_data);
            }
        }

        if data.len() == 0 {
            return;
        }

        t!("({} bytes, {} hashes, enabled: {:?})",
           data.len(), self.sig_group().hashes.len(), self.hashing);

        if self.hashing == Hashing::Disabled {
            t!("    hash_update: NOT hashing {} bytes: {}.",
               data.len(), crate::fmt::to_hex(data, true));
            return;
        }

        let topmost_group = |i| i == ngroups - 1;
        for (i, sig_group) in self.sig_groups.iter_mut().enumerate() {
            if topmost_group(i) && self.hashing != Hashing::Enabled {
                t!("topmost group {} NOT hashing {} bytes: {}.",
                   i, data.len(), crate::fmt::to_hex(data, true));

                return;
            }

            for (algo, ref mut h) in sig_group.hashes.iter_mut() {
                t!("{:?}): group {} {:?} hashing {} bytes.",
                   hashes_for, i, algo, data.len());
                h.update(data);
            }
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

    fn get_mut(&mut self) -> Option<&mut dyn BufferedReader<Cookie>> {
        Some(&mut self.reader)
    }

    fn get_ref(&self) -> Option<&dyn BufferedReader<Cookie>> {
        Some(&self.reader)
    }

    fn into_inner<'b>(self: Box<Self>)
            -> Option<Box<dyn BufferedReader<Cookie> + 'b>>
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
                = buffered_reader::Generic::with_cookie(
                    test.data, None, Default::default());
            let mut reader
                = HashedReader::new(reader, HashesFor::MDC,
                                    test.expected.keys().cloned().collect());

            assert_eq!(reader.steal_eof().unwrap(), test.data);

            let cookie = reader.cookie_mut();

            let mut hashes = mem::replace(&mut cookie.sig_group_mut().hashes,
                                          Default::default());
            for (algo, ref mut hash) in hashes.iter_mut() {
                let mut digest = vec![0u8; hash.digest_size()];
                hash.digest(&mut digest);

                assert_eq!(digest,
                           &crate::fmt::from_hex(test.expected.get(algo)
                                                    .unwrap(), true)
                           .unwrap()[..],
                           "Algo: {:?}", algo);
            }
        }
    }
}
