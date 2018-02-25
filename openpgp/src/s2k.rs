use std::cmp;

use nettle::Hash;

use hash::hash_context;
use Result;
use HashAlgo;
use S2K;

impl S2K {
    /// Return the interation count.
    pub fn iteration_count(&self) -> u32 {
        if let Some(cc) = self.coded_count {
            let cc = cc as u32;
            16u32 + (cc & 15) << ((cc >> 4) + 6)
        } else {
            0
        }
    }

    /// Convert the string to a key using the S2K's paramters.
    pub fn s2k(&self, string: &[u8], key_size: usize) -> Result<Vec<u8>> {
        let algo = HashAlgo::from_numeric(self.hash_algo)?;
        let h = hash_context(algo);

        // If the digest length is shorter than the key length,
        // then we need to concatenate multiple hashes, each
        // preloaded with i 0s.
        let contexts = (key_size + h.digest_size() - 1) / h.digest_size();

        let mut hs = Vec::with_capacity(contexts);
        hs.push(h);

        let zeros = vec![0u8; contexts - 1];
        for i in 1..contexts {
            let mut h = hash_context(algo);
            h.update(&zeros[..i]);
            hs.push(h);
        }

        fn update(hs: &mut Vec<Box<Hash>>, data: &[u8]) {
            for h in hs {
                h.update(data);
            }
        }

        // Independent of what the iteration count is, we always hash
        // the whole salt and password once.
        let salt_len;
        if let Some(salt) = self.salt {
            update(&mut hs, &salt[..]);
            salt_len = salt.len();
        } else {
            salt_len = 0;
        }
        update(&mut hs, string);

        let mut todo
            = self.iteration_count() as usize
            - cmp::min(self.iteration_count() as usize,
                       salt_len + string.len());

        while todo > 0 {
            if let Some(salt) = self.salt {
                let l = cmp::min(salt.len(), todo);
                todo -= l;
                update(&mut hs, &salt[..l]);
            }

            let l = cmp::min(string.len(), todo);
            todo -= l;
            update(&mut hs, &string[..l]);
        }

        let mut digest = vec![0u8; key_size];
        let mut start = 0;
        for mut h in hs {
            let end = cmp::min(start+h.digest_size(), key_size);
            h.digest(&mut digest[start..end]);
            start = end;
        }

        Ok(digest)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use to_hex;
    use Tag;
    use SymmetricAlgo;
    use SKESK;
    use Packet;

    use std::fs::File;

    use buffered_reader::BufferedReaderGeneric;
    use parse::{header, BufferedReaderState};
    use symmetric::symmetric_key_size;

    use std::path::PathBuf;
    fn path_to(artifact: &str) -> PathBuf {
        [env!("CARGO_MANIFEST_DIR"), "tests", "data", "messages", "s2k", artifact]
            .iter().collect()
    }

    #[test]
    fn s2k_parser_test() {
        struct Test<'a> {
            filename: &'a str,
            s2k: S2K,
            cipher_algo: SymmetricAlgo,
            password: &'a [u8],
            key_hex: &'a str,
        };

        // Note: this test only works with SK-ESK packets that don't
        // contain an encrypted session key, i.e., the session key is
        // the result of the s2k function.  gpg generates this type of
        // SK-ESK packet when invoked with -c, but not -e.  (When
        // invoked with -c and -e, it generates SK-ESK packets that
        // include an encrypted session key.)
        let tests = [
            Test {
                filename: "mode-0-password-1234.gpg",
                cipher_algo: SymmetricAlgo::AES256,
                s2k: S2K {
                    hash_algo: 2,
                    salt: None,
                    coded_count: None,
                },
                password: &b"1234"[..],
                key_hex: "7110EDA4D09E062AA5E4A390B0A572AC0D2C0220F352B0D292B65164C2A67301",
            },
            Test {
                filename: "mode-1-password-123456-1.gpg",
                cipher_algo: SymmetricAlgo::AES256,
                s2k: S2K {
                    hash_algo: 2,
                    salt: Some([0xa8, 0x42, 0xa7, 0xa9, 0x59, 0xfa, 0x42, 0x2a]),
                    coded_count: None,
                },
                password: &b"123456"[..],
                key_hex: "8B79077CA448F6FB3D3AD2A264D3B938D357C9FB3E41219FD962DF960A9AFA08",
            },
            Test {
                filename: "mode-1-password-foobar-2.gpg",
                cipher_algo: SymmetricAlgo::AES256,
                s2k: S2K {
                    hash_algo: 2,
                    salt: Some([0xbc, 0x95, 0x58, 0x45, 0x81, 0x3c, 0x7c, 0x37]),
                    coded_count: None,
                },
                password: &b"foobar"[..],
                key_hex: "B7D48AAE9B943B22A4D390083E8460B5EDFA118FE1688BF0C473B8094D1A8D10",
            },
            Test {
                filename: "mode-3-password-qwerty-1.gpg",
                cipher_algo: SymmetricAlgo::AES256,
                s2k: S2K {
                    hash_algo: 2,
                    salt: Some([0x78, 0x45, 0xf0, 0x5b, 0x55, 0xf7, 0xb4, 0x9e]),
                    coded_count: Some(241),
                },
                password: &b"qwerty"[..],
                key_hex: "575AD156187A3F8CEC11108309236EB499F1E682F0D1AFADFAC4ECF97613108A",
            },
            Test {
                filename: "mode-3-password-9876-2.gpg",
                cipher_algo: SymmetricAlgo::AES256,
                s2k: S2K {
                    hash_algo: 2,
                    salt: Some([0xb9, 0x67, 0xea, 0x96, 0x53, 0xdb, 0x6a, 0xc8]),
                    coded_count: Some(43),
                },
                password: &b"9876"[..],
                key_hex: "736C226B8C64E4E6D0325C6C552EF7C0738F98F48FED65FD8C93265103EFA23A",
            },
            Test {
                filename: "mode-3-aes192-password-123.gpg",
                cipher_algo: SymmetricAlgo::AES192,
                s2k: S2K {
                    hash_algo: 2,
                    salt: Some([0x8f, 0x81, 0x74, 0xc5, 0xd9, 0x61, 0xc7, 0x79]),
                    coded_count: Some(238),
                },
                password: &b"123"[..],
                key_hex: "915E96FC694E7F90A6850B740125EA005199C725F3BD27E3",
            },
            Test {
                filename: "mode-3-twofish-password-13-times-0123456789.gpg",
                cipher_algo: SymmetricAlgo::Twofish,
                s2k: S2K {
                    hash_algo: 2,
                    salt: Some([0x51, 0xed, 0xfc, 0x15, 0x45, 0x40, 0x65, 0xac]),
                    coded_count: Some(238),
                },
                password: &b"0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"[..],
                key_hex: "EA264FADA5A859C40D88A159B344ECF1F51FF327FDB3C558B0A7DC299777173E",
            },
            Test {
                filename: "mode-3-aes128-password-13-times-0123456789.gpg",
                cipher_algo: SymmetricAlgo::AES128,
                s2k: S2K {
                    hash_algo: 2,
                    salt: Some([0x06, 0xe4, 0x61, 0x5c, 0xa4, 0x48, 0xf9, 0xdd]),
                    coded_count: Some(238),
                },
                password: &b"0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"[..],
                key_hex: "F3D0CE52ED6143637443E3399437FD0F",
            },
        ];

        for test in tests.iter() {
            let path = path_to(test.filename);
            let mut f = File::open(&path).expect(&path.to_string_lossy());
            let mut bio = BufferedReaderGeneric::with_cookie(
                &mut f, None, BufferedReaderState::default());

            let h = header(&mut bio).unwrap();
            assert_eq!(h.ctb.tag, Tag::SKESK);

            let (packet, _, _, _)
                = SKESK::parse(bio, 0).unwrap().next().unwrap();

            if let Packet::SKESK(skesk) = packet {
                eprintln!("{:?}", skesk);

                assert_eq!(skesk.symm_algo,
                           SymmetricAlgo::to_numeric(test.cipher_algo));
                assert_eq!(skesk.s2k, test.s2k);

                let key = skesk.s2k.s2k(
                    test.password,
                    symmetric_key_size(skesk.symm_algo).unwrap());
                if let Ok(key) = key {
                    let key = to_hex(&key[..], false);
                    assert_eq!(key, test.key_hex);
                } else {
                    panic!("Session key: None!");
                }
            } else {
                unreachable!();
            }
        }
    }
}
