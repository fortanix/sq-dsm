//! String-to-Key (S2K) specifiers.
//!
//! String-to-key (S2K) specifiers are used to convert password
//! strings into symmetric-key encryption/decryption keys.  See
//! [Section 3.7 of RFC 4880].
//!
//!   [Section 3.7 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-3.7

use crate::Error;
use crate::Result;
use crate::HashAlgorithm;
use crate::crypto::Password;
use crate::crypto::SessionKey;

use std::fmt;

use quickcheck::{Arbitrary, Gen};
use rand::Rng;

/// String-to-Key (S2K) specifiers.
///
/// String-to-key (S2K) specifiers are used to convert password
/// strings into symmetric-key encryption/decryption keys.  See
/// [Section 3.7 of RFC 4880].
///
///   [Section 3.7 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-3.7
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum S2K {
    /// Simply hashes the password.
    Simple {
        /// Hash used for key derivation.
        hash: HashAlgorithm
    },
    /// Hashes the password with a public `salt` value.
    Salted {
        /// Hash used for key derivation.
        hash: HashAlgorithm,
        /// Public salt value mixed into the password.
        salt: [u8; 8],
    },
    /// Repeatently hashes the password with a public `salt` value.
    Iterated {
        /// Hash used for key derivation.
        hash: HashAlgorithm,
        /// Public salt value mixed into the password.
        salt: [u8; 8],
        /// Number of bytes to hash.
        hash_bytes: u32,
    },
    /// Private S2K algorithm
    Private(u8),
    /// Unknown S2K algorithm
    Unknown(u8),
}

impl Default for S2K {
    fn default() -> Self {
        let mut salt = [0u8; 8];
        crate::crypto::random(&mut salt);
        S2K::Iterated {
            // SHA2-256, being optimized for implementations on
            // architectures with a word size of 32 bit, has a more
            // consistent runtime across different architectures than
            // SHA2-512.  Furthermore, the digest size is large enough
            // for every cipher algorithm currently in use.
            hash: HashAlgorithm::SHA256,
            salt: salt,
            // This is the largest count that OpenPGP can represent.
            // On moderate machines, like my Intel(R) Core(TM) i5-2400
            // CPU @ 3.10GHz, it takes ~354ms to derive a key.
            hash_bytes: 65_011_712,
        }
    }
}

impl S2K {
    /// Convert the string to a key using the S2K's parameters.
    pub fn derive_key(&self, string: &Password, key_size: usize)
    -> Result<SessionKey> {
        match self {
            &S2K::Simple { hash } | &S2K::Salted { hash, .. }
            | &S2K::Iterated { hash, .. } => {
                let mut hash = hash.context()?;

                // If the digest length is shorter than the key length,
                // then we need to concatenate multiple hashes, each
                // preloaded with i 0s.
                let hash_sz = hash.digest_size();
                let num_contexts = (key_size + hash_sz - 1) / hash_sz;
                let mut zeros = Vec::with_capacity(num_contexts + 1);
                let mut ret = vec![0u8; key_size];

                for data in ret.chunks_mut(hash_sz) {
                    hash.update(&zeros[..]);

                    match self {
                        &S2K::Simple { .. } => {
                            hash.update(string);
                        }
                        &S2K::Salted { ref salt, .. } => {
                            hash.update(salt);
                            hash.update(string);
                        }
                        &S2K::Iterated { ref salt, hash_bytes, .. }
                        if (hash_bytes as usize) < salt.len() + string.len() =>
                        {
                            // Independent of what the hash count is, we
                            // always hash the whole salt and password once.
                            hash.update(&salt[..]);
                            hash.update(&string);
                        },
                        &S2K::Iterated { ref salt, hash_bytes, .. } => {
                            // Unroll the processing loop N times.
                            const N: usize = 16;
                            let data_len = salt.len() + string.len();
                            let octs_per_iter = N * data_len;
                            let mut data: SessionKey =
                                vec![0u8; octs_per_iter].into();
                            let full = hash_bytes as usize / octs_per_iter;
                            let tail = hash_bytes as usize - (full * octs_per_iter);

                            for i in 0..N {
                                let o = data_len * i;
                                data[o..o + salt.len()]
                                    .clone_from_slice(salt);
                                data[o + salt.len()..o + data_len]
                                    .clone_from_slice(string);
                            }

                            for _ in 0..full {
                                hash.update(&data);
                            }

                            if tail != 0 {
                                hash.update(&data[0..tail]);
                            }
                        }
                        &S2K::Unknown(_) | &S2K::Private(_) => unreachable!(),
                    }

                    hash.digest(data);
                    zeros.push(0);
                }

                Ok(ret.into())
            }
            &S2K::Unknown(u) | &S2K::Private(u) =>
                Err(Error::MalformedPacket(
                        format!("Unknown S2K type {:#x}", u)).into()),
        }
    }

    /// This function returns an encodabled iteration count larger or
    /// equal `hash_bytes`.
    ///
    /// Not all iteration counts are encodable as *Iterated and Salted
    /// S2K*.  The largest encodable hash count is `0x3e00000`.
    pub fn nearest_hash_count(hash_bytes: usize) -> u32 {
        use std::usize;

        match hash_bytes {
            0..=1024 => 1024,
            1025..=2048 => hash_bytes as u32,
            0x3e00001..=usize::MAX => 0x3e00000,
            hash_bytes => {
                let hash_bytes = hash_bytes as u32;
                let msb = 32 - hash_bytes.leading_zeros();
                let mantissa_mask = 0b1111_000000 << (msb - 11);
                let tail_mask = (1 << (msb - 11)) - 1;
                let mantissa = (hash_bytes & mantissa_mask) >> (msb - 5);
                let exp = if msb < 11 { 0 } else { msb - 11 };

                if hash_bytes & tail_mask != 0 {
                    if mantissa < 0b1111 {
                        Self::decode_count((mantissa as u8 + 1) | exp as u8)
                    } else {
                        Self::decode_count(mantissa as u8 | (exp as u8 + 1))
                    }
                } else {
                    hash_bytes
                }
            }
        }
     }

    /// Decodes the OpenPGP encoding of the number of bytes to hash.
    pub fn decode_count(coded: u8) -> u32 {
        use std::cmp;

        let mantissa = 16 + (coded as u32 & 15);
        let exp = (coded as u32 >> 4) + 6;

        mantissa << cmp::min(32 - 5, exp)
    }

    /// Converts `hash_bytes` into coded count representation.
    ///
    /// # Errors
    ///
    /// Fails with `Error::InvalidArgument` if `hash_bytes` cannot be
    /// encoded. See also [`S2K::nearest_hash_count()`].
    ///
    /// [`S2K::nearest_hash_count()`]: #method.nearest_hash_count
    pub fn encode_count(hash_bytes: u32) -> Result<u8> {
        // eeee.mmmm -> (16 + mmmm) * 2^(6 + e)

        let msb = 32 - hash_bytes.leading_zeros();
        let (mantissa_mask, tail_mask) = match msb {
            0..=10 => {
                return Err(Error::InvalidArgument(
                    format!("S2K: cannot encode iteration count of {}",
                            hash_bytes)).into());
            }
            11..=32 => {
                let m = 0b1111_000000 << (msb - 11);
                let t = 1 << (msb - 11);

                (m, t - 1)
            }
            _ => unreachable!()
        };
        let exp = if msb < 11 { 0 } else { msb - 11 };
        let mantissa = (hash_bytes & mantissa_mask) >> (msb - 5);

        if tail_mask & hash_bytes != 0 {
            return Err(Error::InvalidArgument(
                format!("S2K: cannot encode iteration count of {}",
                        hash_bytes)).into());
        }

        Ok(mantissa as u8 | (exp as u8) << 4)
    }
}

impl fmt::Display for S2K {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            S2K::Simple{ hash } =>
                f.write_fmt(format_args!("Simple S2K with {}", hash)),
            S2K::Salted{ hash, salt } => {
                f.write_fmt(
                    format_args!("Salted S2K with {} and salt\
                        {:x}{:x}{:x}{:x}{:x}{:x}{:x}{:x}",
                    hash,
                    salt[0], salt[1], salt[2], salt[3],
                    salt[4], salt[5], salt[6], salt[7]))
            }
            S2K::Iterated{ hash, salt, hash_bytes, } => {
                f.write_fmt(
                    format_args!("Iterated and Salted S2K with {}, \
                      salt {:x}{:x}{:x}{:x}{:x}{:x}{:x}{:x} and \
                      {} bytes to hash",
                    hash,
                    salt[0], salt[1], salt[2], salt[3],
                    salt[4], salt[5], salt[6], salt[7],
                    hash_bytes))
            }
            S2K::Private(u) =>
                f.write_fmt(format_args!("Private/Experimental S2K {}", u)),
            S2K::Unknown(u) => f.write_fmt(format_args!("Unknown S2K {}", u)),
        }
    }
}

impl Arbitrary for S2K {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        match g.gen_range(0, 5) {
            0 => S2K::Simple{ hash: HashAlgorithm::arbitrary(g) },
            1 => S2K::Salted{
                hash: HashAlgorithm::arbitrary(g),
                salt: g.gen(),
            },
            2 => S2K::Iterated{
                hash: HashAlgorithm::arbitrary(g),
                salt: g.gen(),
                hash_bytes: S2K::nearest_hash_count(g.gen()),
            },
            3 => S2K::Private(g.gen_range(100, 111)),
            4 => S2K::Unknown(g.gen_range(4, 100)),
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::fmt::to_hex;
    use crate::SymmetricAlgorithm;
    use crate::Packet;
    use crate::parse::{Parse, PacketParser};
    use crate::serialize::Serialize;

    #[test]
    fn s2k_parser_test() {
        use crate::packet::SKESK;

        struct Test<'a> {
            filename: &'a str,
            s2k: S2K,
            cipher_algo: SymmetricAlgorithm,
            password: Password,
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
                cipher_algo: SymmetricAlgorithm::AES256,
                s2k: S2K::Simple{ hash: HashAlgorithm::SHA1, },
                password: "1234".into(),
                key_hex: "7110EDA4D09E062AA5E4A390B0A572AC0D2C0220F352B0D292B65164C2A67301",
            },
            Test {
                filename: "mode-1-password-123456-1.gpg",
                cipher_algo: SymmetricAlgorithm::AES256,
                s2k: S2K::Salted{
                    hash: HashAlgorithm::SHA1,
                    salt: [0xa8, 0x42, 0xa7, 0xa9, 0x59, 0xfa, 0x42, 0x2a],
                },
                password: "123456".into(),
                key_hex: "8B79077CA448F6FB3D3AD2A264D3B938D357C9FB3E41219FD962DF960A9AFA08",
            },
            Test {
                filename: "mode-1-password-foobar-2.gpg",
                cipher_algo: SymmetricAlgorithm::AES256,
                s2k: S2K::Salted{
                    hash: HashAlgorithm::SHA1,
                    salt: [0xbc, 0x95, 0x58, 0x45, 0x81, 0x3c, 0x7c, 0x37],
                },
                password: "foobar".into(),
                key_hex: "B7D48AAE9B943B22A4D390083E8460B5EDFA118FE1688BF0C473B8094D1A8D10",
            },
            Test {
                filename: "mode-3-password-qwerty-1.gpg",
                cipher_algo: SymmetricAlgorithm::AES256,
                s2k: S2K::Iterated {
                    hash: HashAlgorithm::SHA1,
                    salt: [0x78, 0x45, 0xf0, 0x5b, 0x55, 0xf7, 0xb4, 0x9e],
                    hash_bytes: S2K::decode_count(241),
                },
                password: "qwerty".into(),
                key_hex: "575AD156187A3F8CEC11108309236EB499F1E682F0D1AFADFAC4ECF97613108A",
            },
            Test {
                filename: "mode-3-password-9876-2.gpg",
                cipher_algo: SymmetricAlgorithm::AES256,
                s2k: S2K::Iterated {
                    hash: HashAlgorithm::SHA1,
                    salt: [0xb9, 0x67, 0xea, 0x96, 0x53, 0xdb, 0x6a, 0xc8],
                    hash_bytes: S2K::decode_count(43),
                },
                password: "9876".into(),
                key_hex: "736C226B8C64E4E6D0325C6C552EF7C0738F98F48FED65FD8C93265103EFA23A",
            },
            Test {
                filename: "mode-3-aes192-password-123.gpg",
                cipher_algo: SymmetricAlgorithm::AES192,
                s2k: S2K::Iterated {
                    hash: HashAlgorithm::SHA1,
                    salt: [0x8f, 0x81, 0x74, 0xc5, 0xd9, 0x61, 0xc7, 0x79],
                    hash_bytes: S2K::decode_count(238),
                },
                password: "123".into(),
                key_hex: "915E96FC694E7F90A6850B740125EA005199C725F3BD27E3",
            },
            Test {
                filename: "mode-3-twofish-password-13-times-0123456789.gpg",
                cipher_algo: SymmetricAlgorithm::Twofish,
                s2k: S2K::Iterated {
                    hash: HashAlgorithm::SHA1,
                    salt: [0x51, 0xed, 0xfc, 0x15, 0x45, 0x40, 0x65, 0xac],
                    hash_bytes: S2K::decode_count(238),
                },
                password: "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789".into(),
                key_hex: "EA264FADA5A859C40D88A159B344ECF1F51FF327FDB3C558B0A7DC299777173E",
            },
            Test {
                filename: "mode-3-aes128-password-13-times-0123456789.gpg",
                cipher_algo: SymmetricAlgorithm::AES128,
                s2k: S2K::Iterated {
                    hash: HashAlgorithm::SHA1,
                    salt: [0x06, 0xe4, 0x61, 0x5c, 0xa4, 0x48, 0xf9, 0xdd],
                    hash_bytes: S2K::decode_count(238),
                },
                password: "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789".into(),
                key_hex: "F3D0CE52ED6143637443E3399437FD0F",
            },
        ];

        for test in tests.iter() {
            let path = crate::tests::message(&format!("s2k/{}", test.filename));
            let pp = PacketParser::from_bytes(path).unwrap().unwrap();
            if let Packet::SKESK(SKESK::V4(ref skesk)) = pp.packet {
                assert_eq!(skesk.symmetric_algo(), test.cipher_algo);
                assert_eq!(skesk.s2k(), &test.s2k);

                let key = skesk.s2k().derive_key(
                    &test.password,
                    skesk.symmetric_algo().key_size().unwrap());
                if let Ok(key) = key {
                    let key = to_hex(&key[..], false);
                    assert_eq!(key, test.key_hex);
                } else {
                    panic!("Session key: None!");
                }
            } else {
                panic!("Wrong packet!");
            }

            // Get the next packet.
            let (_, ppr) = pp.next().unwrap();
            assert!(ppr.is_none());
        }
    }

    quickcheck! {
        fn s2k_roundtrip(s2k: S2K) -> bool {
            use crate::serialize::SerializeInto;

            eprintln!("in {:?}", s2k);
            use std::io::Cursor;

            let mut w = Cursor::new(Vec::new());
            let l = s2k.serialized_len();
            s2k.serialize(&mut w).unwrap();
            let buf = w.into_inner();
            eprintln!("raw: {:?}", buf);

            assert_eq!(buf.len(), l);
            let mut r = Cursor::new(buf.into_boxed_slice());
            let s = S2K::from_reader(&mut r).unwrap();
            eprintln!("out {:?}", s);

            s2k == s
        }
    }

    quickcheck! {
        fn s2k_display(s2k: S2K) -> bool {
            let s = format!("{}", s2k);
            !s.is_empty()
        }
    }

    quickcheck! {
        fn s2k_parse(s2k: S2K) -> bool {
            match s2k {
                S2K::Unknown(u) => (u > 3 && u < 100) || u == 2 || u > 110,
                S2K::Private(u) => u >= 100 && u <= 110,
                _ => true
            }
        }
    }

    #[test]
    fn s2k_coded_count_roundtrip() {
        for cc in 0..0x100usize {
            let hash_bytes = S2K::decode_count(cc as u8);
            assert!(hash_bytes >= 1024
                    && S2K::encode_count(hash_bytes).unwrap() == cc as u8);
        }
    }

    quickcheck!{
        fn s2k_coded_count_approx(i: usize) -> bool {
            let approx = S2K::nearest_hash_count(i);
            let cc = S2K::encode_count(approx).unwrap();

            (approx as usize >= i || i > 0x3e00000) && S2K::decode_count(cc) == approx
        }
    }
}
