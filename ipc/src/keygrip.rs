use std::fmt;
use std::io::Write;

use sequoia_openpgp as openpgp;
use openpgp::Error;
use openpgp::Result;
use openpgp::crypto::mpi::{MPI, PublicKey};
use openpgp::types::{Curve, HashAlgorithm};

/// A proprietary, protocol agnostic identifier for public keys.
///
/// This is defined and used by GnuPG.
///
/// # Examples
///
/// ```
/// # fn main() -> sequoia_openpgp::Result<()> {
/// use sequoia_ipc as ipc;
/// use ipc::Keygrip;
///
/// let k: Keygrip = "DD143ABA8D1D7D09875D6209E01BCF020788FF77".parse()?;
/// assert_eq!(&k.to_string(), "DD143ABA8D1D7D09875D6209E01BCF020788FF77");
/// # Ok(()) }
/// ```
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Keygrip([u8; 20]);

impl fmt::Debug for Keygrip {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for b in self.0.iter() {
            write!(f, "{:02X}", *b)?;
        }
        Ok(())
    }
}

impl fmt::Display for Keygrip {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for b in self.0.iter() {
            write!(f, "{:02X}", *b)?;
        }
        Ok(())
    }
}

impl std::str::FromStr for Keygrip {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let bytes = openpgp::fmt::hex::decode_pretty(s)?;
        if bytes.len() == 20 {
            let mut digest = [0; 20];
            digest[..].copy_from_slice(&bytes[..]);
            Ok(Keygrip(digest))
        } else {
            Err(Error::InvalidArgument(
                format!("Expected 20 bytes, got {}", bytes.len())).into())
        }
    }
}

impl Keygrip {
    /// Computes the keygrip of the given public key.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use sequoia_openpgp as openpgp;
    /// use sequoia_ipc as ipc;
    /// use ipc::Keygrip;
    ///
    /// let cert: openpgp::Cert = // ...
    /// #   "-----BEGIN PGP PUBLIC KEY BLOCK-----
    /// #
    /// #   xjMEWlNvABYJKwYBBAHaRw8BAQdA+EC2pvebpEbzPA9YplVgVXzkIG5eK+7wEAez
    /// #   lcBgLJrNMVRlc3R5IE1jVGVzdGZhY2UgKG15IG5ldyBrZXkpIDx0ZXN0eUBleGFt
    /// #   cGxlLm9yZz7CkAQTFggAOBYhBDnRAKtn1b2MBAECBfs3UfFYfa7xBQJaU28AAhsD
    /// #   BQsJCAcCBhUICQoLAgQWAgMBAh4BAheAAAoJEPs3UfFYfa7xJHQBAO4/GABMWUcJ
    /// #   5D/DZ9b+6YiFnysSjCT/gILJgxMgl7uoAPwJherI1pAAh49RnPHBR1IkWDtwzX65
    /// #   CJG8sDyO2FhzDs44BFpTbwASCisGAQQBl1UBBQEBB0B+A0GRHuBgdDX50T1nePjb
    /// #   mKQ5PeqXJbWEtVrUtVJaPwMBCAfCeAQYFggAIBYhBDnRAKtn1b2MBAECBfs3UfFY
    /// #   fa7xBQJaU28AAhsMAAoJEPs3UfFYfa7xzjIBANX2/FgDX3WkmvwpEHg/sn40zACM
    /// #   W2hrBY5x0sZ8H7JlAP47mCfCuRVBqyaePuzKbxLJeLe2BpDdc0n2izMVj8t9Cg==
    /// #   =QetZ
    /// #   -----END PGP PUBLIC KEY BLOCK-----".parse()?;
    /// assert_eq!(Keygrip::of(cert.primary_key().key().mpis())?.to_string(),
    ///            "DD143ABA8D1D7D09875D6209E01BCF020788FF77");
    /// # Ok(()) }
    /// ```
    pub fn of(key: &PublicKey) -> Result<Keygrip> {
        use openpgp::crypto::hash;
        use self::PublicKey::*;
        let mut hash =
            HashAlgorithm::SHA1.context().unwrap().for_digest();

        fn hash_sexp_mpi(hash: &mut hash::Context, kind: char, mpi: &MPI)
        {
            // gcrypt's MPIs can be signed or unsigned.  Our MPIs are
            // always unsigned (well, for us they are opaque byte
            // strings, so the concept of a sign does not apply).
            // Every now and then we need to pay attention to this, as
            // gcrypt sometimes prepends a zero to prevent the most
            // significant bit from being interpreted as a sign bit.
            // Computing keygrips is one of these times.
            let prefix = if mpi.value().get(0).map(|msb| msb & 0x80 > 0)
                .unwrap_or(false)
            {
                // The most significant bit is set.  Prepend a zero
                // byte so that the MSB will not be interpreted as a
                // sign bit.
                &b"\x00"[..]
            } else {
                // The MSB is not set, no need to prepend anything.
                &b""[..]
            };
            hash_sexp(hash, kind, prefix, mpi.value());
        }

        fn hash_sexp(hash: &mut hash::Context, kind: char, prefix: &[u8],
                     buf: &[u8])
        {
            write!(hash, "(1:{}{}:",
                   kind, buf.len() + prefix.len()).unwrap();
            hash.update(prefix);
            hash.update(buf);
            write!(hash, ")").unwrap();
        }

        fn hash_ecc(hash: &mut hash::Context, curve: &Curve, q: &MPI)
            -> Result<()>
        {
            for (i, name) in "pabgnhq".chars().enumerate() {
                if i == 5 {
                    continue;  // Skip cofactor.
                }

                let param;
                let mut m = if i == 6 {
                    q.value()
                } else {
                    param = ecc_param(curve, i)?;
                    param.value()
                };

                // Opaque encoding?
                if m[0] == 0x40 {
                    // Drop the prefix!
                    m = &m[1..];
                }

                hash_sexp(hash, name, &[], m);
            }

            Ok(())
        }

        match key {
            // From libgcrypt/cipher/rsa.c:
            //
            //     PKCS-15 says that for RSA only the modulus should be
            //     hashed - however, it is not clear whether this is meant
            //     to use the raw bytes (assuming this is an unsigned
            //     integer) or whether the DER required 0 should be
            //     prefixed.  We hash the raw bytes.
            &RSA { ref n, .. } => {
                // Contrary to the comment reproduced above,
                // overwhelming empirical evidence suggest that we
                // need to prepend a 0.
                hash.update(&[0]);
                hash.update(n.value());
            },

            &DSA { ref p, ref q, ref g, ref y } => {
                hash_sexp_mpi(&mut hash, 'p', p);
                hash_sexp_mpi(&mut hash, 'q', q);
                hash_sexp_mpi(&mut hash, 'g', g);
                hash_sexp_mpi(&mut hash, 'y', y);
            },

            &ElGamal { ref p, ref g, ref y } => {
                hash_sexp_mpi(&mut hash, 'p', p);
                hash_sexp_mpi(&mut hash, 'g', g);
                hash_sexp_mpi(&mut hash, 'y', y);
            },

            &EdDSA { ref curve, ref q } => hash_ecc(&mut hash, curve, q)?,
            &ECDSA { ref curve, ref q } => hash_ecc(&mut hash, curve, q)?,
            &ECDH { ref curve, ref q, .. } => hash_ecc(&mut hash, curve, q)?,

            // crypto::mpi::PublicKey is non_exhaustive, match on &_ to handle
            // future additions.
            &Unknown { .. } | &_ =>
                return Err(Error::InvalidOperation(
                    "Keygrip not defined for this kind of public key".into())
                           .into()),
        }

        let mut digest = [0; 20];
        let _ = hash.digest(&mut digest);
        Ok(Keygrip(digest))
    }
}

/// Returns curve parameters.
///
/// These parameters are a courtesy of libgcrypt.
fn ecc_param(curve: &Curve, i: usize) -> Result<MPI> {
    use self::Curve::*;
    assert!(i < 6);
    let hex = match (curve, i) {
        (NistP256, 0) => "0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        (NistP256, 1) => "0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
        (NistP256, 2) => "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
        (NistP256, 4) => "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        (NistP256, 3) => "0x04\
                          6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296\
                          4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        (NistP256, 5) => "0x01",

        (NistP384, 0) => "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
        (NistP384, 1) => "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc",
        (NistP384, 2) => "0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
        (NistP384, 4) => "0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
        (NistP384, 3) => "0x04\
                          aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7\
                          3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
        (NistP384, 5) => "0x01",

        (NistP521, 0) => "0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        (NistP521, 1) => "0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc",
        (NistP521, 2) => "0x51953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
        (NistP521, 4) => "0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
        (NistP521, 3) => "0x04\
                          00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66\
                          011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650",
        (NistP521, 5) => "0x01",

        (BrainpoolP256, 0) => "0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377",
        (BrainpoolP256, 1) => "0x7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9",
        (BrainpoolP256, 2) => "0x26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6",
        (BrainpoolP256, 4) => "0xa9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7",
        (BrainpoolP256, 3) => "0x04\
                               8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262\
                               547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997",
        (BrainpoolP256, 5) => "0x01",

        (BrainpoolP512, 0) => "0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3",
        (BrainpoolP512, 1) => "0x7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca",
        (BrainpoolP512, 2) => "0x3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723",
        (BrainpoolP512, 4) => "0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069",
        (BrainpoolP512, 3) => "0x04\
                               81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822\
                               7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892",
        (BrainpoolP512, 5) => "0x01",

        (Ed25519, 0) => "0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED",
        (Ed25519, 1) => /* - */ "0x01",
        (Ed25519, 2) => /* - */ "0x2DFC9311D490018C7338BF8688861767FF8FF5B2BEBE27548A14B235ECA6874A",
        (Ed25519, 4) => "0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED",
        (Ed25519, 3) => "0x04\
                         216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A\
                         6666666666666666666666666666666666666666666666666666666666666658",
        (Ed25519, 5) => "0x08",

        (Cv25519, 0) => "0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED",
        (Cv25519, 1) => "0x01DB41",
        (Cv25519, 2) => "0x01",
        (Cv25519, 4) => "0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED",
        (Cv25519, 3) => "0x04\
                         0000000000000000000000000000000000000000000000000000000000000009\
                         20AE19A1B8A086B4E01EDD2C7748D14C923D4D7E6D7C61B229E9C5A27ECED3D9",
        (Cv25519, 5) => "0x08",

        (_, _) => {
            let error = || {
                Err(Error::InvalidArgument(
                    format!("Invalid or unknown curve parameters: \
                             curve: {}, i: {}",
                            curve, i)).into())
            };

            const BRAINPOOL_P384_OID: &[u8] =
                &[0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B];

            if curve.oid() == BRAINPOOL_P384_OID {
                match i {
                    0 => "0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53",
                    1 => "0x7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826",
                    2 => "0x04a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c11",
                    4 => "0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565",
                    3 => "0x04\
                          1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e\
                          8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315",
                    5 => "0x01",
                    _ => return error(),
                }
            } else {
                return error();
            }
        }
    };

    Ok(openpgp::fmt::hex::decode_pretty(hex).unwrap().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openpgp::fmt::hex;

    /// Test vectors from libgcrypt/tests/basic.c.
    #[test]
    fn libgcrypt_basic() {
        let tests = vec![
            (PublicKey::RSA {
                n: hex::decode(
                    "00e0ce96f90b6c9e02f3922beada93fe50a875eac6bcc18bb9a9cf2e84965caa\
                     2d1ff95a7f542465c6c0c19d276e4526ce048868a7a914fd343cc3a87dd74291\
                     ffc565506d5bbb25cbac6a0e2dd1f8bcaab0d4a29c2f37c950f363484bf269f7\
                     891440464baf79827e03a36e70b814938eebdc63e964247be75dc58b014b7ea2\
                     51").unwrap().into(),
                e: hex::decode("010001").unwrap().into(),
            }, Keygrip(*b"\x32\x10\x0c\x27\x17\x3e\xf6\xe9\xc4\xe9\
                          \xa2\x5d\x3d\x69\xf8\x6d\x37\xa4\xf9\x39")),
            (PublicKey::DSA {
                p: hex::decode(
                    "00AD7C0025BA1A15F775F3F2D673718391D00456978D347B33D7B49E7F32EDAB\
                     96273899DD8B2BB46CD6ECA263FAF04A28903503D59062A8865D2AE8ADFB5191\
                     CF36FFB562D0E2F5809801A1F675DAE59698A9E01EFE8D7DCFCA084F4C6F5A44\
                     44D499A06FFAEA5E8EF5E01F2FD20A7B7EF3F6968AFBA1FB8D91F1559D52D877\
                     7B").unwrap().into(),
                q: hex::decode(
                    "00EB7B5751D25EBBB7BD59D920315FD840E19AEBF9").unwrap().into(),
                g: hex::decode(
                    "1574363387FDFD1DDF38F4FBE135BB20C7EE4772FB94C337AF86EA8E49666503\
                     AE04B6BE81A2F8DD095311E0217ACA698A11E6C5D33CCDAE71498ED35D13991E\
                     B02F09AB40BD8F4C5ED8C75DA779D0AE104BC34C960B002377068AB4B5A1F984\
                     3FBA91F537F1B7CAC4D8DD6D89B0D863AF7025D549F9C765D2FC07EE208F8D15\
                     ").unwrap().into(),
                y: hex::decode(
                    "64B11EF8871BE4AB572AA810D5D3CA11A6CDBC637A8014602C72960DB135BF46\
                     A1816A724C34F87330FC9E187C5D66897A04535CC2AC9164A7150ABFA8179827\
                     6E45831AB811EEE848EBB24D9F5F2883B6E5DDC4C659DEF944DCFD80BF4D0A20\
                     42CAA7DC289F0C5A9D155F02D3D551DB741A81695B74D4C8F477F9C7838EB0FB\
                     ").unwrap().into(),
            }, Keygrip(*b"\xc6\x39\x83\x1a\x43\xe5\x05\x5d\xc6\xd8\
                          \x4a\xa6\xf9\xeb\x23\xbf\xa9\x12\x2d\x5b")),
            (PublicKey::ElGamal {
                p: hex::decode(
                    "00B93B93386375F06C2D38560F3B9C6D6D7B7506B20C1773F73F8DE56E6CD65D\
                     F48DFAAA1E93F57A2789B168362A0F787320499F0B2461D3A4268757A7B27517\
                     B7D203654A0CD484DEC6AF60C85FEB84AAC382EAF2047061FE5DAB81A20A0797\
                     6E87359889BAE3B3600ED718BE61D4FC993CC8098A703DD0DC942E965E8F18D2\
                     A7").unwrap().into(),
                g: hex::decode("05").unwrap().into(),
                y: hex::decode(
                    "72DAB3E83C9F7DD9A931FDECDC6522C0D36A6F0A0FEC955C5AC3C09175BBFF2B\
                     E588DB593DC2E420201BEB3AC17536918417C497AC0F8657855380C1FCF11C5B\
                     D20DB4BEE9BDF916648DE6D6E419FA446C513AAB81C30CB7B34D6007637BE675\
                     56CE6473E9F9EE9B9FADD275D001563336F2186F424DEC6199A0F758F6A00FF4\
                     ").unwrap().into(),
            }, Keygrip(*b"\xa7\x99\x61\xeb\x88\x83\xd2\xf4\x05\xc8\
                          \x4f\xba\x06\xf8\x78\x09\xbc\x1e\x20\xe5")),
        ];

        for (key, keygrip) in tests {
            assert_eq!(Keygrip::of(&key).unwrap(), keygrip);
        }
    }

    /// Tests from our test keys, using GnuPG as oracle.
    #[test]
    fn our_keys() {
        use std::collections::HashMap;
        use openpgp::Fingerprint as FP;
        use super::Keygrip as KG;
        use openpgp::parse::Parse;

        let keygrips: HashMap<FP, KG> = [
            // testy.pgp
            ("3E8877C877274692975189F5D03F6F865226FE8B".parse::<FP>().unwrap(),
             "71ADDE3BBC0B7F1BFC2DA414C4F473B197763733".parse::<KG>().unwrap()),
            ("01F187575BD45644046564C149E2118166C92632".parse::<FP>().unwrap(),
             "CB6149C50DF90DC88626283A6B6C918A1C29E37D".parse::<KG>().unwrap()),
            // neal.pgp
            ("8F17777118A33DDA9BA48E62AACB3243630052D9".parse::<FP>().unwrap(),
             "C45986381F54F967C2F6B104521C8634090F326A".parse::<KG>().unwrap()),
            ("C03FA6411B03AE12576461187223B56678E02528".parse::<FP>().unwrap(),
             "BE2FE8C8793141322AC30E3EAFD1E4F9D8DACCC4".parse::<KG>().unwrap()),
            ("50E6D924308DBF223CFB510AC2B819056C652598".parse::<FP>().unwrap(),
             "9873FD355DE470DDC151CD9919AC9785C3C2FDDE".parse::<KG>().unwrap()),
            ("2DC50AB55BE2F3B04C2D2CF8A3506AFB820ABD08".parse::<FP>().unwrap(),
             "9483454871CC1239D4C2A1416F2742D39A14DB14".parse::<KG>().unwrap()),
            // dennis-simon-anton.pgp
            ("5BFBCD2A23E6866B77198C1147606B18E3D45CE9".parse::<FP>().unwrap(),
             "D3E87BECEF18FB4C561F3C4E73A92C4D7A43FD90".parse::<KG>().unwrap()),
            // testy-new.pgp
            ("39D100AB67D5BD8C04010205FB3751F1587DAEF1".parse::<FP>().unwrap(),
             "DD143ABA8D1D7D09875D6209E01BCF020788FF77".parse::<KG>().unwrap()),
            ("F4D1450B041F622FCEFBFDB18BD88E94C0D20333".parse::<FP>().unwrap(),
             "583225FBC0A88293472FB95F37E9595E1367188C".parse::<KG>().unwrap()),
            // emmelie-dorothea-dina-samantha-awina-ed25519.pgp
            ("8E8C33FA4626337976D97978069C0C348DD82C19".parse::<FP>().unwrap(),
             "8BFFDC31BCFC3F31304DACD55AC5F15839A64040".parse::<KG>().unwrap()),
            ("061C3CA44AFF0EC58DC66E9522E3FAFE96B56C32".parse::<FP>().unwrap(),
             "E80BBB4AC2048A708ADB376C6491E8302150DCC9".parse::<KG>().unwrap()),
            // erika-corinna-daniela-simone-antonia-nistp256.pgp
            ("B45FB2CD7B227C057D6BD690DA6846EEA212A3C0".parse::<FP>().unwrap(),
             "CA791A9F0F2EF0163461BA991BFEB2315EDF13F5".parse::<KG>().unwrap()),
            // erika-corinna-daniela-simone-antonia-nistp384.pgp
            ("E837639193664C9BB1C212E70CB719D5AA7D91F1".parse::<FP>().unwrap(),
             "625CC3D9A795AD7AC6B666E92E46156917773CBC".parse::<KG>().unwrap()),
            // erika-corinna-daniela-simone-antonia-nistp521.pgp
            ("B9E41C493B8988A7EDC502D99A404C898D411DC8".parse::<FP>().unwrap(),
             "8F669049015534649776D0F1F439D37EE3F3D948".parse::<KG>().unwrap()),
            // keygrip-issue-439.pgp
            ("597B1FEA9F1B91F6749E8A24652CC528EBDA1B20".parse::<FP>().unwrap(),
             "EF0CCDE02FFF9E24EFCCBF6F6FFE52716820E497".parse::<KG>().unwrap()),
            ("7147EB2C548AEF87E425B9543EF9867F7073B689".parse::<FP>().unwrap(),
             "642314FF90E6F8DA595EF51B7BA6B25071D3B0F1".parse::<KG>().unwrap()),
        ].iter().cloned().collect();

        for (name, cert) in [
            "testy.pgp",
            "neal.pgp",
            "dennis-simon-anton.pgp",
            "testy-new.pgp",
            "emmelie-dorothea-dina-samantha-awina-ed25519.pgp",
            "erika-corinna-daniela-simone-antonia-nistp256.pgp",
            "erika-corinna-daniela-simone-antonia-nistp384.pgp",
            "erika-corinna-daniela-simone-antonia-nistp521.pgp",
            "keygrip-issue-439.pgp",
        ]
            .iter().map(|n| (n, openpgp::Cert::from_bytes(crate::tests::key(n)).unwrap()))
        {
            eprintln!("{}", name);
            for key in cert.keys().map(|a| a.key()) {
                let fp = key.fingerprint();
                eprintln!("(sub)key: {}", fp);
                assert_eq!(&Keygrip::of(key.mpis()).unwrap(),
                           keygrips.get(&fp).unwrap());
            }
        }
    }

    /// Tests vectors from GPGME, using GnuPG as oracle.
    #[test]
    fn gpgme_keys() {
        use std::collections::HashMap;
        use openpgp::Fingerprint as FP;
        use super::Keygrip as KG;
        use openpgp::parse::Parse;

        let keygrips: HashMap<FP, KG> = [
            // alpha.pgp
            ("A0FF4590BB6122EDEF6E3C542D727CC768697734".parse::<FP>().unwrap(),
             "76F7E2B35832976B50A27A282D9B87E44577EB66".parse::<KG>().unwrap()),
            ("3B3FBC948FE59301ED629EFB6AE6D7EE46A871F8".parse::<FP>().unwrap(),
             "A0747D5F9425E6664F4FFBEED20FBCA79FDED2BD".parse::<KG>().unwrap()),
            // zulu.pgp
            ("23FD347A419429BACCD5E72D6BC4778054ACD246".parse::<FP>().unwrap(),
             "13CBE3758AFE42B5E5E2AE4CED27AFA455E3F87F".parse::<KG>().unwrap()),
            ("2DCA5A1392DE06ED4FCB8C53EF9DC276A172C881".parse::<FP>().unwrap(),
             "7A030357C0F253A5BBCD282FFC4E521B37558F5C".parse::<KG>().unwrap()),
        ].iter().cloned().collect();

        for (name, cert) in [
            "alpha.pgp",
            "zulu.pgp",
        ]
            .iter().map(|n| (n, openpgp::Cert::from_bytes(crate::tests::key(n)).unwrap()))
        {
            eprintln!("{}", name);
            for key in cert.keys().map(|a| a.key()) {
                let fp = key.fingerprint();
                eprintln!("(sub)key: {}", fp);
                assert_eq!(&Keygrip::of(key.mpis()).unwrap(),
                           keygrips.get(&fp).unwrap());
            }
        }
    }
}
