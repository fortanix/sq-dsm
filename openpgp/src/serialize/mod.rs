//! OpenPGP packet serializer.
//!
//! There are two interfaces to serialize OpenPGP data.  Which one is
//! applicable depends on whether or not the packet structure is
//! already assembled in memory, with all information already in place
//! (e.g. because it was parsed).
//!
//! If it is, you can use the `Serialize` or `SerializeKey`.
//!
//! Otherwise, please use our streaming serialization interface.

use std::io::{self, Write};
use std::cmp;

use super::*;

mod partial_body;
use self::partial_body::PartialBodyFilter;
pub mod writer;
pub mod stream;
use crypto::s2k::S2K;
use packet::signature::subpacket::{
    Subpacket, SubpacketValue, SubpacketLengthTrait,
};
use conversions::{
    Time,
    Duration,
};
use packet::{
    Tag,
    Unknown,
    Signature,
    OnePassSig,
    Key,
    key::SecretKey,
    UserID,
    UserAttribute,
    Literal,
    CompressedData,
    PKESK,
    SKESK,
    SKESK4,
    SKESK5,
    SEIP,
    MDC,
    AED,
};

// Whether to trace the modules execution (on stderr).
const TRACE : bool = false;

#[cfg(test)]
use std::path::PathBuf;

#[cfg(test)]
fn path_to(artifact: &str) -> PathBuf {
    [env!("CARGO_MANIFEST_DIR"), "tests", "data", "messages", artifact]
        .iter().collect()
}

fn write_byte<W: io::Write>(o: &mut W, b: u8) -> io::Result<()> {
    let b : [u8; 1] = [b; 1];
    o.write_all(&b[..])
}

fn write_be_u16<W: io::Write>(o: &mut W, n: u16) -> io::Result<()> {
    let b : [u8; 2] = [ ((n >> 8) & 0xFF) as u8, (n & 0xFF) as u8 ];
    o.write_all(&b[..])
}

fn write_be_u32<W: io::Write>(o: &mut W, n: u32) -> io::Result<()> {
    let b : [u8; 4] = [ (n >> 24) as u8, ((n >> 16) & 0xFF) as u8,
                         ((n >> 8) & 0xFF) as u8, (n & 0xFF) as u8 ];
    o.write_all(&b[..])
}

// Compute the log2 of an integer.  (This is simply the most
// significant bit.)  Note: log2(0) = -Inf, but this function returns
// log2(0) as 0 (which is the closest number that we can represent).
fn log2(x: u32) -> usize {
    if x == 0 {
        0
    } else {
        31 - x.leading_zeros() as usize
    }
}

#[test]
fn log2_test() {
    for i in 0..32 {
        // eprintln!("log2(1 << {} = {}) = {}", i, 1u32 << i, log2(1u32 << i));
        assert_eq!(log2(1u32 << i), i);
        if i > 0 {
            assert_eq!(log2((1u32 << i) - 1), i - 1);
            assert_eq!(log2((1u32 << i) + 1), i);
        }
    }
}

impl Serialize for BodyLength {
    /// Emits the length encoded for use with new-style CTBs.
    ///
    /// Note: the CTB itself is not emitted.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if invoked on
    /// [`BodyLength::Indeterminate`].  If you want to serialize an
    /// old-style length, use [`serialize_old(..)`].
    ///
    /// [`Error::InvalidArgument`]: ../enum.Error.html#variant.InvalidArgument
    /// [`BodyLength::Indeterminate`]: ../packet/enum.BodyLength.html#variant.Indeterminate
    /// [`serialize_old(..)`]: #method.serialize_old
    fn serialize<W: io::Write>(&self, o: &mut W) -> Result<()> {
        match self {
            &BodyLength::Full(l) => {
                if l <= 191 {
                    write_byte(o, l as u8)?;
                } else if l <= 8383 {
                    let v = l - 192;
                    let v = v + (192 << 8);
                    write_be_u16(o, v as u16)?;
                } else {
                    write_byte(o, 0xff)?;
                    write_be_u32(o, l)?;
                }
            },
            &BodyLength::Partial(l) => {
                if l > 1 << 30 {
                    return Err(Error::InvalidArgument(
                        format!("Partial length too large: {}", l)).into());
                }

                let chunk_size_log2 = log2(l);
                let chunk_size = 1 << chunk_size_log2;

                if l != chunk_size {
                    return Err(Error::InvalidArgument(
                        format!("Not a power of two: {}", l)).into());
                }

                let size_byte = 224 + chunk_size_log2;
                assert!(size_byte < 255);
                write_byte(o, size_byte as u8)?;
            },
            &BodyLength::Indeterminate =>
                return Err(Error::InvalidArgument(
                    "Indeterminate lengths are not support for new format packets".
                        into()).into()),
        }

        Ok(())
    }
}

impl BodyLength {
    /// Emits the length encoded for use with old-style CTBs.
    ///
    /// Note: the CTB itself is not emitted.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if invoked on
    /// [`BodyLength::Partial`].  If you want to serialize a
    /// new-style length, use [`serialize(..)`].
    ///
    /// [`Error::InvalidArgument`]: ../enum.Error.html#variant.InvalidArgument
    /// [`BodyLength::Partial`]: ../packet/enum.BodyLength.html#variant.Partial
    /// [`serialize(..)`]: #impl-Serialize
    pub fn serialize_old<W: io::Write>(&self, o: &mut W) -> Result<()> {
        // Assume an optimal encoding is desired.
        let mut buffer = Vec::with_capacity(4);
        match self {
            &BodyLength::Full(l) => {
                match l {
                    // One octet length.
                    // write_byte can't fail for a Vec.
                    0 ... 0xFF =>
                        write_byte(&mut buffer, l as u8).unwrap(),
                    // Two octet length.
                    0x1_00 ... 0xFF_FF =>
                        write_be_u16(&mut buffer, l as u16).unwrap(),
                    // Four octet length,
                    _ =>
                        write_be_u32(&mut buffer, l as u32).unwrap(),
                }
            },
            &BodyLength::Indeterminate => {},
            &BodyLength::Partial(_) =>
                return Err(Error::InvalidArgument(
                    "Partial body lengths are not support for old format packets".
                        into()).into()),
        }

        o.write_all(&buffer)?;
        Ok(())
    }
}

impl Serialize for CTBNew {
    fn serialize<W: io::Write>(&self, o: &mut W) -> Result<()> {
        let tag: u8 = self.common.tag.into();
        o.write_all(&[0b1100_0000u8 | tag])?;
        Ok(())
    }
}

impl Serialize for CTBOld {
    fn serialize<W: io::Write>(&self, o: &mut W) -> Result<()> {
        let tag: u8 = self.common.tag.into();
        let length_type: u8 = self.length_type.into();
        o.write_all(&[0b1000_0000u8 | (tag << 2) | length_type])?;
        Ok(())
    }
}

impl Serialize for CTB {
    fn serialize<W: io::Write>(&self, o: &mut W) -> Result<()> {
        match self {
            &CTB::New(ref c) => c.serialize(o),
            &CTB::Old(ref c) => c.serialize(o),
        }?;
        Ok(())
    }
}

impl Serialize for Header {
    fn serialize<W: io::Write>(&self, o: &mut W) -> Result<()> {
        self.ctb.serialize(o)?;
        self.length.serialize(o)?;
        Ok(())
    }
}

impl Serialize for KeyID {
    /// Writes a serialized version of the specified `KeyID` to `o`.
    fn serialize<W: io::Write>(&self, o: &mut W) -> Result<()> {
        let raw = match self {
            &KeyID::V4(ref fp) => &fp[..],
            &KeyID::Invalid(ref fp) => &fp[..],
        };
        o.write_all(raw)?;
        Ok(())
    }

    /// Serializes the packet to a vector.
    fn to_vec(&self) -> Result<Vec<u8>> {
        let mut o = Vec::with_capacity(8);
        self.serialize(&mut o)?;
        Ok(o)
    }
}

impl Serialize for crypto::mpis::MPI {
    fn serialize<W: io::Write>(&self, w: &mut W) -> Result<()> {
        write_be_u16(w, self.bits as u16)?;
        w.write_all(&self.value)?;
        Ok(())
    }
}

impl Serialize for crypto::mpis::PublicKey {
    fn serialize<W: io::Write>(&self, w: &mut W) -> Result<()> {
        use crypto::mpis::PublicKey::*;

        match self {
            &RSA { ref e, ref n } => {
                n.serialize(w)?;
                e.serialize(w)?;
            }

            &DSA { ref p, ref q, ref g, ref y } => {
                p.serialize(w)?;
                q.serialize(w)?;
                g.serialize(w)?;
                y.serialize(w)?;
            }

            &Elgamal { ref p, ref g, ref y } => {
                p.serialize(w)?;
                g.serialize(w)?;
                y.serialize(w)?;
            }

            &EdDSA { ref curve, ref q } => {
                w.write_all(&[curve.oid().len() as u8])?;
                w.write_all(curve.oid())?;
                q.serialize(w)?;
            }

            &ECDSA { ref curve, ref q } => {
                w.write_all(&[curve.oid().len() as u8])?;
                w.write_all(curve.oid())?;
                q.serialize(w)?;
            }

            &ECDH { ref curve, ref q, hash, sym } => {
                w.write_all(&[curve.oid().len() as u8])?;
                w.write_all(curve.oid())?;
                q.serialize(w)?;
                w.write_all(&[3u8, 1u8, u8::from(hash), u8::from(sym)])?;
            }

            &Unknown { ref mpis, ref rest } => {
                for mpi in mpis.iter() {
                    mpi.serialize(w)?;
                }
                w.write_all(rest)?;
            }
        }

        Ok(())
    }
}

impl Serialize for crypto::mpis::SecretKey {
    fn serialize<W: io::Write>(&self, w: &mut W) -> Result<()> {
        use crypto::mpis::SecretKey::*;

        match self {
            &RSA{ ref d, ref p, ref q, ref u } => {
                d.serialize(w)?;
                p.serialize(w)?;
                q.serialize(w)?;
                u.serialize(w)?;
            }

            &DSA{ ref x } => {
                x.serialize(w)?;
            }

            &Elgamal{ ref x } => {
                x.serialize(w)?;
            }

            &EdDSA{ ref scalar } => {
                scalar.serialize(w)?;
            }

            &ECDSA{ ref scalar } => {
                scalar.serialize(w)?;
            }

            &ECDH{ ref scalar } => {
                scalar.serialize(w)?;
            }

            &Unknown { ref mpis, ref rest } => {
                for mpi in mpis.iter() {
                    mpi.serialize(w)?;
                }
                w.write_all(rest)?;
            }
        }

        Ok(())
    }
}

impl Serialize for crypto::mpis::Ciphertext {
    fn serialize<W: io::Write>(&self, w: &mut W) -> Result<()> {
        use crypto::mpis::Ciphertext::*;

        match self {
            &crypto::mpis::Ciphertext::RSA{ ref c } => {
                c.serialize(w)?;
            }

            &crypto::mpis::Ciphertext::Elgamal{ ref e, ref c } => {
                e.serialize(w)?;
                c.serialize(w)?;
            }

            &crypto::mpis::Ciphertext::ECDH{ ref e, ref key } => {
                e.serialize(w)?;

                w.write_all(&[key.len() as u8])?;
                w.write_all(&key)?;
            }

            &Unknown { ref mpis, ref rest } => {
                for mpi in mpis.iter() {
                    mpi.serialize(w)?;
                }
                w.write_all(rest)?;
            }
        }

        Ok(())
    }
}

impl Serialize for crypto::mpis::Signature {
    fn serialize<W: io::Write>(&self, w: &mut W) -> Result<()> {
        use crypto::mpis::Signature::*;

        match self {
            &RSA { ref s } => {
                s.serialize(w)?;
            }
            &DSA { ref r, ref s } => {
                r.serialize(w)?;
                s.serialize(w)?;
            }
            &Elgamal { ref r, ref s } => {
                r.serialize(w)?;
                s.serialize(w)?;
            }
            &EdDSA { ref r, ref s } => {
                r.serialize(w)?;
                s.serialize(w)?;
            }
            &ECDSA { ref r, ref s } => {
                r.serialize(w)?;
                s.serialize(w)?;
            }

            &Unknown { ref mpis, ref rest } => {
                for mpi in mpis.iter() {
                    mpi.serialize(w)?;
                }
                w.write_all(rest)?;
            }
        }

        Ok(())
    }
}

/// Packet serialization.
///
/// This interfaces serializes packets and packet trees.
pub trait Serialize {
    /// Writes a serialized version of the packet to `o`.
    fn serialize<W: io::Write>(&self, o: &mut W) -> Result<()>;

    /// Serializes the packet to a vector.
    fn to_vec(&self) -> Result<Vec<u8>> {
        let mut o = Vec::with_capacity(4096);
        self.serialize(&mut o)?;
        Ok(o)
    }
}

/// Key packet serialization.
///
/// This interface serializes key packets.
pub trait SerializeKey {
    /// Writes a serialized version of the key packet to `o`.
    ///
    /// Tag identifies the kind of packet to write.
    fn serialize<W: io::Write>(&self, o: &mut W, tag: Tag) -> Result<()>;

    /// Serializes the packet to a vector.
    fn to_vec(&self, tag: Tag) -> Result<Vec<u8>> {
        let mut o = Vec::with_capacity(4096);
        self.serialize(&mut o, tag)?;
        Ok(o)
    }
}

impl Serialize for S2K {
    /// Serializes this S2K instance.
    fn serialize<W: io::Write>(&self, w: &mut W) -> Result<()> {
        match self {
            &S2K::Simple{ hash } => {
                w.write_all(&[0, hash.into()])?;
            }
            &S2K::Salted{ hash, salt } => {
                w.write_all(&[1, hash.into()])?;
                w.write_all(&salt[..])?;
            }
            &S2K::Iterated{ hash, salt, iterations } => {
                w.write_all(&[3, hash.into()])?;
                w.write_all(&salt[..])?;
                w.write_all(&[S2K::encode_count(iterations)?])?;
            }
            &S2K::Private(s2k) | &S2K::Unknown(s2k) => {
                w.write_all(&[s2k])?;
            }
        }

        Ok(())
    }
}

impl S2K {
    /// Return the length of the serialized S2K data structure.
    pub fn serialized_len(&self) -> usize {
        match self {
            &S2K::Simple{ .. } => 2,
            &S2K::Salted{ .. } => 2 + 8,
            &S2K::Iterated{ .. } => 2 + 8 + 1,
            &S2K::Private(_) | &S2K::Unknown(_) => 1,
        }
    }
}

impl Serialize for Unknown {
    /// Writes a serialized version of the specified `Unknown` packet
    /// to `o`.
    fn serialize<W: io::Write>(&self, o: &mut W) -> Result<()> {
        let body = if let Some(ref body) = self.common.body {
            &body[..]
        } else {
            &b""[..]
        };

        CTB::new(self.tag()).serialize(o)?;
        BodyLength::Full(body.len() as u32).serialize(o)?;
        o.write_all(&body[..])?;

        Ok(())
    }
}

impl<'a> Serialize for Subpacket<'a> {
    fn serialize<W: io::Write>(&self, o: &mut W) -> Result<()> {
        let tag = u8::from(self.tag)
            | if self.critical { 1 << 7 } else { 0 };
        let len = 1 + self.value.len();

        len.serialize(o)?;
        o.write_all(&[tag])?;
        self.value.serialize(o)
    }
}

impl<'a> Serialize for SubpacketValue<'a> {
    fn serialize<W: io::Write>(&self, o: &mut W) -> Result<()> {
        use self::SubpacketValue::*;
        match self {
            SignatureCreationTime(t) =>
                write_be_u32(o, t.to_pgp()?)?,
            SignatureExpirationTime(t) =>
                write_be_u32(o, t.to_pgp()?)?,
            ExportableCertification(e) =>
                o.write_all(&[if *e { 1 } else { 0 }])?,
            TrustSignature { ref level, ref trust } =>
                o.write_all(&[*level, *trust])?,
            RegularExpression(ref re) => {
                o.write_all(re)?;
                o.write_all(&[0])?;
            },
            Revocable(r) =>
                o.write_all(&[if *r { 1 } else { 0 }])?,
            KeyExpirationTime(t) =>
                write_be_u32(o, t.to_pgp()?)?,
            PreferredSymmetricAlgorithms(ref p) =>
                for a in p {
                    o.write_all(&[(*a).into()])?;
                },
            RevocationKey { ref class, ref pk_algo, ref fp } => {
                o.write_all(&[*class, (*pk_algo).into()])?;
                o.write_all(fp.as_slice())?;
            },
            Issuer(ref id) =>
                o.write_all(id.as_slice())?,
            NotationData(nd) => {
                write_be_u32(o, nd.flags())?;
                write_be_u16(o, nd.name().len() as u16)?;
                write_be_u16(o, nd.value().len() as u16)?;
                o.write_all(nd.name())?;
                o.write_all(nd.value())?;
            },
            PreferredHashAlgorithms(ref p) =>
                for a in p {
                    o.write_all(&[(*a).into()])?;
                },
            PreferredCompressionAlgorithms(ref p) =>
                for a in p {
                    o.write_all(&[(*a).into()])?;
                },
            KeyServerPreferences(ref p) =>
                o.write_all(&p.as_vec())?,
            PreferredKeyServer(ref p) =>
                o.write_all(p)?,
            PrimaryUserID(p) =>
                o.write_all(&[if *p { 1 } else { 0 }])?,
            PolicyURI(ref p) =>
                o.write_all(p)?,
            KeyFlags(ref f) =>
                o.write_all(&f.as_vec())?,
            SignersUserID(ref uid) =>
                o.write_all(uid)?,
            ReasonForRevocation { ref code, ref reason } => {
                o.write_all(&[(*code).into()])?;
                o.write_all(reason)?;
            },
            Features(ref f) =>
                o.write_all(&f.as_vec())?,
            SignatureTarget { pk_algo, hash_algo, ref digest } => {
                o.write_all(&[(*pk_algo).into(), (*hash_algo).into()])?;
                o.write_all(digest)?;
            },
            EmbeddedSignature(ref p) => match p {
                &Packet::Signature(ref sig) => sig.serialize_naked(o)?,
                _ => return Err(Error::InvalidArgument(
                    format!("Not a signature: {:?}", p)).into()),
            },
            IssuerFingerprint(ref fp) => match fp {
                Fingerprint::V4(_) => {
                    o.write_all(&[4])?;
                    o.write_all(fp.as_slice())?;
                },
                _ => return Err(Error::InvalidArgument(
                    "Unknown kind of fingerprint".into()).into()),
            }
            PreferredAEADAlgorithms(ref p) =>
                for a in p {
                    o.write_all(&[(*a).into()])?;
                },
            IntendedRecipient(ref fp) => match fp {
                Fingerprint::V4(_) => {
                    o.write_all(&[4])?;
                    o.write_all(fp.as_slice())?;
                },
                _ => return Err(Error::InvalidArgument(
                    "Unknown kind of fingerprint".into()).into()),
            }
            Unknown(ref raw) =>
                o.write_all(raw)?,
            Invalid(ref raw) =>
                o.write_all(raw)?,
        }
        Ok(())
    }
}

impl Serialize for Signature {
    /// Writes a serialized version of the specified `Signature`
    /// packet to `o`.
    ///
    /// Note: this function does not compute the signature (which
    /// would require access to the private key); it assumes that
    /// sig.mpis is up to date.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if invoked on a
    /// non-version 4 signature, or if either the hashed-area or the
    /// unhashed-area exceeds the size limit of 2^16.
    ///
    /// [`Error::InvalidArgument`]: ../../enum.Error.html#variant.InvalidArgument
    fn serialize<W: io::Write>(&self, o: &mut W) -> Result<()> {
        let len = 1 // version
            + 1 // signature type.
            + 1 // pk algorithm
            + 1 // hash algorithm
            + 2 // hashed area size
            + self.hashed_area().data.len()
            + 2 // unhashed area size
            + self.unhashed_area().data.len()
            + 2 // hash prefix
            + self.mpis().serialized_len();

        CTB::new(Tag::Signature).serialize(o)?;
        BodyLength::Full(len as u32).serialize(o)?;

        self.serialize_naked(o)
    }
}

impl Signature {
    /// Writes a serialized version of the specified `Signature`
    /// packet without framing to `o`.
    ///
    /// Note: this function does not compute the signature (which
    /// would require access to the private key); it assumes that
    /// sig.mpis is up to date.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if invoked on a
    /// non-version 4 signature, or if either the hashed-area or the
    /// unhashed-area exceeds the size limit of 2^16.
    ///
    /// [`Error::InvalidArgument`]: ../enum.Error.html#variant.InvalidArgument
    pub(crate) fn serialize_naked<W: io::Write>(&self, o: &mut W) -> Result<()> {
        if self.version() != 4 {
            return Err(Error::InvalidArgument(
                "Don't know how to serialize \
                 non-version 4 packets.".into()).into());
        }
        write_byte(o, self.version())?;
        write_byte(o, self.sigtype().into())?;
        write_byte(o, self.pk_algo().into())?;
        write_byte(o, self.hash_algo().into())?;

        if self.hashed_area().data.len() > std::u16::MAX as usize {
            return Err(Error::InvalidArgument(
                "Hashed area too large".into()).into());
        }
        write_be_u16(o, self.hashed_area().data.len() as u16)?;
        o.write_all(&self.hashed_area().data[..])?;

        if self.unhashed_area().data.len() > std::u16::MAX as usize {
            return Err(Error::InvalidArgument(
                "Unhashed area too large".into()).into());
        }
        write_be_u16(o, self.unhashed_area().data.len() as u16)?;
        o.write_all(&self.unhashed_area().data[..])?;

        write_byte(o, self.hash_prefix()[0])?;
        write_byte(o, self.hash_prefix()[1])?;

        self.mpis.serialize(o)?;

        Ok(())
    }
}

impl Serialize for OnePassSig {
    /// Writes a serialized version of the specified `OnePassSig`
    /// packet to `o`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if invoked on a
    /// non-version 3 one-pass-signature packet.
    ///
    /// [`Error::InvalidArgument`]: ../enum.Error.html#variant.InvalidArgument
    fn serialize<W: io::Write>(&self, o: &mut W) -> Result<()> {
        let len = 1 // version
            + 1 // signature type.
            + 1 // hash algorithm
            + 1 // pk algorithm
            + 8 // issuer
            + 1 // last
            ;

        CTB::new(Tag::OnePassSig).serialize(o)?;
        BodyLength::Full(len as u32).serialize(o)?;

        if self.version() != 3 {
            return Err(Error::InvalidArgument(
                "Don't know how to serialize \
                 non-version 3 packets.".into()).into());
        }

        write_byte(o, self.version())?;
        write_byte(o, self.sigtype().into())?;
        write_byte(o, self.hash_algo().into())?;
        write_byte(o, self.pk_algo().into())?;
        o.write_all(self.issuer().as_slice())?;
        write_byte(o, self.last_raw())?;

        Ok(())
    }

    /// Serializes the packet to a vector.
    fn to_vec(&self) -> Result<Vec<u8>> {
        let mut o = Vec::with_capacity(32);
        self.serialize(&mut o)?;
        Ok(o)
    }
}

impl SerializeKey for Key {
    /// Writes a serialized version of the specified `Key` packet to
    /// `o`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if invoked on a
    /// non-version 4 key.
    ///
    /// [`Error::InvalidArgument`]: ../enum.Error.html#variant.InvalidArgument
    fn serialize<W: io::Write>(&self, o: &mut W, tag: Tag) -> Result<()> {
        assert!(tag == Tag::PublicKey
                || tag == Tag::PublicSubkey
                || tag == Tag::SecretKey
                || tag == Tag::SecretSubkey);
        let have_secret_key =
            (tag == Tag::SecretKey || tag == Tag::SecretSubkey)
            && self.secret().is_some();

        // Only emit packets with the SecretKey or SecretSubkey tags
        // if we have secrets.
        let tag = match tag {
            Tag::SecretKey    if ! have_secret_key => Tag::PublicKey,
            Tag::SecretSubkey if ! have_secret_key => Tag::PublicSubkey,
            t => t,
        };

        let len = 1 + 4 + 1
            + self.mpis().serialized_len()
            + if have_secret_key {
                1 + match self.secret().as_ref().unwrap() {
                    &SecretKey::Unencrypted { ref mpis } =>
                        mpis.serialized_len() + 2,
                    &SecretKey::Encrypted {
                        ref s2k,
                        ref ciphertext,
                        ..
                    } =>
                        1
                        // If serialization fails here, it will fail
                        // further down, so the length doesn't matter.
                        + s2k.to_vec().map(|o| o.len()).unwrap_or(0)
                        + ciphertext.len(),
                }
            } else {
                0
            };

        CTB::new(tag).serialize(o)?;
        BodyLength::Full(len as u32).serialize(o)?;

        if self.version() != 4 {
            return Err(Error::InvalidArgument(
                "Don't know how to serialize \
                 non-version 4 packets.".into()).into());
        }
        write_byte(o, self.version())?;
        write_be_u32(o, self.creation_time().to_pgp()?)?;
        write_byte(o, self.pk_algo().into())?;
        self.mpis().serialize(o)?;

        if have_secret_key {
            match self.secret().unwrap() {
                &SecretKey::Unencrypted { ref mpis } => {
                    // S2K usage.
                    write_byte(o, 0)?;

                    // To compute the checksum, serialize to a buffer first.
                    let mut buf = Vec::new();
                    mpis.serialize(&mut buf)?;
                    let checksum: usize = buf.iter().map(|x| *x as usize)
                        .sum();

                    // Then, just write out the buffer.
                    o.write_all(&buf)?;
                    write_be_u16(o, checksum as u16)?;
                },
                &SecretKey::Encrypted {
                    ref s2k,
                    algorithm,
                    ref ciphertext,
                } => {
                    // S2K usage.
                    write_byte(o, 254)?;
                    write_byte(o, algorithm.into())?;
                    s2k.serialize(o)?;
                    o.write_all(ciphertext)?;
                },
            }
        }

        Ok(())
    }
}

impl Serialize for UserID {
    /// Writes a serialized version of the specified `UserID` packet to
    /// `o`.
    fn serialize<W: io::Write>(&self, o: &mut W) -> Result<()> {
        let len = self.value.len();

        CTB::new(Tag::UserID).serialize(o)?;
        BodyLength::Full(len as u32).serialize(o)?;
        o.write_all(&self.value[..])?;

        Ok(())
    }

    /// Serializes the packet to a vector.
    fn to_vec(&self) -> Result<Vec<u8>> {
        let mut o = Vec::with_capacity(16 + self.value.len());
        // Writing to a vec can't fail.
        self.serialize(&mut o)?;
        Ok(o)
    }
}

impl Serialize for UserAttribute {
    /// Writes a serialized version of the specified `UserAttribute`
    /// packet to `o`.
    fn serialize<W: io::Write>(&self, o: &mut W) -> Result<()> {
        let len = self.user_attribute().len();

        CTB::new(Tag::UserAttribute).serialize(o)?;
        BodyLength::Full(len as u32).serialize(o)?;
        o.write_all(self.user_attribute())?;

        Ok(())
    }

    /// Serializes the packet to a vector.
    fn to_vec(&self) -> Result<Vec<u8>> {
        let mut o = Vec::with_capacity(16 + self.user_attribute().len());
        self.serialize(&mut o)?;
        Ok(o)
    }
}

impl Literal {
    /// Writes the headers of the `Literal` data packet to `o`.
    pub(crate) fn serialize_headers<W>(&self, o: &mut W,
                                       write_tag: bool)
                                       -> Result<()>
        where W: io::Write
    {
        let filename = if let Some(ref filename) = self.filename() {
            let len = cmp::min(filename.len(), 255) as u8;
            &filename[..len as usize]
        } else {
            &b""[..]
        };

        let date = if let Some(d) = self.date() {
            d.to_pgp()?
        } else {
            0
        };

        if write_tag {
            let len = 1 + (1 + filename.len()) + 4
                + self.common.body.as_ref().map(|b| b.len()).unwrap_or(0);
            CTB::new(Tag::Literal).serialize(o)?;
            BodyLength::Full(len as u32).serialize(o)?;
        }
        write_byte(o, self.format().into())?;
        write_byte(o, filename.len() as u8)?;
        o.write_all(filename)?;
        write_be_u32(o, date)?;
        Ok(())
    }
}

impl Serialize for Literal {
    /// Writes a serialized version of the `Literal` data packet to `o`.
    fn serialize<W: io::Write>(&self, o: &mut W) -> Result<()> {
        let body = if let Some(ref body) = self.common.body {
            &body[..]
        } else {
            &b""[..]
        };

        if TRACE {
            let prefix = &body[..cmp::min(body.len(), 20)];
            eprintln!("Literal::serialize({}{}, {} bytes)",
                      String::from_utf8_lossy(prefix),
                      if body.len() > 20 { "..." } else { "" },
                      body.len());
        }

        self.serialize_headers(o, true)?;
        o.write_all(body)?;

        Ok(())
    }

    /// Serializes the packet to a vector.
    fn to_vec(&self) -> Result<Vec<u8>> {
        let mut o = Vec::with_capacity(
            32 + self.common.body.as_ref().map(|b| b.len()).unwrap_or(0)
            + self.filename().map(|b| b.len()).unwrap_or(0));

        self.serialize(&mut o)?;
        Ok(o)
    }
}

impl Serialize for CompressedData {
    /// Writes a serialized version of the specified `CompressedData`
    /// packet to `o`.
    ///
    /// This function works recursively: if the `CompressedData` packet
    /// contains any packets, they are also serialized.
    fn serialize<W: io::Write>(&self, o: &mut W) -> Result<()> {
        if TRACE {
            eprintln!("CompressedData::serialize(\
                       algo: {}, {:?} children, {:?} bytes)",
                      self.algorithm(),
                      self.common.children.as_ref().map(
                          |cont| cont.children().len()),
                      self.common.body.as_ref().map(|body| body.len()));
        }

        let o = stream::Message::new(o);
        let mut o = stream::Compressor::new(o, self.algorithm())?;

        // Serialize the packets.
        if let Some(ref children) = self.common.children {
            for p in children.children() {
                p.serialize(&mut o)?;
            }
        }

        // Append the data.
        if let Some(ref data) = self.common.body {
            o.write_all(data)?;
        }

        Ok(())
    }

    /// Serializes the packet to a vector.
    fn to_vec(&self) -> Result<Vec<u8>> {
        let mut o = Vec::with_capacity(4 * 1024 * 1024);
        self.serialize(&mut o)?;
        o.shrink_to_fit();
        Ok(o)
    }
}

impl Serialize for PKESK {
    /// Writes a serialized version of the specified `PKESK`
    /// packet to `o`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if invoked on a
    /// non-version 3 PKESK packet.
    ///
    /// [`Error::InvalidArgument`]: ../enum.Error.html#variant.InvalidArgument
    fn serialize<W: io::Write>(&self, o: &mut W) -> Result<()> {
        if self.version() != 3 {
            return Err(Error::InvalidArgument(
                "Don't know how to serialize \
                 non-version 3 packets.".into()).into());
        }

        let len =
            1 // Version
            + 8 // Recipient's key id
            + 1 // Algo
            + self.esk().serialized_len(); // ESK.

        CTB::new(Tag::PKESK).serialize(o)?;
        BodyLength::Full(len as u32).serialize(o)?;

        write_byte(o, self.version())?;
        self.recipient().serialize(o)?;
        write_byte(o, self.pk_algo().into())?;
        self.esk().serialize(o)?;

        Ok(())
    }
}

impl Serialize for SKESK {
    fn serialize<W: io::Write>(&self, o: &mut W) -> Result<()> {
        match self {
            &SKESK::V4(ref s) => s.serialize(o),
            &SKESK::V5(ref s) => s.serialize(o),
        }
    }
}

impl Serialize for SKESK4 {
    /// Writes a serialized version of the specified `SKESK`
    /// packet to `o`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if invoked on a
    /// non-version 4 SKESK packet.
    ///
    /// [`Error::InvalidArgument`]: ../enum.Error.html#variant.InvalidArgument
    fn serialize<W: io::Write>(&self, o: &mut W) -> Result<()> {
        if self.version() != 4 {
            return Err(Error::InvalidArgument(
                "Don't know how to serialize \
                 non-version 4 packets.".into()).into());
        }

        let len =
            1 // Version
            + 1 // Algo
            + self.s2k().serialized_len() // s2k.
            + self.esk().map(|esk| esk.len()).unwrap_or(0); // ESK.

        CTB::new(Tag::SKESK).serialize(o)?;
        BodyLength::Full(len as u32).serialize(o)?;

        write_byte(o, self.version())?;
        write_byte(o, self.symmetric_algo().into())?;
        self.s2k().serialize(o)?;
        if let Some(ref esk) = self.esk() {
            o.write_all(&esk[..])?;
        }

        Ok(())
    }
}

impl Serialize for SKESK5 {
    /// Writes a serialized version of the specified `SKESK`
    /// packet to `o`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if invoked on a
    /// non-version 5 SKESK packet.
    ///
    /// [`Error::InvalidArgument`]: ../enum.Error.html#variant.InvalidArgument
    fn serialize<W: io::Write>(&self, o: &mut W) -> Result<()> {
        if self.version() != 5 {
            return Err(Error::InvalidArgument(
                "Don't know how to serialize \
                 non-version 4 packets.".into()).into());
        }

        let len =
            1 // Version.
            + 1 // Cipher algo.
            + 1 // AEAD algo.
            + self.s2k().serialized_len() // S2K.
            + self.aead_iv().len() // AEAD IV.
            + self.esk().map(|esk| esk.len()).unwrap_or(0) // ESK.
            + self.aead_digest().len(); // AEAD digest.

        CTB::new(Tag::SKESK).serialize(o)?;
        BodyLength::Full(len as u32).serialize(o)?;

        write_byte(o, self.version())?;
        write_byte(o, self.symmetric_algo().into())?;
        write_byte(o, self.aead_algo().into())?;
        self.s2k().serialize(o)?;
        o.write_all(self.aead_iv())?;
        if let Some(ref esk) = self.esk() {
            o.write_all(&esk[..])?;
        }
        o.write_all(self.aead_digest())?;

        Ok(())
    }
}

impl Serialize for SEIP {
    /// Writes a serialized version of the specified `SEIP`
    /// packet to `o`.
    fn serialize<W: io::Write>(&self, o: &mut W) -> Result<()> {
        if let Some(ref _children) = self.common.children {
            unimplemented!("XXX: Serialize and encrypt the content.");
        } else {
            // XXX: We assume that the content is encrypted.
            let body_len = 1
                + self.common.body.as_ref().map(|b| b.len()).unwrap_or(0);

            CTB::new(Tag::SEIP).serialize(o)?;
            BodyLength::Full(body_len as u32).serialize(o)?;
            o.write_all(&[self.version()])?;
            if let Some(ref body) = self.common.body {
                o.write_all(&body[..])?;
            }
        }

        Ok(())
    }
}

impl Serialize for MDC {
    /// Writes a serialized version of the specified `MDC`
    /// packet to `o`.
    fn serialize<W: io::Write>(&self, o: &mut W) -> Result<()> {
        CTB::new(Tag::MDC).serialize(o)?;
        BodyLength::Full(20).serialize(o)?;
        o.write_all(self.hash())?;
        Ok(())
    }
}

impl AED {
    /// Writes the headers of the `AED` data packet to `o`.
    fn serialize_headers<W: io::Write>(&self, o: &mut W)
                                       -> Result<()> {
        o.write_all(&[self.version(),
                      self.cipher().into(),
                      self.aead().into(),
                      self.chunk_size().trailing_zeros() as u8 - 6])?;
        o.write_all(self.iv())?;
        Ok(())
    }
}

impl Serialize for AED {
    /// Writes a serialized version of the specified `AED`
    /// packet to `o`.
    fn serialize<W: io::Write>(&self, o: &mut W) -> Result<()> {
        if let Some(ref _children) = self.common.children {
            unimplemented!("XXX: Serialize and encrypt the content.");
        } else {
            // XXX: We assume that the content is encrypted.
            let body_len = 4
                + self.iv().len()
                + self.common.body.as_ref().map(|b| b.len()).unwrap_or(0)
                + self.aead().digest_size()?;

            CTB::new(Tag::SEIP).serialize(o)?;
            BodyLength::Full(body_len as u32).serialize(o)?;
            self.serialize_headers(o)?;

            if let Some(ref body) = self.common.body {
                o.write_all(&body[..])?;
            }
        }

        Ok(())
    }
}

impl Serialize for Packet {
    /// Writes a serialized version of the specified `Packet` to `o`.
    ///
    /// This function works recursively: if the packet contains any
    /// packets, they are also serialized.
    fn serialize<W: io::Write>(&self, o: &mut W) -> Result<()> {
        let tag = self.tag();
        match self {
            &Packet::Unknown(ref p) => p.serialize(o),
            &Packet::Signature(ref p) => p.serialize(o),
            &Packet::OnePassSig(ref p) => p.serialize(o),
            &Packet::PublicKey(ref p) => p.serialize(o, tag),
            &Packet::PublicSubkey(ref p) => p.serialize(o, tag),
            &Packet::SecretKey(ref p) => p.serialize(o, tag),
            &Packet::SecretSubkey(ref p) => p.serialize(o, tag),
            &Packet::UserID(ref p) => p.serialize(o),
            &Packet::UserAttribute(ref p) => p.serialize(o),
            &Packet::Literal(ref p) => p.serialize(o),
            &Packet::CompressedData(ref p) => p.serialize(o),
            &Packet::PKESK(ref p) => p.serialize(o),
            &Packet::SKESK(ref p) => p.serialize(o),
            &Packet::SEIP(ref p) => p.serialize(o),
            &Packet::MDC(ref p) => p.serialize(o),
            &Packet::AED(ref p) => p.serialize(o),
        }
    }

    /// Serializes the packet to a vector.
    fn to_vec(&self) -> Result<Vec<u8>> {
        let mut o = Vec::with_capacity(4 * 1024 * 1024);
        self.serialize(&mut o)?;
        o.shrink_to_fit();
        Ok(o)
    }
}

impl Serialize for PacketPile {
    /// Writes a serialized version of the specified `PacketPile` to `o`.
    fn serialize<W: io::Write>(&self, o: &mut W) -> Result<()> {
        for p in self.children() {
            p.serialize(o)?;
        }

        Ok(())
    }

    /// Serializes the packet to a vector.
    fn to_vec(&self) -> Result<Vec<u8>> {
        let mut o = Vec::with_capacity(4 * 1024 * 1024);
        self.serialize(&mut o)?;
        o.shrink_to_fit();
        Ok(o)
    }
}

#[cfg(test)]
mod test {
    use std::fs::File;
    use std::io::Read;

    use super::*;
    use constants::CompressionAlgorithm;
    use parse::to_unknown_packet;
    use parse::PacketParserBuilder;

    // A convenient function to dump binary data to stdout.
    fn binary_pp(data: &[u8]) -> String {
        let mut output = Vec::with_capacity(data.len() * 2 + 3 * data.len() / 4);

        for i in 0..data.len() {
            if i > 0 && i % (4 * 4 * 2) == 0 {
                output.push('\n' as u8);
            } else {
                if i > 0 && i % 2 == 0 {
                    output.push(' ' as u8);
                }
                if i > 0 && i % (4 * 2) == 0 {
                    output.push(' ' as u8);
                }
            }

            let top = data[i] >> 4;
            let bottom = data[i] & 0xFu8;

            if top < 10u8 {
                output.push('0' as u8 + top)
            } else {
                output.push('A' as u8 + (top - 10u8))
            }

            if bottom < 10u8 {
                output.push('0' as u8 + bottom)
            } else {
                output.push('A' as u8 + (bottom - 10u8))
            }
        }

        // We know the content is valid UTF-8.
        String::from_utf8(output).unwrap()
    }

    // Does a bit-wise comparison of two packets ignoring the CTB
    // format, the body length encoding, and whether partial body
    // length encoding was used.
    fn packets_bitwise_compare(filename: &str, packet: &Packet,
                               expected: &[u8], got: &[u8]) {
        let expected = to_unknown_packet(expected).unwrap();
        let got = to_unknown_packet(got).unwrap();

        let expected_body = if let Some(ref data) = expected.common.body {
            &data[..]
        } else {
            &b""[..]
        };
        let got_body = if let Some(ref data) = got.common.body {
            &data[..]
        } else {
            &b""[..]
        };

        let mut fail = false;
        if expected.tag() != got.tag() {
            eprintln!("Expected a {:?}, got a {:?}", expected.tag(), got.tag());
            fail = true;
        }
        if expected_body != got_body {
            eprintln!("Packet contents don't match (for {}):",
                      filename);
            eprintln!("Expected ({} bytes):\n{}",
                      expected_body.len(), binary_pp(&expected_body));
            eprintln!("Got ({} bytes):\n{}",
                      got_body.len(), binary_pp(&got_body));
            eprintln!("Packet: {:#?}", packet);
            fail = true;
        }
        if fail {
            panic!("Packets don't match (for {}).", filename);
        }
    }

    #[test]
    fn serialize_test_1() {
        // Given a packet in serialized form:
        //
        // - Parse and reserialize it;
        //
        // - Do a bitwise comparison (modulo the body length encoding)
        //   of the original and reserialized data.
        //
        // Note: This test only works on messages with a single packet.
        //
        // Note: This test does not work with non-deterministic
        // packets, like compressed data packets, since the serialized
        // forms may be different.

        let filenames = [
            "literal-mode-b.gpg",
            "literal-mode-t-partial-body.gpg",

            "sig.gpg",

            "public-key-bare.gpg",
            "public-subkey-bare.gpg",
            "userid-bare.gpg",

            "s2k/mode-0-password-1234.gpg",
            "s2k/mode-0-password-1234.gpg",
            "s2k/mode-1-password-123456-1.gpg",
            "s2k/mode-1-password-foobar-2.gpg",
            "s2k/mode-3-aes128-password-13-times-0123456789.gpg",
            "s2k/mode-3-aes192-password-123.gpg",
            "s2k/mode-3-encrypted-key-password-bgtyhn.gpg",
            "s2k/mode-3-password-9876-2.gpg",
            "s2k/mode-3-password-qwerty-1.gpg",
            "s2k/mode-3-twofish-password-13-times-0123456789.gpg",
        ];

        for filename in filenames.iter() {
            // 1. Read the message byte stream into a local buffer.
            let path = path_to(filename);
            let mut data = Vec::new();
            File::open(&path).expect(&path.to_string_lossy())
                .read_to_end(&mut data).expect("Reading test data");

            // 2. Parse the message.
            let pile = PacketPile::from_bytes(&data[..]).unwrap();

            // The following test only works if the message has a
            // single top-level packet.
            assert_eq!(pile.children().len(), 1);

            // 3. Serialize the packet it into a local buffer.
            let p = pile.descendants().next().unwrap();
            let mut buffer = Vec::new();
            match p {
                &Packet::Literal(ref l) => {
                    l.serialize(&mut buffer).unwrap();
                },
                &Packet::Signature(ref s) => {
                    s.serialize(&mut buffer).unwrap();
                },
                &Packet::PublicKey(ref pk) => {
                    pk.serialize(&mut buffer, Tag::PublicKey).unwrap();
                },
                &Packet::PublicSubkey(ref pk) => {
                    pk.serialize(&mut buffer, Tag::PublicSubkey).unwrap();
                },
                &Packet::UserID(ref userid) => {
                    userid.serialize(&mut buffer).unwrap();
                },
                &Packet::SKESK(ref skesk) => {
                    skesk.serialize(&mut buffer).unwrap();
                },
                ref p => {
                    panic!("Didn't expect a {:?} packet.", p.tag());
                },
            }

            // 4. Modulo the body length encoding, check that the
            // reserialized content is identical to the original data.
            packets_bitwise_compare(filename, p, &data[..], &buffer[..]);
        }
    }

    #[test]
    fn serialize_test_1_unknown() {
        // This is an variant of serialize_test_1 that tests the
        // unknown packet serializer.
        let filenames = [
            "compressed-data-algo-1.gpg",
            "compressed-data-algo-2.gpg",
            "compressed-data-algo-3.gpg",
            "recursive-2.gpg",
            "recursive-3.gpg",
        ];

        for filename in filenames.iter() {
            // 1. Read the message byte stream into a local buffer.
            let path = path_to(filename);
            let mut data = Vec::new();
            File::open(&path).expect(&path.to_string_lossy())
                .read_to_end(&mut data).expect("Reading test data");

            // 2. Parse the message.
            let u = to_unknown_packet(&data[..]).unwrap();

            // 3. Serialize the packet it into a local buffer.
            let data2 = u.to_vec().unwrap();

            // 4. Modulo the body length encoding, check that the
            // reserialized content is identical to the original data.
            packets_bitwise_compare(filename, &Packet::Unknown(u),
                                    &data[..], &data2[..]);
        }

    }

    #[cfg(feature = "compression-deflate")]
    #[test]
    fn serialize_test_2() {
        // Given a packet in serialized form:
        //
        // - Parse, reserialize, and reparse it;
        //
        // - Compare the messages.
        //
        // Note: This test only works on messages with a single packet
        // top-level packet.
        //
        // Note: serialize_test_1 is a better test, because it
        // compares the serialized data, but serialize_test_1 doesn't
        // work if the content is non-deterministic.
        let filenames = [
            "compressed-data-algo-1.gpg",
            "compressed-data-algo-2.gpg",
            "compressed-data-algo-3.gpg",
            "recursive-2.gpg",
            "recursive-3.gpg",
        ];

        for filename in filenames.iter() {
            eprintln!("{}...", filename);

            // 1. Read the message into a local buffer.
            let path = path_to(filename);
            let mut data = Vec::new();
            File::open(&path).expect(&path.to_string_lossy())
                .read_to_end(&mut data).expect("Reading test data");

            // 2. Do a shallow parse of the messsage.  In other words,
            // never recurse so that the resulting message only
            // contains the top-level packets.  Any containers will
            // have their raw content stored in packet.content.
            let pile = PacketParserBuilder::from_bytes(&data[..]).unwrap()
                .max_recursion_depth(0)
                .buffer_unread_content()
                //.trace()
                .to_packet_pile().unwrap();

            // 3. Get the first packet.
            let po = pile.descendants().next();
            if let Some(&Packet::CompressedData(ref cd)) = po {
                // 4. Serialize the container.
                let buffer = cd.to_vec().unwrap();

                // 5. Reparse it.
                let pile2 = PacketParserBuilder::from_bytes(&buffer[..]).unwrap()
                    .max_recursion_depth(0)
                    .buffer_unread_content()
                    //.trace()
                    .to_packet_pile().unwrap();

                // 6. Make sure the original message matches the
                // serialized and reparsed message.
                if pile != pile2 {
                    eprintln!("Orig:");
                    let p = pile.children().next().unwrap();
                    eprintln!("{:?}", p);
                    let body = &p.body.as_ref().unwrap()[..];
                    eprintln!("Body: {}", body.len());
                    eprintln!("{}", binary_pp(body));

                    eprintln!("Reparsed:");
                    let p = pile2.children().next().unwrap();
                    eprintln!("{:?}", p);
                    let body = &p.body.as_ref().unwrap()[..];
                    eprintln!("Body: {}", body.len());
                    eprintln!("{}", binary_pp(body));

                    assert_eq!(pile, pile2);
                }
            } else {
                panic!("Expected a compressed data data packet.");
            }
        }
    }

    // Create some crazy nesting structures, serialize the messages,
    // reparse them, and make sure we get the same result.
    #[test]
    fn serialize_test_3() {
        use constants::DataFormat::Text as T;

        // serialize_test_1 and serialize_test_2 parse a byte stream.
        // This tests creates the message, and then serializes and
        // reparses it.

        let mut messages = Vec::new();

        // 1: CompressedData(CompressedData { algo: 0 })
        //  1: Literal(Literal { body: "one (3 bytes)" })
        //  2: Literal(Literal { body: "two (3 bytes)" })
        // 2: Literal(Literal { body: "three (5 bytes)" })
        let mut one = Literal::new(T);
        one.set_body(b"one".to_vec());
        let mut two = Literal::new(T);
        two.set_body(b"two".to_vec());
        let mut three = Literal::new(T);
        three.set_body(b"three".to_vec());
        let mut four = Literal::new(T);
        four.set_body(b"four".to_vec());
        let mut five = Literal::new(T);
        five.set_body(b"five".to_vec());
        let mut six = Literal::new(T);
        six.set_body(b"six".to_vec());

        let mut top_level = Vec::new();
        top_level.push(
            CompressedData::new(CompressionAlgorithm::Uncompressed)
                .push(one.clone().to_packet())
                .push(two.clone().to_packet())
                .to_packet());
        top_level.push(three.clone().to_packet());
        messages.push(top_level);

        // 1: CompressedData(CompressedData { algo: 0 })
        //  1: CompressedData(CompressedData { algo: 0 })
        //   1: Literal(Literal { body: "one (3 bytes)" })
        //   2: Literal(Literal { body: "two (3 bytes)" })
        //  2: CompressedData(CompressedData { algo: 0 })
        //   1: Literal(Literal { body: "three (5 bytes)" })
        //   2: Literal(Literal { body: "four (4 bytes)" })
        let mut top_level = Vec::new();
        top_level.push(
            CompressedData::new(CompressionAlgorithm::Uncompressed)
                .push(CompressedData::new(CompressionAlgorithm::Uncompressed)
                      .push(one.clone().to_packet())
                      .push(two.clone().to_packet())
                      .to_packet())
                .push(CompressedData::new(CompressionAlgorithm::Uncompressed)
                      .push(three.clone().to_packet())
                      .push(four.clone().to_packet())
                      .to_packet())
                .to_packet());
        messages.push(top_level);

        // 1: CompressedData(CompressedData { algo: 0 })
        //  1: CompressedData(CompressedData { algo: 0 })
        //   1: CompressedData(CompressedData { algo: 0 })
        //    1: CompressedData(CompressedData { algo: 0 })
        //     1: Literal(Literal { body: "one (3 bytes)" })
        //     2: Literal(Literal { body: "two (3 bytes)" })
        //  2: CompressedData(CompressedData { algo: 0 })
        //   1: CompressedData(CompressedData { algo: 0 })
        //    1: Literal(Literal { body: "three (5 bytes)" })
        //   2: Literal(Literal { body: "four (4 bytes)" })
        let mut top_level = Vec::new();
        top_level.push(
            CompressedData::new(CompressionAlgorithm::Uncompressed)
                .push(CompressedData::new(CompressionAlgorithm::Uncompressed)
                    .push(CompressedData::new(CompressionAlgorithm::Uncompressed)
                        .push(CompressedData::new(CompressionAlgorithm::Uncompressed)
                            .push(one.clone().to_packet())
                            .push(two.clone().to_packet())
                            .to_packet())
                        .to_packet())
                    .to_packet())
                .push(CompressedData::new(CompressionAlgorithm::Uncompressed)
                    .push(CompressedData::new(CompressionAlgorithm::Uncompressed)
                        .push(three.clone().to_packet())
                        .to_packet())
                    .push(four.clone().to_packet())
                    .to_packet())
                .to_packet());
        messages.push(top_level);

        // 1: CompressedData(CompressedData { algo: 0 })
        //  1: Literal(Literal { body: "one (3 bytes)" })
        //  2: Literal(Literal { body: "two (3 bytes)" })
        // 2: Literal(Literal { body: "three (5 bytes)" })
        // 3: Literal(Literal { body: "four (4 bytes)" })
        // 4: CompressedData(CompressedData { algo: 0 })
        //  1: Literal(Literal { body: "five (4 bytes)" })
        //  2: Literal(Literal { body: "six (3 bytes)" })
        let mut top_level = Vec::new();
        top_level.push(
            CompressedData::new(CompressionAlgorithm::Uncompressed)
                .push(one.clone().to_packet())
                .push(two.clone().to_packet())
                .to_packet());
        top_level.push(
            three.clone().to_packet());
        top_level.push(
            four.clone().to_packet());
        top_level.push(
            CompressedData::new(CompressionAlgorithm::Uncompressed)
                .push(five.to_packet())
                .push(six.to_packet())
                .to_packet());
        messages.push(top_level);

        // 1: UserID(UserID { value: "Foo" })
        let mut top_level = Vec::new();
        let mut uid = UserID::new();
        uid.set_userid("Foo");
        top_level.push(uid.to_packet());
        messages.push(top_level);

        for m in messages.into_iter() {
            // 1. The message.
            let pile = PacketPile::from_packets(m);

            pile.pretty_print();

            // 2. Serialize the message into a buffer.
            let mut buffer = Vec::new();
            pile.clone().serialize(&mut buffer).unwrap();

            // 3. Reparse it.
            let pile2 = PacketParserBuilder::from_bytes(&buffer[..]).unwrap()
                //.trace()
                .buffer_unread_content()
                .to_packet_pile().unwrap();

            // 4. Compare the messages.
            if pile != pile2 {
                eprintln!("ORIG...");
                pile.pretty_print();
                eprintln!("REPARSED...");
                pile2.pretty_print();
                panic!("Reparsed packet does not match original packet!");
            }
        }
    }

    #[test]
    fn body_length_edge_cases() {
        {
            let mut buf = vec![];
            BodyLength::Full(0).serialize(&mut buf).unwrap();
            assert_eq!(&buf[..], &b"\x00"[..]);
        }

        {
            let mut buf = vec![];
            BodyLength::Full(1).serialize(&mut buf).unwrap();
            assert_eq!(&buf[..], &b"\x01"[..]);
        }
        {
            let mut buf = vec![];
            BodyLength::Full(191).serialize(&mut buf).unwrap();
            assert_eq!(&buf[..], &b"\xbf"[..]);
        }
        {
            let mut buf = vec![];
            BodyLength::Full(192).serialize(&mut buf).unwrap();
            assert_eq!(&buf[..], &b"\xc0\x00"[..]);
        }
        {
            let mut buf = vec![];
            BodyLength::Full(193).serialize(&mut buf).unwrap();
            assert_eq!(&buf[..], &b"\xc0\x01"[..]);
        }
        {
            let mut buf = vec![];
            BodyLength::Full(8383).serialize(&mut buf).unwrap();
            assert_eq!(&buf[..], &b"\xdf\xff"[..]);
        }
        {
            let mut buf = vec![];
            BodyLength::Full(8384).serialize(&mut buf).unwrap();
            assert_eq!(&buf[..], &b"\xff\x00\x00\x20\xc0"[..]);
        }
        {
            let mut buf = vec![];
            BodyLength::Full(0xffffffff).serialize(&mut buf).unwrap();
            assert_eq!(&buf[..], &b"\xff\xff\xff\xff\xff"[..]);
        }
    }
}
