use crate::Result;
use crate::TPK;
use crate::packet::{Key, Signature, Tag};
use crate::serialize::{
    PacketRef, Serialize, SerializeInto,
    generic_serialize_into, generic_export_into,
};

impl Serialize for TPK {
    fn serialize(&self, o: &mut dyn std::io::Write) -> Result<()> {
        self.serialize_common(o, false)
    }

    fn export(&self, o: &mut dyn std::io::Write) -> Result<()> {
        self.serialize_common(o, true)
    }
}

impl TPK {
    /// Serializes or exports the TPK.
    ///
    /// If `export` is true, then non-exportable signatures are not
    /// written, and components without any exportable binding
    /// signature or revocation are not exported.
    fn serialize_common(&self, o: &mut dyn std::io::Write, export: bool)
                        -> Result<()>
    {
        PacketRef::PublicKey(self.primary()).serialize(o)?;

        // Writes a signature if it is exportable or `! export`.
        let serialize_sig =
            |o: &mut dyn std::io::Write, sig: &Signature| -> Result<()>
        {
            if export {
                if sig.exportable_certification().unwrap_or(true) {
                    PacketRef::Signature(sig).export(o)?;
                }
            } else {
                PacketRef::Signature(sig).serialize(o)?;
            }
            Ok(())
        };

        for s in self.selfsigs() {
            serialize_sig(o, s)?;
        }
        for s in self.self_revocations() {
            serialize_sig(o, s)?;
        }
        for s in self.other_revocations() {
            serialize_sig(o, s)?;
        }
        for s in self.certifications() {
            serialize_sig(o, s)?;
        }

        for u in self.userids.iter() {
            if export && ! u.selfsigs().iter().chain(u.self_revocations()).any(
                |s| s.exportable_certification().unwrap_or(true))
            {
                // No exportable selfsig on this component, skip it.
                continue;
            }

            PacketRef::UserID(u.userid()).serialize(o)?;
            for s in u.self_revocations() {
                serialize_sig(o, s)?;
            }
            for s in u.selfsigs() {
                serialize_sig(o, s)?;
            }
            for s in u.other_revocations() {
                serialize_sig(o, s)?;
            }
            for s in u.certifications() {
                serialize_sig(o, s)?;
            }
        }

        for u in self.user_attributes.iter() {
            if export && ! u.selfsigs().iter().chain(u.self_revocations()).any(
                |s| s.exportable_certification().unwrap_or(true))
            {
                // No exportable selfsig on this component, skip it.
                continue;
            }

            PacketRef::UserAttribute(u.user_attribute()).serialize(o)?;
            for s in u.self_revocations() {
                serialize_sig(o, s)?;
            }
            for s in u.selfsigs() {
                serialize_sig(o, s)?;
            }
            for s in u.other_revocations() {
                serialize_sig(o, s)?;
            }
            for s in u.certifications() {
                serialize_sig(o, s)?;
            }
        }

        for k in self.subkeys.iter() {
            if export && ! k.selfsigs().iter().chain(k.self_revocations()).any(
                |s| s.exportable_certification().unwrap_or(true))
            {
                // No exportable selfsig on this component, skip it.
                continue;
            }

            PacketRef::PublicSubkey(k.subkey()).serialize(o)?;
            for s in k.self_revocations() {
                serialize_sig(o, s)?;
            }
            for s in k.selfsigs() {
                serialize_sig(o, s)?;
            }
            for s in k.other_revocations() {
                serialize_sig(o, s)?;
            }
            for s in k.certifications() {
                serialize_sig(o, s)?;
            }
        }

        for u in self.unknowns.iter() {
            if export && ! u.certifications().iter().any(
                |s| s.exportable_certification().unwrap_or(true))
            {
                // No exportable selfsig on this component, skip it.
                continue;
            }

            PacketRef::Unknown(u.unknown()).serialize(o)?;

            for s in u.certifications().iter() {
                serialize_sig(o, s)?;
            }
        }

        for s in self.bad.iter() {
            serialize_sig(o, s)?;
        }

        Ok(())
    }
}

impl SerializeInto for TPK {
    fn serialized_len(&self) -> usize {
        let mut l = 0;
        l += PacketRef::PublicKey(self.primary()).serialized_len();

        for s in self.selfsigs() {
            l += PacketRef::Signature(s).serialized_len();
        }
        for s in self.self_revocations() {
            l += PacketRef::Signature(s).serialized_len();
        }
        for s in self.other_revocations() {
            l += PacketRef::Signature(s).serialized_len();
        }
        for s in self.certifications() {
            l += PacketRef::Signature(s).serialized_len();
        }

        for u in self.userids.iter() {
            l += PacketRef::UserID(u.userid()).serialized_len();

            for s in u.self_revocations() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in u.selfsigs() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in u.other_revocations() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in u.certifications() {
                l += PacketRef::Signature(s).serialized_len();
            }
        }

        for u in self.user_attributes.iter() {
            l += PacketRef::UserAttribute(u.user_attribute()).serialized_len();

            for s in u.self_revocations() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in u.selfsigs() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in u.other_revocations() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in u.certifications() {
                l += PacketRef::Signature(s).serialized_len();
            }
        }

        for k in self.subkeys.iter() {
            l += PacketRef::PublicSubkey(k.subkey()).serialized_len();

            for s in k.self_revocations() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in k.selfsigs() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in k.other_revocations() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in k.certifications() {
                l += PacketRef::Signature(s).serialized_len();
            }
        }

        for u in self.unknowns.iter() {
            l += PacketRef::Unknown(u.unknown()).serialized_len();

            for s in u.certifications().iter() {
                l += PacketRef::Signature(s).serialized_len();
            }
        }

        for s in self.bad.iter() {
            l += PacketRef::Signature(s).serialized_len();
        }

        l
    }

    fn serialize_into(&self, buf: &mut [u8]) -> Result<usize> {
        generic_serialize_into(self, buf)
    }

    fn export_into(&self, buf: &mut [u8]) -> Result<usize> {
        generic_export_into(self, buf)
    }
}

impl TPK {
    /// Derive a [`TSK`] object from this key.
    ///
    /// This object writes out secret keys during serialization.
    ///
    /// [`TSK`]: serialize/struct.TSK.html
    pub fn as_tsk<'a>(&'a self) -> TSK<'a> {
        TSK::new(self)
    }
}

/// A reference to a TPK that allows serialization of secret keys.
///
/// To avoid accidental leakage `TPK::serialize()` skips secret keys.
/// To serialize `TPK`s with secret keys, use [`TPK::as_tsk()`] to
/// create a `TSK`, which is a shim on top of the `TPK`, and serialize
/// this.
///
/// [`TPK::as_tsk()`]: ../struct.TPK.html#method.as_tsk
///
/// # Example
/// ```
/// # use sequoia_openpgp::{*, tpk::*, parse::Parse, serialize::Serialize};
/// # f().unwrap();
/// # fn f() -> Result<()> {
/// let (tpk, _) = TPKBuilder::new().generate()?;
/// assert!(tpk.is_tsk());
///
/// let mut buf = Vec::new();
/// tpk.as_tsk().serialize(&mut buf)?;
///
/// let tpk_ = TPK::from_bytes(&buf)?;
/// assert!(tpk_.is_tsk());
/// assert_eq!(tpk, tpk_);
/// # Ok(()) }
pub struct TSK<'a> {
    tpk: &'a TPK,
    filter: Option<Box<'a + Fn(&'a Key) -> bool>>,
}

impl<'a> TSK<'a> {
    /// Creates a new view for the given `TPK`.
    fn new(tpk: &'a TPK) -> Self {
        Self {
            tpk: tpk,
            filter: None,
        }
    }

    /// Filters which secret keys to export using the given predicate.
    ///
    /// Note that the given filter replaces any existing filter.
    ///
    /// # Example
    /// ```
    /// # use sequoia_openpgp::{*, tpk::*, parse::Parse, serialize::Serialize};
    /// # f().unwrap();
    /// # fn f() -> Result<()> {
    /// let (tpk, _) = TPKBuilder::new().add_signing_subkey().generate()?;
    /// assert_eq!(tpk.keys_valid().secret(true).count(), 2);
    ///
    /// // Only write out the primary key's secret.
    /// let mut buf = Vec::new();
    /// tpk.as_tsk().set_filter(|k| k == tpk.primary()).serialize(&mut buf)?;
    ///
    /// let tpk_ = TPK::from_bytes(&buf)?;
    /// assert_eq!(tpk_.keys_valid().secret(true).count(), 1);
    /// assert!(tpk_.primary().secret().is_some());
    /// # Ok(()) }
    pub fn set_filter<P>(mut self, predicate: P) -> Self
        where P: 'a + Fn(&'a Key) -> bool
    {
        self.filter = Some(Box::new(predicate));
        self
    }

    /// Serializes or exports the TPK.
    ///
    /// If `export` is true, then non-exportable signatures are not
    /// written, and components without any exportable binding
    /// signature or revocation are not exported.
    fn serialize_common(&self, o: &mut dyn std::io::Write, export: bool)
                        -> Result<()>
    {
        // Writes a signature if it is exportable or `! export`.
        let serialize_sig =
            |o: &mut dyn std::io::Write, sig: &Signature| -> Result<()>
        {
            if export {
                if sig.exportable_certification().unwrap_or(true) {
                    PacketRef::Signature(sig).export(o)?;
                }
            } else {
                PacketRef::Signature(sig).serialize(o)?;
            }
            Ok(())
        };

        // Serializes public or secret key depending on the filter.
        let serialize_key =
            |o: &mut dyn std::io::Write, key: &'a Key, tag_public, tag_secret|
        {
            let tag = if key.secret().is_some()
                && self.filter.as_ref().map(|f| f(key)).unwrap_or(true) {
                tag_secret
            } else {
                tag_public
            };

            let packet = match tag {
                Tag::PublicKey => PacketRef::PublicKey(key),
                Tag::PublicSubkey => PacketRef::PublicSubkey(key),
                Tag::SecretKey => PacketRef::SecretKey(key),
                Tag::SecretSubkey => PacketRef::SecretSubkey(key),
                _ => unreachable!(),
            };

            packet.serialize(o)
        };
        serialize_key(o, &self.tpk.primary, Tag::PublicKey, Tag::SecretKey)?;

        for s in self.tpk.primary_selfsigs.iter() {
            serialize_sig(o, s)?;
        }
        for s in self.tpk.primary_self_revocations.iter() {
            serialize_sig(o, s)?;
        }
        for s in self.tpk.primary_certifications.iter() {
            serialize_sig(o, s)?;
        }
        for s in self.tpk.primary_other_revocations.iter() {
            serialize_sig(o, s)?;
        }

        for u in self.tpk.userids() {
            if export && ! u.selfsigs().iter().chain(u.self_revocations()).any(
                |s| s.exportable_certification().unwrap_or(true))
            {
                // No exportable selfsig on this component, skip it.
                continue;
            }

            PacketRef::UserID(u.userid()).serialize(o)?;
            for s in u.self_revocations() {
                serialize_sig(o, s)?;
            }
            for s in u.selfsigs() {
                serialize_sig(o, s)?;
            }
            for s in u.other_revocations() {
                serialize_sig(o, s)?;
            }
            for s in u.certifications() {
                serialize_sig(o, s)?;
            }
        }

        for u in self.tpk.user_attributes() {
            if export && ! u.selfsigs().iter().chain(u.self_revocations()).any(
                |s| s.exportable_certification().unwrap_or(true))
            {
                // No exportable selfsig on this component, skip it.
                continue;
            }

            PacketRef::UserAttribute(u.user_attribute()).serialize(o)?;
            for s in u.self_revocations() {
                serialize_sig(o, s)?;
            }
            for s in u.selfsigs() {
                serialize_sig(o, s)?;
            }
            for s in u.other_revocations() {
                serialize_sig(o, s)?;
            }
            for s in u.certifications() {
                serialize_sig(o, s)?;
            }
        }

        for k in self.tpk.subkeys() {
            if export && ! k.selfsigs().iter().chain(k.self_revocations()).any(
                |s| s.exportable_certification().unwrap_or(true))
            {
                // No exportable selfsig on this component, skip it.
                continue;
            }

            serialize_key(o, k.subkey(), Tag::PublicSubkey, Tag::SecretSubkey)?;
            for s in k.self_revocations() {
                serialize_sig(o, s)?;
            }
            for s in k.selfsigs() {
                serialize_sig(o, s)?;
            }
            for s in k.other_revocations() {
                serialize_sig(o, s)?;
            }
            for s in k.certifications() {
                serialize_sig(o, s)?;
            }
        }

        for u in self.tpk.unknowns.iter() {
            if export && ! u.certifications().iter().any(
                |s| s.exportable_certification().unwrap_or(true))
            {
                // No exportable selfsig on this component, skip it.
                continue;
            }

            PacketRef::Unknown(&u.unknown()).serialize(o)?;

            for s in u.certifications().iter() {
                serialize_sig(o, s)?;
            }
        }

        for s in self.tpk.bad.iter() {
            serialize_sig(o, s)?;
        }

        Ok(())
    }
}

impl<'a> Serialize for TSK<'a> {
    fn serialize(&self, o: &mut dyn std::io::Write) -> Result<()> {
        self.serialize_common(o, false)
    }

    fn export(&self, o: &mut dyn std::io::Write) -> Result<()> {
        self.serialize_common(o, true)
    }
}

impl<'a> SerializeInto for TSK<'a> {
    fn serialized_len(&self) -> usize {
        let mut l = 0;

        // Serializes public or secret key depending on the filter.
        let serialized_len_key = |key: &'a Key, tag_public, tag_secret|
        {
            let tag = if key.secret().is_some()
                && self.filter.as_ref().map(|f| f(key)).unwrap_or(true) {
                tag_secret
            } else {
                tag_public
            };

            let packet = match tag {
                Tag::PublicKey => PacketRef::PublicKey(key),
                Tag::PublicSubkey => PacketRef::PublicSubkey(key),
                Tag::SecretKey => PacketRef::SecretKey(key),
                Tag::SecretSubkey => PacketRef::SecretSubkey(key),
                _ => unreachable!(),
            };

            packet.serialized_len()
        };
        l += serialized_len_key(&self.tpk.primary,
                                Tag::PublicKey, Tag::SecretKey);

        for s in self.tpk.selfsigs() {
            l += PacketRef::Signature(s).serialized_len();
        }
        for s in self.tpk.self_revocations() {
            l += PacketRef::Signature(s).serialized_len();
        }
        for s in self.tpk.other_revocations() {
            l += PacketRef::Signature(s).serialized_len();
        }
        for s in self.tpk.certifications() {
            l += PacketRef::Signature(s).serialized_len();
        }

        for u in self.tpk.userids.iter() {
            l += PacketRef::UserID(u.userid()).serialized_len();

            for s in u.self_revocations() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in u.selfsigs() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in u.other_revocations() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in u.certifications() {
                l += PacketRef::Signature(s).serialized_len();
            }
        }

        for u in self.tpk.user_attributes.iter() {
            l += PacketRef::UserAttribute(u.user_attribute()).serialized_len();

            for s in u.self_revocations() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in u.selfsigs() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in u.other_revocations() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in u.certifications() {
                l += PacketRef::Signature(s).serialized_len();
            }
        }

        for k in self.tpk.subkeys.iter() {
            l += serialized_len_key(k.subkey(),
                                    Tag::PublicSubkey, Tag::SecretSubkey);

            for s in k.self_revocations() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in k.selfsigs() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in k.other_revocations() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in k.certifications() {
                l += PacketRef::Signature(s).serialized_len();
            }
        }

        for u in self.tpk.unknowns.iter() {
            l += PacketRef::Unknown(u.unknown()).serialized_len();

            for s in u.certifications().iter() {
                l += PacketRef::Signature(s).serialized_len();
            }
        }

        for s in self.tpk.bad.iter() {
            l += PacketRef::Signature(s).serialized_len();
        }

        l
    }

    fn serialize_into(&self, buf: &mut [u8]) -> Result<usize> {
        generic_serialize_into(self, buf)
    }

    fn export_into(&self, buf: &mut [u8]) -> Result<usize> {
        generic_export_into(self, buf)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::parse::Parse;
    use crate::serialize::Serialize;

    /// Demonstrates that public keys and all components are
    /// serialized.
    #[test]
    fn roundtrip_tpk() {
        for test in crate::tests::TPKS {
            let tpk = match TPK::from_bytes(test.bytes) {
                Ok(t) => t,
                Err(_) => continue,
            };
            assert!(! tpk.is_tsk());
            let buf = tpk.as_tsk().to_vec().unwrap();
            let tpk_ = TPK::from_bytes(&buf).unwrap();

            assert_eq!(tpk, tpk_, "roundtripping {}.pgp failed", test);
        }
    }

    /// Demonstrates that secret keys and all components are
    /// serialized.
    #[test]
    fn roundtrip_tsk() {
        for test in crate::tests::TSKS {
            let tpk = TPK::from_bytes(test.bytes).unwrap();
            assert!(tpk.is_tsk());

            let mut buf = Vec::new();
            tpk.as_tsk().serialize(&mut buf).unwrap();
            let tpk_ = TPK::from_bytes(&buf).unwrap();

            assert_eq!(tpk, tpk_, "roundtripping {}-private.pgp failed", test);

            // This time, use a trivial filter.
            let mut buf = Vec::new();
            tpk.as_tsk().set_filter(|_| true).serialize(&mut buf).unwrap();
            let tpk_ = TPK::from_bytes(&buf).unwrap();

            assert_eq!(tpk, tpk_, "roundtripping {}-private.pgp failed", test);
        }
    }

    /// Demonstrates that TSK::serialize() with the right filter
    /// reduces to TPK::serialize().
    #[test]
    fn reduce_to_tpk_serialize() {
        for test in crate::tests::TSKS {
            let tpk = TPK::from_bytes(test.bytes).unwrap();
            assert!(tpk.is_tsk());

            // First, use TPK::serialize().
            let mut buf_tpk = Vec::new();
            tpk.serialize(&mut buf_tpk).unwrap();

            // When serializing using TSK::serialize, filter out all
            // secret keys.
            let mut buf_tsk = Vec::new();
            tpk.as_tsk().set_filter(|_| false).serialize(&mut buf_tsk).unwrap();

            // Check for equality.
            let tpk_ = TPK::from_bytes(&buf_tpk).unwrap();
            let tsk_ = TPK::from_bytes(&buf_tsk).unwrap();
            assert_eq!(tpk_, tsk_,
                       "reducing failed on {}-private.pgp: not TPK::eq",
                       test);

            // Check for identinty.
            assert_eq!(buf_tpk, buf_tsk,
                       "reducing failed on {}-private.pgp: serialized identity",
                       test);
        }
    }

    #[test]
    fn export() {
        use crate::Packet;
        use crate::tpk::TPKBuilder;
        use crate::constants::{Curve, SignatureType};
        use crate::packet::{
            signature, UserID, user_attribute::{UserAttribute, Subpacket},
            Key, KeyFlags, key::Key4,
        };

        let (tpk, _) = TPKBuilder::new().generate().unwrap();
        let mut keypair = tpk.primary().clone().into_keypair().unwrap();

        let key: Key =
            Key4::generate_ecc(false, Curve::Cv25519).unwrap().into();
        let key_binding = key.bind(
            &mut keypair, &tpk,
            signature::Builder::new(SignatureType::SubkeyBinding)
                .set_key_flags(
                    &KeyFlags::default().set_encrypt_for_transport(true))
                .unwrap()
                .set_exportable_certification(false).unwrap(),
            None, None).unwrap();

        let uid = UserID::from("foo");
        let uid_binding = uid.bind(
            &mut keypair, &tpk,
            signature::Builder::from(
                tpk.primary_key_signature().unwrap().clone())
                .set_type(SignatureType::PositiveCertificate)
                .set_exportable_certification(false).unwrap(),
            None, None).unwrap();

        let ua = UserAttribute::new(&[
            Subpacket::Unknown(2, b"foo".to_vec().into_boxed_slice()),
        ]).unwrap();
        let ua_binding = ua.bind(
            &mut keypair, &tpk,
            signature::Builder::from(
                tpk.primary_key_signature().unwrap().clone())
                .set_type(SignatureType::PositiveCertificate)
                .set_exportable_certification(false).unwrap(),
            None, None).unwrap();

        let tpk = tpk.merge_packets(vec![
            Packet::SecretSubkey(key), key_binding.into(),
            uid.into(), uid_binding.into(),
            ua.into(), ua_binding.into(),
        ]).unwrap();

        assert_eq!(tpk.subkeys().count(), 1);
        assert!(tpk.subkeys().nth(0).unwrap().binding_signature().is_some());
        assert_eq!(tpk.userids().count(), 1);
        assert!(tpk.userids().nth(0).unwrap().binding_signature().is_some());
        assert_eq!(tpk.user_attributes().count(), 1);
        assert!(tpk.user_attributes().nth(0).unwrap().binding_signature()
                .is_some());

        // The binding signature is not exportable, so when we export
        // and re-parse, we expect the userid to be gone.
        let mut buf = Vec::new();
        tpk.export(&mut buf).unwrap();
        let tpk_ = TPK::from_bytes(&buf).unwrap();
        assert_eq!(tpk_.subkeys().count(), 0);
        assert_eq!(tpk_.userids().count(), 0);
        assert_eq!(tpk_.user_attributes().count(), 0);

        let mut buf = vec![0; tpk.serialized_len()];
        let l = tpk.export_into(&mut buf).unwrap();
        buf.truncate(l);
        let tpk_ = TPK::from_bytes(&buf).unwrap();
        assert_eq!(tpk_.subkeys().count(), 0);
        assert_eq!(tpk_.userids().count(), 0);
        assert_eq!(tpk_.user_attributes().count(), 0);

        let tpk_ = TPK::from_bytes(&tpk.export_to_vec().unwrap()).unwrap();
        assert_eq!(tpk_.subkeys().count(), 0);
        assert_eq!(tpk_.userids().count(), 0);
        assert_eq!(tpk_.user_attributes().count(), 0);

        // Same, this time using the armor encoder.
        let mut buf = Vec::new();
        tpk.armored().export(&mut buf).unwrap();
        let tpk_ = TPK::from_bytes(&buf).unwrap();
        assert_eq!(tpk_.subkeys().count(), 0);
        assert_eq!(tpk_.userids().count(), 0);
        assert_eq!(tpk_.user_attributes().count(), 0);

        let mut buf = vec![0; tpk.serialized_len()];
        let l = tpk.armored().export_into(&mut buf).unwrap();
        buf.truncate(l);
        let tpk_ = TPK::from_bytes(&buf).unwrap();
        assert_eq!(tpk_.subkeys().count(), 0);
        assert_eq!(tpk_.userids().count(), 0);
        assert_eq!(tpk_.user_attributes().count(), 0);

        let tpk_ =
            TPK::from_bytes(&tpk.armored().export_to_vec().unwrap()).unwrap();
        assert_eq!(tpk_.subkeys().count(), 0);
        assert_eq!(tpk_.userids().count(), 0);
        assert_eq!(tpk_.user_attributes().count(), 0);

        // Same, this time as TSKs.
        let mut buf = Vec::new();
        tpk.as_tsk().export(&mut buf).unwrap();
        let tpk_ = TPK::from_bytes(&buf).unwrap();
        assert_eq!(tpk_.subkeys().count(), 0);
        assert_eq!(tpk_.userids().count(), 0);
        assert_eq!(tpk_.user_attributes().count(), 0);

        let mut buf = vec![0; tpk.serialized_len()];
        let l = tpk.as_tsk().export_into(&mut buf).unwrap();
        buf.truncate(l);
        let tpk_ = TPK::from_bytes(&buf).unwrap();
        assert_eq!(tpk_.subkeys().count(), 0);
        assert_eq!(tpk_.userids().count(), 0);
        assert_eq!(tpk_.user_attributes().count(), 0);

        let tpk_ =
            TPK::from_bytes(&tpk.as_tsk().export_to_vec().unwrap()).unwrap();
        assert_eq!(tpk_.subkeys().count(), 0);
        assert_eq!(tpk_.userids().count(), 0);
        assert_eq!(tpk_.user_attributes().count(), 0);
    }
}
