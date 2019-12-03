use crate::Result;
use crate::Cert;
use crate::packet::{key, Signature, Tag};
use crate::serialize::{
    PacketRef, Serialize, SerializeInto,
    generic_serialize_into, generic_export_into,
};

impl Serialize for Cert {
    fn serialize(&self, o: &mut dyn std::io::Write) -> Result<()> {
        self.serialize_common(o, false)
    }

    fn export(&self, o: &mut dyn std::io::Write) -> Result<()> {
        self.serialize_common(o, true)
    }
}

impl Cert {
    /// Serializes or exports the Cert.
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

        for s in self.direct_signatures() {
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

        for u in self.userids() {
            if export && ! u.self_signatures().iter().chain(u.self_revocations()).any(
                |s| s.exportable_certification().unwrap_or(true))
            {
                // No exportable selfsig on this component, skip it.
                continue;
            }

            PacketRef::UserID(u.userid()).serialize(o)?;
            for s in u.self_revocations() {
                serialize_sig(o, s)?;
            }
            for s in u.self_signatures() {
                serialize_sig(o, s)?;
            }
            for s in u.other_revocations() {
                serialize_sig(o, s)?;
            }
            for s in u.certifications() {
                serialize_sig(o, s)?;
            }
        }

        for u in self.user_attributes() {
            if export && ! u.self_signatures().iter().chain(u.self_revocations()).any(
                |s| s.exportable_certification().unwrap_or(true))
            {
                // No exportable selfsig on this component, skip it.
                continue;
            }

            PacketRef::UserAttribute(u.user_attribute()).serialize(o)?;
            for s in u.self_revocations() {
                serialize_sig(o, s)?;
            }
            for s in u.self_signatures() {
                serialize_sig(o, s)?;
            }
            for s in u.other_revocations() {
                serialize_sig(o, s)?;
            }
            for s in u.certifications() {
                serialize_sig(o, s)?;
            }
        }

        for k in self.subkeys() {
            if export && ! k.self_signatures().iter().chain(k.self_revocations()).any(
                |s| s.exportable_certification().unwrap_or(true))
            {
                // No exportable selfsig on this component, skip it.
                continue;
            }

            PacketRef::PublicSubkey(k.key()).serialize(o)?;
            for s in k.self_revocations() {
                serialize_sig(o, s)?;
            }
            for s in k.self_signatures() {
                serialize_sig(o, s)?;
            }
            for s in k.other_revocations() {
                serialize_sig(o, s)?;
            }
            for s in k.certifications() {
                serialize_sig(o, s)?;
            }
        }

        for u in self.unknowns() {
            if export && ! u.certifications().iter().any(
                |s| s.exportable_certification().unwrap_or(true))
            {
                // No exportable selfsig on this component, skip it.
                continue;
            }

            PacketRef::Unknown(u.unknown()).serialize(o)?;

            for s in u.self_revocations() {
                serialize_sig(o, s)?;
            }
            for s in u.self_signatures() {
                serialize_sig(o, s)?;
            }
            for s in u.other_revocations() {
                serialize_sig(o, s)?;
            }
            for s in u.certifications() {
                serialize_sig(o, s)?;
            }
        }

        for s in self.bad_signatures() {
            serialize_sig(o, s)?;
        }

        Ok(())
    }
}

impl SerializeInto for Cert {
    fn serialized_len(&self) -> usize {
        let mut l = 0;
        l += PacketRef::PublicKey(self.primary()).serialized_len();

        for s in self.direct_signatures() {
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

        for u in self.userids() {
            l += PacketRef::UserID(u.userid()).serialized_len();

            for s in u.self_revocations() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in u.self_signatures() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in u.other_revocations() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in u.certifications() {
                l += PacketRef::Signature(s).serialized_len();
            }
        }

        for u in self.user_attributes() {
            l += PacketRef::UserAttribute(u.user_attribute()).serialized_len();

            for s in u.self_revocations() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in u.self_signatures() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in u.other_revocations() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in u.certifications() {
                l += PacketRef::Signature(s).serialized_len();
            }
        }

        for k in self.subkeys() {
            l += PacketRef::PublicSubkey(k.key()).serialized_len();

            for s in k.self_revocations() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in k.self_signatures() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in k.other_revocations() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in k.certifications() {
                l += PacketRef::Signature(s).serialized_len();
            }
        }

        for u in self.unknowns() {
            l += PacketRef::Unknown(u.unknown()).serialized_len();

            for s in u.self_revocations() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in u.self_signatures() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in u.other_revocations() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in u.certifications() {
                l += PacketRef::Signature(s).serialized_len();
            }
        }

        for s in self.bad_signatures() {
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

impl Cert {
    /// Derive a [`TSK`] object from this key.
    ///
    /// This object writes out secret keys during serialization.
    ///
    /// [`TSK`]: serialize/struct.TSK.html
    pub fn as_tsk<'a>(&'a self) -> TSK<'a> {
        TSK::new(self)
    }
}

/// A reference to a Cert that allows serialization of secret keys.
///
/// To avoid accidental leakage `Cert::serialize()` skips secret keys.
/// To serialize `Cert`s with secret keys, use [`Cert::as_tsk()`] to
/// create a `TSK`, which is a shim on top of the `Cert`, and serialize
/// this.
///
/// [`Cert::as_tsk()`]: ../struct.Cert.html#method.as_tsk
///
/// # Example
/// ```
/// # use sequoia_openpgp::{*, cert::*, parse::Parse, serialize::Serialize};
/// # f().unwrap();
/// # fn f() -> Result<()> {
/// let (cert, _) = CertBuilder::new().generate()?;
/// assert!(cert.is_tsk());
///
/// let mut buf = Vec::new();
/// cert.as_tsk().serialize(&mut buf)?;
///
/// let cert_ = Cert::from_bytes(&buf)?;
/// assert!(cert_.is_tsk());
/// assert_eq!(cert, cert_);
/// # Ok(()) }
pub struct TSK<'a> {
    cert: &'a Cert,
    filter: Option<Box<dyn Fn(&'a key::UnspecifiedSecret) -> bool + 'a>>,
}

impl<'a> TSK<'a> {
    /// Creates a new view for the given `Cert`.
    fn new(cert: &'a Cert) -> Self {
        Self {
            cert: cert,
            filter: None,
        }
    }

    /// Filters which secret keys to export using the given predicate.
    ///
    /// Note that the given filter replaces any existing filter.
    ///
    /// # Example
    /// ```
    /// # use sequoia_openpgp::{*, cert::*, parse::Parse, serialize::Serialize};
    /// # f().unwrap();
    /// # fn f() -> Result<()> {
    /// let (cert, _) = CertBuilder::new().add_signing_subkey().generate()?;
    /// assert_eq!(cert.keys_valid().secret().count(), 2);
    ///
    /// // Only write out the primary key's secret.
    /// let mut buf = Vec::new();
    /// cert.as_tsk()
    ///     .set_filter(
    ///         |k| k == cert.primary()
    ///                  .mark_parts_secret_ref().unwrap()
    ///                  .mark_role_unspecified_ref())
    ///     .serialize(&mut buf)?;
    ///
    /// let cert_ = Cert::from_bytes(&buf)?;
    /// assert_eq!(cert_.keys_valid().secret().count(), 1);
    /// assert!(cert_.primary().secret().is_some());
    /// # Ok(()) }
    pub fn set_filter<P>(mut self, predicate: P) -> Self
        where P: 'a + Fn(&'a key::UnspecifiedSecret) -> bool
    {
        self.filter = Some(Box::new(predicate));
        self
    }

    /// Serializes or exports the Cert.
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
            |o: &mut dyn std::io::Write, key: &'a key::UnspecifiedSecret,
             tag_public, tag_secret|
        {
            let tag = if key.secret().is_some()
                && self.filter.as_ref().map(|f| f(key)).unwrap_or(true) {
                tag_secret
            } else {
                tag_public
            };

            match tag {
                Tag::PublicKey =>
                    PacketRef::PublicKey(key.into()).serialize(o),
                Tag::PublicSubkey =>
                    PacketRef::PublicSubkey(key.into()).serialize(o),
                Tag::SecretKey =>
                    PacketRef::SecretKey(key.into()).serialize(o),
                Tag::SecretSubkey =>
                    PacketRef::SecretSubkey(key.into()).serialize(o),
                _ => unreachable!(),
            }
        };
        serialize_key(o, self.cert.primary().into(),
                      Tag::PublicKey, Tag::SecretKey)?;

        for s in self.cert.direct_signatures() {
            serialize_sig(o, s)?;
        }
        for s in self.cert.self_revocations() {
            serialize_sig(o, s)?;
        }
        for s in self.cert.certifications() {
            serialize_sig(o, s)?;
        }
        for s in self.cert.other_revocations() {
            serialize_sig(o, s)?;
        }

        for u in self.cert.userids() {
            if export && ! u.self_signatures().iter().chain(u.self_revocations()).any(
                |s| s.exportable_certification().unwrap_or(true))
            {
                // No exportable selfsig on this component, skip it.
                continue;
            }

            PacketRef::UserID(u.userid()).serialize(o)?;
            for s in u.self_revocations() {
                serialize_sig(o, s)?;
            }
            for s in u.self_signatures() {
                serialize_sig(o, s)?;
            }
            for s in u.other_revocations() {
                serialize_sig(o, s)?;
            }
            for s in u.certifications() {
                serialize_sig(o, s)?;
            }
        }

        for u in self.cert.user_attributes() {
            if export && ! u.self_signatures().iter().chain(u.self_revocations()).any(
                |s| s.exportable_certification().unwrap_or(true))
            {
                // No exportable selfsig on this component, skip it.
                continue;
            }

            PacketRef::UserAttribute(u.user_attribute()).serialize(o)?;
            for s in u.self_revocations() {
                serialize_sig(o, s)?;
            }
            for s in u.self_signatures() {
                serialize_sig(o, s)?;
            }
            for s in u.other_revocations() {
                serialize_sig(o, s)?;
            }
            for s in u.certifications() {
                serialize_sig(o, s)?;
            }
        }

        for k in self.cert.subkeys() {
            if export && ! k.self_signatures().iter().chain(k.self_revocations()).any(
                |s| s.exportable_certification().unwrap_or(true))
            {
                // No exportable selfsig on this component, skip it.
                continue;
            }

            serialize_key(o, k.key().into(),
                          Tag::PublicSubkey, Tag::SecretSubkey)?;
            for s in k.self_revocations() {
                serialize_sig(o, s)?;
            }
            for s in k.self_signatures() {
                serialize_sig(o, s)?;
            }
            for s in k.other_revocations() {
                serialize_sig(o, s)?;
            }
            for s in k.certifications() {
                serialize_sig(o, s)?;
            }
        }

        for u in self.cert.unknowns() {
            if export && ! u.certifications().iter().any(
                |s| s.exportable_certification().unwrap_or(true))
            {
                // No exportable selfsig on this component, skip it.
                continue;
            }

            PacketRef::Unknown(&u.unknown()).serialize(o)?;

            for s in u.self_revocations() {
                serialize_sig(o, s)?;
            }
            for s in u.self_signatures() {
                serialize_sig(o, s)?;
            }
            for s in u.other_revocations() {
                serialize_sig(o, s)?;
            }
            for s in u.certifications() {
                serialize_sig(o, s)?;
            }
        }

        for s in self.cert.bad_signatures() {
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
        let serialized_len_key
            = |key: &'a key::UnspecifiedSecret, tag_public, tag_secret|
        {
            let tag = if key.secret().is_some()
                && self.filter.as_ref().map(|f| f(key)).unwrap_or(true) {
                tag_secret
            } else {
                tag_public
            };

            let packet = match tag {
                Tag::PublicKey => PacketRef::PublicKey(key.into()),
                Tag::PublicSubkey => PacketRef::PublicSubkey(key.into()),
                Tag::SecretKey => PacketRef::SecretKey(key.into()),
                Tag::SecretSubkey => PacketRef::SecretSubkey(key.into()),
                _ => unreachable!(),
            };

            packet.serialized_len()
        };
        l += serialized_len_key(self.cert.primary().into(),
                                Tag::PublicKey, Tag::SecretKey);

        for s in self.cert.direct_signatures() {
            l += PacketRef::Signature(s).serialized_len();
        }
        for s in self.cert.self_revocations() {
            l += PacketRef::Signature(s).serialized_len();
        }
        for s in self.cert.other_revocations() {
            l += PacketRef::Signature(s).serialized_len();
        }
        for s in self.cert.certifications() {
            l += PacketRef::Signature(s).serialized_len();
        }

        for u in self.cert.userids() {
            l += PacketRef::UserID(u.userid()).serialized_len();

            for s in u.self_revocations() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in u.self_signatures() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in u.other_revocations() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in u.certifications() {
                l += PacketRef::Signature(s).serialized_len();
            }
        }

        for u in self.cert.user_attributes() {
            l += PacketRef::UserAttribute(u.user_attribute()).serialized_len();

            for s in u.self_revocations() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in u.self_signatures() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in u.other_revocations() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in u.certifications() {
                l += PacketRef::Signature(s).serialized_len();
            }
        }

        for k in self.cert.subkeys() {
            l += serialized_len_key(k.key().into(),
                                    Tag::PublicSubkey, Tag::SecretSubkey);

            for s in k.self_revocations() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in k.self_signatures() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in k.other_revocations() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in k.certifications() {
                l += PacketRef::Signature(s).serialized_len();
            }
        }

        for u in self.cert.unknowns() {
            l += PacketRef::Unknown(u.unknown()).serialized_len();

            for s in u.self_revocations() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in u.self_signatures() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in u.other_revocations() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in u.certifications() {
                l += PacketRef::Signature(s).serialized_len();
            }
        }

        for s in self.cert.bad_signatures() {
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
    use crate::vec_truncate;
    use crate::parse::Parse;
    use crate::serialize::Serialize;
    use crate::packet::key;

    /// Demonstrates that public keys and all components are
    /// serialized.
    #[test]
    fn roundtrip_cert() {
        for test in crate::tests::CERTS {
            let cert = match Cert::from_bytes(test.bytes) {
                Ok(t) => t,
                Err(_) => continue,
            };
            assert!(! cert.is_tsk());
            let buf = cert.as_tsk().to_vec().unwrap();
            let cert_ = Cert::from_bytes(&buf).unwrap();

            assert_eq!(cert, cert_, "roundtripping {}.pgp failed", test);
        }
    }

    /// Demonstrates that secret keys and all components are
    /// serialized.
    #[test]
    fn roundtrip_tsk() {
        for test in crate::tests::TSKS {
            let cert = Cert::from_bytes(test.bytes).unwrap();
            assert!(cert.is_tsk());

            let mut buf = Vec::new();
            cert.as_tsk().serialize(&mut buf).unwrap();
            let cert_ = Cert::from_bytes(&buf).unwrap();

            assert_eq!(cert, cert_, "roundtripping {}-private.pgp failed", test);

            // This time, use a trivial filter.
            let mut buf = Vec::new();
            cert.as_tsk().set_filter(|_| true).serialize(&mut buf).unwrap();
            let cert_ = Cert::from_bytes(&buf).unwrap();

            assert_eq!(cert, cert_, "roundtripping {}-private.pgp failed", test);
        }
    }

    /// Demonstrates that TSK::serialize() with the right filter
    /// reduces to Cert::serialize().
    #[test]
    fn reduce_to_cert_serialize() {
        for test in crate::tests::TSKS {
            let cert = Cert::from_bytes(test.bytes).unwrap();
            assert!(cert.is_tsk());

            // First, use Cert::serialize().
            let mut buf_cert = Vec::new();
            cert.serialize(&mut buf_cert).unwrap();

            // When serializing using TSK::serialize, filter out all
            // secret keys.
            let mut buf_tsk = Vec::new();
            cert.as_tsk().set_filter(|_| false).serialize(&mut buf_tsk).unwrap();

            // Check for equality.
            let cert_ = Cert::from_bytes(&buf_cert).unwrap();
            let tsk_ = Cert::from_bytes(&buf_tsk).unwrap();
            assert_eq!(cert_, tsk_,
                       "reducing failed on {}-private.pgp: not Cert::eq",
                       test);

            // Check for identinty.
            assert_eq!(buf_cert, buf_tsk,
                       "reducing failed on {}-private.pgp: serialized identity",
                       test);
        }
    }

    #[test]
    fn export() {
        use crate::Packet;
        use crate::cert::CertBuilder;
        use crate::types::{Curve, KeyFlags, SignatureType};
        use crate::packet::{
            signature, UserID, user_attribute::{UserAttribute, Subpacket},
            key::Key4,
        };

        let (cert, _) = CertBuilder::new().generate().unwrap();
        let mut keypair = cert.primary().clone().mark_parts_secret()
            .unwrap().into_keypair().unwrap();

        let key: key::SecretSubkey =
            Key4::generate_ecc(false, Curve::Cv25519).unwrap().into();
        let key_binding = key.mark_parts_public_ref().bind(
            &mut keypair, &cert,
            signature::Builder::new(SignatureType::SubkeyBinding)
                .set_key_flags(
                    &KeyFlags::default().set_transport_encryption(true))
                .unwrap()
                .set_exportable_certification(false).unwrap(),
            None).unwrap();

        let uid = UserID::from("foo");
        let uid_binding = uid.bind(
            &mut keypair, &cert,
            signature::Builder::from(
                cert.primary_key_signature(None).unwrap().clone())
                .set_type(SignatureType::PositiveCertificate)
                .set_exportable_certification(false).unwrap(),
            None).unwrap();

        let ua = UserAttribute::new(&[
            Subpacket::Unknown(2, b"foo".to_vec().into_boxed_slice()),
        ]).unwrap();
        let ua_binding = ua.bind(
            &mut keypair, &cert,
            signature::Builder::from(
                cert.primary_key_signature(None).unwrap().clone())
                .set_type(SignatureType::PositiveCertificate)
                .set_exportable_certification(false).unwrap(),
            None).unwrap();

        let cert = cert.merge_packets(vec![
            Packet::SecretSubkey(key), key_binding.into(),
            uid.into(), uid_binding.into(),
            ua.into(), ua_binding.into(),
        ]).unwrap();

        assert_eq!(cert.subkeys().count(), 1);
        assert!(cert.subkeys().nth(0).unwrap().binding_signature(None).is_some());
        assert_eq!(cert.userids().count(), 1);
        assert!(cert.userids().nth(0).unwrap().binding_signature(None).is_some());
        assert_eq!(cert.user_attributes().count(), 1);
        assert!(cert.user_attributes().nth(0).unwrap().binding_signature(None)
                .is_some());

        // The binding signature is not exportable, so when we export
        // and re-parse, we expect the userid to be gone.
        let mut buf = Vec::new();
        cert.export(&mut buf).unwrap();
        let cert_ = Cert::from_bytes(&buf).unwrap();
        assert_eq!(cert_.subkeys().count(), 0);
        assert_eq!(cert_.userids().count(), 0);
        assert_eq!(cert_.user_attributes().count(), 0);

        let mut buf = vec![0; cert.serialized_len()];
        let l = cert.export_into(&mut buf).unwrap();
        vec_truncate(&mut buf, l);
        let cert_ = Cert::from_bytes(&buf).unwrap();
        assert_eq!(cert_.subkeys().count(), 0);
        assert_eq!(cert_.userids().count(), 0);
        assert_eq!(cert_.user_attributes().count(), 0);

        let cert_ = Cert::from_bytes(&cert.export_to_vec().unwrap()).unwrap();
        assert_eq!(cert_.subkeys().count(), 0);
        assert_eq!(cert_.userids().count(), 0);
        assert_eq!(cert_.user_attributes().count(), 0);

        // Same, this time using the armor encoder.
        let mut buf = Vec::new();
        cert.armored().export(&mut buf).unwrap();
        let cert_ = Cert::from_bytes(&buf).unwrap();
        assert_eq!(cert_.subkeys().count(), 0);
        assert_eq!(cert_.userids().count(), 0);
        assert_eq!(cert_.user_attributes().count(), 0);

        let mut buf = vec![0; cert.serialized_len()];
        let l = cert.armored().export_into(&mut buf).unwrap();
        vec_truncate(&mut buf, l);
        let cert_ = Cert::from_bytes(&buf).unwrap();
        assert_eq!(cert_.subkeys().count(), 0);
        assert_eq!(cert_.userids().count(), 0);
        assert_eq!(cert_.user_attributes().count(), 0);

        let cert_ =
            Cert::from_bytes(&cert.armored().export_to_vec().unwrap()).unwrap();
        assert_eq!(cert_.subkeys().count(), 0);
        assert_eq!(cert_.userids().count(), 0);
        assert_eq!(cert_.user_attributes().count(), 0);

        // Same, this time as TSKs.
        let mut buf = Vec::new();
        cert.as_tsk().export(&mut buf).unwrap();
        let cert_ = Cert::from_bytes(&buf).unwrap();
        assert_eq!(cert_.subkeys().count(), 0);
        assert_eq!(cert_.userids().count(), 0);
        assert_eq!(cert_.user_attributes().count(), 0);

        let mut buf = vec![0; cert.serialized_len()];
        let l = cert.as_tsk().export_into(&mut buf).unwrap();
        vec_truncate(&mut buf, l);
        let cert_ = Cert::from_bytes(&buf).unwrap();
        assert_eq!(cert_.subkeys().count(), 0);
        assert_eq!(cert_.userids().count(), 0);
        assert_eq!(cert_.user_attributes().count(), 0);

        let cert_ =
            Cert::from_bytes(&cert.as_tsk().export_to_vec().unwrap()).unwrap();
        assert_eq!(cert_.subkeys().count(), 0);
        assert_eq!(cert_.userids().count(), 0);
        assert_eq!(cert_.user_attributes().count(), 0);
    }
}
