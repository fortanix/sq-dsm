use crate::Error;
use crate::Result;
use crate::TPK;
use crate::constants::{HashAlgorithm, SignatureType};
use crate::crypto::Signer;
use crate::packet::{UserID, UserAttribute, key, Key, signature, Signature};

impl Key<key::PublicParts, key::SubordinateRole> {
    /// Creates a binding signature.
    ///
    /// The signature binds this userid to `tpk`. `signer` will be used
    /// to create a signature using `signature` as builder.
    /// The`hash_algo` defaults to SHA512, `creation_time` to the
    /// current time.
    ///
    /// This function adds a creation time subpacket, a issuer
    /// fingerprint subpacket, and a issuer subpacket to the
    /// signature.
    ///
    /// # Example
    ///
    /// This example demonstrates how to bind this key to a TPK.  Note
    /// that in general, the `TPKBuilder` is a better way to add
    /// subkeys to a TPK.
    ///
    /// ```
    /// # use sequoia_openpgp::{*, packet::prelude::*, constants::*, tpk::*};
    /// # f().unwrap();
    /// # fn f() -> Result<()> {
    /// // Generate a TPK, and create a keypair from the primary key.
    /// let (tpk, _) = TPKBuilder::new().generate()?;
    /// let mut keypair = tpk.primary().clone()
    ///     .mark_parts_secret().into_keypair()?;
    ///
    /// // Let's add an encryption subkey.
    /// let flags = KeyFlags::default().set_encrypt_at_rest(true);
    /// assert_eq!(tpk.keys_valid().key_flags(flags.clone()).count(), 0);
    ///
    /// // Generate a subkey and a binding signature.
    /// let subkey : key::PublicSubkey
    ///     = Key::V4(Key4::generate_ecc(false, Curve::Cv25519)?);
    /// let builder = signature::Builder::new(SignatureType::SubkeyBinding)
    ///     .set_key_flags(&flags)?;
    /// let binding = subkey.bind(&mut keypair, &tpk, builder, None, None)?;
    ///
    /// // Now merge the key and binding signature into the TPK.
    /// let tpk = tpk.merge_packets(vec![subkey.into(),
    ///                                  binding.into()])?;
    ///
    /// // Check that we have an encryption subkey.
    /// assert_eq!(tpk.keys_valid().key_flags(flags).count(), 1);
    /// # Ok(()) }
    pub fn bind<H, T, R>(&self, signer: &mut dyn Signer<R>, tpk: &TPK,
                         signature: signature::Builder,
                         hash_algo: H, creation_time: T)
        -> Result<Signature>
        where H: Into<Option<HashAlgorithm>>,
              T: Into<Option<time::Tm>>,
              R: key::KeyRole
    {
        signature
            .set_signature_creation_time(
                creation_time.into().unwrap_or_else(time::now_utc))?
            .set_issuer_fingerprint(signer.public().fingerprint())?
            .set_issuer(signer.public().keyid())?
            .sign_subkey_binding(
                signer, tpk.primary(), self,
                hash_algo.into().unwrap_or(HashAlgorithm::SHA512))
    }
}

impl UserID {
    /// Creates a binding signature.
    ///
    /// The signature binds this userid to `tpk`. `signer` will be used
    /// to create a signature using `signature` as builder.
    /// The`hash_algo` defaults to SHA512, `creation_time` to the
    /// current time.
    ///
    /// This function adds a creation time subpacket, a issuer
    /// fingerprint subpacket, and a issuer subpacket to the
    /// signature.
    ///
    /// # Example
    ///
    /// This example demonstrates how to bind this userid to a TPK.
    /// Note that in general, the `TPKBuilder` is a better way to add
    /// userids to a TPK.
    ///
    /// ```
    /// # use sequoia_openpgp::{*, packet::prelude::*, constants::*, tpk::*};
    /// # f().unwrap();
    /// # fn f() -> Result<()> {
    /// // Generate a TPK, and create a keypair from the primary key.
    /// let (tpk, _) = TPKBuilder::new().generate()?;
    /// let mut keypair = tpk.primary().clone()
    ///     .mark_parts_secret().into_keypair()?;
    /// assert_eq!(tpk.userids().len(), 0);
    ///
    /// // Generate a userid and a binding signature.
    /// let userid = UserID::from("test@example.org");
    /// let builder =
    ///     signature::Builder::new(SignatureType::PositiveCertificate);
    /// let binding = userid.bind(&mut keypair, &tpk, builder, None, None)?;
    ///
    /// // Now merge the userid and binding signature into the TPK.
    /// let tpk = tpk.merge_packets(vec![userid.into(), binding.into()])?;
    ///
    /// // Check that we have a userid.
    /// assert_eq!(tpk.userids().len(), 1);
    /// # Ok(()) }
    pub fn bind<H, T, R>(&self, signer: &mut dyn Signer<R>, tpk: &TPK,
                      signature: signature::Builder,
                      hash_algo: H, creation_time: T)
                      -> Result<Signature>
        where H: Into<Option<HashAlgorithm>>,
              T: Into<Option<time::Tm>>,
              R: key::KeyRole
    {
        signature
            .set_signature_creation_time(
                creation_time.into().unwrap_or_else(time::now_utc))?
            .set_issuer_fingerprint(signer.public().fingerprint())?
            .set_issuer(signer.public().keyid())?
            .sign_userid_binding(
                signer, tpk.primary(), self,
                hash_algo.into().unwrap_or(HashAlgorithm::SHA512))
    }

    /// Returns a certificate for the user id.
    ///
    /// The signature binds this userid to `tpk`. `signer` will be
    /// used to create a certification signature of type
    /// `signature_type`.  `signature_type` defaults to
    /// `SignatureType::GenericCertificate`, `hash_algo` to SHA512,
    /// `creation_time` to the current time.
    ///
    /// This function adds a creation time subpacket, a issuer
    /// fingerprint subpacket, and a issuer subpacket to the
    /// signature.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidArgument` if `signature_type` is not
    /// one of `SignatureType::{Generic, Persona, Casual,
    /// Positive}Certificate`
    ///
    /// # Example
    ///
    /// This example demonstrates how to certify a userid.
    ///
    /// ```
    /// # use sequoia_openpgp::{*, packet::prelude::*, constants::*, tpk::*};
    /// # f().unwrap();
    /// # fn f() -> Result<()> {
    /// // Generate a TPK, and create a keypair from the primary key.
    /// let (alice, _) = TPKBuilder::new()
    ///     .primary_keyflags(KeyFlags::default().set_certify(true))
    ///     .add_userid("alice@example.org")
    ///     .generate()?;
    /// let mut keypair = alice.primary().clone()
    ///     .mark_parts_secret().into_keypair()?;
    ///
    /// // Generate a TPK for Bob.
    /// let (bob, _) = TPKBuilder::new()
    ///     .primary_keyflags(KeyFlags::default().set_certify(true))
    ///     .add_userid("bob@example.org")
    ///     .generate()?;
    ///
    /// // Alice now certifies the binding between `bob@example.org` and `bob`.
    /// let certificate =
    ///     bob.userids().nth(0).unwrap().userid()
    ///     .certify(&mut keypair, &bob, SignatureType::PositiveCertificate,
    ///              None, None)?;
    ///
    /// // `certificate` can now be used, e.g. by merging it into `bob`.
    /// let bob = bob.merge_packets(vec![certificate.into()])?;
    ///
    /// // Check that we have a certification on the userid.
    /// assert_eq!(bob.userids().nth(0).unwrap().certifications().len(), 1);
    /// # Ok(()) }
    pub fn certify<S, H, T, R>(&self, signer: &mut dyn Signer<R>, tpk: &TPK,
                               signature_type: S,
                               hash_algo: H, creation_time: T)
        -> Result<Signature>
        where S: Into<Option<SignatureType>>,
              H: Into<Option<HashAlgorithm>>,
              T: Into<Option<time::Tm>>,
              R: key::KeyRole
    {
        let typ = signature_type.into();
        let typ = match typ {
            Some(SignatureType::GenericCertificate)
                | Some(SignatureType::PersonaCertificate)
                | Some(SignatureType::CasualCertificate)
                | Some(SignatureType::PositiveCertificate) => typ.unwrap(),
            Some(t) => return Err(Error::InvalidArgument(
                format!("Invalid signature type: {}", t)).into()),
            None => SignatureType::GenericCertificate,
        };
        self.bind(signer, tpk, signature::Builder::new(typ),
                  // Unwrap arguments to prevent further
                  // monomorphization of bind().
                  hash_algo.into().unwrap_or(HashAlgorithm::SHA512),
                  creation_time.into().unwrap_or_else(time::now_utc))
    }
}

impl UserAttribute {
    /// Creates a binding signature.
    ///
    /// The signature binds this user attribute to `tpk`. `signer`
    /// will be used to create a signature using `signature` as
    /// builder.  The`hash_algo` defaults to SHA512, `creation_time`
    /// to the current time.
    ///
    /// This function adds a creation time subpacket, a issuer
    /// fingerprint subpacket, and a issuer subpacket to the
    /// signature.
    ///
    /// # Example
    ///
    /// This example demonstrates how to bind this user attribute to a
    /// TPK.  Note that in general, the `TPKBuilder` is a better way
    /// to add userids to a TPK.
    ///
    /// ```
    /// # use sequoia_openpgp::{*, packet::prelude::*, constants::*, tpk::*,
    ///                         packet::user_attribute::*};
    /// # f().unwrap();
    /// # fn f() -> Result<()> {
    /// // Generate a TPK, and create a keypair from the primary key.
    /// let (tpk, _) = TPKBuilder::new()
    ///     .generate()?;
    /// let mut keypair = tpk.primary().clone()
    ///     .mark_parts_secret().into_keypair()?;
    /// assert_eq!(tpk.userids().len(), 0);
    ///
    /// // Generate a user attribute and a binding signature.
    /// let user_attr = UserAttribute::new(&[
    ///     Subpacket::Image(
    ///         Image::Private(100, vec![0, 1, 2].into_boxed_slice())),
    /// ])?;
    /// let builder =
    ///     signature::Builder::new(SignatureType::PositiveCertificate);
    /// let binding = user_attr.bind(&mut keypair, &tpk, builder, None, None)?;
    ///
    /// // Now merge the user attribute and binding signature into the TPK.
    /// let tpk = tpk.merge_packets(vec![user_attr.into(), binding.into()])?;
    ///
    /// // Check that we have a user attribute.
    /// assert_eq!(tpk.user_attributes().len(), 1);
    /// # Ok(()) }
    pub fn bind<H, T, R>(&self, signer: &mut dyn Signer<R>, tpk: &TPK,
                         signature: signature::Builder,
                         hash_algo: H, creation_time: T)
        -> Result<Signature>
        where H: Into<Option<HashAlgorithm>>,
              T: Into<Option<time::Tm>>,
              R: key::KeyRole
    {
        signature
            .set_signature_creation_time(
                creation_time.into().unwrap_or_else(time::now_utc))?
            .set_issuer_fingerprint(signer.public().fingerprint())?
            .set_issuer(signer.public().keyid())?
            .sign_user_attribute_binding(
                signer, tpk.primary(), self,
                hash_algo.into().unwrap_or(HashAlgorithm::SHA512))
    }

    /// Returns a certificate for the user attribute.
    ///
    /// The signature binds this user attribute to `tpk`. `signer` will be
    /// used to create a certification signature of type
    /// `signature_type`.  `signature_type` defaults to
    /// `SignatureType::GenericCertificate`, `hash_algo` to SHA512,
    /// `creation_time` to the current time.
    ///
    /// This function adds a creation time subpacket, a issuer
    /// fingerprint subpacket, and a issuer subpacket to the
    /// signature.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidArgument` if `signature_type` is not
    /// one of `SignatureType::{Generic, Persona, Casual,
    /// Positive}Certificate`
    ///
    /// # Example
    ///
    /// This example demonstrates how to certify a userid.
    ///
    /// ```
    /// # use sequoia_openpgp::{*, packet::prelude::*, constants::*, tpk::*,
    ///                         packet::user_attribute::*};
    /// # f().unwrap();
    /// # fn f() -> Result<()> {
    /// // Generate a TPK, and create a keypair from the primary key.
    /// let (alice, _) = TPKBuilder::new()
    ///     .add_userid("alice@example.org")
    ///     .generate()?;
    /// let mut keypair = alice.primary().clone()
    ///     .mark_parts_secret().into_keypair()?;
    ///
    /// // Generate a TPK for Bob.
    /// let user_attr = UserAttribute::new(&[
    ///     Subpacket::Image(
    ///         Image::Private(100, vec![0, 1, 2].into_boxed_slice())),
    /// ])?;
    /// let (bob, _) = TPKBuilder::new()
    ///     .primary_keyflags(KeyFlags::default().set_certify(true))
    ///     .add_user_attribute(user_attr)
    ///     .generate()?;
    ///
    /// // Alice now certifies the binding between `bob@example.org` and `bob`.
    /// let certificate =
    ///     bob.user_attributes().nth(0).unwrap().user_attribute()
    ///     .certify(&mut keypair, &bob, SignatureType::PositiveCertificate,
    ///              None, None)?;
    ///
    /// // `certificate` can now be used, e.g. by merging it into `bob`.
    /// let bob = bob.merge_packets(vec![certificate.into()])?;
    ///
    /// // Check that we have a certification on the userid.
    /// assert_eq!(bob.user_attributes().nth(0).unwrap().certifications().len(),
    ///            1);
    /// # Ok(()) }
    pub fn certify<S, H, T, R>(&self, signer: &mut dyn Signer<R>, tpk: &TPK,
                               signature_type: S,
                               hash_algo: H, creation_time: T)
        -> Result<Signature>
        where S: Into<Option<SignatureType>>,
              H: Into<Option<HashAlgorithm>>,
              T: Into<Option<time::Tm>>,
              R: key::KeyRole
    {
        let typ = signature_type.into();
        let typ = match typ {
            Some(SignatureType::GenericCertificate)
                | Some(SignatureType::PersonaCertificate)
                | Some(SignatureType::CasualCertificate)
                | Some(SignatureType::PositiveCertificate) => typ.unwrap(),
            Some(t) => return Err(Error::InvalidArgument(
                format!("Invalid signature type: {}", t)).into()),
            None => SignatureType::GenericCertificate,
        };
        self.bind(signer, tpk, signature::Builder::new(typ),
                  // Unwrap arguments to prevent further
                  // monomorphization of bind().
                  hash_algo.into().unwrap_or(HashAlgorithm::SHA512),
                  creation_time.into().unwrap_or_else(time::now_utc))
    }
}
