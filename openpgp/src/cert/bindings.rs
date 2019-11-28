use std::time;

use crate::Error;
use crate::Result;
use crate::Cert;
use crate::types::{HashAlgorithm, SignatureType};
use crate::conversions::Time;
use crate::crypto::Signer;
use crate::packet::{UserID, UserAttribute, key, Key, signature, Signature};

impl<P: key::KeyParts> Key<P, key::SubordinateRole> {
    /// Creates a binding signature.
    ///
    /// The signature binds this userid to `cert`. `signer` will be used
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
    /// This example demonstrates how to bind this key to a Cert.  Note
    /// that in general, the `CertBuilder` is a better way to add
    /// subkeys to a Cert.
    ///
    /// ```
    /// # use sequoia_openpgp::{*, packet::prelude::*, types::*, cert::*};
    /// # f().unwrap();
    /// # fn f() -> Result<()> {
    /// // Generate a Cert, and create a keypair from the primary key.
    /// let (cert, _) = CertBuilder::new().generate()?;
    /// let mut keypair = cert.primary().clone()
    ///     .mark_parts_secret()?.into_keypair()?;
    ///
    /// // Let's add an encryption subkey.
    /// let flags = KeyFlags::default().set_encrypt_at_rest(true);
    /// assert_eq!(cert.keys_valid().key_flags(flags.clone()).count(), 0);
    ///
    /// // Generate a subkey and a binding signature.
    /// let subkey : key::SecretSubkey
    ///     = Key4::generate_ecc(false, Curve::Cv25519)?.into();
    /// let builder = signature::Builder::new(SignatureType::SubkeyBinding)
    ///     .set_key_flags(&flags)?;
    /// let binding = subkey.bind(&mut keypair, &cert, builder, None)?;
    ///
    /// // Now merge the key and binding signature into the Cert.
    /// let cert = cert.merge_packets(vec![subkey.into(),
    ///                                  binding.into()])?;
    ///
    /// // Check that we have an encryption subkey.
    /// assert_eq!(cert.keys_valid().key_flags(flags).count(), 1);
    /// # Ok(()) }
    pub fn bind<T, R>(&self, signer: &mut dyn Signer<R>, cert: &Cert,
                      signature: signature::Builder,
                      creation_time: T)
        -> Result<Signature>
        where T: Into<Option<time::SystemTime>>,
              R: key::KeyRole
    {
        signature
            .set_signature_creation_time(
                creation_time.into().unwrap_or_else(|| {
                    time::SystemTime::now().canonicalize()
                }))?
            .set_issuer_fingerprint(signer.public().fingerprint())?
            .set_issuer(signer.public().keyid())?
            .sign_subkey_binding(signer, cert.primary(), self)
    }
}

impl UserID {
    /// Creates a binding signature.
    ///
    /// The signature binds this userid to `cert`. `signer` will be used
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
    /// This example demonstrates how to bind this userid to a Cert.
    /// Note that in general, the `CertBuilder` is a better way to add
    /// userids to a Cert.
    ///
    /// ```
    /// # use sequoia_openpgp::{*, packet::prelude::*, types::*, cert::*};
    /// # f().unwrap();
    /// # fn f() -> Result<()> {
    /// // Generate a Cert, and create a keypair from the primary key.
    /// let (cert, _) = CertBuilder::new().generate()?;
    /// let mut keypair = cert.primary().clone()
    ///     .mark_parts_secret()?.into_keypair()?;
    /// assert_eq!(cert.userids().len(), 0);
    ///
    /// // Generate a userid and a binding signature.
    /// let userid = UserID::from("test@example.org");
    /// let builder =
    ///     signature::Builder::new(SignatureType::PositiveCertificate);
    /// let binding = userid.bind(&mut keypair, &cert, builder, None)?;
    ///
    /// // Now merge the userid and binding signature into the Cert.
    /// let cert = cert.merge_packets(vec![userid.into(), binding.into()])?;
    ///
    /// // Check that we have a userid.
    /// assert_eq!(cert.userids().len(), 1);
    /// # Ok(()) }
    pub fn bind<T, R>(&self, signer: &mut dyn Signer<R>, cert: &Cert,
                      signature: signature::Builder,
                      creation_time: T)
                      -> Result<Signature>
        where T: Into<Option<time::SystemTime>>,
              R: key::KeyRole
    {
        signature
            .set_signature_creation_time(
                creation_time.into().unwrap_or_else(|| {
                    time::SystemTime::now().canonicalize()
                }))?
            .set_issuer_fingerprint(signer.public().fingerprint())?
            .set_issuer(signer.public().keyid())?
            .sign_userid_binding(
                signer, cert.primary(), self)
    }

    /// Returns a certificate for the user id.
    ///
    /// The signature binds this userid to `cert`. `signer` will be
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
    /// # use sequoia_openpgp::{*, packet::prelude::*, types::*, cert::*};
    /// # f().unwrap();
    /// # fn f() -> Result<()> {
    /// // Generate a Cert, and create a keypair from the primary key.
    /// let (alice, _) = CertBuilder::new()
    ///     .primary_keyflags(KeyFlags::default().set_certify(true))
    ///     .add_userid("alice@example.org")
    ///     .generate()?;
    /// let mut keypair = alice.primary().clone()
    ///     .mark_parts_secret()?.into_keypair()?;
    ///
    /// // Generate a Cert for Bob.
    /// let (bob, _) = CertBuilder::new()
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
    pub fn certify<S, H, T, R>(&self, signer: &mut dyn Signer<R>, cert: &Cert,
                               signature_type: S,
                               hash_algo: H, creation_time: T)
        -> Result<Signature>
        where S: Into<Option<SignatureType>>,
              H: Into<Option<HashAlgorithm>>,
              T: Into<Option<time::SystemTime>>,
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
        let mut sig = signature::Builder::new(typ);
        if let Some(algo) = hash_algo.into() {
            sig = sig.set_hash_algo(algo);
        }
        self.bind(signer, cert, sig,
                  // Unwrap arguments to prevent further
                  // monomorphization of bind().
                  creation_time.into().unwrap_or_else(|| {
                      time::SystemTime::now().canonicalize()
                  }))
    }
}

impl UserAttribute {
    /// Creates a binding signature.
    ///
    /// The signature binds this user attribute to `cert`. `signer`
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
    /// Cert.  Note that in general, the `CertBuilder` is a better way
    /// to add userids to a Cert.
    ///
    /// ```
    /// # use sequoia_openpgp::{*, packet::prelude::*, types::*, cert::*,
    ///                         packet::user_attribute::*};
    /// # f().unwrap();
    /// # fn f() -> Result<()> {
    /// // Generate a Cert, and create a keypair from the primary key.
    /// let (cert, _) = CertBuilder::new()
    ///     .generate()?;
    /// let mut keypair = cert.primary().clone()
    ///     .mark_parts_secret()?.into_keypair()?;
    /// assert_eq!(cert.userids().len(), 0);
    ///
    /// // Generate a user attribute and a binding signature.
    /// let user_attr = UserAttribute::new(&[
    ///     Subpacket::Image(
    ///         Image::Private(100, vec![0, 1, 2].into_boxed_slice())),
    /// ])?;
    /// let builder =
    ///     signature::Builder::new(SignatureType::PositiveCertificate);
    /// let binding = user_attr.bind(&mut keypair, &cert, builder, None)?;
    ///
    /// // Now merge the user attribute and binding signature into the Cert.
    /// let cert = cert.merge_packets(vec![user_attr.into(), binding.into()])?;
    ///
    /// // Check that we have a user attribute.
    /// assert_eq!(cert.user_attributes().len(), 1);
    /// # Ok(()) }
    pub fn bind<T, R>(&self, signer: &mut dyn Signer<R>, cert: &Cert,
                      signature: signature::Builder,
                      creation_time: T)
        -> Result<Signature>
        where T: Into<Option<time::SystemTime>>,
              R: key::KeyRole
    {
        signature
            .set_signature_creation_time(
                creation_time.into().unwrap_or_else(|| {
                    time::SystemTime::now().canonicalize()
                }))?
            .set_issuer_fingerprint(signer.public().fingerprint())?
            .set_issuer(signer.public().keyid())?
            .sign_user_attribute_binding(signer, cert.primary(), self)
    }

    /// Returns a certificate for the user attribute.
    ///
    /// The signature binds this user attribute to `cert`. `signer` will be
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
    /// # use sequoia_openpgp::{*, packet::prelude::*, types::*, cert::*,
    ///                         packet::user_attribute::*};
    /// # f().unwrap();
    /// # fn f() -> Result<()> {
    /// // Generate a Cert, and create a keypair from the primary key.
    /// let (alice, _) = CertBuilder::new()
    ///     .add_userid("alice@example.org")
    ///     .generate()?;
    /// let mut keypair = alice.primary().clone()
    ///     .mark_parts_secret()?.into_keypair()?;
    ///
    /// // Generate a Cert for Bob.
    /// let user_attr = UserAttribute::new(&[
    ///     Subpacket::Image(
    ///         Image::Private(100, vec![0, 1, 2].into_boxed_slice())),
    /// ])?;
    /// let (bob, _) = CertBuilder::new()
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
    pub fn certify<S, H, T, R>(&self, signer: &mut dyn Signer<R>, cert: &Cert,
                               signature_type: S,
                               hash_algo: H, creation_time: T)
        -> Result<Signature>
        where S: Into<Option<SignatureType>>,
              H: Into<Option<HashAlgorithm>>,
              T: Into<Option<time::SystemTime>>,
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
        let mut sig = signature::Builder::new(typ);
        if let Some(algo) = hash_algo.into() {
            sig = sig.set_hash_algo(algo);
        }
        self.bind(signer, cert, sig,
                  // Unwrap arguments to prevent further
                  // monomorphization of bind().
                  creation_time.into().unwrap_or_else(|| {
                      time::SystemTime::now().canonicalize()
                  }))
    }
}
