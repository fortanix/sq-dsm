use std::ops::Deref;
use std::time;

use crate::{
    HashAlgorithm,
    Result,
    SignatureType,
};
use crate::types::{
    ReasonForRevocation,
};
use crate::crypto::hash::Hash;
use crate::crypto::Signer;
use crate::packet::{
    Key,
    key,
    signature,
    Signature,
    UserAttribute,
    UserID,
};
use crate::cert::Cert;

/// A `Cert` revocation builder.
///
/// Note: a Cert revocation has two degrees of freedom: the Cert, and
/// the key used to generate the revocation.
///
/// Normally, the key used to generate the revocation is the Cert's
/// primary key.  However, this is not required.
///
/// If Alice has marked Robert's key (R) as a designated revoker
/// for her key (A), then R can revoke A or parts of A.  In this
/// case, the Cert is A, and the key used to generate the
/// revocation comes from R.
///
/// # Example
///
/// ```rust
/// # extern crate sequoia_openpgp as openpgp;
/// # use openpgp::Result;
/// use openpgp::RevocationStatus;
/// use openpgp::types::{ReasonForRevocation, SignatureType};
/// use openpgp::cert::{CipherSuite, CertBuilder, CertRevocationBuilder};
/// use openpgp::crypto::KeyPair;
/// use openpgp::parse::Parse;
///
/// # fn main() { f().unwrap(); }
/// # fn f() -> Result<()>
/// # {
/// let (cert, _) = CertBuilder::new()
///     .set_cipher_suite(CipherSuite::Cv25519)
///     .generate()?;
/// assert_eq!(RevocationStatus::NotAsFarAsWeKnow,
///            cert.revoked(None));
///
/// let mut signer = cert.primary().clone()
///     .mark_parts_secret()?.into_keypair()?;
/// let sig = CertRevocationBuilder::new()
///     .set_reason_for_revocation(ReasonForRevocation::KeyCompromised,
///                                b"It was the maid :/")?
///     .build(&mut signer, &cert, None)?;
/// assert_eq!(sig.typ(), SignatureType::KeyRevocation);
///
/// let cert = cert.merge_packets(vec![sig.clone().into()])?;
/// assert_eq!(RevocationStatus::Revoked(vec![&sig]),
///            cert.revoked(None));
/// # Ok(())
/// # }
pub struct CertRevocationBuilder {
    builder: signature::Builder,
}

impl CertRevocationBuilder {
    /// Returns a new `CertRevocationBuilder`.
    pub fn new() -> Self {
        Self {
            builder:
                signature::Builder::new(SignatureType::KeyRevocation)
        }
    }

    /// Sets the reason for revocation.
    pub fn set_reason_for_revocation(self, code: ReasonForRevocation,
                                     reason: &[u8])
        -> Result<Self>
    {
        Ok(Self {
            builder: self.builder.set_reason_for_revocation(code, reason)?
        })
    }

    /// Sets the revocation signature's creation time.
    pub fn set_signature_creation_time(self, creation_time: time::SystemTime)
        -> Result<Self>
    {
        Ok(Self {
            builder: self.builder.set_signature_creation_time(creation_time)?
        })
    }

    /// Returns a revocation certificate for the cert `Cert` signed by
    /// `signer`.
    pub fn build<H>(self, signer: &mut dyn Signer, cert: &Cert, hash_algo: H)
        -> Result<Signature>
        where H: Into<Option<HashAlgorithm>>
    {
        let hash_algo = hash_algo.into().unwrap_or(HashAlgorithm::SHA512);
        let mut hash = hash_algo.context()?;

        cert.primary().hash(&mut hash);

        let creation_time
            = self.signature_creation_time()
            .unwrap_or_else(|| time::SystemTime::now());

        self.builder
            // If not set, set it to now.
            .set_signature_creation_time(creation_time)?
            .set_issuer_fingerprint(signer.public().fingerprint())?
            .set_issuer(signer.public().keyid())?
            .sign_hash(signer, hash)
    }
}

impl Deref for CertRevocationBuilder {
    type Target = signature::Builder;

    fn deref(&self) -> &Self::Target {
        &self.builder
    }
}


/// A `Subkey` revocation builder.
///
/// Note: this function has three degrees of freedom: the Cert, the
/// key used to generate the revocation, and the subkey.
///
/// Normally, the key used to generate the revocation is the Cert's
/// primary key, and the subkey is a subkey that is bound to the
/// Cert.  However, this is not required.
///
/// If Alice has marked Robert's key (R) as a designated revoker
/// for her key (A), then R can revoke A or parts of A.  In this
/// case, the Cert is A, the key used to generate the revocation
/// comes from R, and the User ID is bound to A.
///
/// But, the component doesn't technically need to be bound to the
/// Cert.  For instance, it is possible for R to revoke the User ID
/// "bob@example.org" in the context of A, even if
/// "bob@example.org" is not bound to A.
///
/// # Example
///
/// ```
/// # use sequoia_openpgp::{*, packet::*, types::*, cert::*};
/// # f().unwrap();
/// # fn f() -> Result<()> {
/// // Generate a Cert, and create a keypair from the primary key.
/// let (cert, _) = CertBuilder::new()
///     .add_transport_encryption_subkey()
///     .generate()?;
/// let mut keypair = cert.primary().clone()
///     .mark_parts_secret()?.into_keypair()?;
/// let subkey = cert.keys().subkeys().nth(0).unwrap();
///
/// // Generate the revocation for the first and only Subkey.
/// let revocation =
///     SubkeyRevocationBuilder::new()
///         .set_reason_for_revocation(
///             ReasonForRevocation::KeyRetired,
///             b"Smells funny.").unwrap()
///         .build(&mut keypair, &cert, subkey.key(), None)?;
/// assert_eq!(revocation.typ(), SignatureType::SubkeyRevocation);
///
/// // Now merge the revocation signature into the Cert.
/// let cert = cert.merge_packets(vec![revocation.clone().into()])?;
///
/// // Check that it is revoked.
/// let subkey = cert.keys().subkeys().nth(0).unwrap();
/// if let RevocationStatus::Revoked(revocations) = subkey.revoked(None) {
///     assert_eq!(revocations.len(), 1);
///     assert_eq!(*revocations[0], revocation);
/// } else {
///     panic!("Subkey is not revoked.");
/// }
/// # Ok(()) }
/// ```
pub struct SubkeyRevocationBuilder {
    builder: signature::Builder,
}

impl SubkeyRevocationBuilder {
    /// Returns a new `SubkeyRevocationBuilder`.
    pub fn new() -> Self {
        Self {
            builder:
                signature::Builder::new(SignatureType::SubkeyRevocation)
        }
    }

    /// Sets the reason for revocation.
    pub fn set_reason_for_revocation(self, code: ReasonForRevocation,
                                     reason: &[u8])
        -> Result<Self>
    {
        Ok(Self {
            builder: self.builder.set_reason_for_revocation(code, reason)?
        })
    }

    /// Sets the revocation signature's creation time.
    pub fn set_signature_creation_time(self, creation_time: time::SystemTime)
        -> Result<Self>
    {
        Ok(Self {
            builder: self.builder.set_signature_creation_time(creation_time)?
        })
    }

    /// Returns a revocation certificate for the cert `Cert` signed by
    /// `signer`.
    pub fn build<H, P>(mut self, signer: &mut dyn Signer,
                       cert: &Cert, key: &Key<P, key::SubordinateRole>,
                       hash_algo: H)
        -> Result<Signature>
        where H: Into<Option<HashAlgorithm>>,
              P: key::KeyParts,
    {
        let hash_algo = hash_algo.into().unwrap_or(HashAlgorithm::SHA512);

        if let Some(algo) = hash_algo.into() {
            self.builder = self.builder.set_hash_algo(algo);
        }
        key.bind(signer, cert, self.builder)
    }
}

impl Deref for SubkeyRevocationBuilder {
    type Target = signature::Builder;

    fn deref(&self) -> &Self::Target {
        &self.builder
    }
}

/// A `UserID` revocation builder.
///
/// Note: this function has three degrees of freedom: the Cert, the
/// key used to generate the revocation, and the user id.
///
/// Normally, the key used to generate the revocation is the Cert's
/// primary key, and the user id is a user id that is bound to the
/// Cert.  However, this is not required.
///
/// If Alice has marked Robert's key (R) as a designated revoker
/// for her key (A), then R can revoke A or parts of A.  In this
/// case, the Cert is A, the key used to generate the revocation
/// comes from R, and the User ID is bound to A.
///
/// But, the component doesn't technically need to be bound to the
/// Cert.  For instance, it is possible for R to revoke the User ID
/// "bob@example.org" in the context of A, even if
/// "bob@example.org" is not bound to A.
///
/// # Example
///
/// ```
/// # use sequoia_openpgp::{*, packet::*, types::*, cert::*};
/// # f().unwrap();
/// # fn f() -> Result<()> {
/// // Generate a Cert, and create a keypair from the primary key.
/// let (cert, _) = CertBuilder::new()
///     .add_userid("some@example.org")
///     .generate()?;
/// let mut keypair = cert.primary().clone()
///     .mark_parts_secret()?.into_keypair()?;
/// let userid = cert.userids().nth(0).unwrap();
///
/// // Generate the revocation for the first and only UserID.
/// let revocation =
///     UserIDRevocationBuilder::new()
///         .set_reason_for_revocation(
///             ReasonForRevocation::KeyRetired,
///             b"Left example.org.").unwrap()
///         .build(&mut keypair, &cert, userid, None)?;
/// assert_eq!(revocation.typ(), SignatureType::CertificationRevocation);
///
/// // Now merge the revocation signature into the Cert.
/// let cert = cert.merge_packets(vec![revocation.clone().into()])?;
///
/// // Check that it is revoked.
/// let userid = cert.userids().policy(None).nth(0).unwrap();
/// if let RevocationStatus::Revoked(revocations) = userid.revoked() {
///     assert_eq!(revocations.len(), 1);
///     assert_eq!(*revocations[0], revocation);
/// } else {
///     panic!("UserID is not revoked.");
/// }
/// # Ok(()) }
/// ```
pub struct UserIDRevocationBuilder {
    builder: signature::Builder,
}

impl UserIDRevocationBuilder {
    /// Returns a new `UserIDRevocationBuilder`.
    pub fn new() -> Self {
        Self {
            builder:
                signature::Builder::new(SignatureType::CertificationRevocation)
        }
    }

    /// Sets the reason for revocation.
    pub fn set_reason_for_revocation(self, code: ReasonForRevocation,
                                     reason: &[u8])
        -> Result<Self>
    {
        Ok(Self {
            builder: self.builder.set_reason_for_revocation(code, reason)?
        })
    }

    /// Sets the revocation signature's creation time.
    pub fn set_signature_creation_time(self, creation_time: time::SystemTime)
        -> Result<Self>
    {
        Ok(Self {
            builder: self.builder.set_signature_creation_time(creation_time)?
        })
    }

    /// Returns a revocation certificate for the cert `Cert` signed by
    /// `signer`.
    pub fn build<H>(mut self, signer: &mut dyn Signer,
                    cert: &Cert, userid: &UserID,
                    hash_algo: H)
        -> Result<Signature>
        where H: Into<Option<HashAlgorithm>>
    {
        let hash_algo = hash_algo.into().unwrap_or(HashAlgorithm::SHA512);

        if let Some(algo) = hash_algo.into() {
            self.builder = self.builder.set_hash_algo(algo);
        }
        userid.bind(signer, cert, self.builder)
    }
}

impl Deref for UserIDRevocationBuilder {
    type Target = signature::Builder;

    fn deref(&self) -> &Self::Target {
        &self.builder
    }
}

/// A `UserAttribute` revocation builder.
///
/// Note: this function has three degrees of freedom: the Cert, the
/// key used to generate the revocation, and the user attribute.
///
/// Normally, the key used to generate the revocation is the Cert's
/// primary key, and the user attribute is a user attribute that is
/// bound to the Cert.  However, this is not required.
///
/// If Alice has marked Robert's key (R) as a designated revoker
/// for her key (A), then R can revoke A or parts of A.  In this
/// case, the Cert is A, the key used to generate the revocation
/// comes from R, and the User Attribute is bound to A.
///
/// But, the component doesn't technically need to be bound to the
/// Cert.  For instance, it is possible for R to revoke the User ID
/// "bob@example.org" in the context of A, even if
/// "bob@example.org" is not bound to A.
///
/// # Example
///
/// ```
/// # use sequoia_openpgp::{*, packet::*, types::*, cert::*};
/// # f().unwrap();
/// # fn f() -> Result<()> {
/// # let subpacket
/// #     = user_attribute::Subpacket::Unknown(1, [ 1 ].to_vec().into_boxed_slice());
/// # let some_user_attribute = UserAttribute::new(&[ subpacket ])?;
/// // Generate a Cert, and create a keypair from the primary key.
/// let (cert, _) = CertBuilder::new()
///     .add_user_attribute(some_user_attribute)
///     .generate()?;
/// let mut keypair = cert.primary().clone()
///     .mark_parts_secret()?.into_keypair()?;
/// let ua = cert.user_attributes().nth(0).unwrap();
///
/// // Generate the revocation for the first and only UserAttribute.
/// let revocation =
///     UserAttributeRevocationBuilder::new()
///         .set_reason_for_revocation(
///             ReasonForRevocation::KeyRetired,
///             b"Left example.org.").unwrap()
///         .build(&mut keypair, &cert, ua, None)?;
/// assert_eq!(revocation.typ(), SignatureType::CertificationRevocation);
///
/// // Now merge the revocation signature into the Cert.
/// let cert = cert.merge_packets(vec![revocation.clone().into()])?;
///
/// // Check that it is revoked.
/// let ua = cert.user_attributes().policy(None).nth(0).unwrap();
/// if let RevocationStatus::Revoked(revocations) = ua.revoked() {
///     assert_eq!(revocations.len(), 1);
///     assert_eq!(*revocations[0], revocation);
/// } else {
///     panic!("UserAttribute is not revoked.");
/// }
/// # Ok(()) }
/// ```
pub struct UserAttributeRevocationBuilder {
    builder: signature::Builder,
}

impl UserAttributeRevocationBuilder {
    /// Returns a new `UserAttributeRevocationBuilder`.
    pub fn new() -> Self {
        Self {
            builder:
                signature::Builder::new(SignatureType::CertificationRevocation)
        }
    }

    /// Sets the reason for revocation.
    pub fn set_reason_for_revocation(self, code: ReasonForRevocation,
                                     reason: &[u8])
        -> Result<Self>
    {
        Ok(Self {
            builder: self.builder.set_reason_for_revocation(code, reason)?
        })
    }

    /// Sets the revocation signature's creation time.
    pub fn set_signature_creation_time(self, creation_time: time::SystemTime)
        -> Result<Self>
    {
        Ok(Self {
            builder: self.builder.set_signature_creation_time(creation_time)?
        })
    }

    /// Returns a revocation certificate for the cert `Cert` signed by
    /// `signer`.
    pub fn build<H>(mut self, signer: &mut dyn Signer,
                    cert: &Cert, ua: &UserAttribute,
                    hash_algo: H)
        -> Result<Signature>
        where H: Into<Option<HashAlgorithm>>
    {
        let hash_algo = hash_algo.into().unwrap_or(HashAlgorithm::SHA512);

        if let Some(algo) = hash_algo.into() {
            self.builder = self.builder.set_hash_algo(algo);
        }
        ua.bind(signer, cert, self.builder)
    }
}

impl Deref for UserAttributeRevocationBuilder {
    type Target = signature::Builder;

    fn deref(&self) -> &Self::Target {
        &self.builder
    }
}
