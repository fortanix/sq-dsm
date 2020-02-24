//! A mechanism to specify policy.
//!
//! A major goal of the Sequoia OpenPGP crate is to be policy free.
//! However, many mid-level operations build on low-level primitives.
//! For instance, finding a certificate's primary User ID means
//! examining each of its User IDs and their current self-signature.
//! Some algorithms are considered broken (e.g., MD5) and some are
//! considered weak (e.g. SHA-1).  When dealing with data from an
//! untrusted source, for instance, callers will often prefer to
//! ignore signatures that rely on these algorithms even though [RFC
//! 4880] says that "[i]mplementations MUST implement SHA-1."  When
//! trying to decrypt old archives, however, users probably don't want
//! to ignore keys using MD5, even though [RFC 4880] deprecates MD5.
//!
//! Rather than not provide this mid-level functionality, the `Policy`
//! trait allows callers to specify their prefer policy.  This can be
//! highly customized by providing a custom implementation of the
//! `Policy` trait, or it can be slightly refined by tweaking the
//! `StandardPolicy`'s parameters.
//!
//! When implementing the `Policy` trait, it is *essential* that the
//! functions are [idempotent].  That is, if the same `Policy` is used
//! to determine whether a given `Signature` is valid, it must always
//! return the same value.
//!
//! [RFC 4880]: https://tools.ietf.org/html/rfc4880#section-9.4
//! [pure]: https://en.wikipedia.org/wiki/Pure_function
use std::fmt;
use std::time::{SystemTime, Duration};
use std::u32;

use failure::ResultExt;

use crate::{
    cert::components::ValidKeyAmalgamation,
    Error,
    Packet,
    packet::{
        key,
        Signature,
        signature::subpacket::{
            SubpacketTag,
            SubpacketValue,
        },
        Tag,
    },
    Result,
    types::{
        AEADAlgorithm,
        HashAlgorithm,
        SignatureType,
        SymmetricAlgorithm,
        Timestamp,
    },
};

#[macro_use] mod cutofflist;
use cutofflist::{
    CutoffList,
    REJECT,
    ACCEPT,
};

/// A policy for cryptographic operations.
pub trait Policy : fmt::Debug {
    /// Returns an error if the signature violates the policy.
    ///
    /// This function performs the last check before the library
    /// decides that a signature is valid.  That is, after the library
    /// has determined that the signature is well-formed, alive, not
    /// revoked, etc., it calls this function to allow you to
    /// implement any additional policy.  For instance, you may reject
    /// signatures that make use of cryptographically insecure
    /// algorithms like SHA-1.
    ///
    /// Note: Whereas it is generally better to reject suspicious
    /// signatures, one should be more liberal when considering
    /// revocations: if you reject a revocation certificate, it may
    /// inadvertently make something else valid!
    fn signature(&self, _sig: &Signature) -> Result<()> {
        Ok(())
    }

    /// Returns an error if the key violates the policy.
    ///
    /// This function performs one of the last checks before a
    /// `KeyAmalgamation` or a related data structures is turned into
    /// a `ValidKeyAmalgamation`, or similar.
    ///
    /// Internally, the library always does this before using a key.
    /// The sole exception is when creating a key using `CertBuilder`.
    /// In that case, the primary key is not validated before it is
    /// used to create any binding signatures.
    ///
    /// Thus, you can prevent keys that make use of insecure
    /// algoriths, don't have a sufficiently high security margin
    /// (e.g., 1024-bit RSA keys), are on a bad list, etc. from being
    /// used here.
    fn key(&self, _ka: &ValidKeyAmalgamation<key::PublicParts>)
        -> Result<()>
    {
        Ok(())
    }

    /// Returns an error if the symmetric encryption algorithm
    /// violates the policy.
    ///
    /// This function performs the last check before an encryption
    /// container is decrypted by the streaming decryptor.
    ///
    /// With this function, you can prevent the use of insecure
    /// symmetric encryption algorithms.
    fn symmetric_algorithm(&self, _algo: SymmetricAlgorithm) -> Result<()> {
        Ok(())
    }

    /// Returns an error if the AEAD mode violates the policy.
    ///
    /// This function performs the last check before an encryption
    /// container is decrypted by the streaming decryptor.
    ///
    /// With this function, you can prevent the use of insecure AEAD
    /// constructions.
    fn aead_algorithm(&self, _algo: AEADAlgorithm) -> Result<()> {
        Ok(())
    }

    /// Returns an error if the packet violates the policy.
    ///
    /// This function performs the last check before a packet is
    /// considered by the streaming verifier and decryptor.
    ///
    /// With this function, you can prevent the use of insecure
    /// encryption containers, notably the *Symmetrically Encrypted
    /// Data Packet*.
    fn packet(&self, _packet: &Packet) -> Result<()> {
        Ok(())
    }
}

/// The standard policy.
///
/// The standard policy stores when each algorithm in a family of
/// algorithms is no longer considered safe.  Attempts to use an
/// algorithm after its cutoff time should fail.
///
/// When validating a signature, we normally want to know whether the
/// algorithms used are safe *now*.  That is, we don't use the
/// signature's alleged creation time when considering whether an
/// algorithm is safe, because if an algorithm is discovered to be
/// compromised at time X, then an attacker could forge a message
/// after time X with a signature creation time that is prior to X,
/// which would be incorrectly accepted.
///
/// Occasionally, we know that a signature has not been tampered with
/// since some time in the past.  We might know this if the signature
/// was stored on some tamper-proof medium.  In those cases, it is
/// reasonable to use the time that the signature was saved, since an
/// attacker could not have taken advantage of any weaknesses found
/// after that time.
#[derive(Clone, Debug)]
pub struct StandardPolicy<'a> {
    // The time.  If None, the current time is used.
    time: Option<Timestamp>,

    // Hash algorithms.
    hash_algos_normal: NormalHashCutoffList,
    hash_algos_revocation: RevocationHashCutoffList,

    // Critical subpacket tags.
    critical_subpackets: SubpacketTagCutoffList,

    // Critical notation good-list.
    good_critical_notations: &'a [&'a str],

    // Packet types.
    packet_tags: PacketTagCutoffList,

    // Symmetric algorithms.
    symmetric_algos: SymmetricAlgorithmCutoffList,

    // AEAD algorithms.
    aead_algos: AEADAlgorithmCutoffList,

    // Asymmetric algorithms.
    asymmetric_algos: AsymmetricAlgorithmCutoffList,
}

impl<'a> Default for StandardPolicy<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> From<&'a StandardPolicy<'a>> for Option<&'a dyn Policy> {
    fn from(p: &'a StandardPolicy<'a>) -> Self {
        Some(p as &dyn Policy)
    }
}

a_cutoff_list!(NormalHashCutoffList, HashAlgorithm, 12,
               [
                   REJECT,                 // 0. Not assigned.
                   Some(Timestamp::Y1997), // 1. MD5
                   Some(Timestamp::Y2013), // 2. SHA-1
                   Some(Timestamp::Y2013), // 3. RIPE-MD/160
                   REJECT,                 // 4. Reserved.
                   REJECT,                 // 5. Reserved.
                   REJECT,                 // 6. Reserved.
                   REJECT,                 // 7. Reserved.
                   ACCEPT,                 // 8. SHA256
                   ACCEPT,                 // 9. SHA384
                   ACCEPT,                 // 10. SHA512
                   ACCEPT,                 // 11. SHA224
               ]);
a_cutoff_list!(RevocationHashCutoffList, HashAlgorithm, 12,
               [
                   REJECT,                 // 0. Not assigned.
                   Some(Timestamp::Y2004), // 1. MD5
                   Some(Timestamp::Y2020), // 2. SHA-1
                   Some(Timestamp::Y2020), // 3. RIPE-MD/160
                   REJECT,                 // 4. Reserved.
                   REJECT,                 // 5. Reserved.
                   REJECT,                 // 6. Reserved.
                   REJECT,                 // 7. Reserved.
                   ACCEPT,                 // 8. SHA256
                   ACCEPT,                 // 9. SHA384
                   ACCEPT,                 // 10. SHA512
                   ACCEPT,                 // 11. SHA224
               ]);

a_cutoff_list!(SubpacketTagCutoffList, SubpacketTag, 36,
               [
                   REJECT,                 // 0. Reserved.
                   REJECT,                 // 1. Reserved.
                   ACCEPT,                 // 2. SignatureCreationTime.
                   ACCEPT,                 // 3. SignatureExpirationTime.
                   ACCEPT,                 // 4. ExportableCertification.
                   REJECT,                 // 5. TrustSignature.
                   REJECT,                 // 6. RegularExpression.
                   // Note: Even though we don't explicitly honor the
                   // Revocable flag, we don't support signature
                   // revocations, hence it is safe to ACCEPT it.
                   ACCEPT,                 // 7. Revocable.
                   REJECT,                 // 8. Reserved.
                   ACCEPT,                 // 9. KeyExpirationTime.
                   REJECT,                 // 10. PlaceholderForBackwardCompatibility.
                   ACCEPT,                 // 11. PreferredSymmetricAlgorithms.
                   ACCEPT,                 // 12. RevocationKey.
                   REJECT,                 // 13. Reserved.
                   REJECT,                 // 14. Reserved.
                   REJECT,                 // 15. Reserved.
                   ACCEPT,                 // 16. Issuer.
                   REJECT,                 // 17. Reserved.
                   REJECT,                 // 18. Reserved.
                   REJECT,                 // 19. Reserved.
                   ACCEPT,                 // 20. NotationData.
                   ACCEPT,                 // 21. PreferredHashAlgorithms.
                   ACCEPT,                 // 22. PreferredCompressionAlgorithms.
                   ACCEPT,                 // 23. KeyServerPreferences.
                   ACCEPT,                 // 24. PreferredKeyServer.
                   ACCEPT,                 // 25. PrimaryUserID.
                   ACCEPT,                 // 26. PolicyURI.
                   ACCEPT,                 // 27. KeyFlags.
                   ACCEPT,                 // 28. SignersUserID.
                   ACCEPT,                 // 29. ReasonForRevocation.
                   ACCEPT,                 // 30. Features.
                   REJECT,                 // 31. SignatureTarget.
                   ACCEPT,                 // 32. EmbeddedSignature.
                   ACCEPT,                 // 33. IssuerFingerprint.
                   ACCEPT,                 // 34. PreferredAEADAlgorithms.
                   ACCEPT,                 // 35. IntendedRecipient.
               ]);

a_cutoff_list!(AsymmetricAlgorithmCutoffList, AsymmetricAlgorithm, 18,
               [
                   Some(Timestamp::Y2014), // 0. RSA1024.
                   ACCEPT,                 // 1. RSA2048.
                   ACCEPT,                 // 2. RSA3072.
                   ACCEPT,                 // 3. RSA4096.
                   Some(Timestamp::Y2014), // 4. ElGamal1024.
                   ACCEPT,                 // 5. ElGamal2048.
                   ACCEPT,                 // 6. ElGamal3072.
                   ACCEPT,                 // 7. ElGamal4096.
                   Some(Timestamp::Y2014), // 8. DSA1024.
                   ACCEPT,                 // 9. DSA2048.
                   ACCEPT,                 // 10. DSA3072.
                   ACCEPT,                 // 11. DSA4096.
                   ACCEPT,                 // 12. NistP256.
                   ACCEPT,                 // 13. NistP384.
                   ACCEPT,                 // 14. NistP521.
                   ACCEPT,                 // 15. BrainpoolP256.
                   ACCEPT,                 // 16. BrainpoolP512.
                   ACCEPT,                 // 17. Cv25519.
               ]);

a_cutoff_list!(SymmetricAlgorithmCutoffList, SymmetricAlgorithm, 14,
               [
                   REJECT,                 // 0. Unencrypted.
                   ACCEPT,                 // 1. IDEA.
                   Some(Timestamp::Y2017), // 2. TripleDES.
                   ACCEPT,                 // 3. CAST5.
                   ACCEPT,                 // 4. Blowfish.
                   REJECT,                 // 5. Reserved.
                   REJECT,                 // 6. Reserved.
                   ACCEPT,                 // 7. AES128.
                   ACCEPT,                 // 8. AES192.
                   ACCEPT,                 // 9. AES256.
                   ACCEPT,                 // 10. Twofish.
                   ACCEPT,                 // 11. Camellia128.
                   ACCEPT,                 // 12. Camellia192.
                   ACCEPT,                 // 13. Camellia256.
               ]);

a_cutoff_list!(AEADAlgorithmCutoffList, AEADAlgorithm, 3,
               [
                   REJECT,                 // 0. Reserved.
                   ACCEPT,                 // 1. EAX.
                   ACCEPT,                 // 2. OCB.
               ]);

a_cutoff_list!(PacketTagCutoffList, Tag, 21,
               [
                   REJECT,                 // 0. Reserved.
                   ACCEPT,                 // 1. PKESK.
                   ACCEPT,                 // 2. Signature.
                   ACCEPT,                 // 3. SKESK.
                   ACCEPT,                 // 4. OnePassSig.
                   ACCEPT,                 // 5. SecretKey.
                   ACCEPT,                 // 6. PublicKey.
                   ACCEPT,                 // 7. SecretSubkey.
                   ACCEPT,                 // 8. CompressedData.
                   Some(Timestamp::Y2004), // 9. SED.
                   ACCEPT,                 // 10. Marker.
                   ACCEPT,                 // 11. Literal.
                   ACCEPT,                 // 12. Trust.
                   ACCEPT,                 // 13. UserID.
                   ACCEPT,                 // 14. PublicSubkey.
                   REJECT,                 // 15. Not assigned.
                   REJECT,                 // 16. Not assigned.
                   ACCEPT,                 // 17. UserAttribute.
                   ACCEPT,                 // 18. SEIP.
                   ACCEPT,                 // 19. MDC.
                   ACCEPT,                 // 20. AED.
               ]);

// We need to convert a `SystemTime` to a `Timestamp` in
// `StandardPolicy::reject_hash_at`.  Unfortunately, a `SystemTime`
// can represent a larger range of time than a `Timestamp` can.  Since
// the times passed to this function are cutoff points, and we only
// compare them to OpenPGP timestamps, any `SystemTime` that is prior
// to the Unix Epoch is equivalent to the Unix Epoch: it will reject
// all timestamps.  Similarly, any `SystemTime` that is later than the
// latest time representable by a `Timestamp` is equivalent to
// accepting all time stamps, which is equivalent to passing None.
fn system_time_cutoff_to_timestamp(t: SystemTime) -> Option<Timestamp> {
    let t = t
        .duration_since(SystemTime::UNIX_EPOCH)
        // An error can only occur if the SystemTime is less than the
        // reference time (SystemTime::UNIX_EPOCH).  Map that to
        // SystemTime::UNIX_EPOCH, as above.
        .unwrap_or(Duration::new(0, 0));
    let t = t.as_secs();
    if t > u32::MAX as u64 {
        // Map to None, as above.
        None
    } else {
        Some((t as u32).into())
    }
}

impl<'a> StandardPolicy<'a> {
    /// Instantiates a new `StandardPolicy` with the default parameters.
    pub const fn new() -> Self {
        const EMPTY_LIST: &'static [&'static str] = &[];
        Self {
            time: None,
            hash_algos_normal: NormalHashCutoffList::Default(),
            hash_algos_revocation: RevocationHashCutoffList::Default(),
            critical_subpackets: SubpacketTagCutoffList::Default(),
            good_critical_notations: EMPTY_LIST,
            asymmetric_algos: AsymmetricAlgorithmCutoffList::Default(),
            symmetric_algos: SymmetricAlgorithmCutoffList::Default(),
            aead_algos: AEADAlgorithmCutoffList::Default(),
            packet_tags: PacketTagCutoffList::Default(),
        }
    }

    /// Instantiates a new `StandardPolicy` with parameters
    /// appropriate for `time`.
    ///
    /// `time` is a meta-parameter that selects a security profile
    /// that is appropriate for the given point in time.  When
    /// evaluating an object, the reference time should be set to the
    /// time that the object was stored to non-tamperable storage.
    /// Since most applications don't record when they received an
    /// object, they should conservatively use the current time.
    ///
    /// Note that the reference time is a security parameter and is
    /// different from the time that the object was allegedly created.
    /// Consider evaluating a signature whose `Signature Creation
    /// Time` subpacket indicates that it was created in 2007.  Since
    /// the subpacket is under the control of the sender, setting the
    /// reference time according to the subpacket means that the
    /// sender chooses the security profile.  If the sender were an
    /// attacker, she could have forged this to take advantage of
    /// security weaknesses found since 2007.  This is why the
    /// reference time must be set---at the earliest---to the time
    /// that the message was stored to non-tamperable storage.  When
    /// that is not available, the current time should be used.
    pub fn at(time: SystemTime) -> Self {
        let mut p = Self::new();
        p.time = Some(system_time_cutoff_to_timestamp(time)
                          // Map "ACCEPT" to the end of time (None
                          // here means the current time).
                          .unwrap_or(Timestamp::MAX));
        p
    }

    /// Returns the policy's reference time.
    ///
    /// The current time is None.
    ///
    /// See `StandardPolicy::at` for details.
    pub fn time(&self) -> Option<SystemTime> {
        self.time.map(Into::into)
    }

    /// Always considers `h` to be secure.
    pub fn accept_hash(&mut self, h: HashAlgorithm) {
        self.hash_algos_normal.set(h, ACCEPT);
        self.hash_algos_revocation.set(h, ACCEPT);
    }

    /// Always considers `h` to be insecure.
    pub fn reject_hash(&mut self, h: HashAlgorithm) {
        self.hash_algos_normal.set(h, REJECT);
        self.hash_algos_revocation.set(h, REJECT);
    }

    /// Considers `h` to be insecure starting at `normal` for normal
    /// signatures and at `revocation` for revocation certificates.
    ///
    /// For each algorithm, there are two different cutoffs: when the
    /// algorithm is no longer safe for normal use (e.g., binding
    /// signatures, document signatures), and when the algorithm is no
    /// longer safe for revocations.  Normally, an algorithm should be
    /// allowed for use in a revocation longer than it should be
    /// allowed for normal use, because once we consider a revocation
    /// certificate to be invalid, it may cause something else to be
    /// considered valid!
    ///
    /// A cutoff of `None` means that there is no cutoff and the
    /// algorithm has no known vulnerabilities.
    ///
    /// As a rule of thumb, we want to stop accepting a Hash algorithm
    /// for normal signature when there is evidence that it is broken,
    /// and we want to stop accepting it for revocations shortly
    /// before collisions become practical.
    ///
    /// As such, we start rejecting [MD5] in 1997 and completely
    /// reject it starting in 2004:
    ///
    /// >  In 1996, Dobbertin announced a collision of the
    /// >  compression function of MD5 (Dobbertin, 1996). While this
    /// >  was not an attack on the full MD5 hash function, it was
    /// >  close enough for cryptographers to recommend switching to
    /// >  a replacement, such as SHA-1 or RIPEMD-160.
    /// >
    /// >  MD5CRK ended shortly after 17 August 2004, when collisions
    /// >  for the full MD5 were announced by Xiaoyun Wang, Dengguo
    /// >  Feng, Xuejia Lai, and Hongbo Yu. Their analytical attack
    /// >  was reported to take only one hour on an IBM p690 cluster.
    /// >
    /// > (Accessed Feb. 2020.)
    ///
    /// [MD5]: https://en.wikipedia.org/wiki/MD5
    ///
    /// And we start rejecting [SHA-1] in 2013 and completely reject
    /// it in 2020:
    ///
    /// > Since 2005 SHA-1 has not been considered secure against
    /// > well-funded opponents, as of 2010 many organizations have
    /// > recommended its replacement. NIST formally deprecated use
    /// > of SHA-1 in 2011 and disallowed its use for digital
    /// > signatures in 2013. As of 2020, attacks against SHA-1 are
    /// > as practical as against MD5; as such, it is recommended to
    /// > remove SHA-1 from products as soon as possible and use
    /// > instead SHA-256 or SHA-3. Replacing SHA-1 is urgent where
    /// > it's used for signatures.
    /// >
    /// > (Accessed Feb. 2020.)
    ///
    /// [SHA-1]: https://en.wikipedia.org/wiki/SHA-1
    ///
    /// Since RIPE-MD is structured similarly to SHA-1, we
    /// conservatively consider it to be broken as well.
    pub fn reject_hash_at<N, R>(&mut self, h: HashAlgorithm,
                                normal: N, revocation: R)
        where N: Into<Option<SystemTime>>,
              R: Into<Option<SystemTime>>,
    {
        self.hash_algos_normal.set(
            h,
            normal.into().and_then(system_time_cutoff_to_timestamp));
        self.hash_algos_revocation.set(
            h,
            revocation.into().and_then(system_time_cutoff_to_timestamp));
    }

    /// Returns the cutoff times for the specified hash algorithm.
    pub fn hash_cutoffs(&self, h: HashAlgorithm)
        -> (Option<SystemTime>, Option<SystemTime>)
    {
        (self.hash_algos_normal.cutoff(h).map(|t| t.into()),
         self.hash_algos_revocation.cutoff(h).map(|t| t.into()))
    }

    /// Always considers `s` to be secure.
    pub fn accept_critical_subpacket(&mut self, s: SubpacketTag) {
        self.critical_subpackets.set(s, ACCEPT);
    }

    /// Always considers `s` to be insecure.
    pub fn reject_critical_subpacket(&mut self, s: SubpacketTag) {
        self.critical_subpackets.set(s, REJECT);
    }

    /// Considers `s` to be insecure starting at `cutoff`.
    ///
    /// A cutoff of `None` means that there is no cutoff and the
    /// subpacket has no known vulnerabilities.
    ///
    /// By default, we accept all critical subpackets that Sequoia
    /// understands and honors.
    pub fn reject_critical_subpacket_at<C>(&mut self, s: SubpacketTag,
                                       cutoff: C)
        where C: Into<Option<SystemTime>>,
    {
        self.critical_subpackets.set(
            s,
            cutoff.into().and_then(system_time_cutoff_to_timestamp));
    }

    /// Returns the cutoff times for the specified subpacket tag.
    pub fn critical_subpacket_cutoff(&self, s: SubpacketTag)
                                 -> Option<SystemTime> {
        self.critical_subpackets.cutoff(s).map(|t| t.into())
    }

    /// Sets the list of accepted critical notations.
    ///
    /// By default, we reject all critical notations.
    pub fn good_critical_notations(&mut self, good_list: &'a [&'a str]) {
        self.good_critical_notations = good_list;
    }

    /// Always considers `s` to be secure.
    pub fn accept_asymmetric_algo(&mut self, a: AsymmetricAlgorithm) {
        self.asymmetric_algos.set(a, ACCEPT);
    }

    /// Always considers `s` to be insecure.
    pub fn reject_asymmetric_algo(&mut self, a: AsymmetricAlgorithm) {
        self.asymmetric_algos.set(a, REJECT);
    }

    /// Considers `a` to be insecure starting at `cutoff`.
    ///
    /// A cutoff of `None` means that there is no cutoff and the
    /// algorithm has no known vulnerabilities.
    ///
    /// By default, we reject the use of asymmetric key sizes lower
    /// than 2048 bits starting in 2014 following [NIST Special
    /// Publication 800-131A].
    ///
    ///   [NIST Special Publication 800-131A]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf
    pub fn reject_asymmetric_algo_at<C>(&mut self, a: AsymmetricAlgorithm,
                                       cutoff: C)
        where C: Into<Option<SystemTime>>,
    {
        self.asymmetric_algos.set(
            a,
            cutoff.into().and_then(system_time_cutoff_to_timestamp));
    }

    /// Returns the cutoff times for the specified hash algorithm.
    pub fn asymmetric_algo_cutoff(&self, a: AsymmetricAlgorithm)
                                 -> Option<SystemTime> {
        self.asymmetric_algos.cutoff(a).map(|t| t.into())
    }

    /// Always considers `s` to be secure.
    pub fn accept_symmetric_algo(&mut self, s: SymmetricAlgorithm) {
        self.symmetric_algos.set(s, ACCEPT);
    }

    /// Always considers `s` to be insecure.
    pub fn reject_symmetric_algo(&mut self, s: SymmetricAlgorithm) {
        self.symmetric_algos.set(s, REJECT);
    }

    /// Considers `s` to be insecure starting at `cutoff`.
    ///
    /// A cutoff of `None` means that there is no cutoff and the
    /// algorithm has no known vulnerabilities.
    ///
    /// By default, we reject the use of TripleDES (3DES) starting in
    /// the year 2017.  While 3DES is still a ["MUST implement"]
    /// algorithm in RFC4880, released in 2007, there are plenty of
    /// other symmetric algorithms defined in RFC4880, and it says
    /// AES-128 SHOULD be implemented.  Support for other algorithms
    /// in OpenPGP implementations is [excellent].  We chose 2017 as
    /// the cutoff year because [NIST deprecated 3DES] that year.
    ///
    ///   ["MUST implement"]: https://tools.ietf.org/html/rfc4880#section-9.2
    ///   [excellent]: https://tests.sequoia-pgp.org/#Symmetric_Encryption_Algorithm_support
    ///   [NIST deprecated 3DES]: https://csrc.nist.gov/News/2017/Update-to-Current-Use-and-Deprecation-of-TDEA
    pub fn reject_symmetric_algo_at<C>(&mut self, s: SymmetricAlgorithm,
                                       cutoff: C)
        where C: Into<Option<SystemTime>>,
    {
        self.symmetric_algos.set(
            s,
            cutoff.into().and_then(system_time_cutoff_to_timestamp));
    }

    /// Returns the cutoff times for the specified hash algorithm.
    pub fn symmetric_algo_cutoff(&self, s: SymmetricAlgorithm)
                                 -> Option<SystemTime> {
        self.symmetric_algos.cutoff(s).map(|t| t.into())
    }

    /// Always considers `s` to be secure.
    pub fn accept_aead_algo(&mut self, a: AEADAlgorithm) {
        self.aead_algos.set(a, ACCEPT);
    }

    /// Always considers `s` to be insecure.
    pub fn reject_aead_algo(&mut self, a: AEADAlgorithm) {
        self.aead_algos.set(a, REJECT);
    }

    /// Considers `a` to be insecure starting at `cutoff`.
    ///
    /// A cutoff of `None` means that there is no cutoff and the
    /// algorithm has no known vulnerabilities.
    ///
    /// By default, we accept all AEAD modes.
    pub fn reject_aead_algo_at<C>(&mut self, a: AEADAlgorithm,
                                       cutoff: C)
        where C: Into<Option<SystemTime>>,
    {
        self.aead_algos.set(
            a,
            cutoff.into().and_then(system_time_cutoff_to_timestamp));
    }

    /// Returns the cutoff times for the specified hash algorithm.
    pub fn aead_algo_cutoff(&self, a: AEADAlgorithm)
                                 -> Option<SystemTime> {
        self.aead_algos.cutoff(a).map(|t| t.into())
    }

    /// Always accept packets with the given tag.
    pub fn accept_packet_tag(&mut self, tag: Tag) {
        self.packet_tags.set(tag, ACCEPT);
    }

    /// Always reject packets with the given tag.
    pub fn reject_packet_tag(&mut self, tag: Tag) {
        self.packet_tags.set(tag, REJECT);
    }

    /// Start rejecting packets with the given tag at `t`.
    ///
    /// A cutoff of `None` means that there is no cutoff and the
    /// packet has no known vulnerabilities.
    ///
    /// By default, we consider the *Symmetrically Encrypted Data
    /// Packet* (SED) insecure in messages created in the year 2004 or
    /// later.  The rationale here is that *Symmetrically Encrypted
    /// Integrity Protected Data Packet* (SEIP) can be downgraded to
    /// SED packets, enabling attacks exploiting the malleability of
    /// the CFB stream (see [EFAIL]).
    ///
    ///   [EFAIL]: https://en.wikipedia.org/wiki/EFAIL
    ///
    /// We chose 2004 as a cutoff-date because [Debian 3.0] (Woody),
    /// released on 2002-07-19, was the first release of Debian to
    /// ship a version of GnuPG that emitted SEIP packets by default.
    /// The first version that emitted SEIP packets was [GnuPG 1.0.3],
    /// released on 2000-09-18.  Mid 2002 plus a 18 months grace
    /// period of people still using older versions is 2004.
    ///
    ///   [Debian 3.0]: https://www.debian.org/News/2002/20020719
    ///   [GnuPG 1.0.3]: https://lists.gnupg.org/pipermail/gnupg-announce/2000q3/000075.html
    pub fn reject_packet_tag_at<C>(&mut self, tag: Tag, cutoff: C)
        where C: Into<Option<SystemTime>>,
    {
        self.packet_tags.set(
            tag,
            cutoff.into().and_then(system_time_cutoff_to_timestamp));
    }

    /// Returns the cutoff times for the specified hash algorithm.
    pub fn packet_tag_cutoff(&self, tag: Tag) -> Option<SystemTime> {
        self.packet_tags.cutoff(tag).map(|t| t.into())
    }
}

impl<'a> Policy for StandardPolicy<'a> {
    fn signature(&self, sig: &Signature) -> Result<()> {
        let time = self.time.unwrap_or_else(Timestamp::now);

        match sig.typ() {
            t @ SignatureType::KeyRevocation
                | t @ SignatureType::SubkeyRevocation
                | t @ SignatureType::CertificationRevocation =>
            {
                self.hash_algos_revocation.check(sig.hash_algo(), time)
                    .context(format!("revocation signature ({})", t))?
            }
            t =>
            {
                self.hash_algos_normal.check(sig.hash_algo(), time)
                    .context(format!("non-revocation signature ({})", t))?
            }
        }

        for csp in sig.hashed_area().iter().filter(|sp| sp.critical()) {
            self.critical_subpackets.check(csp.tag(), time)?;
            if let SubpacketValue::NotationData(n) = csp.value() {
                if ! self.good_critical_notations.contains(&n.name()) {
                    return Err(Error::PolicyViolation(
                        format!("Critical notation {:?} rejected",
                                n.name()), None).into());
                }
            }
        }

        Ok(())
    }

    fn key(&self, ka: &ValidKeyAmalgamation<key::PublicParts>)
        -> Result<()>
    {
        use self::AsymmetricAlgorithm::{*, Unknown};
        use crate::types::PublicKeyAlgorithm::*;
        use crate::crypto::mpis::PublicKey;

        #[allow(deprecated)]
        let a = match (ka.pk_algo(), ka.mpis().bits()) {
            // RSA.
            (RSAEncryptSign, Some(b))
                | (RSAEncrypt, Some(b))
                | (RSASign, Some(b)) if b < 2048 => RSA1024,
            (RSAEncryptSign, Some(b))
                | (RSAEncrypt, Some(b))
                | (RSASign, Some(b)) if b < 3072 => RSA2048,
            (RSAEncryptSign, Some(b))
                | (RSAEncrypt, Some(b))
                | (RSASign, Some(b)) if b < 4096 => RSA3072,
            (RSAEncryptSign, Some(_))
                | (RSAEncrypt, Some(_))
                | (RSASign, Some(_)) => RSA4096,
            (RSAEncryptSign, None)
                | (RSAEncrypt, None)
                | (RSASign, None) => unreachable!(),

            // ElGamal.
            (ElGamalEncryptSign, Some(b))
                | (ElGamalEncrypt, Some(b)) if b < 2048 => ElGamal1024,
            (ElGamalEncryptSign, Some(b))
                | (ElGamalEncrypt, Some(b)) if b < 3072 => ElGamal2048,
            (ElGamalEncryptSign, Some(b))
                | (ElGamalEncrypt, Some(b)) if b < 4096 => ElGamal3072,
            (ElGamalEncryptSign, Some(_))
                | (ElGamalEncrypt, Some(_)) => ElGamal4096,
            (ElGamalEncryptSign, None)
                | (ElGamalEncrypt, None) => unreachable!(),

            // DSA.
            (DSA, Some(b)) if b < 2048 => DSA1024,
            (DSA, Some(b)) if b < 3072 => DSA2048,
            (DSA, Some(b)) if b < 4096 => DSA3072,
            (DSA, Some(_)) => DSA4096,
            (DSA, None) => unreachable!(),

            // ECC.
            (ECDH, _) | (ECDSA, _) | (EdDSA, _) => {
                let curve = match ka.mpis() {
                    PublicKey::EdDSA { curve, .. } => curve,
                    PublicKey::ECDSA { curve, .. } => curve,
                    PublicKey::ECDH { curve, .. } => curve,
                    _ => unreachable!(),
                };
                use crate::types::Curve;
                match curve {
                    Curve::NistP256 => NistP256,
                    Curve::NistP384 => NistP384,
                    Curve::NistP521 => NistP521,
                    Curve::BrainpoolP256 => BrainpoolP256,
                    Curve::BrainpoolP512 => BrainpoolP512,
                    Curve::Ed25519 => Cv25519,
                    Curve::Cv25519 => Cv25519,
                    Curve::Unknown(_) => Unknown,
                    Curve::__Nonexhaustive => unreachable!(),
                }
            },

            _ => Unknown,
        };

        let time = self.time.unwrap_or_else(Timestamp::now);
        self.asymmetric_algos.check(a, time)
    }

    fn packet(&self, packet: &Packet) -> Result<()> {
        let time = self.time.unwrap_or_else(Timestamp::now);
        self.packet_tags.check(packet.tag(), time)
    }

    fn symmetric_algorithm(&self, algo: SymmetricAlgorithm) -> Result<()> {
        let time = self.time.unwrap_or_else(Timestamp::now);
        self.symmetric_algos.check(algo, time)
    }

    fn aead_algorithm(&self, algo: AEADAlgorithm) -> Result<()> {
        let time = self.time.unwrap_or_else(Timestamp::now);
        self.aead_algos.check(algo, time)
    }
}

/// Asymmetric encryption algorithms.
///
/// This type is for refining the [`StandardPolicy`] with respect to
/// asymmetric algorithms.  In contrast to [`PublicKeyAlgorithm`], it
/// does not concern itself with the use (encryption or signing), and
/// it does include key sizes (if applicable) and elliptic curves.
///
///   [`StandardPolicy`]: struct.StandardPolicy.html
///   [`PublicKeyAlgorithm`]: ../types/enum.PublicKeyAlgorithm.html
///
/// Key sizes put into are buckets, rounding down to the nearest
/// bucket.  For example, a 3253-bit RSA key is categorized as
/// `RSA3072`.
#[derive(Clone, Debug)]
pub enum AsymmetricAlgorithm {
    /// RSA with key sizes up to 2048-1 bit.
    RSA1024,
    /// RSA with key sizes up to 3072-1 bit.
    RSA2048,
    /// RSA with key sizes up to 4096-1 bit.
    RSA3072,
    /// RSA with key sizes larger or equal to 4096 bit.
    RSA4096,
    /// ElGamal with key sizes up to 2048-1 bit.
    ElGamal1024,
    /// ElGamal with key sizes up to 3072-1 bit.
    ElGamal2048,
    /// ElGamal with key sizes up to 4096-1 bit.
    ElGamal3072,
    /// ElGamal with key sizes larger or equal to 4096 bit.
    ElGamal4096,
    /// DSA with key sizes up to 2048-1 bit.
    DSA1024,
    /// DSA with key sizes up to 3072-1 bit.
    DSA2048,
    /// DSA with key sizes up to 4096-1 bit.
    DSA3072,
    /// DSA with key sizes larger or equal to 4096 bit.
    DSA4096,
    /// NIST curve P-256.
    NistP256,
    /// NIST curve P-384.
    NistP384,
    /// NIST curve P-521.
    NistP521,
    /// brainpoolP256r1.
    BrainpoolP256,
    /// brainpoolP512r1.
    BrainpoolP512,
    /// D.J. Bernstein's Curve25519.
    Cv25519,
    /// Unknown algorithm.
    Unknown,

    /// This marks this enum as non-exhaustive.  Do not use this
    /// variant.
    #[doc(hidden)] __Nonexhaustive,
}

impl std::fmt::Display for AsymmetricAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<AsymmetricAlgorithm> for u8 {
    fn from(a: AsymmetricAlgorithm) -> Self {
        use self::AsymmetricAlgorithm::*;
        match a {
            RSA1024 => 0,
            RSA2048 => 1,
            RSA3072 => 2,
            RSA4096 => 3,
            ElGamal1024 => 4,
            ElGamal2048 => 5,
            ElGamal3072 => 6,
            ElGamal4096 => 7,
            DSA1024 => 8,
            DSA2048 => 9,
            DSA3072 => 10,
            DSA4096 => 11,
            NistP256 => 12,
            NistP384 => 13,
            NistP521 => 14,
            BrainpoolP256 => 15,
            BrainpoolP512 => 16,
            Cv25519 => 17,
            Unknown => 255,
            __Nonexhaustive => unreachable!(),
        }
    }
}

#[cfg(test)]
mod test {
    use std::io::Read;
    use std::time::Duration;

    use super::*;
    use crate::Error;
    use crate::Fingerprint;
    use crate::cert::{Cert, CertBuilder, CipherSuite};
    use crate::cert::components::Amalgamation;
    use crate::crypto::SessionKey;
    use crate::packet::key::Key4;
    use crate::packet::signature;
    use crate::packet::{PKESK, SKESK};
    use crate::parse::Parse;
    use crate::parse::stream::DecryptionHelper;
    use crate::parse::stream::Decryptor;
    use crate::parse::stream::DetachedVerifier;
    use crate::parse::stream::MessageLayer;
    use crate::parse::stream::MessageStructure;
    use crate::parse::stream::VerificationHelper;
    use crate::parse::stream::Verifier;
    use crate::policy::StandardPolicy as P;
    use crate::types::Curve;
    use crate::types::KeyFlags;
    use crate::types::SymmetricAlgorithm;

    // Test that the constructor is const.
    const _A_STANDARD_POLICY: StandardPolicy = StandardPolicy::new();

    #[test]
    fn binding_signature() {
        let p = &P::new();

        // A primary and two subkeys.
        let (cert, _) = CertBuilder::new()
            .add_signing_subkey()
            .add_transport_encryption_subkey()
            .generate().unwrap();

        assert_eq!(cert.keys().with_policy(p, None).count(), 3);

        // Reject all direct key signatures.
        #[derive(Debug)]
        struct NoDirectKeySigs;
        impl Policy for NoDirectKeySigs {
            fn signature(&self, sig: &Signature) -> Result<()> {
                use crate::types::SignatureType::*;

                match sig.typ() {
                    DirectKey => Err(format_err!("direct key!")),
                    _ => Ok(()),
                }
            }
        }

        let p = &NoDirectKeySigs {};
        assert_eq!(cert.keys().with_policy(p, None).count(), 0);

        // Reject all subkey signatures.
        #[derive(Debug)]
        struct NoSubkeySigs;
        impl Policy for NoSubkeySigs {
            fn signature(&self, sig: &Signature) -> Result<()> {
                use crate::types::SignatureType::*;

                match sig.typ() {
                    SubkeyBinding => Err(format_err!("subkey signature!")),
                    _ => Ok(()),
                }
            }
        }

        let p = &NoSubkeySigs {};
        assert_eq!(cert.keys().with_policy(p, None).count(), 1);
    }

    #[test]
    fn revocation() -> Result<()> {
        use crate::cert::UserIDRevocationBuilder;
        use crate::cert::SubkeyRevocationBuilder;
        use crate::types::SignatureType;
        use crate::types::ReasonForRevocation;

        let p = &P::new();

        // A primary and two subkeys.
        let (cert, _) = CertBuilder::new()
            .add_userid("Alice")
            .add_signing_subkey()
            .add_transport_encryption_subkey()
            .generate()?;

        // Make sure we have all keys and all user ids.
        assert_eq!(cert.keys().with_policy(p, None).count(), 3);
        assert_eq!(cert.userids().with_policy(p, None).count(), 1);

        // Reject all user id signatures.
        #[derive(Debug)]
        struct NoPositiveCertifications;
        impl Policy for NoPositiveCertifications {
            fn signature(&self, sig: &Signature) -> Result<()> {
                use crate::types::SignatureType::*;
                match sig.typ() {
                    PositiveCertification =>
                        Err(format_err!("positive certification!")),
                    _ => Ok(()),
                }
            }
        }
        let p = &NoPositiveCertifications {};
        assert_eq!(cert.userids().with_policy(p, None).count(), 0);


        // Revoke it.
        let mut keypair = cert.primary_key().key().clone()
            .mark_parts_secret()?.into_keypair()?;
        let ca = cert.userids().nth(0).unwrap();

        // Generate the revocation for the first and only UserID.
        let revocation =
            UserIDRevocationBuilder::new()
            .set_reason_for_revocation(
                ReasonForRevocation::KeyRetired,
                b"Left example.org.")?
            .build(&mut keypair, &cert, ca.userid(), None)?;
        assert_eq!(revocation.typ(), SignatureType::CertificationRevocation);

        // Now merge the revocation signature into the Cert.
        let cert = cert.merge_packets(vec![revocation.clone().into()])?;

        // Check that it is revoked.
        assert_eq!(cert.userids().with_policy(p, None).revoked(false).count(), 0);

        // Reject all user id signatures.
        #[derive(Debug)]
        struct NoCertificationRevocation;
        impl Policy for NoCertificationRevocation {
            fn signature(&self, sig: &Signature) -> Result<()> {
                use crate::types::SignatureType::*;
                match sig.typ() {
                    CertificationRevocation =>
                        Err(format_err!("certification certification!")),
                    _ => Ok(()),
                }
            }
        }
        let p = &NoCertificationRevocation {};

        // Check that the user id is no longer revoked.
        assert_eq!(cert.userids().with_policy(p, None).revoked(false).count(), 1);


        // Generate the revocation for the first subkey.
        let subkey = cert.keys().subkeys().nth(0).unwrap();
        let revocation =
            SubkeyRevocationBuilder::new()
                .set_reason_for_revocation(
                    ReasonForRevocation::KeyRetired,
                    b"Smells funny.").unwrap()
                .build(&mut keypair, &cert, subkey.key(), None)?;
        assert_eq!(revocation.typ(), SignatureType::SubkeyRevocation);

        // Now merge the revocation signature into the Cert.
        assert_eq!(cert.keys().with_policy(p, None).revoked(false).count(), 3);
        let cert = cert.merge_packets(vec![revocation.clone().into()])?;
        assert_eq!(cert.keys().with_policy(p, None).revoked(false).count(), 2);

        // Reject all subkey revocations.
        #[derive(Debug)]
        struct NoSubkeyRevocation;
        impl Policy for NoSubkeyRevocation {
            fn signature(&self, sig: &Signature) -> Result<()> {
                use crate::types::SignatureType::*;
                match sig.typ() {
                    SubkeyRevocation =>
                        Err(format_err!("subkey revocation!")),
                    _ => Ok(()),
                }
            }
        }
        let p = &NoSubkeyRevocation {};

        // Check that the key is no longer revoked.
        assert_eq!(cert.keys().with_policy(p, None).revoked(false).count(), 3);

        Ok(())
    }


    #[test]
    fn binary_signature() {
        #[derive(PartialEq, Debug)]
        struct VHelper {
            good: usize,
            errors: usize,
            keys: Vec<Cert>,
        }

        impl VHelper {
            fn new(keys: Vec<Cert>) -> Self {
                VHelper {
                    good: 0,
                    errors: 0,
                    keys: keys,
                }
            }
        }

        impl VerificationHelper for VHelper {
            fn get_public_keys(&mut self, _ids: &[crate::KeyHandle])
                -> Result<Vec<Cert>>
            {
                Ok(self.keys.clone())
            }

            fn check(&mut self, structure: MessageStructure) -> Result<()>
            {
                for layer in structure.iter() {
                    match layer {
                        MessageLayer::SignatureGroup { ref results } =>
                            for result in results {
                                eprintln!("result: {:?}", result);
                                match result {
                                    Ok(_) => self.good += 1,
                                    Err(_) => self.errors += 1,
                                }
                            }
                        MessageLayer::Compression { .. } => (),
                        _ => unreachable!(),
                    }
                }

                Ok(())
            }
        }

        impl DecryptionHelper for VHelper {
            fn decrypt<D>(&mut self, _: &[PKESK], _: &[SKESK],
                          _: Option<SymmetricAlgorithm>,_: D)
                          -> Result<Option<Fingerprint>>
                where D: FnMut(SymmetricAlgorithm, &SessionKey) -> Result<()>
            {
                unreachable!();
            }
        }

        // Reject all data (binary) signatures.
        #[derive(Debug)]
        struct NoBinarySigantures;
        impl Policy for NoBinarySigantures {
            fn signature(&self, sig: &Signature) -> Result<()> {
                use crate::types::SignatureType::*;
                eprintln!("{:?}", sig.typ());
                match sig.typ() {
                    Binary =>
                        Err(format_err!("binary!")),
                    _ => Ok(()),
                }
            }
        }
        let no_binary_signatures = &NoBinarySigantures {};

        // Reject all subkey signatures.
        #[derive(Debug)]
        struct NoSubkeySigs;
        impl Policy for NoSubkeySigs {
            fn signature(&self, sig: &Signature) -> Result<()> {
                use crate::types::SignatureType::*;

                match sig.typ() {
                    SubkeyBinding => Err(format_err!("subkey signature!")),
                    _ => Ok(()),
                }
            }
        }
        let no_subkey_signatures = &NoSubkeySigs {};

        let standard = &P::new();

        let keys = [
            "neal.pgp",
        ].iter()
            .map(|f| Cert::from_bytes(crate::tests::key(f)).unwrap())
            .collect::<Vec<_>>();
        let data = "messages/signed-1.gpg";

        let reference = crate::tests::manifesto();



        // Test Verifier.

        // Standard policy => ok.
        let h = VHelper::new(keys.clone());
        let mut v =
            match Verifier::from_bytes(standard, crate::tests::file(data), h,
                                       crate::frozen_time()) {
                Ok(v) => v,
                Err(e) => panic!("{}", e),
            };
        assert!(v.message_processed());
        assert_eq!(v.helper_ref().good, 1);
        assert_eq!(v.helper_ref().errors, 0);

        let mut content = Vec::new();
        v.read_to_end(&mut content).unwrap();
        assert_eq!(reference.len(), content.len());
        assert_eq!(reference, &content[..]);


        // Kill the subkey.
        let h = VHelper::new(keys.clone());
        let mut v = match Verifier::from_bytes(no_subkey_signatures,
                                   crate::tests::file(data), h,
                                   crate::frozen_time()) {
            Ok(v) => v,
            Err(e) => panic!("{}", e),
        };
        assert!(v.message_processed());
        assert_eq!(v.helper_ref().good, 0);
        assert_eq!(v.helper_ref().errors, 1);

        let mut content = Vec::new();
        v.read_to_end(&mut content).unwrap();
        assert_eq!(reference.len(), content.len());
        assert_eq!(reference, &content[..]);


        // Kill the data signature.
        let h = VHelper::new(keys.clone());
        let mut v =
            match Verifier::from_bytes(no_binary_signatures,
                                       crate::tests::file(data), h,
                                       crate::frozen_time()) {
                Ok(v) => v,
                Err(e) => panic!("{}", e),
            };
        assert!(v.message_processed());
        assert_eq!(v.helper_ref().good, 0);
        assert_eq!(v.helper_ref().errors, 1);

        let mut content = Vec::new();
        v.read_to_end(&mut content).unwrap();
        assert_eq!(reference.len(), content.len());
        assert_eq!(reference, &content[..]);



        // Test Decryptor.

        // Standard policy.
        let h = VHelper::new(keys.clone());
        let mut v =
            match Decryptor::from_bytes(standard, crate::tests::file(data), h,
                                        crate::frozen_time()) {
                Ok(v) => v,
                Err(e) => panic!("{}", e),
            };
        assert!(v.message_processed());
        assert_eq!(v.helper_ref().good, 1);
        assert_eq!(v.helper_ref().errors, 0);

        let mut content = Vec::new();
        v.read_to_end(&mut content).unwrap();
        assert_eq!(reference.len(), content.len());
        assert_eq!(reference, &content[..]);


        // Kill the subkey.
        let h = VHelper::new(keys.clone());
        let mut v = match Decryptor::from_bytes(no_subkey_signatures,
                                                crate::tests::file(data), h,
                                                crate::frozen_time()) {
            Ok(v) => v,
            Err(e) => panic!("{}", e),
        };
        assert!(v.message_processed());
        assert_eq!(v.helper_ref().good, 0);
        assert_eq!(v.helper_ref().errors, 1);

        let mut content = Vec::new();
        v.read_to_end(&mut content).unwrap();
        assert_eq!(reference.len(), content.len());
        assert_eq!(reference, &content[..]);


        // Kill the data signature.
        let h = VHelper::new(keys.clone());
        let mut v =
            match Decryptor::from_bytes(no_binary_signatures,
                                        crate::tests::file(data), h,
                                        crate::frozen_time()) {
                Ok(v) => v,
                Err(e) => panic!("{}", e),
            };
        assert!(v.message_processed());
        assert_eq!(v.helper_ref().good, 0);
        assert_eq!(v.helper_ref().errors, 1);

        let mut content = Vec::new();
        v.read_to_end(&mut content).unwrap();
        assert_eq!(reference.len(), content.len());
        assert_eq!(reference, &content[..]);
    }

    #[test]
    fn hash_algo() -> Result<()> {
        use crate::types::RevocationStatus;
        use crate::types::ReasonForRevocation;

        const SECS_IN_YEAR : u64 = 365 * 24 * 60 * 60;

        // A `const fn` is only guaranteed to be evaluated at compile
        // time if the result is assigned to a `const` variable.  Make
        // sure that works.
        const DEFAULT : StandardPolicy = StandardPolicy::new();

        let (cert, _) = CertBuilder::new()
            .add_userid("Alice")
            .generate()?;

        let algo = cert.primary_key().bundle()
            .binding_signature(&DEFAULT, None).unwrap().hash_algo();

        eprintln!("{:?}", algo);

        // Create a revoked version.
        let mut keypair = cert.primary_key().key().clone()
            .mark_parts_secret()?.into_keypair()?;
        let cert_revoked = cert.clone().revoke_in_place(
            &mut keypair,
            ReasonForRevocation::KeyCompromised,
            b"It was the maid :/")?;

        match cert_revoked.revoked(&DEFAULT, None) {
            RevocationStatus::Revoked(sigs) => {
                assert_eq!(sigs.len(), 1);
                assert_eq!(sigs[0].hash_algo(), algo);
            }
            _ => panic!("not revoked"),
        }


        // Reject the hash algorithm unconditionally.
        let mut reject : StandardPolicy = StandardPolicy::new();
        reject.reject_hash(algo);
        assert!(cert.primary_key().bundle()
                    .binding_signature(&reject, None).is_none());
        assert_match!(RevocationStatus::NotAsFarAsWeKnow
                      = cert_revoked.revoked(&reject, None));

        // Reject the hash algorithm next year.
        let mut reject : StandardPolicy = StandardPolicy::new();
        reject.reject_hash_at(
            algo,
            SystemTime::now() + Duration::from_secs(SECS_IN_YEAR),
            SystemTime::now() + Duration::from_secs(SECS_IN_YEAR));
        assert!(cert.primary_key().bundle()
                    .binding_signature(&reject, None).is_some());
        assert_match!(RevocationStatus::Revoked(_)
                      = cert_revoked.revoked(&reject, None));

        // Reject the hash algorithm last year.
        let mut reject : StandardPolicy = StandardPolicy::new();
        reject.reject_hash_at(
            algo,
            SystemTime::now() - Duration::from_secs(SECS_IN_YEAR),
            SystemTime::now() - Duration::from_secs(SECS_IN_YEAR));
        assert!(cert.primary_key().bundle()
                    .binding_signature(&reject, None).is_none());
        assert_match!(RevocationStatus::NotAsFarAsWeKnow
                      = cert_revoked.revoked(&reject, None));

        // Reject the hash algorithm for normal signatures last year,
        // and revocations next year.
        let mut reject : StandardPolicy = StandardPolicy::new();
        reject.reject_hash_at(
            algo,
            SystemTime::now() - Duration::from_secs(SECS_IN_YEAR),
            SystemTime::now() + Duration::from_secs(SECS_IN_YEAR));
        assert!(cert.primary_key().bundle()
                    .binding_signature(&reject, None).is_none());
        assert_match!(RevocationStatus::Revoked(_)
                      = cert_revoked.revoked(&reject, None));

        // Accept algo, but reject the algos with id - 1 and id + 1.
        let mut reject : StandardPolicy = StandardPolicy::new();
        let algo_u8 : u8 = algo.into();
        assert!(algo_u8 != 0u8);
        reject.reject_hash_at(
            (algo_u8 - 1).into(),
            SystemTime::now() - Duration::from_secs(SECS_IN_YEAR),
            SystemTime::now() - Duration::from_secs(SECS_IN_YEAR));
        reject.reject_hash_at(
            (algo_u8 + 1).into(),
            SystemTime::now() - Duration::from_secs(SECS_IN_YEAR),
            SystemTime::now() - Duration::from_secs(SECS_IN_YEAR));
        assert!(cert.primary_key().bundle()
                    .binding_signature(&reject, None).is_some());
        assert_match!(RevocationStatus::Revoked(_)
                      = cert_revoked.revoked(&reject, None));

        // Reject the hash algorithm since before the Unix epoch.
        // Since the earliest representable time using a Timestamp is
        // the Unix epoch, this is equivalent to rejecting everything.
        let mut reject : StandardPolicy = StandardPolicy::new();
        reject.reject_hash_at(
            algo,
            SystemTime::UNIX_EPOCH - Duration::from_secs(SECS_IN_YEAR),
            SystemTime::UNIX_EPOCH - Duration::from_secs(SECS_IN_YEAR));
        assert!(cert.primary_key().bundle()
                    .binding_signature(&reject, None).is_none());
        assert_match!(RevocationStatus::NotAsFarAsWeKnow
                      = cert_revoked.revoked(&reject, None));

        // Reject the hash algorithm after the end of time that is
        // representable by a Timestamp (2106).  This should accept
        // everything.
        let mut reject : StandardPolicy = StandardPolicy::new();
        reject.reject_hash_at(
            algo,
            SystemTime::UNIX_EPOCH + Duration::from_secs(500 * SECS_IN_YEAR),
            SystemTime::UNIX_EPOCH + Duration::from_secs(500 * SECS_IN_YEAR));
        assert!(cert.primary_key().bundle()
                    .binding_signature(&reject, None).is_some());
        assert_match!(RevocationStatus::Revoked(_)
                      = cert_revoked.revoked(&reject, None));

        Ok(())
    }

    #[test]
    fn key_verify_self_signature() -> Result<()> {
        let p = &P::new();

        #[derive(Debug)]
        struct NoRsa;
        impl Policy for NoRsa {
            fn key(&self, ka: &ValidKeyAmalgamation<key::PublicParts>)
                   -> Result<()>
            {
                use crate::types::PublicKeyAlgorithm::*;

                eprintln!("algo: {}", ka.key().pk_algo());
                if ka.key().pk_algo() == RSAEncryptSign {
                    Err(format_err!("RSA!"))
                } else {
                    Ok(())
                }
            }
        }
        let norsa = &NoRsa {};

        // Generate a certificate with an RSA primary and two RSA
        // subkeys.
        let (cert,_) = CertBuilder::new()
            .set_cipher_suite(CipherSuite::RSA4k)
            .add_signing_subkey()
            .add_signing_subkey()
            .generate()?;
        assert_eq!(cert.keys().with_policy(p, None).count(), 3);
        assert_eq!(cert.keys().with_policy(norsa, None).count(), 0);
        assert!(cert.primary_key().with_policy(p, None).is_ok());
        assert!(cert.primary_key().with_policy(norsa, None).is_err());

        // Generate a certificate with an ECC primary, an ECC subkey,
        // and an RSA subkey.
        let (cert,_) = CertBuilder::new()
            .set_cipher_suite(CipherSuite::Cv25519)
            .add_signing_subkey()
            .generate()?;

        let pk = cert.primary_key().key().mark_parts_secret_ref()?;
        let subkey: key::SecretSubkey
            = Key4::generate_rsa(4096)?.into();
        let binding = signature::Builder::new(SignatureType::SubkeyBinding)
            .set_key_flags(&KeyFlags::default().set_transport_encryption(true))?
            .set_issuer_fingerprint(cert.fingerprint())?
            .set_issuer(cert.keyid())?
            .sign_subkey_binding(&mut pk.clone().into_keypair()?,
                                 &pk, &subkey)?;

        let cert = cert.merge_packets(vec![ subkey.into(), binding.into() ])?;

        assert_eq!(cert.keys().with_policy(p, None).count(), 3);
        assert_eq!(cert.keys().with_policy(norsa, None).count(), 2);
        assert!(cert.primary_key().with_policy(p, None).is_ok());
        assert!(cert.primary_key().with_policy(norsa, None).is_ok());

        // Generate a certificate with an RSA primary, an RSA subkey,
        // and an ECC subkey.
        let (cert,_) = CertBuilder::new()
            .set_cipher_suite(CipherSuite::RSA4k)
            .add_signing_subkey()
            .generate()?;

        let pk = cert.primary_key().key().mark_parts_secret_ref()?;
        let subkey: key::SecretSubkey
            = key::Key4::generate_ecc(true, Curve::Ed25519)?.into();
        let binding = signature::Builder::new(SignatureType::SubkeyBinding)
            .set_key_flags(&KeyFlags::default().set_transport_encryption(true))?
            .set_issuer_fingerprint(cert.fingerprint())?
            .set_issuer(cert.keyid())?
            .sign_subkey_binding(&mut pk.clone().into_keypair()?,
                                 &pk, &subkey)?;

        let cert = cert.merge_packets(vec![ subkey.into(), binding.into() ])?;

        assert_eq!(cert.keys().with_policy(p, None).count(), 3);
        assert_eq!(cert.keys().with_policy(norsa, None).count(), 0);
        assert!(cert.primary_key().with_policy(p, None).is_ok());
        assert!(cert.primary_key().with_policy(norsa, None).is_err());

        // Generate a certificate with an ECC primary and two ECC
        // subkeys.
        let (cert,_) = CertBuilder::new()
            .set_cipher_suite(CipherSuite::Cv25519)
            .add_signing_subkey()
            .add_signing_subkey()
            .generate()?;
        assert_eq!(cert.keys().with_policy(p, None).count(), 3);
        assert_eq!(cert.keys().with_policy(norsa, None).count(), 3);
        assert!(cert.primary_key().with_policy(p, None).is_ok());
        assert!(cert.primary_key().with_policy(norsa, None).is_ok());

        Ok(())
    }

    #[test]
    fn key_verify_binary_signature() -> Result<()> {
        use crate::packet::signature;
        use crate::serialize::Serialize;
        use crate::Packet;
        use crate::types::KeyFlags;

        let p = &P::new();

        #[derive(Debug)]
        struct NoRsa;
        impl Policy for NoRsa {
            fn key(&self, ka: &ValidKeyAmalgamation<key::PublicParts>)
                   -> Result<()>
            {
                use crate::types::PublicKeyAlgorithm::*;

                eprintln!("algo: {} is {}",
                          ka.fingerprint(), ka.key().pk_algo());
                if ka.key().pk_algo() == RSAEncryptSign {
                    Err(format_err!("RSA!"))
                } else {
                    Ok(())
                }
            }
        }
        let norsa = &NoRsa {};

        #[derive(PartialEq, Debug)]
        struct VHelper {
            good: usize,
            errors: usize,
            keys: Vec<Cert>,
        }

        impl VHelper {
            fn new(keys: Vec<Cert>) -> Self {
                VHelper {
                    good: 0,
                    errors: 0,
                    keys: keys,
                }
            }
        }

        impl VerificationHelper for VHelper {
            fn get_public_keys(&mut self, _ids: &[crate::KeyHandle])
                -> Result<Vec<Cert>>
            {
                Ok(self.keys.clone())
            }

            fn check(&mut self, structure: MessageStructure) -> Result<()>
            {
                for layer in structure.iter() {
                    match layer {
                        MessageLayer::SignatureGroup { ref results } =>
                            for result in results {
                                match result {
                                    Ok(_) => self.good += 1,
                                    Err(_) => self.errors += 1,
                                }
                            }
                        MessageLayer::Compression { .. } => (),
                        _ => unreachable!(),
                    }
                }

                Ok(())
            }
        }

        impl DecryptionHelper for VHelper {
            fn decrypt<D>(&mut self, _: &[PKESK], _: &[SKESK],
                          _: Option<SymmetricAlgorithm>,_: D)
                          -> Result<Option<Fingerprint>>
                where D: FnMut(SymmetricAlgorithm, &SessionKey) -> Result<()>
            {
                unreachable!();
            }
        }

        // Sign msg using cert's first subkey, return the signature.
        fn sign_and_verify(p: &dyn Policy, cert: &Cert, good: bool) {
            eprintln!("Expect verification to be {}",
                      if good { "good" } else { "bad" });
            for (i, k) in cert.keys().enumerate() {
                eprintln!("  {}. {}", i, k.fingerprint());
            }

            let msg = b"Hello, World";

            // We always use the first subkey.
            let key = cert.keys().nth(1).unwrap().key();
            let mut keypair = key.clone()
                .mark_parts_secret().unwrap()
                .into_keypair().unwrap();

            // Create a signature.
            let sig = signature::Builder::new(SignatureType::Binary)
                .set_signature_creation_time(
                    std::time::SystemTime::now()).unwrap()
                .set_issuer_fingerprint(key.fingerprint()).unwrap()
                .set_issuer(key.keyid()).unwrap()
                .sign_message(&mut keypair, msg).unwrap();

            // Make sure the signature is ok.
            sig.verify_message(key, msg).unwrap();

            // Turn it into a detached signature.
            let sig = {
                let mut v = Vec::new();
                let sig : Packet = sig.into();
                sig.serialize(&mut v).unwrap();
                v
            };

            let h = VHelper::new(vec![ cert.clone() ]);
            let mut v =
                match DetachedVerifier::from_bytes(p, &sig, msg, h, None) {
                    Ok(v) => v,
                    Err(e) => panic!("{}", e),
                };
            assert!(v.message_processed());
            assert_eq!(v.helper_ref().good, if good { 1 } else { 0 });
            assert_eq!(v.helper_ref().errors, if good { 0 } else { 1 });

            let mut content = Vec::new();
            v.read_to_end(&mut content).unwrap();
            assert_eq!(msg.len(), content.len());
            assert_eq!(msg, &content[..]);
        }


        // A certificate with an ECC primary and an ECC signing
        // subkey.
        eprintln!("Trying ECC primary, ECC sub:");
        let (cert,_) = CertBuilder::new()
            .set_cipher_suite(CipherSuite::Cv25519)
            .add_subkey(KeyFlags::default().set_signing(true), None,
                        None)
            .generate()?;

        assert_eq!(cert.keys().with_policy(p, None).count(), 2);
        assert_eq!(cert.keys().with_policy(norsa, None).count(), 2);
        assert!(cert.primary_key().with_policy(p, None).is_ok());
        assert!(cert.primary_key().with_policy(norsa, None).is_ok());

        sign_and_verify(p, &cert, true);
        sign_and_verify(norsa, &cert, true);

        // A certificate with an RSA primary and an RCC signing
        // subkey.
        eprintln!("Trying RSA primary, ECC sub:");
        let (cert,_) = CertBuilder::new()
            .set_cipher_suite(CipherSuite::RSA4k)
            .add_subkey(KeyFlags::default().set_signing(true), None,
                        CipherSuite::Cv25519)
            .generate()?;

        assert_eq!(cert.keys().with_policy(p, None).count(), 2);
        assert_eq!(cert.keys().with_policy(norsa, None).count(), 0);
        assert!(cert.primary_key().with_policy(p, None).is_ok());
        assert!(cert.primary_key().with_policy(norsa, None).is_err());

        sign_and_verify(p, &cert, true);
        sign_and_verify(norsa, &cert, false);

        // A certificate with an ECC primary and an RSA signing
        // subkey.
        eprintln!("Trying ECC primary, RSA sub:");
        let (cert,_) = CertBuilder::new()
            .set_cipher_suite(CipherSuite::Cv25519)
            .add_subkey(KeyFlags::default().set_signing(true), None,
                        CipherSuite::RSA4k)
            .generate()?;

        assert_eq!(cert.keys().with_policy(p, None).count(), 2);
        assert_eq!(cert.keys().with_policy(norsa, None).count(), 1);
        assert!(cert.primary_key().with_policy(p, None).is_ok());
        assert!(cert.primary_key().with_policy(norsa, None).is_ok());

        sign_and_verify(p, &cert, true);
        sign_and_verify(norsa, &cert, false);

        Ok(())
    }

    #[test]
    fn reject_seip_packet() {
        #[derive(PartialEq, Debug)]
        struct Helper {}
        impl VerificationHelper for Helper {
            fn get_public_keys(&mut self, _: &[crate::KeyHandle])
                -> Result<Vec<Cert>> {
                unreachable!()
            }

            fn check(&mut self, _: MessageStructure) -> Result<()> {
                unreachable!()
            }
        }

        impl DecryptionHelper for Helper {
            fn decrypt<D>(&mut self, _: &[PKESK], _: &[SKESK],
                          _: Option<SymmetricAlgorithm>, _: D)
                          -> Result<Option<Fingerprint>>
                where D: FnMut(SymmetricAlgorithm, &SessionKey) -> Result<()> {
                Ok(None)
            }
        }

        let p = &P::new();
        let r = Decryptor::from_bytes(
            p, crate::tests::message("encrypted-to-testy.gpg"),
            Helper {}, crate::frozen_time());
        match r {
            Ok(_) => panic!(),
            Err(e) => assert_match!(Error::MissingSessionKey(_)
                                    = e.downcast().unwrap()),
        }

        // Reject the SEIP packet.
        let p = &mut P::new();
        p.reject_packet_tag(Tag::SEIP);
        let r = Decryptor::from_bytes(
            p, crate::tests::message("encrypted-to-testy.gpg"),
            Helper {}, crate::frozen_time());
        match r {
            Ok(_) => panic!(),
            Err(e) => assert_match!(Error::PolicyViolation(_, _)
                                    = e.downcast().unwrap()),
        }
    }

    #[test]
    fn reject_cipher() {
        struct Helper {}
        impl VerificationHelper for Helper {
            fn get_public_keys(&mut self, _: &[crate::KeyHandle])
                -> Result<Vec<Cert>> {
                Ok(Default::default())
            }

            fn check(&mut self, _: MessageStructure) -> Result<()> {
                Ok(())
            }
        }

        impl DecryptionHelper for Helper {
            fn decrypt<D>(&mut self, pkesks: &[PKESK], _: &[SKESK],
                          algo: Option<SymmetricAlgorithm>, mut decrypt: D)
                          -> Result<Option<Fingerprint>>
                where D: FnMut(SymmetricAlgorithm, &SessionKey) -> Result<()>
            {
                let p = &P::new();
                let mut pair = Cert::from_bytes(
                    crate::tests::key("testy-private.pgp"))?
                    .keys().with_policy(p, None)
                    .for_transport_encryption().secret().nth(0).unwrap()
                    .key().clone().into_keypair()?;
                pkesks[0].decrypt(&mut pair, algo)
                    .and_then(|(algo, session_key)| decrypt(algo, &session_key))
                    .map(|_| None)
            }
        }

        let p = &P::new();
        Decryptor::from_bytes(
            p, crate::tests::message("encrypted-to-testy.gpg"),
            Helper {}, crate::frozen_time()).unwrap();

        // Reject the AES256.
        let p = &mut P::new();
        p.reject_symmetric_algo(SymmetricAlgorithm::AES256);
        let r = Decryptor::from_bytes(
            p, crate::tests::message("encrypted-to-testy.gpg"),
            Helper {}, crate::frozen_time());
        match r {
            Ok(_) => panic!(),
            Err(e) => assert_match!(Error::PolicyViolation(_, _)
                                    = e.downcast().unwrap()),
        }
    }

    #[test]
    fn reject_asymmetric_algos() -> Result<()> {
        let cert = Cert::from_bytes(crate::tests::key("neal.pgp"))?;
        let p = &mut P::new();
        let t = crate::frozen_time();

        assert_eq!(cert.with_policy(p, t).keys().count(), 4);
        p.reject_asymmetric_algo(AsymmetricAlgorithm::RSA1024);
        assert_eq!(cert.with_policy(p, t).keys().count(), 4);
        p.reject_asymmetric_algo(AsymmetricAlgorithm::RSA2048);
        assert_eq!(cert.with_policy(p, t).keys().count(), 1);
        Ok(())
    }
}
