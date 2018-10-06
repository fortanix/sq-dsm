//! Streaming decryption and verification.
//!
//! This module provides convenient filters for decryption and
//! verification of OpenPGP messages.

use std::cmp;
use std::collections::HashMap;
use std::io::{self, Read};
use std::path::Path;

use buffered_reader::{
    BufferedReader, BufferedReaderGeneric, BufferedReaderMemory,
    BufferedReaderFile,
};
use {
    Error,
    Fingerprint,
    constants::SymmetricAlgorithm,
    packet::{Key, PKESK, SKESK},
    KeyID,
    Packet,
    Result,
    packet,
    packet::Signature,
    TPK,
    mpis,
    Password,
    SessionKey,
};
use parse::{
    Cookie,
    PacketParser,
    PacketParserBuilder,
    PacketParserResult,
};

/// How much data to buffer before giving it to the caller.
const BUFFER_SIZE: usize = 25 * 1024 * 1024;

/// Verifies a signed OpenPGP message.
///
/// Signature verification requires processing the whole message
/// first.  Therefore, OpenPGP implementations supporting streaming
/// operations necessarily must output unverified data.  This has been
/// a source of problems in the past.  To alleviate this, we buffer up
/// to 25 megabytes of net message data first, and verify the
/// signatures if the message fits into our buffer.  Nevertheless it
/// is important to treat the data as unverified and untrustworthy
/// until you have seen a positive verification.
///
/// # Example
///
/// ```
/// #[macro_use] extern crate openpgp;
/// extern crate failure;
/// use std::io::Read;
/// use openpgp::{KeyID, TPK, Result};
/// use openpgp::parse::stream::*;
/// # fn main() { f().unwrap(); }
/// # fn f() -> Result<()> {
///
/// // This fetches keys and computes the validity of the verification.
/// struct Helper {};
/// impl VerificationHelper for Helper {
///     fn get_public_keys(&mut self, _ids: &[KeyID]) -> Result<Vec<TPK>> {
///         Ok(Vec::new()) // Feed the TPKs to the verifier here...
///     }
///     fn check(&mut self, sigs: Vec<Vec<VerificationResult>>) -> Result<()> {
///         Ok(()) // Implement your verification policy here.
///     }
/// }
///
/// let mut reader = armored!(
///     "-----BEGIN PGP MESSAGE-----
///
///      xA0DAAoWBpwMNI3YLBkByxJiAAAAAABIZWxsbyBXb3JsZCHCdQQAFgoAJwWCW37P
///      8RahBI6MM/pGJjN5dtl5eAacDDSN2CwZCZAGnAw0jdgsGQAAeZQA/2amPbBXT96Q
///      O7PFms9DRuehsVVrFkaDtjN2WSxI4RGvAQDq/pzNdCMpy/Yo7AZNqZv5qNMtDdhE
///      b2WH5lghfKe/AQ==
///      =DjuO
///      -----END PGP MESSAGE-----"
/// );
/// let h = Helper {};
/// let mut v = Verifier::from_reader(reader, h)?;
///
/// let mut content = Vec::new();
/// v.read_to_end(&mut content)
///     .map_err(|e| if e.get_ref().is_some() {
///         // Wrapped failure::Error.  Recover it.
///         failure::Error::from_boxed_compat(e.into_inner().unwrap())
///     } else {
///         // Plain io::Error.
///         e.into()
///     })?;
///
/// assert_eq!(content, b"Hello World!");
/// # Ok(())
/// # }
pub struct Verifier<'a, H: VerificationHelper> {
    helper: H,
    tpks: Vec<TPK>,
    /// Maps KeyID to tpks[i].keys().nth(j).
    keys: HashMap<KeyID, (usize, usize)>,
    oppr: Option<PacketParserResult<'a>>,
    sigs: Vec<Vec<VerificationResult>>,

    // The reserve data.
    reserve: Option<Vec<u8>>,
}

/// Contains the result of a signature verification.
#[derive(Debug)]
pub enum VerificationResult {
    /// The signature is good.
    ///
    /// Note: A signature is considered good if it can be
    /// mathematically verified.  This doesn't mean that the key that
    /// generated the signature is in anyway trustworthy in the sense
    /// that it belongs to the person or entity that the user thinks
    /// it belongs to.  This can only be evaluated within a trust
    /// model, such as the [web of trust] (WoT).
    ///
    /// [web of trust]: https://en.wikipedia.org/wiki/Web_of_trust
    GoodChecksum(Signature),
    /// Unable to verify the signature because the key is missing.
    MissingKey(Signature),
    /// The signature is bad.
    BadChecksum(Signature),
}

impl VerificationResult {
    /// Simple private forwarder.
    fn level(&self) -> usize {
        use self::VerificationResult::*;
        match self {
            &GoodChecksum(ref sig) => sig.level(),
            &MissingKey(ref sig) => sig.level(),
            &BadChecksum(ref sig) => sig.level(),
        }
    }
}

/// Helper for signature verification.
pub trait VerificationHelper {
    /// Retrieves the TPKs containing the specified keys.
    fn get_public_keys(&mut self, &[KeyID]) -> Result<Vec<TPK>>;

    /// Conveys the result of a signature verification.
    ///
    /// This is called after the last signature has been verified.
    /// This is the place to implement your verification policy.
    /// Check that the required number of signatures or notarizations
    /// were confirmed as valid.
    ///
    /// The argument is a vector, with `sigs[0]` being the vector of
    /// signatures over the data, `vec[1]` being notarizations over
    /// signatures of level 0, and the data, and so on.
    ///
    /// This callback is only called before all data is returned.
    /// That is, once `io::Read` returns EOF, this callback will not
    /// be called again.  As such, any error returned by this function
    /// will abort reading, and the error will be propagated via the
    /// `io::Read` operation.
    fn check(&mut self, sigs: Vec<Vec<VerificationResult>>) -> Result<()>;
}

impl<'a, H: VerificationHelper> Verifier<'a, H> {
    /// Creates a `Verifier` from the given reader.
    pub fn from_reader<R>(reader: R, helper: H) -> Result<Verifier<'a, H>>
        where R: io::Read + 'a
    {
        Verifier::from_buffered_reader(
            Box::new(BufferedReaderGeneric::with_cookie(reader, None,
                                                        Default::default())),
            helper)
    }

    /// Creates a `Verifier` from the given file.
    pub fn from_file<P>(path: P, helper: H) -> Result<Verifier<'a, H>>
        where P: AsRef<Path>
    {
        Verifier::from_buffered_reader(
            Box::new(BufferedReaderFile::with_cookie(path,
                                                     Default::default())?),
            helper)
    }

    /// Creates a `Verifier` from the given buffer.
    pub fn from_bytes(bytes: &'a [u8], helper: H) -> Result<Verifier<'a, H>> {
        Verifier::from_buffered_reader(
            Box::new(BufferedReaderMemory::with_cookie(bytes,
                                                       Default::default())),
            helper)
    }

    /// Returns a reference to the helper.
    pub fn helper_ref(&self) -> &H {
        &self.helper
    }

    /// Returns a mutable reference to the helper.
    pub fn helper_mut(&mut self) -> &mut H {
        &mut self.helper
    }

    /// Recovers the helper.
    pub fn into_helper(self) -> H {
        self.helper
    }

    /// Returns true if the whole message has been processed and the verification result is ready.
    /// If the function returns false the message did not fit into the internal buffer and
    /// **unverified** data must be `read()` from the instance until EOF.
    pub fn message_processed(&self) -> bool {
        // oppr is only None after we've processed the packet sequence.
        self.oppr.is_none()
    }

    /// Creates the `Verifier`, and buffers the data up to `BUFFER_SIZE`.
    pub(crate) fn from_buffered_reader(bio: Box<BufferedReader<Cookie> + 'a>,
                                       helper: H) -> Result<Verifier<'a, H>>
    {
        let mut ppr = PacketParser::from_buffered_reader(bio)?;

        let mut v = Verifier {
            helper: helper,
            tpks: Vec::new(),
            keys: HashMap::new(),
            oppr: None,
            sigs: Vec::new(),
            reserve: None,
        };

        let mut issuers = Vec::new();
        while let PacketParserResult::Some(pp) = ppr {
            if ! pp.possible_message() {
                return Err(Error::MalformedMessage(
                    "Malformed OpenPGP message".into()).into());
            }

            match pp.packet {
                Packet::OnePassSig(ref ops) =>
                    issuers.push(ops.issuer.clone()),
                Packet::Literal(_) => {
                    // Query keys.
                    v.tpks = v.helper.get_public_keys(&issuers)?;

                    for (i, tpk) in v.tpks.iter().enumerate() {
                        let can_sign = |key: &Key, sig: Option<&Signature>| -> bool {
                            if let Some(sig) = sig {
                                sig.key_flags().can_sign()
                                // Check expiry.
                                    && sig.signature_alive()
                                    && sig.key_alive(key)
                            } else {
                                false
                            }
                        };

                        if can_sign(tpk.primary(),
                                    tpk.primary_key_signature()) {
                            v.keys.insert(tpk.fingerprint().to_keyid(), (i, 0));
                        }

                        for (j, skb) in tpk.subkeys().enumerate() {
                            let key = skb.subkey();
                            if can_sign(key, skb.binding_signature()) {
                                v.keys.insert(key.fingerprint().to_keyid(),
                                              (i, j + 1));
                            }
                        }
                    }

                    v.oppr = Some(PacketParserResult::Some(pp));
                    v.finish_maybe()?;
                    return Ok(v);
                },
                _ => (),
            }

            let ((p, _), (ppr_tmp, _)) = pp.recurse()?;
            v.verify(p)?;
            ppr = ppr_tmp;
        }

        // We can only get here if we didn't encounter a literal data
        // packet.
        Err(Error::MalformedMessage(
            "Malformed OpenPGP message".into()).into())
    }


    /// Verifies the given Signature (if it is one), and stores the
    /// result.
    fn verify(&mut self, p: Packet) -> Result<()> {
        match p {
            Packet::Signature(sig) => {
                if self.sigs.is_empty() {
                    self.sigs.push(Vec::new());
                }

                if let Some(current_level) = self.sigs.iter().last()
                    .expect("sigs is never empty")
                    .get(0).map(|r| r.level())
                {
                    if current_level != sig.level() {
                        self.sigs.push(Vec::new());
                    }
                }

                if let Some(issuer) = sig.get_issuer() {
                    if let Some((i, j)) = self.keys.get(&issuer) {
                        let (_, key) = self.tpks[*i].keys().nth(*j).unwrap();
                        if sig.verify(key).unwrap_or(false) {
                            self.sigs.iter_mut().last()
                                .expect("sigs is never empty").push(
                                    VerificationResult::GoodChecksum(sig));
                        } else {
                            self.sigs.iter_mut().last()
                                .expect("sigs is never empty").push(
                                    VerificationResult::BadChecksum(sig));
                        }
                    } else {
                        self.sigs.iter_mut().last()
                            .expect("sigs is never empty").push(
                                VerificationResult::MissingKey(sig));
                    }
                } else {
                    self.sigs.iter_mut().last()
                        .expect("sigs is never empty").push(
                            VerificationResult::BadChecksum(sig));
                }
            },
            _ => (),
        }
        Ok(())
    }

    // If the amount of remaining data does not exceed the reserve,
    // finish processing the OpenPGP packet sequence.
    //
    // Note: once this call succeeds, you may not call it again.
    fn finish_maybe(&mut self) -> Result<()> {
        if let Some(PacketParserResult::Some(mut pp)) = self.oppr.take() {
            // Check if we hit EOF.
            let data_len = pp.data(BUFFER_SIZE + 1)?.len();
            if data_len <= BUFFER_SIZE {
                // Stash the reserve.
                self.reserve = Some(pp.steal_eof()?);

                // Process the rest of the packets.
                let mut ppr = PacketParserResult::Some(pp);
                while let PacketParserResult::Some(mut pp) = ppr {
                    if ! pp.possible_message() {
                        return Err(Error::MalformedMessage(
                            "Malformed OpenPGP message".into()).into());
                    }

                    let ((p, _), (ppr_tmp, _)) = pp.recurse()?;
                    self.verify(p)?;
                    ppr = ppr_tmp;
                }

                // Verify the signatures.
                self.helper.check(::std::mem::replace(&mut self.sigs,
                                                      Vec::new()))
            } else {
                self.oppr = Some(PacketParserResult::Some(pp));
                Ok(())
            }
        } else {
            panic!("No ppr.");
        }
    }

    /// Like `io::Read::read()`, but returns our `Result`.
    fn read_helper(&mut self, buf: &mut [u8]) -> Result<usize> {
        if buf.len() == 0 {
            return Ok(0);
        }

        if let Some(ref mut reserve) = self.reserve {
            // The message has been verified.  We can now drain the
            // reserve.
            assert!(self.oppr.is_none());

            let n = cmp::min(buf.len(), reserve.len());
            &mut buf[..n].copy_from_slice(&reserve[..n]);
            reserve.drain(..n);
            return Ok(n);
        }

        // Read the data from the Literal data packet.
        if let Some(PacketParserResult::Some(mut pp)) = self.oppr.take() {
            // Be careful to not read from the reserve.
            let data_len = pp.data(BUFFER_SIZE + buf.len())?.len();
            if data_len <= BUFFER_SIZE {
                self.oppr = Some(PacketParserResult::Some(pp));
                self.finish_maybe()?;
                self.read_helper(buf)
            } else {
                let n = cmp::min(buf.len(), data_len - BUFFER_SIZE);
                let buf = &mut buf[..n];
                let result = pp.read(buf);
                self.oppr = Some(PacketParserResult::Some(pp));
                Ok(result?)
            }
        } else {
            panic!("No ppr.");
        }
    }
}

impl<'a, H: VerificationHelper> io::Read for Verifier<'a, H> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.read_helper(buf) {
            Ok(n) => Ok(n),
            Err(e) => match e.downcast::<io::Error>() {
                // An io::Error.  Pass as-is.
                Ok(e) => Err(e),
                // A failure.  Create a compat object and wrap it.
                Err(e) => Err(io::Error::new(io::ErrorKind::Other,
                                             e.compat())),
            },
        }
    }
}

/// Decrypts and verifies an encrypted and optionally signed OpenPGP
/// message.
///
/// Signature verification requires processing the whole message
/// first.  Therefore, OpenPGP implementations supporting streaming
/// operations necessarily must output unverified data.  This has been
/// a source of problems in the past.  To alleviate this, we buffer up
/// to 25 megabytes of net message data first, and verify the
/// signatures if the message fits into our buffer.  Nevertheless it
/// is important to treat the data as unverified and untrustworthy
/// until you have seen a positive verification.
///
/// # Example
///
/// ```
/// #[macro_use] extern crate openpgp;
/// extern crate failure;
/// use std::io::Read;
/// use openpgp::{KeyID, TPK, Result, packet::{Key, PKESK, SKESK},
///               mpis::SecretKey};
/// use openpgp::parse::stream::*;
/// # fn main() { f().unwrap(); }
/// # fn f() -> Result<()> {
///
/// // This fetches keys and computes the validity of the verification.
/// struct Helper {};
/// impl VerificationHelper for Helper {
///     fn get_public_keys(&mut self, _ids: &[KeyID]) -> Result<Vec<TPK>> {
///         Ok(Vec::new()) // Feed the TPKs to the verifier here...
///     }
///     fn check(&mut self, sigs: Vec<Vec<VerificationResult>>) -> Result<()> {
///         Ok(()) // Implement your verification policy here.
///     }
/// }
/// impl DecryptionHelper for Helper {
///     fn get_secret(&mut self, _: &[&PKESK], _: &[&SKESK])
///                   -> Result<Option<Secret>> {
///         Ok(Some(Secret::Symmetric {
///             password: "streng geheim".into(),
///         }))
///     }
/// }
///
/// let mut reader = armored!(
///     "-----BEGIN PGP MESSAGE-----
///
///      wy4ECQMIY5Zs8RerVcXp85UgoUKjKkevNPX3WfcS5eb7rkT9I6kw6N2eEc5PJUDh
///      0j0B9mnPKeIwhp2kBHpLX/en6RfNqYauX9eSeia7aqsd/AOLbO9WMCLZS5d2LTxN
///      rwwb8Aggyukj13Mi0FF5
///      =OB/8
///      -----END PGP MESSAGE-----"
/// );
/// let h = Helper {};
/// let mut v = Decryptor::from_reader(reader, h)?;
///
/// let mut content = Vec::new();
/// v.read_to_end(&mut content)
///     .map_err(|e| if e.get_ref().is_some() {
///         // Wrapped failure::Error.  Recover it.
///         failure::Error::from_boxed_compat(e.into_inner().unwrap())
///     } else {
///         // Plain io::Error.
///         e.into()
///     })?;
///
/// assert_eq!(content, b"Hello World!");
/// # Ok(())
/// # }
pub struct Decryptor<'a, H: VerificationHelper + DecryptionHelper> {
    helper: H,
    tpks: Vec<TPK>,
    /// Maps KeyID to tpks[i].keys().nth(j).
    keys: HashMap<KeyID, (usize, usize)>,
    oppr: Option<PacketParserResult<'a>>,
    identity: Option<Fingerprint>,
    sigs: Vec<Vec<VerificationResult>>,
    reserve: Option<Vec<u8>>,
}

/// Helper for decrypting messages.
pub trait DecryptionHelper {
    /// Turns mapping on or off.
    ///
    /// If this function returns true, the packet parser will create a
    /// map of the packets.  Note that this buffers the packets
    /// contents, and is not recommended unless you know that the
    /// packets are small.  The default implementation returns false.
    fn mapping(&self) -> bool {
        false
    }

    /// Called once per packet.
    ///
    /// Can be used to dump packets in encrypted messages.  The
    /// default implementation does nothing.
    fn inspect(&mut self, _pp: &PacketParser) -> Result<()> {
        Ok(())
    }

    /// Retrieves the secret needed to decrypt the data.
    ///
    /// This function is called with every `PKESK` and `SKESK` found
    /// in the message.  It is called repeatedly until either the
    /// decryption succeeds, or this function returns None.
    fn get_secret(&mut self, pkesks: &[&PKESK], skesks: &[&SKESK])
                  -> Result<Option<Secret>>;

    /// Signals success decrypting the given `PKESK`.
    ///
    /// This can be used to cache the result of the asymmetric crypto
    /// operation.  The default implementation does nothing.
    fn cache_asymmetric_secret(&mut self, pkesk: &PKESK,
                               algo: SymmetricAlgorithm, key: Box<[u8]>) {
        // Do nothing.
        let _ = (pkesk, algo, key);
    }

    /// Signals success decrypting the given `SKESK`.
    ///
    /// This can be used to cache the result of the symmetric crypto
    /// operation.  The default implementation does nothing.
    fn cache_symmetric_secret(&mut self, skesk: &SKESK,
                              algo: SymmetricAlgorithm, key: Box<[u8]>) {
        // Do nothing.
        let _ = (skesk, algo, key);
    }
}

/// Represents a secret to decrypt a message.
pub enum Secret {
    /// A key pair for asymmetric decryption.
    Asymmetric {
        /// The primary key's fingerprint.
        identity: Fingerprint,
        /// The public key.
        key: packet::Key,
        /// The secret key.
        secret: mpis::SecretKey,
    },

    /// A password for symmetric decryption.
    Symmetric {
        /// The password.
        password: Password,
    },

    /// A cached session key.
    Cached {
        /// The symmetric algorithm used to encrypt the SEIP packet.
        algo: SymmetricAlgorithm,
        /// The decrypted session key.
        session_key: SessionKey,
    },
}

impl<'a, H: VerificationHelper + DecryptionHelper> Decryptor<'a, H> {
    /// Creates a `Decryptor` from the given reader.
    pub fn from_reader<R>(reader: R, helper: H) -> Result<Decryptor<'a, H>>
        where R: io::Read + 'a
    {
        Decryptor::from_buffered_reader(
            Box::new(BufferedReaderGeneric::with_cookie(reader, None,
                                                        Default::default())),
            helper)
    }

    /// Creates a `Decryptor` from the given file.
    pub fn from_file<P>(path: P, helper: H) -> Result<Decryptor<'a, H>>
        where P: AsRef<Path>
    {
        Decryptor::from_buffered_reader(
            Box::new(BufferedReaderFile::with_cookie(path,
                                                     Default::default())?),
            helper)
    }

    /// Creates a `Decryptor` from the given buffer.
    pub fn from_bytes(bytes: &'a [u8], helper: H) -> Result<Decryptor<'a, H>> {
        Decryptor::from_buffered_reader(
            Box::new(BufferedReaderMemory::with_cookie(bytes,
                                                       Default::default())),
            helper)
    }

    /// Returns a reference to the helper.
    pub fn helper_ref(&self) -> &H {
        &self.helper
    }

    /// Returns a mutable reference to the helper.
    pub fn helper_mut(&mut self) -> &mut H {
        &mut self.helper
    }

    /// Recovers the helper.
    pub fn into_helper(self) -> H {
        self.helper
    }

    /// Returns true if the whole message has been processed and the verification result is ready.
    /// If the function returns false the message did not fit into the internal buffer and
    /// **unverified** data must be `read()` from the instance until EOF.
    pub fn message_processed(&self) -> bool {
        // oppr is only None after we've processed the packet sequence.
        self.oppr.is_none()
    }

    /// Creates the `Decryptor`, and buffers the data up to `BUFFER_SIZE`.
    pub(crate) fn from_buffered_reader(bio: Box<BufferedReader<Cookie> + 'a>,
                                       helper: H) -> Result<Decryptor<'a, H>>
    {
        let mut ppr = PacketParserBuilder::from_buffered_reader(bio)?
            .map(helper.mapping()).finalize()?;

        let mut v = Decryptor {
            helper: helper,
            tpks: Vec::new(),
            keys: HashMap::new(),
            oppr: None,
            identity: None,
            sigs: Vec::new(),
            reserve: None,
        };

        let mut issuers = Vec::new();
        let mut pkesks: Vec<packet::PKESK> = Vec::new();
        let mut skesks: Vec<packet::SKESK> = Vec::new();
        while let PacketParserResult::Some(mut pp) = ppr {
            v.helper.inspect(&pp)?;
            if ! pp.possible_message() {
                return Err(Error::MalformedMessage(
                    "Malformed OpenPGP message".into()).into());
            }

            match pp.packet {
                Packet::SEIP(_) => {
                    let mut decrypted = false;
                    let pkesk_refs: Vec<&PKESK> = pkesks.iter().collect();
                    let skesk_refs: Vec<&SKESK> = skesks.iter().collect();

                    'decrypt_seip: while let Some(secret) =
                        v.helper.get_secret(&pkesk_refs[..], &skesk_refs[..])?
                    {
                        match secret {
                            Secret::Asymmetric {
                                ref identity, ref key, ref secret,
                            } => {
                                let keyid = key.fingerprint().to_keyid();

                                for pkesk in pkesks.iter().filter(|p| {
                                    let r = p.recipient();
                                    *r == keyid || r.is_wildcard()
                                }) {
                                    if let Ok((algo, key)) =
                                        pkesk.decrypt(&key, &secret)
                                    {
                                        if pp.decrypt(algo, &key).is_ok() {
                                            v.identity = Some(identity.clone());
                                            decrypted = true;
                                            break 'decrypt_seip;
                                        }
                                    }
                                }
                            },

                            Secret::Symmetric { ref password } => {
                                for skesk in skesks.iter() {
                                    let (algo, key) = skesk.decrypt(password)?;

                                    if pp.decrypt(algo, &key).is_ok() {
                                        decrypted = true;
                                        break 'decrypt_seip;
                                    }
                                }
                            },

                            Secret::Cached { ref algo, ref session_key } =>
                                if pp.decrypt(*algo, session_key).is_ok() {
                                    decrypted = true;
                                    break 'decrypt_seip;
                                },
                        }
                    }

                    if ! decrypted {
                        // XXX: That is not quite the right error to return.
                        return Err(
                            Error::InvalidSessionKey("No session key".into())
                                .into());
                    }
                },
                Packet::OnePassSig(ref ops) =>
                    issuers.push(ops.issuer.clone()),
                Packet::Literal(_) => {
                    // Query keys.
                    v.tpks = v.helper.get_public_keys(&issuers)?;

                    for (i, tpk) in v.tpks.iter().enumerate() {
                        let can_sign = |key: &Key, sig: Option<&Signature>| -> bool {
                            if let Some(sig) = sig {
                                sig.key_flags().can_sign()
                                // Check expiry.
                                    && sig.signature_alive()
                                    && sig.key_alive(key)
                            } else {
                                false
                            }
                        };

                        if can_sign(tpk.primary(),
                                    tpk.primary_key_signature()) {
                            v.keys.insert(tpk.fingerprint().to_keyid(), (i, 0));
                        }

                        for (j, skb) in tpk.subkeys().enumerate() {
                            let key = skb.subkey();
                            if can_sign(key, skb.binding_signature()) {
                                v.keys.insert(key.fingerprint().to_keyid(),
                                              (i, j + 1));
                            }
                        }
                    }

                    v.oppr = Some(PacketParserResult::Some(pp));
                    v.finish_maybe()?;
                    return Ok(v);
                },
                Packet::MDC(ref mdc) => if ! mdc.valid() {
                    return Err(Error::ManipulatedMessage.into());
                },
                _ => (),
            }

            let ((p, _), (ppr_tmp, _)) = pp.recurse()?;
            match p {
                Packet::PKESK(pkesk) => pkesks.push(pkesk),
                Packet::SKESK(skesk) => skesks.push(skesk),
                Packet::Signature(_) => v.verify(p)?,
                _ => (),
            }
            ppr = ppr_tmp;
        }

        // We can only get here if we didn't encounter a literal data
        // packet.
        Err(Error::MalformedMessage(
            "Malformed OpenPGP message".into()).into())
    }

    /// Verifies the given Signature (if it is one), and stores the
    /// result.
    fn verify(&mut self, p: Packet) -> Result<()> {
        match p {
            Packet::Signature(sig) => {
                if self.sigs.is_empty() {
                    self.sigs.push(Vec::new());
                }

                if let Some(current_level) = self.sigs.iter().last()
                    .expect("sigs is never empty")
                    .get(0).map(|r| r.level())
                {
                    if current_level != sig.level() {
                        self.sigs.push(Vec::new());
                    }
                }

                // Check intended recipients.
                if let Some(identity) = self.identity.as_ref() {
                    let ir = sig.intended_recipients();
                    if !ir.is_empty() && !ir.contains(identity) {
                        // The signature contains intended recipients,
                        // but we are not one.  Treat the signature as
                        // bad.
                        self.sigs.iter_mut().last()
                            .expect("sigs is never empty").push(
                                VerificationResult::BadChecksum(sig));
                        return Ok(());
                    }
                }

                if let Some(issuer) = sig.get_issuer() {
                    if let Some((i, j)) = self.keys.get(&issuer) {
                        let (_, key) = self.tpks[*i].keys().nth(*j).unwrap();
                        if sig.verify(key).unwrap_or(false) {
                            self.sigs.iter_mut().last()
                                .expect("sigs is never empty").push(
                                    VerificationResult::GoodChecksum(sig));
                        } else {
                            self.sigs.iter_mut().last()
                                .expect("sigs is never empty").push(
                                    VerificationResult::BadChecksum(sig));
                        }
                    } else {
                        self.sigs.iter_mut().last()
                            .expect("sigs is never empty").push(
                                VerificationResult::MissingKey(sig));
                    }
                } else {
                    self.sigs.iter_mut().last()
                        .expect("sigs is never empty").push(
                            VerificationResult::BadChecksum(sig));
                }
            },
            _ => (),
        }
        Ok(())
    }

    // If the amount of remaining data does not exceed the reserve,
    // finish processing the OpenPGP packet sequence.
    //
    // Note: once this call succeeds, you may not call it again.
    fn finish_maybe(&mut self) -> Result<()> {
        if let Some(PacketParserResult::Some(mut pp)) = self.oppr.take() {
            // Check if we hit EOF.
            let data_len = pp.data(BUFFER_SIZE + 1)?.len();
            if data_len <= BUFFER_SIZE {
                // Stash the reserve.
                self.reserve = Some(pp.steal_eof()?);

                // Process the rest of the packets.
                let mut ppr = PacketParserResult::Some(pp);
                let mut first = true;
                while let PacketParserResult::Some(mut pp) = ppr {
                    // The literal data packet was already inspected.
                    if first {
                        assert_eq!(pp.packet.tag(), packet::Tag::Literal);
                        first = false;
                    } else {
                        self.helper.inspect(&pp)?;
                    }

                    if ! pp.possible_message() {
                        return Err(Error::MalformedMessage(
                            "Malformed OpenPGP message".into()).into());
                    }

                    match pp.packet {
                        Packet::MDC(ref mdc) => if ! mdc.valid() {
                            return Err(Error::ManipulatedMessage.into());
                        }
                        _ => (),
                    }

                    let ((p, _), (ppr_tmp, _)) = pp.recurse()?;
                    self.verify(p)?;
                    ppr = ppr_tmp;
                }

                // Verify the signatures.
                self.helper.check(::std::mem::replace(&mut self.sigs,
                                                      Vec::new()))
            } else {
                self.oppr = Some(PacketParserResult::Some(pp));
                Ok(())
            }
        } else {
            panic!("No ppr.");
        }
    }

    /// Like `io::Read::read()`, but returns our `Result`.
    fn read_helper(&mut self, buf: &mut [u8]) -> Result<usize> {
        if buf.len() == 0 {
            return Ok(0);
        }

        if let Some(ref mut reserve) = self.reserve {
            // The message has been verified.  We can now drain the
            // reserve.
            assert!(self.oppr.is_none());

            let n = cmp::min(buf.len(), reserve.len());
            &mut buf[..n].copy_from_slice(&reserve[..n]);
            reserve.drain(..n);
            return Ok(n);
        }

        // Read the data from the Literal data packet.
        if let Some(PacketParserResult::Some(mut pp)) = self.oppr.take() {
            // Be careful to not read from the reserve.
            let data_len = pp.data(BUFFER_SIZE + buf.len())?.len();
            if data_len <= BUFFER_SIZE {
                self.oppr = Some(PacketParserResult::Some(pp));
                self.finish_maybe()?;
                self.read_helper(buf)
            } else {
                let n = cmp::min(buf.len(), data_len - BUFFER_SIZE);
                let buf = &mut buf[..n];
                let result = pp.read(buf);
                self.oppr = Some(PacketParserResult::Some(pp));
                Ok(result?)
            }
        } else {
            panic!("No ppr.");
        }
    }
}

impl<'a, H: VerificationHelper + DecryptionHelper> io::Read for Decryptor<'a, H>
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.read_helper(buf) {
            Ok(n) => Ok(n),
            Err(e) => match e.downcast::<io::Error>() {
                // An io::Error.  Pass as-is.
                Ok(e) => Err(e),
                // A failure.  Create a compat object and wrap it.
                Err(e) => Err(io::Error::new(io::ErrorKind::Other,
                                             e.compat())),
            },
        }
    }
}

#[cfg(test)]
mod test {
    use failure;
    use std::fs::File;
    use std::path::PathBuf;
    use super::*;

    fn path_to(artifact: &str) -> PathBuf {
    [env!("CARGO_MANIFEST_DIR"), "tests", "data", artifact]
        .iter().collect()
    }

    #[derive(Debug, PartialEq)]
    struct Helper {
        good: usize,
        unknown: usize,
        bad: usize,
        error: usize,
        keys: Vec<TPK>,
    }

    impl Default for Helper {
        fn default() -> Self {
            Helper {
                good: 0,
                unknown: 0,
                bad: 0,
                error: 0,
                keys: Vec::default(),
            }
        }
    }

    impl Helper {
        fn new(good: usize, unknown: usize, bad: usize, error: usize, keys: Vec<TPK>) -> Self {
            Helper {
                good: good,
                unknown: unknown,
                bad: bad,
                error: error,
                keys: keys,
            }
        }
    }

    impl VerificationHelper for Helper {
        fn get_public_keys(&mut self, _ids: &[KeyID]) -> Result<Vec<TPK>> {
            Ok(self.keys.clone())
        }

        fn check(&mut self, sigs: Vec<Vec<VerificationResult>>) -> Result<()> {
            use self::VerificationResult::*;
            for level in sigs {
                for result in level {
                    match result {
                        GoodChecksum(_) => self.good += 1,
                        MissingKey(_) => self.unknown += 1,
                        BadChecksum(_) => self.bad += 1,
                    }
                }
            }

            if self.good > 0 && self.bad == 0 {
                Ok(())
            } else {
                Err(failure::err_msg("Verification failed"))
            }
        }
    }

    #[test]
    fn verifier() {
        let keys = [
            "neal.pgp",
            "emmelie-dorothea-dina-samantha-awina-ed25519.pgp"
        ].iter()
         .map(|f| TPK::from_file(
            path_to(&format!("keys/{}", f))).unwrap())
         .collect::<Vec<_>>();
        let tests = &[
            ("messages/signed-1.gpg",                      Helper::new(1, 0, 0, 0, keys.clone())),
            ("messages/signed-1-sha256-testy.gpg",         Helper::new(0, 1, 0, 0, keys.clone())),
            ("messages/signed-1-notarized-by-ed25519.pgp", Helper::new(2, 0, 0, 0, keys.clone())),
            ("keys/neal.pgp",                              Helper::new(0, 0, 0, 1, keys.clone())),
        ];

        let mut reference = Vec::new();
        File::open(path_to("messages/a-cypherpunks-manifesto.txt"))
            .unwrap()
            .read_to_end(&mut reference)
            .unwrap();

        for (f, r) in tests {
            let mut h = Helper::new(0, 0, 0, 0, keys.clone());
            let mut v =
                match Verifier::from_file(path_to(f), h) {
                    Ok(v) => v,
                    Err(e) => if r.error > 0 || r.unknown > 0 {
                        // Expected error.  No point in trying to read
                        // something.
                        continue;
                    } else {
                        panic!(e);
                    },
                };
            assert!(v.message_processed());
            assert_eq!(v.helper_ref(), r);

            if v.helper_ref().error > 0 {
                // Expected error.  No point in trying to read
                // something.
                continue;
            }

            let mut content = Vec::new();
            v.read_to_end(&mut content).unwrap();
            assert_eq!(reference.len(), content.len());
            assert_eq!(reference, content);
        }
    }

    #[test]
    fn verify_long_message() {
        use constants::DataFormat;
        use tpk::{TPKBuilder, CipherSuite};
        use serialize::stream::{LiteralWriter, Signer, wrap};
        use std::io::Write;

        let tpk = TPKBuilder::default()
            .set_cipher_suite(CipherSuite::Cv25519)
            .add_signing_subkey()
            .generate().unwrap();

        // sign 30MiB message
        let mut buf = vec![];
        {
            let signer = Signer::new(wrap(&mut buf), &[&tpk]).unwrap();
            let mut ls = LiteralWriter::new(signer, DataFormat::Binary, None, None).unwrap();

            ls.write_all(&mut vec![42u8; 30 * 1024 * 1024]).unwrap();
            ls.finalize().unwrap();
        }

        let h = Helper::new(0, 0, 0, 0, vec![tpk.clone()]);
        let mut v = Verifier::from_bytes(&buf, h).unwrap();

        assert!(!v.message_processed());
        assert!(v.helper_ref().good == 0);
        assert!(v.helper_ref().bad == 0);
        assert!(v.helper_ref().unknown == 0);
        assert!(v.helper_ref().error == 0);

        let mut message = Vec::new();

        v.read_to_end(&mut message).unwrap();

        assert!(v.message_processed());
        assert_eq!(30 * 1024 * 1024, message.len());
        assert!(message.iter().all(|&b| b == 42));
        assert!(v.helper_ref().good == 1);
        assert!(v.helper_ref().bad == 0);
        assert!(v.helper_ref().unknown == 0);
        assert!(v.helper_ref().error == 0);

        // Try the same, but this time we let .check() fail.
        let h = Helper::new(0, 0, /* makes check() fail: */ 1, 0,
                            vec![tpk.clone()]);
        let mut v = Verifier::from_bytes(&buf, h).unwrap();

        assert!(!v.message_processed());
        assert!(v.helper_ref().good == 0);
        assert!(v.helper_ref().bad == 1);
        assert!(v.helper_ref().unknown == 0);
        assert!(v.helper_ref().error == 0);

        let mut message = Vec::new();
        let r = v.read_to_end(&mut message);
        assert!(r.is_err());

        // Check that we only got a truncated message.
        assert!(v.message_processed());
        assert!(message.len() > 0);
        assert!(message.len() <= 5 * 1024 * 1024);
        assert!(message.iter().all(|&b| b == 42));
        assert!(v.helper_ref().good == 1);
        assert!(v.helper_ref().bad == 1);
        assert!(v.helper_ref().unknown == 0);
        assert!(v.helper_ref().error == 0);
    }
}
