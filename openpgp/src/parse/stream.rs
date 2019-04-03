//! Streaming decryption and verification.
//!
//! This module provides convenient filters for decryption and
//! verification of OpenPGP messages.  It is the preferred interface
//! to process OpenPGP messages.  These implementations use constant
//! space.
//!
//! See the [verification example].
//!
//! [verification example]: struct.Verifier.html#example

use std::cmp;
use std::collections::HashMap;
use std::io::{self, Read};
use std::path::Path;

use buffered_reader::BufferedReader;
use {
    Error,
    Fingerprint,
    constants::{
        DataFormat,
        SymmetricAlgorithm,
    },
    packet::{
        BodyLength,
        ctb::CTB,
        Key,
        Literal,
        one_pass_sig::OnePassSig3,
        PKESK,
        SKESK,
        Tag,
    },
    KeyID,
    Packet,
    Result,
    RevocationStatus,
    packet,
    packet::Signature,
    TPK,
    crypto::SessionKey,
    serialize::Serialize,
};
use parse::{
    Cookie,
    PacketParser,
    PacketParserBuilder,
    PacketParserResult,
};

/// Whether to trace execution by default (on stderr).
const TRACE : bool = false;

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
/// extern crate sequoia_openpgp as openpgp;
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
/// let message =
///    b"-----BEGIN PGP MESSAGE-----
///
///      xA0DAAoWBpwMNI3YLBkByxJiAAAAAABIZWxsbyBXb3JsZCHCdQQAFgoAJwWCW37P
///      8RahBI6MM/pGJjN5dtl5eAacDDSN2CwZCZAGnAw0jdgsGQAAeZQA/2amPbBXT96Q
///      O7PFms9DRuehsVVrFkaDtjN2WSxI4RGvAQDq/pzNdCMpy/Yo7AZNqZv5qNMtDdhE
///      b2WH5lghfKe/AQ==
///      =DjuO
///      -----END PGP MESSAGE-----";
///
/// let h = Helper {};
/// let mut v = Verifier::from_bytes(message, h)?;
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
    /// Maps KeyID to tpks[i].keys_all().nth(j).
    keys: HashMap<KeyID, (usize, usize)>,
    oppr: Option<PacketParserResult<'a>>,
    sigs: Vec<Vec<Signature>>,

    // The reserve data.
    reserve: Option<Vec<u8>>,
}

/// Contains the result of a signature verification.
#[derive(Debug)]
pub enum VerificationResult<'a> {
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
    GoodChecksum(Signature,
                 &'a TPK, &'a Key, Option<&'a Signature>, RevocationStatus<'a>),
    /// Unable to verify the signature because the key is missing.
    MissingKey(Signature),
    /// The signature is bad.
    BadChecksum(Signature),
}

impl<'a> VerificationResult<'a> {
    /// Simple forwarder.
    pub fn level(&self) -> usize {
        use self::VerificationResult::*;
        match self {
            &GoodChecksum(ref sig, ..) => sig.level(),
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
            Box::new(buffered_reader::Generic::with_cookie(reader, None,
                                                        Default::default())),
            helper)
    }

    /// Creates a `Verifier` from the given file.
    pub fn from_file<P>(path: P, helper: H) -> Result<Verifier<'a, H>>
        where P: AsRef<Path>
    {
        Verifier::from_buffered_reader(
            Box::new(buffered_reader::File::with_cookie(path,
                                                     Default::default())?),
            helper)
    }

    /// Creates a `Verifier` from the given buffer.
    pub fn from_bytes(bytes: &'a [u8], helper: H) -> Result<Verifier<'a, H>> {
        Verifier::from_buffered_reader(
            Box::new(buffered_reader::Memory::with_cookie(bytes,
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
        // The following structure is allowed:
        //
        //   SIG LITERAL
        //
        // In this case, we queue the signature packets.
        let mut sigs = Vec::new();

        while let PacketParserResult::Some(pp) = ppr {
            if ! pp.possible_message() {
                return Err(Error::MalformedMessage(
                    "Malformed OpenPGP message".into()).into());
            }

            match pp.packet {
                Packet::OnePassSig(ref ops) =>
                    issuers.push(ops.issuer().clone()),
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

                    // Stash signatures.
                    for sig in sigs.into_iter() {
                        v.push_sig(Packet::Signature(sig))?;
                    }

                    return Ok(v);
                },
                _ => (),
            }

            let (p, ppr_tmp) = pp.recurse()?;
            if let Packet::Signature(sig) = p {
                if let Some(issuer) = sig.get_issuer() {
                    issuers.push(issuer);
                } else {
                    issuers.push(KeyID::wildcard());
                }
                sigs.push(sig);
            }

            ppr = ppr_tmp;
        }

        // We can only get here if we didn't encounter a literal data
        // packet.
        Err(Error::MalformedMessage(
            "Malformed OpenPGP message".into()).into())
    }


    /// Stashes the given Signature (if it is one) for later
    /// verification.
    fn push_sig(&mut self, p: Packet) -> Result<()> {
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

                self.sigs.iter_mut().last()
                    .expect("sigs is never empty").push(sig);
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

                    let (p, ppr_tmp) = pp.recurse()?;
                    self.push_sig(p)?;
                    ppr = ppr_tmp;
                }

                // Verify the signatures.
                let mut results = Vec::new();
                for sigs in ::std::mem::replace(&mut self.sigs, Vec::new())
                    .into_iter()
                {
                    results.push(Vec::new());
                    for sig in sigs.into_iter() {
                        results.iter_mut().last().expect("never empty").push(
                            if let Some(issuer) = sig.get_issuer() {
                                if let Some((i, j)) = self.keys.get(&issuer) {
                                    let tpk = &self.tpks[*i];
                                    let (binding, revocation, key)
                                        = tpk.keys_all().nth(*j).unwrap();
                                    if sig.verify(key).unwrap_or(false) {
                                        VerificationResult::GoodChecksum
                                            (sig, tpk, key, binding, revocation)
                                    } else {
                                        VerificationResult::BadChecksum(sig)
                                    }
                                } else {
                                    VerificationResult::MissingKey(sig)
                                }
                            } else {
                                // No issuer.
                                VerificationResult::BadChecksum(sig)
                            }
                        )
                    }
                }

                self.helper.check(results)
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

/// Transforms a detached signature and content into a signed message
/// on the fly.
struct Transformer<'a> {
    state: TransformationState,
    sigs: Vec<Signature>,
    reader: Box<'a + BufferedReader<()>>,
    buffer: Vec<u8>,
}

#[derive(PartialEq, Debug)]
enum TransformationState {
    OPSs,
    Data,
    Sigs,
    Done,
}

impl<'a> Transformer<'a> {
    fn new<'b>(signatures: Box<'b + BufferedReader<Cookie>>,
               data: Box<'a + BufferedReader<()>>)
               -> Result<Transformer<'a>>
    {
        let mut sigs = Vec::new();

        // Gather signatures.
        let mut ppr = PacketParser::from_buffered_reader(signatures)?;
        while let PacketParserResult::Some(pp) = ppr {
            let (packet, ppr_) = pp.next()?;
            ppr = ppr_;

            match packet {
                Packet::Signature(sig) => sigs.push(sig),
                _ => return Err(Error::InvalidArgument(
                    format!("Not a signature packet: {:?}",
                            packet.tag())).into()),
            }
        }

        let mut opss = Vec::new();
        for (i, sig) in sigs.iter().rev().enumerate() {
            let mut ops = Result::<OnePassSig3>::from(sig)?;
            if i == sigs.len() - 1 {
                ops.set_last(true);
            }

            ops.serialize(&mut opss)?;
        }

        Ok(Self {
            state: TransformationState::OPSs,
            sigs: sigs,
            reader: data,
            buffer: opss,
        })
    }

    fn read_helper(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.buffer.is_empty() {
            self.state = match self.state {
                TransformationState::OPSs => {
                    // Produce a Literal Data Packet header.
                    CTB::new(Tag::Literal).serialize(&mut self.buffer)?;

                    let len = BodyLength::Partial(16);
                    len.serialize(&mut self.buffer)?;

                    let mut lit = Literal::new(DataFormat::Binary);
                    lit.set_filename("aabbccddee").expect("short enough");
                    lit.serialize_headers(&mut self.buffer, false)?;

                    assert_eq!(self.buffer.len(), 18);

                    TransformationState::Data
                },

                TransformationState::Data => {
                    // Find the largest power of two equal or smaller
                    // than the size of buf.
                    let mut s = buf.len().next_power_of_two();
                    if ! buf.len().is_power_of_two() {
                        s >>= 1;
                    }

                    // Cap it.  Drop once we avoid the copies below.
                    const MAX_CHUNK_SIZE: usize = 1 << 22; // 4 megabytes.
                    if s > MAX_CHUNK_SIZE {
                        s = MAX_CHUNK_SIZE;
                    }

                    assert!(s <= ::std::u32::MAX as usize);

                    // Try to read that amount into the buffer.
                    let data = self.reader.data(s)?;

                    // Short read?
                    if data.len() < s {
                        let len = BodyLength::Full(data.len() as u32);
                        len.serialize(&mut self.buffer)?;

                        // XXX: Could avoid the copy here.
                        let l = self.buffer.len();
                        self.buffer.resize(l + data.len(), 0);
                        &mut self.buffer[l..].copy_from_slice(data);

                        TransformationState::Sigs
                    } else {
                        let len = BodyLength::Partial(data.len() as u32);
                        len.serialize(&mut self.buffer)?;

                        // XXX: Could avoid the copy here.
                        let l = self.buffer.len();
                        self.buffer.resize(l + data.len(), 0);
                        &mut self.buffer[l..].copy_from_slice(data);

                        TransformationState::Data
                    }
                },

                TransformationState::Sigs => {
                    for sig in self.sigs.iter() {
                        sig.serialize(&mut self.buffer)?;
                    }

                    TransformationState::Done
                },

                TransformationState::Done =>
                    TransformationState::Done,
            };
        }

        let n = cmp::min(buf.len(), self.buffer.len());
        &mut buf[..n].copy_from_slice(&self.buffer[..n]);
        self.buffer.drain(..n);
        Ok(n)
    }
}

impl<'a> io::Read for Transformer<'a> {
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


/// Verifies a detached signature.
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
/// extern crate sequoia_openpgp as openpgp;
/// extern crate failure;
/// use std::io::{self, Read};
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
/// let signature =
///    b"-----BEGIN SIGNATURE-----
///
///      wnUEABYKACcFglt+z/EWoQSOjDP6RiYzeXbZeXgGnAw0jdgsGQmQBpwMNI3YLBkA
///      AHmUAP9mpj2wV0/ekDuzxZrPQ0bnobFVaxZGg7YzdlksSOERrwEA6v6czXQjKcv2
///      KOwGTamb+ajTLQ3YRG9lh+ZYIXynvwE=
///      =IJ29
///      -----END SIGNATURE-----";
///
/// let data = b"Hello World!";
/// let h = Helper {};
/// let mut v = DetachedVerifier::from_bytes(signature, data, h)?;
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
pub struct DetachedVerifier {
}

impl DetachedVerifier {
    /// Creates a `Verifier` from the given readers.
    pub fn from_reader<'a, 's, H, R, S>(signature_reader: S, reader: R,
                                        helper: H)
                                        -> Result<Verifier<'a, H>>
        where R: io::Read + 'a, S: io::Read + 's, H: VerificationHelper
    {
        Self::from_buffered_reader(
            Box::new(buffered_reader::Generic::with_cookie(signature_reader, None,
                                                        Default::default())),
            Box::new(buffered_reader::Generic::new(reader, None)),
            helper)
    }

    /// Creates a `Verifier` from the given files.
    pub fn from_file<'a, H, P, S>(signature_path: S, path: P,
                                  helper: H)
                                  -> Result<Verifier<'a, H>>
        where P: AsRef<Path>, S: AsRef<Path>, H: VerificationHelper
    {
        Self::from_buffered_reader(
            Box::new(buffered_reader::File::with_cookie(signature_path,
                                                     Default::default())?),
            Box::new(buffered_reader::File::open(path)?),
            helper)
    }

    /// Creates a `Verifier` from the given buffers.
    pub fn from_bytes<'a, 's, H>(signature_bytes: &'s [u8], bytes: &'a [u8],
                                 helper: H)
                                 -> Result<Verifier<'a, H>>
        where H: VerificationHelper
    {
        Self::from_buffered_reader(
            Box::new(buffered_reader::Memory::with_cookie(signature_bytes,
                                                       Default::default())),
            Box::new(buffered_reader::Memory::new(bytes)),
            helper)
    }

    /// Creates the `Verifier`, and buffers the data up to `BUFFER_SIZE`.
    pub(crate) fn from_buffered_reader<'a, 's, H>
        (signature_bio: Box<BufferedReader<Cookie> + 's>,
         reader: Box<'a + BufferedReader<()>>,
         helper: H)
         -> Result<Verifier<'a, H>>
        where H: VerificationHelper
    {
        Verifier::from_buffered_reader(
            Box::new(buffered_reader::Generic::with_cookie(
                Transformer::new(signature_bio, reader)?,
                None, Default::default())),
            helper)
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
/// extern crate sequoia_openpgp as openpgp;
/// extern crate failure;
/// use std::io::Read;
/// use openpgp::crypto::SessionKey;
/// use openpgp::constants::SymmetricAlgorithm;
/// use openpgp::{KeyID, TPK, Result, packet::{Key, PKESK, SKESK}};
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
///     fn decrypt<D>(&mut self, _: &[PKESK], skesks: &[SKESK],
///                   mut decrypt: D) -> Result<Option<openpgp::Fingerprint>>
///         where D: FnMut(SymmetricAlgorithm, &SessionKey) -> Result<()>
///     {
///         skesks[0].decrypt(&"streng geheim".into())
///             .and_then(|(algo, session_key)| decrypt(algo, &session_key))
///             .map(|_| None)
///     }
/// }
///
/// let message =
///    b"-----BEGIN PGP MESSAGE-----
///
///      wy4ECQMIY5Zs8RerVcXp85UgoUKjKkevNPX3WfcS5eb7rkT9I6kw6N2eEc5PJUDh
///      0j0B9mnPKeIwhp2kBHpLX/en6RfNqYauX9eSeia7aqsd/AOLbO9WMCLZS5d2LTxN
///      rwwb8Aggyukj13Mi0FF5
///      =OB/8
///      -----END PGP MESSAGE-----";
///
/// let h = Helper {};
/// let mut v = Decryptor::from_bytes(message, h)?;
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
    /// Maps KeyID to tpks[i].keys_all().nth(j).
    keys: HashMap<KeyID, (usize, usize)>,
    oppr: Option<PacketParserResult<'a>>,
    identity: Option<Fingerprint>,
    sigs: Vec<Vec<Signature>>,
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

    /// Inspects the message.
    ///
    /// Called once per packet.  Can be used to dump packets in
    /// encrypted messages.  The default implementation does nothing.
    fn inspect(&mut self, pp: &PacketParser) -> Result<()> {
        // Do nothing.
        let _ = pp;
        Ok(())
    }

    /// Decrypts the message.
    ///
    /// This function is called with every `PKESK` and `SKESK` found
    /// in the message.  The implementation must decrypt the symmetric
    /// algorithm and session key from one of the PKESK packets, the
    /// SKESKs, or retrieve it from a cache, and then call `decrypt`
    /// with the symmetric algorithm and session key.
    fn decrypt<D>(&mut self, pkesks: &[PKESK], skesks: &[SKESK],
                  decrypt: D) -> Result<Option<Fingerprint>>
        where D: FnMut(SymmetricAlgorithm, &SessionKey) -> Result<()>;
}

impl<'a, H: VerificationHelper + DecryptionHelper> Decryptor<'a, H> {
    /// Creates a `Decryptor` from the given reader.
    pub fn from_reader<R>(reader: R, helper: H) -> Result<Decryptor<'a, H>>
        where R: io::Read + 'a
    {
        Decryptor::from_buffered_reader(
            Box::new(buffered_reader::Generic::with_cookie(reader, None,
                                                        Default::default())),
            helper)
    }

    /// Creates a `Decryptor` from the given file.
    pub fn from_file<P>(path: P, helper: H) -> Result<Decryptor<'a, H>>
        where P: AsRef<Path>
    {
        Decryptor::from_buffered_reader(
            Box::new(buffered_reader::File::with_cookie(path,
                                                     Default::default())?),
            helper)
    }

    /// Creates a `Decryptor` from the given buffer.
    pub fn from_bytes(bytes: &'a [u8], helper: H) -> Result<Decryptor<'a, H>> {
        Decryptor::from_buffered_reader(
            Box::new(buffered_reader::Memory::with_cookie(bytes,
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
        tracer!(TRACE, "Decryptor::from_buffered_reader", 0);

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
        // The following structure is allowed:
        //
        //   SIG LITERAL
        //
        // In this case, we queue the signature packets.
        let mut sigs = Vec::new();
        let mut pkesks: Vec<packet::PKESK> = Vec::new();
        let mut skesks: Vec<packet::SKESK> = Vec::new();
        let mut saw_content = false;

        while let PacketParserResult::Some(mut pp) = ppr {
            v.helper.inspect(&pp)?;
            if ! pp.possible_message() {
                t!("Malformed message");
                return Err(Error::MalformedMessage(
                    "Malformed OpenPGP message".into()).into());
            }

            match pp.packet {
                Packet::SEIP(_) | Packet::AED(_) => {
                    saw_content = true;

                    v.identity =
                        v.helper.decrypt(&pkesks[..], &skesks[..],
                                         |algo, secret| pp.decrypt(algo, secret)
                        )?;
                    if ! pp.decrypted() {
                        // XXX: That is not quite the right error to return.
                        return Err(
                            Error::InvalidSessionKey("No session key".into())
                                .into());
                    }
                },
                Packet::OnePassSig(ref ops) =>
                    issuers.push(ops.issuer().clone()),
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

                    // Stash signatures.
                    for sig in sigs.into_iter() {
                        v.push_sig(Packet::Signature(sig))?;
                    }

                    return Ok(v);
                },
                Packet::MDC(ref mdc) => if ! mdc.valid() {
                    return Err(Error::ManipulatedMessage.into());
                },
                _ => (),
            }

            let (p, ppr_tmp) = pp.recurse()?;
            match p {
                Packet::PKESK(pkesk) => pkesks.push(pkesk),
                Packet::SKESK(skesk) => skesks.push(skesk),
                Packet::Signature(sig) => {
                    if saw_content {
                        v.push_sig(Packet::Signature(sig))?;
                    } else {
                        if let Some(issuer) = sig.get_issuer() {
                            issuers.push(issuer);
                        } else {
                            issuers.push(KeyID::wildcard());
                        }
                        sigs.push(sig);
                    }
                }
                _ => (),
            }
            ppr = ppr_tmp;
        }

        // We can only get here if we didn't encounter a literal data
        // packet.
        Err(Error::MalformedMessage(
            "Malformed OpenPGP message".into()).into())
    }

    /// Stashes the given Signature (if it is one) for later
    /// verification.
    fn push_sig(&mut self, p: Packet) -> Result<()> {
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

                self.sigs.iter_mut().last()
                    .expect("sigs is never empty").push(sig);
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

                    let (p, ppr_tmp) = pp.recurse()?;
                    self.push_sig(p)?;
                    ppr = ppr_tmp;
                }

                // Verify the signatures.
                let mut results = Vec::new();
                for sigs in ::std::mem::replace(&mut self.sigs, Vec::new())
                    .into_iter()
                {
                    results.push(Vec::new());
                    for sig in sigs.into_iter() {
                        results.iter_mut().last().expect("never empty").push(
                            if let Some(issuer) = sig.get_issuer() {
                                if let Some((i, j)) = self.keys.get(&issuer) {
                                    let tpk = &self.tpks[*i];
                                    let (binding, revocation, key)
                                        = tpk.keys_all().nth(*j).unwrap();
                                    if sig.verify(key).unwrap_or(false) {
                                        // Check intended recipients.
                                        if let Some(identity) =
                                            self.identity.as_ref()
                                        {
                                            let ir = sig.intended_recipients();
                                            if !ir.is_empty()
                                                && !ir.contains(identity)
                                            {
                                                // The signature
                                                // contains intended
                                                // recipients, but we
                                                // are not one.  Treat
                                                // the signature as
                                                // bad.
                                                VerificationResult::BadChecksum
                                                    (sig)
                                            } else {
                                                VerificationResult::GoodChecksum
                                                    (sig, tpk, key, binding,
                                                     revocation)
                                            }
                                        } else {
                                            // No identity information.
                                            VerificationResult::GoodChecksum
                                                (sig, tpk, key, binding,
                                                 revocation)
                                        }
                                    } else {
                                        VerificationResult::BadChecksum(sig)
                                    }
                                } else {
                                    VerificationResult::MissingKey(sig)
                                }
                            } else {
                                // No issuer.
                                VerificationResult::BadChecksum(sig)
                            }
                        )
                    }
                }

                self.helper.check(results)
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
    use parse::Parse;

    fn path_to(artifact: &str) -> PathBuf {
    [env!("CARGO_MANIFEST_DIR"), "tests", "data", artifact]
        .iter().collect()
    }

    #[derive(Debug, PartialEq)]
    struct VHelper {
        good: usize,
        unknown: usize,
        bad: usize,
        error: usize,
        keys: Vec<TPK>,
    }

    impl Default for VHelper {
        fn default() -> Self {
            VHelper {
                good: 0,
                unknown: 0,
                bad: 0,
                error: 0,
                keys: Vec::default(),
            }
        }
    }

    impl VHelper {
        fn new(good: usize, unknown: usize, bad: usize, error: usize, keys: Vec<TPK>) -> Self {
            VHelper {
                good: good,
                unknown: unknown,
                bad: bad,
                error: error,
                keys: keys,
            }
        }
    }

    impl VerificationHelper for VHelper {
        fn get_public_keys(&mut self, _ids: &[KeyID]) -> Result<Vec<TPK>> {
            Ok(self.keys.clone())
        }

        fn check(&mut self, sigs: Vec<Vec<VerificationResult>>) -> Result<()> {
            use self::VerificationResult::*;
            for level in sigs {
                for result in level {
                    match result {
                        GoodChecksum(..) => self.good += 1,
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

    impl DecryptionHelper for VHelper {
        fn decrypt<D>(&mut self, _: &[PKESK], _: &[SKESK], _: D)
                      -> Result<Option<Fingerprint>>
            where D: FnMut(SymmetricAlgorithm, &SessionKey) -> Result<()>
        {
            unreachable!();
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
            ("messages/signed-1.gpg",                      VHelper::new(1, 0, 0, 0, keys.clone())),
            ("messages/signed-1-sha256-testy.gpg",         VHelper::new(0, 1, 0, 0, keys.clone())),
            ("messages/signed-1-notarized-by-ed25519.pgp", VHelper::new(2, 0, 0, 0, keys.clone())),
            ("keys/neal.pgp",                              VHelper::new(0, 0, 0, 1, keys.clone())),
        ];

        let mut reference = Vec::new();
        File::open(path_to("messages/a-cypherpunks-manifesto.txt"))
            .unwrap()
            .read_to_end(&mut reference)
            .unwrap();

        for (f, r) in tests {
            // Test Verifier.
            let mut h = VHelper::new(0, 0, 0, 0, keys.clone());
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

            // Test Decryptor.
            let mut h = VHelper::new(0, 0, 0, 0, keys.clone());
            let mut v =
                match Decryptor::from_file(path_to(f), h) {
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

    /// Tests the order of signatures given to
    /// VerificationHelper::check().
    #[test]
    fn verifier_levels() {
        struct VHelper(());
        impl VerificationHelper for VHelper {
            fn get_public_keys(&mut self, _ids: &[KeyID]) -> Result<Vec<TPK>> {
                Ok(Vec::new())
            }

            fn check(&mut self, sigs: Vec<Vec<VerificationResult>>)
                     -> Result<()> {
                assert_eq!(sigs.len(), 2);
                assert_eq!(sigs[0].len(), 1);
                assert_eq!(sigs[1].len(), 1);
                if let VerificationResult::MissingKey(ref sig) = sigs[0][0] {
                    assert_eq!(
                        &sig.issuer_fingerprint().unwrap().to_string(),
                        "C03F A641 1B03 AE12 5764  6118 7223 B566 78E0 2528");
                } else {
                    unreachable!()
                }
                if let VerificationResult::MissingKey(ref sig) = sigs[1][0] {
                    assert_eq!(
                        &sig.issuer_fingerprint().unwrap().to_string(),
                        "8E8C 33FA 4626 3379 76D9  7978 069C 0C34 8DD8 2C19");
                } else {
                    unreachable!()
                }
                Ok(())
            }
        }
        impl DecryptionHelper for VHelper {
            fn decrypt<D>(&mut self, _: &[PKESK], _: &[SKESK], _: D)
                          -> Result<Option<Fingerprint>>
                where D: FnMut(SymmetricAlgorithm, &SessionKey) -> Result<()>
            {
                unreachable!();
            }
        }

        // Test verifier.
        let v = Verifier::from_file(
            path_to("messages/signed-1-notarized-by-ed25519.pgp"),
            VHelper(())).unwrap();
        assert!(v.message_processed());

        // Test decryptor.
        let v = Decryptor::from_file(
            path_to("messages/signed-1-notarized-by-ed25519.pgp"),
            VHelper(())).unwrap();
        assert!(v.message_processed());
    }

    #[test]
    fn detached_verifier() {
        let keys = [
            "emmelie-dorothea-dina-samantha-awina-ed25519.pgp"
        ].iter()
         .map(|f| TPK::from_file(
            path_to(&format!("keys/{}", f))).unwrap())
         .collect::<Vec<_>>();

        let mut reference = Vec::new();
        File::open(path_to("messages/a-cypherpunks-manifesto.txt"))
            .unwrap()
            .read_to_end(&mut reference)
            .unwrap();

        let h = VHelper::new(0, 0, 0, 0, keys.clone());
        let mut v = DetachedVerifier::from_file(
            path_to("messages/a-cypherpunks-manifesto.txt.ed25519.sig"),
            path_to("messages/a-cypherpunks-manifesto.txt"),
            h).unwrap();
        assert!(v.message_processed());

        let mut content = Vec::new();
        v.read_to_end(&mut content).unwrap();
        assert_eq!(reference.len(), content.len());
        assert_eq!(reference, content);

        let h = v.into_helper();
        assert_eq!(h.good, 1);
        assert_eq!(h.bad, 0);

        // Same, but with readers.
        let h = VHelper::new(0, 0, 0, 0, keys.clone());
        let mut v = DetachedVerifier::from_reader(
            File::open(
                path_to("messages/a-cypherpunks-manifesto.txt.ed25519.sig"))
                .unwrap(),
            File::open(
                path_to("messages/a-cypherpunks-manifesto.txt"))
                .unwrap(),
            h).unwrap();
        assert!(v.message_processed());

        let mut content = Vec::new();
        v.read_to_end(&mut content).unwrap();
        assert_eq!(reference.len(), content.len());
        assert_eq!(reference, content);
    }

    #[test]
    fn verify_long_message() {
        use constants::DataFormat;
        use tpk::{TPKBuilder, CipherSuite};
        use serialize::stream::{LiteralWriter, Signer, Message};
        use packet::key::SecretKey;
        use crypto::KeyPair;
        use std::io::Write;

        let (tpk, _) = TPKBuilder::default()
            .set_cipher_suite(CipherSuite::Cv25519)
            .add_signing_subkey()
            .generate().unwrap();

        // sign 30MiB message
        let mut buf = vec![];
        {
            let key = tpk.keys_all().signing_capable().nth(0).unwrap().2;
            let sec = match key.secret() {
                Some(SecretKey::Unencrypted { ref mpis }) => mpis,
                _ => unreachable!(),
            };
            let mut keypair = KeyPair::new(key.clone(), sec.clone()).unwrap();

            let m = Message::new(&mut buf);
            let signer = Signer::new(m, vec![&mut keypair], None).unwrap();
            let mut ls = LiteralWriter::new(signer, DataFormat::Binary, None, None).unwrap();

            ls.write_all(&mut vec![42u8; 30 * 1024 * 1024]).unwrap();
            ls.finalize().unwrap();
        }

        // Test Verifier.
        let h = VHelper::new(0, 0, 0, 0, vec![tpk.clone()]);
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
        let h = VHelper::new(0, 0, /* makes check() fail: */ 1, 0,
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

        // Test Decryptor.
        let h = VHelper::new(0, 0, 0, 0, vec![tpk.clone()]);
        let mut v = Decryptor::from_bytes(&buf, h).unwrap();

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
        let h = VHelper::new(0, 0, /* makes check() fail: */ 1, 0,
                             vec![tpk.clone()]);
        let mut v = Decryptor::from_bytes(&buf, h).unwrap();

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
