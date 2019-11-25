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
use std::convert::TryFrom;
use std::collections::HashMap;
use std::io::{self, Read};
use std::path::Path;
use std::time;

use buffered_reader::BufferedReader;
use crate::{
    Error,
    Fingerprint,
    types::{
        AEADAlgorithm,
        CompressionAlgorithm,
        DataFormat,
        SymmetricAlgorithm,
    },
    conversions::Time,
    packet::{
        header::BodyLength,
        header::CTB,
        key,
        Key,
        Literal,
        OnePassSig,
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
use crate::parse::{
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
///     fn check(&mut self, structure: &MessageStructure) -> Result<()> {
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
/// let mut v = Verifier::from_bytes(message, h, None)?;
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
    structure: IMessageStructure,

    // The reserve data.
    reserve: Option<Vec<u8>>,

    /// Signature verification relative to this time.
    time: time::SystemTime,
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
                 &'a TPK,
                 &'a key::UnspecifiedPublic,
                 Option<&'a Signature>,
                 RevocationStatus<'a>),
    /// The signature is good, but it is not alive at the specified
    /// time.
    ///
    /// See `SubpacketAreas::signature_alive` for a definition of
    /// liveness.
    NotAlive(Signature),
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
            &NotAlive(ref sig, ..) => sig.level(),
            &MissingKey(ref sig) => sig.level(),
            &BadChecksum(ref sig) => sig.level(),
        }
    }
}

/// Communicates the message structure to the VerificationHelper.
#[derive(Debug)]
pub struct MessageStructure<'a>(Vec<MessageLayer<'a>>);

impl<'a> MessageStructure<'a> {
    fn new() -> Self {
        MessageStructure(Vec::new())
    }

    fn new_compression_layer(&mut self, algo: CompressionAlgorithm) {
        self.0.push(MessageLayer::Compression {
            algo: algo,
        })
    }

    fn new_encryption_layer(&mut self, sym_algo: SymmetricAlgorithm,
                            aead_algo: Option<AEADAlgorithm>) {
        self.0.push(MessageLayer::Encryption {
            sym_algo: sym_algo,
            aead_algo: aead_algo,
        })
    }

    fn new_signature_group(&mut self) {
        self.0.push(MessageLayer::SignatureGroup {
            results: Vec::new(),
        })
    }

    fn push_verification_result(&mut self, sig: VerificationResult<'a>) {
        if let Some(MessageLayer::SignatureGroup { ref mut results }) =
            self.0.iter_mut().last()
        {
            results.push(sig);
        } else {
            panic!("cannot push to encryption or compression layer");
        }
    }

    /// Iterates over the message structure.
    pub fn iter(&self) -> MessageStructureIter {
        MessageStructureIter(self.0.iter())
    }
}

/// Iterates over the message structure.
pub struct MessageStructureIter<'a>(::std::slice::Iter<'a, MessageLayer<'a>>);

impl<'a> Iterator for MessageStructureIter<'a> {
    type Item = &'a MessageLayer<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

/// Represents a layer of the message structure.
#[derive(Debug)]
pub enum MessageLayer<'a> {
    /// Represents an compression container.
    Compression {
        /// Compression algorithm used.
        algo: CompressionAlgorithm,
    },
    /// Represents an encryption container.
    Encryption {
        /// Symmetric algorithm used.
        sym_algo: SymmetricAlgorithm,
        /// AEAD algorithm used, if any.
        aead_algo: Option<AEADAlgorithm>,
    },
    /// Represents a signature group.
    SignatureGroup {
        /// The results of the signature verifications.
        results: Vec<VerificationResult<'a>>,
    }
}

/// Internal version of the message structure.
///
/// In contrast to MessageStructure, this owns unverified
/// signature packets.
#[derive(Debug)]
struct IMessageStructure {
    layers: Vec<IMessageLayer>,

    // We insert a SignatureGroup layer every time we see a OnePassSig
    // packet with the last flag.
    //
    // However, we need to make sure that we insert a SignatureGroup
    // layer even if the OnePassSig packet has the last flag set to
    // false.  To do that, we keep track of the fact that we saw such
    // a OPS packet.
    sig_group_counter: usize,
}

impl IMessageStructure {
    fn new() -> Self {
        IMessageStructure {
            layers: Vec::new(),
            sig_group_counter: 0,
        }
    }

    fn new_compression_layer(&mut self, algo: CompressionAlgorithm) {
        self.insert_missing_signature_group();
        self.layers.push(IMessageLayer::Compression {
            algo: algo,
        });
    }

    fn new_encryption_layer(&mut self, sym_algo: SymmetricAlgorithm,
                            aead_algo: Option<AEADAlgorithm>) {
        self.insert_missing_signature_group();
        self.layers.push(IMessageLayer::Encryption {
            sym_algo: sym_algo,
            aead_algo: aead_algo,
        });
    }

    /// Makes sure that we insert a signature group even if the
    /// previous OPS packet had the last flag set to false.
    fn insert_missing_signature_group(&mut self) {
        if self.sig_group_counter > 0 {
            self.layers.push(IMessageLayer::SignatureGroup {
                sigs: Vec::new(),
                count: self.sig_group_counter,
            });
        }
        self.sig_group_counter = 0;
    }

    fn push_ops(&mut self, ops: &OnePassSig) {
        self.sig_group_counter += 1;
        if ops.last() {
            self.layers.push(IMessageLayer::SignatureGroup {
                sigs: Vec::new(),
                count: self.sig_group_counter,
            });
            self.sig_group_counter = 0;
        }
    }

    fn push_signature(&mut self, sig: Signature) {
        for layer in self.layers.iter_mut().rev() {
            match layer {
                IMessageLayer::SignatureGroup {
                    ref mut sigs, ref mut count,
                } if *count > 0 => {
                    sigs.push(sig);
                    *count -= 1;
                    return;
                },
                _ => (),
            }
        }
        panic!("signature unaccounted for");
    }

    fn push_bare_signature(&mut self, sig: Signature) {
        if let Some(IMessageLayer::SignatureGroup { .. }) = self.layers.iter().last() {
            // The last layer is a SignatureGroup.  We will append the
            // signature there without accounting for it.
        } else {
            // The last layer is not a SignatureGroup, or there is no
            // layer at all.  Create one.
            self.layers.push(IMessageLayer::SignatureGroup {
                sigs: Vec::new(),
                count: 0,
            });
        }

        if let IMessageLayer::SignatureGroup { ref mut sigs, .. } =
            self.layers.iter_mut().last().expect("just checked or created")
        {
            sigs.push(sig);
        } else {
            unreachable!()
        }
    }

}

/// Internal version of a layer of the message structure.
///
/// In contrast to MessageLayer, this owns unverified signature packets.
#[derive(Debug)]
enum IMessageLayer {
    Compression {
        algo: CompressionAlgorithm,
    },
    Encryption {
        sym_algo: SymmetricAlgorithm,
        aead_algo: Option<AEADAlgorithm>,
    },
    SignatureGroup {
        sigs: Vec<Signature>,
        count: usize,
    }
}

/// Helper for signature verification.
pub trait VerificationHelper {
    /// Retrieves the TPKs containing the specified keys.
    fn get_public_keys(&mut self, _: &[KeyID]) -> Result<Vec<TPK>>;

    /// Conveys the message structure.
    ///
    /// The message structure contains the results of signature
    /// verifications.  See [`MessageStructure`] for more information.
    ///
    /// [`MessageStructure`]: struct.MessageStructure.html
    ///
    /// This is called after the last signature has been verified.
    /// This is the place to implement your verification policy.
    /// Check that the required number of signatures or notarizations
    /// were confirmed as valid.
    ///
    /// This callback is only called before all data is returned.
    /// That is, once `io::Read` returns EOF, this callback will not
    /// be called again.  As such, any error returned by this function
    /// will abort reading, and the error will be propagated via the
    /// `io::Read` operation.
    fn check(&mut self, structure: &MessageStructure) -> Result<()>;
}

impl<'a, H: VerificationHelper> Verifier<'a, H> {
    /// Creates a `Verifier` from the given reader.
    ///
    /// Signature verifications are done relative to time `t`, or the
    /// current time, if `t` is `None`.
    pub fn from_reader<R, T>(reader: R, helper: H, t: T)
                          -> Result<Verifier<'a, H>>
        where R: io::Read + 'a, T: Into<Option<time::SystemTime>>
    {
        let t = t.into()
            .unwrap_or_else(|| time::SystemTime::now().canonicalize());
        Verifier::from_buffered_reader(
            Box::new(buffered_reader::Generic::with_cookie(reader, None,
                                                        Default::default())),
            helper, t)
    }

    /// Creates a `Verifier` from the given file.
    ///
    /// Signature verifications are done relative to time `t`, or the
    /// current time, if `t` is `None`.
    pub fn from_file<P, T>(path: P, helper: H, t: T) -> Result<Verifier<'a, H>>
        where P: AsRef<Path>,
              T: Into<Option<time::SystemTime>>
    {
        let t = t.into()
            .unwrap_or_else(|| time::SystemTime::now().canonicalize());
        Verifier::from_buffered_reader(
            Box::new(buffered_reader::File::with_cookie(path,
                                                     Default::default())?),
            helper, t)
    }

    /// Creates a `Verifier` from the given buffer.
    ///
    /// Signature verifications are done relative to time `t`, or the
    /// current time, if `t` is `None`.
    pub fn from_bytes<T>(bytes: &'a [u8], helper: H, t: T)
                         -> Result<Verifier<'a, H>>
        where T: Into<Option<time::SystemTime>>
    {
        let t = t.into().unwrap_or_else(|| time::SystemTime::now().canonicalize());
        Verifier::from_buffered_reader(
            Box::new(buffered_reader::Memory::with_cookie(bytes,
                                                       Default::default())),
            helper, t)
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
    ///
    /// Signature verifications are done relative to time `t`, or the
    /// current time, if `t` is `None`.
    pub(crate) fn from_buffered_reader(bio: Box<dyn BufferedReader<Cookie> + 'a>,
                                       helper: H, t: time::SystemTime)
                                       -> Result<Verifier<'a, H>>
    {
        fn can_sign<P, R>(key: &Key<P, R>, sig: Option<&Signature>,
                          t: time::SystemTime)
            -> bool
            where P: key::KeyParts, R: key::KeyRole
        {
            if let Some(sig) = sig {
                sig.key_flags().can_sign()
                // Check expiry.
                    && sig.signature_alive(t, None)
                    && sig.key_alive(key, t)
            } else {
                false
            }
        }

        let mut ppr = PacketParser::from_buffered_reader(bio)?;

        let mut v = Verifier {
            helper: helper,
            tpks: Vec::new(),
            keys: HashMap::new(),
            oppr: None,
            structure: IMessageStructure::new(),
            reserve: None,
            time: t,
        };

        let mut issuers = Vec::new();

        while let PacketParserResult::Some(pp) = ppr {
            if let Err(err) = pp.possible_message() {
                return Err(err.context("Malformed OpenPGP message").into());
            }

            match pp.packet {
                Packet::CompressedData(ref p) =>
                    v.structure.new_compression_layer(p.algorithm()),
                Packet::OnePassSig(ref ops) => {
                    v.structure.push_ops(ops);
                    issuers.push(ops.issuer().clone());
                },
                Packet::Literal(_) => {
                    v.structure.insert_missing_signature_group();
                    // Query keys.
                    v.tpks = v.helper.get_public_keys(&issuers)?;

                    for (i, tpk) in v.tpks.iter().enumerate() {
                        if can_sign(tpk.primary(),
                                    tpk.primary_key_signature(None), t) {
                            v.keys.insert(tpk.keyid(), (i, 0));
                        }

                        for (j, skb) in tpk.subkeys().enumerate() {
                            let key = skb.key();
                            if can_sign(key, skb.binding_signature(None), t) {
                                v.keys.insert(key.keyid(),
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

            let (p, ppr_tmp) = pp.recurse()?;
            if let Packet::Signature(sig) = p {
                // The following structure is allowed:
                //
                //   SIG LITERAL
                //
                // In this case, we get the issuer from the
                // signature itself.
                if let Some(issuer) = sig.get_issuer() {
                    issuers.push(issuer);
                } else {
                    issuers.push(KeyID::wildcard());
                }

                v.structure.push_bare_signature(sig);
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
                self.structure.push_signature(sig);
            },
            _ => (),
        }
        Ok(())
    }

    // Verify the signatures.  This can only be called once the
    // message has been fully processed.
    fn check_signatures(&mut self) -> Result<()> {
        assert!(self.oppr.is_none());

        // Verify the signatures.
        let mut results = MessageStructure::new();
        for layer in ::std::mem::replace(&mut self.structure,
                                         IMessageStructure::new())
            .layers.into_iter()
        {
            match layer {
                IMessageLayer::Compression { algo } =>
                    results.new_compression_layer(algo),
                IMessageLayer::Encryption { .. } =>
                    unreachable!("not decrypting messages"),
                IMessageLayer::SignatureGroup { sigs, .. } => {
                    results.new_signature_group();
                    for sig in sigs.into_iter() {
                        let r = if let Some(issuer) = sig.get_issuer() {
                            if let Some((i, j)) =
                                self.keys.get(&issuer)
                            {
                                let tpk = &self.tpks[*i];
                                let (binding, revocation, key)
                                    = tpk.keys_all().nth(*j).unwrap();
                                if sig.verify(key).unwrap_or(false) {
                                    if sig.signature_alive(self.time, None) {
                                        VerificationResult::GoodChecksum
                                            (sig, tpk, key, binding,
                                             revocation)
                                    } else {
                                        VerificationResult::NotAlive(sig)
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
                        };
                        results.push_verification_result(r)
                    }
                },
            }
        }

        self.helper.check(&results)
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
                let data_len = pp.data(BUFFER_SIZE + 1)?.len();
                assert!(data_len <= BUFFER_SIZE);

                // Stash the reserve.
                self.reserve = Some(pp.steal_eof()?);

                // Process the rest of the packets.
                let mut ppr = PacketParserResult::Some(pp);
                while let PacketParserResult::Some(pp) = ppr {
                    if let Err(err) = pp.possible_message() {
                        return Err(err.context(
                            "Malformed OpenPGP message").into());
                    }

                    let (p, ppr_tmp) = pp.recurse()?;
                    self.push_sig(p)?;
                    ppr = ppr_tmp;
                }

                self.check_signatures()
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
    reader: Box<dyn BufferedReader<()> + 'a>,
    buffer: Vec<u8>,
}

#[derive(PartialEq, Debug)]
enum TransformationState {
    Data,
    Sigs,
    Done,
}

impl<'a> Transformer<'a> {
    fn new<'b>(signatures: Box<dyn BufferedReader<Cookie> + 'b>,
               mut data: Box<dyn BufferedReader<()> + 'a>)
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

        let mut buf = Vec::new();
        for (i, sig) in sigs.iter().rev().enumerate() {
            let mut ops = OnePassSig3::try_from(sig)?;
            if i == sigs.len() - 1 {
                ops.set_last(true);
            }

            Packet::OnePassSig(ops.into()).serialize(&mut buf)?;
        }

        // We need to decide whether to use partial body encoding or
        // not.  For partial body encoding, the first chunk must be at
        // least 512 bytes long.  Try to read 512 - HEADER_LEN bytes
        // from data.
        let state = {
            const HEADER_LEN: usize = 6;
            let data_prefix = data.data_consume(512 - HEADER_LEN)?;
            if data_prefix.len() < 512 - HEADER_LEN {
                // Too little data for a partial body encoding, produce a
                // Literal Data Packet header of known length.
                CTB::new(Tag::Literal).serialize(&mut buf)?;

                let len = BodyLength::Full((data_prefix.len() + HEADER_LEN) as u32);
                len.serialize(&mut buf)?;

                let lit = Literal::new(DataFormat::Binary);
                lit.serialize_headers(&mut buf, false)?;

                // Copy the data, then proceed directly to the signatures.
                buf.extend_from_slice(data_prefix);
                TransformationState::Sigs
            } else {
                // Produce a Literal Data Packet header with partial
                // length encoding.
                CTB::new(Tag::Literal).serialize(&mut buf)?;

                let len = BodyLength::Partial(512);
                len.serialize(&mut buf)?;

                let lit = Literal::new(DataFormat::Binary);
                lit.serialize_headers(&mut buf, false)?;

                // Copy the prefix up to the first chunk, then keep in the
                // data state.
                buf.extend_from_slice(&data_prefix[..512 - HEADER_LEN]);
                TransformationState::Data
            }
        };

        Ok(Self {
            state: state,
            sigs: sigs,
            reader: data,
            buffer: buf,
        })
    }

    fn read_helper(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.buffer.is_empty() {
            self.state = match self.state {
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
                    let data = self.reader.data_consume(s)?;
                    let data = &data[..cmp::min(s, data.len())];

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
                    for sig in self.sigs.drain(..) {
                        Packet::Signature(sig).serialize(&mut self.buffer)?;
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
///     fn check(&mut self, structure: &MessageStructure) -> Result<()> {
///         Ok(()) // Implement your verification policy here.
///     }
/// }
///
/// let signature =
///    b"-----BEGIN PGP SIGNATURE-----
///
///      wnUEABYKACcFglt+z/EWoQSOjDP6RiYzeXbZeXgGnAw0jdgsGQmQBpwMNI3YLBkA
///      AHmUAP9mpj2wV0/ekDuzxZrPQ0bnobFVaxZGg7YzdlksSOERrwEA6v6czXQjKcv2
///      KOwGTamb+ajTLQ3YRG9lh+ZYIXynvwE=
///      =IJ29
///      -----END PGP SIGNATURE-----";
///
/// let data = b"Hello World!";
/// let h = Helper {};
/// let mut v = DetachedVerifier::from_bytes(signature, data, h, None)?;
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
    ///
    /// Signature verifications are done relative to time `t`, or the
    /// current time, if `t` is `None`.
    pub fn from_reader<'a, 's, H, R, S, T>(signature_reader: S, reader: R,
                                           helper: H, t: T)
                                           -> Result<Verifier<'a, H>>
        where R: io::Read + 'a, S: io::Read + 's, H: VerificationHelper,
              T: Into<Option<time::SystemTime>>
    {
        let t = t.into()
            .unwrap_or_else(|| time::SystemTime::now().canonicalize());
        Self::from_buffered_reader(
            Box::new(buffered_reader::Generic::with_cookie(signature_reader, None,
                                                        Default::default())),
            Box::new(buffered_reader::Generic::new(reader, None)),
            helper, t)
    }

    /// Creates a `Verifier` from the given files.
    ///
    /// Signature verifications are done relative to time `t`, or the
    /// current time, if `t` is `None`.
    pub fn from_file<'a, H, P, S, T>(signature_path: S, path: P,
                                     helper: H, t: T)
                                     -> Result<Verifier<'a, H>>
        where P: AsRef<Path>, S: AsRef<Path>, H: VerificationHelper,
              T: Into<Option<time::SystemTime>>
    {
        let t = t.into()
            .unwrap_or_else(|| time::SystemTime::now().canonicalize());
        Self::from_buffered_reader(
            Box::new(buffered_reader::File::with_cookie(signature_path,
                                                     Default::default())?),
            Box::new(buffered_reader::File::open(path)?),
            helper, t)
    }

    /// Creates a `Verifier` from the given buffers.
    ///
    /// Signature verifications are done relative to time `t`, or the
    /// current time, if `t` is `None`.
    pub fn from_bytes<'a, 's, H, T>(signature_bytes: &'s [u8], bytes: &'a [u8],
                                    helper: H, t: T)
                                    -> Result<Verifier<'a, H>>
        where H: VerificationHelper, T: Into<Option<time::SystemTime>>
    {
        let t = t.into().unwrap_or_else(|| time::SystemTime::now().canonicalize());
        Self::from_buffered_reader(
            Box::new(buffered_reader::Memory::with_cookie(signature_bytes,
                                                          Default::default())),
            Box::new(buffered_reader::Memory::new(bytes)),
            helper, t)
    }

    /// Creates the `Verifier`, and buffers the data up to `BUFFER_SIZE`.
    ///
    /// Signature verifications are done relative to time `t`, or the
    /// current time, if `t` is `None`.
    pub(crate) fn from_buffered_reader<'a, 's, H>
        (signature_bio: Box<dyn BufferedReader<Cookie> + 's>,
         reader: Box<dyn BufferedReader<()> + 'a>,
         helper: H, t: time::SystemTime)
         -> Result<Verifier<'a, H>>
        where H: VerificationHelper
    {
        Verifier::from_buffered_reader(
            Box::new(buffered_reader::Generic::with_cookie(
                Transformer::new(signature_bio, reader)?,
                None, Default::default())),
            helper, t)
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
/// use openpgp::types::SymmetricAlgorithm;
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
///     fn check(&mut self, structure: &MessageStructure) -> Result<()> {
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
/// let mut v = Decryptor::from_bytes(message, h, None)?;
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
    structure: IMessageStructure,
    reserve: Option<Vec<u8>>,

    /// Signature verification relative to this time.
    time: time::SystemTime,
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
    ///
    /// Signature verifications are done relative to time `t`, or the
    /// current time, if `t` is `None`.
    pub fn from_reader<R, T>(reader: R, helper: H, t: T)
                          -> Result<Decryptor<'a, H>>
        where R: io::Read + 'a, T: Into<Option<time::SystemTime>>
    {
        let t = t.into()
            .unwrap_or_else(|| time::SystemTime::now().canonicalize());
        Decryptor::from_buffered_reader(
            Box::new(buffered_reader::Generic::with_cookie(reader, None,
                                                        Default::default())),
            helper, t)
    }

    /// Creates a `Decryptor` from the given file.
    ///
    /// Signature verifications are done relative to time `t`, or the
    /// current time, if `t` is `None`.
    pub fn from_file<P, T>(path: P, helper: H, t: T) -> Result<Decryptor<'a, H>>
        where P: AsRef<Path>,
              T: Into<Option<time::SystemTime>>
    {
        let t = t.into()
            .unwrap_or_else(|| time::SystemTime::now().canonicalize());
        Decryptor::from_buffered_reader(
            Box::new(buffered_reader::File::with_cookie(path,
                                                     Default::default())?),
            helper, t)
    }

    /// Creates a `Decryptor` from the given buffer.
    ///
    /// Signature verifications are done relative to time `t`, or the
    /// current time, if `t` is `None`.
    pub fn from_bytes<T>(bytes: &'a [u8], helper: H, t: T)
                         -> Result<Decryptor<'a, H>>
        where T: Into<Option<time::SystemTime>>
    {
        let t = t.into()
            .unwrap_or_else(|| time::SystemTime::now().canonicalize());
        Decryptor::from_buffered_reader(
            Box::new(buffered_reader::Memory::with_cookie(bytes,
                                                       Default::default())),
            helper, t)
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
    pub(crate) fn from_buffered_reader(bio: Box<dyn BufferedReader<Cookie> + 'a>,
                                       helper: H, t: time::SystemTime)
                                       -> Result<Decryptor<'a, H>>
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
            structure: IMessageStructure::new(),
            reserve: None,
            time: t,
        };

        let mut issuers = Vec::new();
        let mut pkesks: Vec<packet::PKESK> = Vec::new();
        let mut skesks: Vec<packet::SKESK> = Vec::new();
        let mut saw_content = false;

        while let PacketParserResult::Some(mut pp) = ppr {
            v.helper.inspect(&pp)?;
            if let Err(err) = pp.possible_message() {
                t!("Malformed message: {}", err);
                return Err(err.context("Malformed OpenPGP message").into());
            }

            match pp.packet {
                Packet::CompressedData(ref p) =>
                    v.structure.new_compression_layer(p.algorithm()),
                Packet::SEIP(_) | Packet::AED(_) => {
                    saw_content = true;

                    // Get the symmetric algorithm from the decryption
                    // proxy function.  This is necessary because we
                    // cannot get the algorithm from the SEIP packet.
                    let mut sym_algo = None;
                    {
                        let decryption_proxy = |algo, secret: &SessionKey| {
                            let result = pp.decrypt(algo, secret);
                            if let Ok(_) = result {
                                sym_algo = Some(algo);
                            }
                            result
                        };

                        v.identity =
                            v.helper.decrypt(&pkesks[..], &skesks[..],
                                             decryption_proxy)?;
                    }
                    if ! pp.decrypted() {
                        // XXX: That is not quite the right error to return.
                        return Err(
                            Error::InvalidSessionKey("No session key".into())
                                .into());
                    }

                    v.structure.new_encryption_layer(
                        sym_algo.expect("if we got here, sym_algo is set"),
                        if let Packet::AED(ref p) = pp.packet {
                            Some(p.aead())
                        } else {
                            None
                        });
                },
                Packet::OnePassSig(ref ops) => {
                    v.structure.push_ops(ops);
                    issuers.push(ops.issuer().clone());
                },
                Packet::Literal(_) => {
                    v.structure.insert_missing_signature_group();
                    // Query keys.
                    v.tpks = v.helper.get_public_keys(&issuers)?;

                    for (i, tpk) in v.tpks.iter().enumerate() {
                        let can_sign = |key: &key::UnspecifiedKey,
                                        sig: Option<&Signature>| -> bool
                        {
                            if let Some(sig) = sig {
                                sig.key_flags().can_sign()
                                // Check expiry.
                                    && sig.signature_alive(t, None)
                                    && sig.key_alive(key, t)
                            } else {
                                false
                            }
                        };

                        if can_sign(tpk.primary().into(),
                                    tpk.primary_key_signature(None)) {
                            v.keys.insert(tpk.keyid(), (i, 0));
                        }

                        for (j, skb) in tpk.subkeys().enumerate() {
                            let key = skb.key();
                            if can_sign(key.into(), skb.binding_signature(None)) {
                                v.keys.insert(key.keyid(), (i, j + 1));
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

            let (p, ppr_tmp) = pp.recurse()?;
            match p {
                Packet::PKESK(pkesk) => pkesks.push(pkesk),
                Packet::SKESK(skesk) => skesks.push(skesk),
                Packet::Signature(sig) => {
                    if ! saw_content {
                        // The following structure is allowed:
                        //
                        //   SIG LITERAL
                        //
                        // In this case, we get the issuer from the
                        // signature itself.
                        if let Some(issuer) = sig.get_issuer() {
                            issuers.push(issuer);
                        } else {
                            issuers.push(KeyID::wildcard());
                        }
                    }
                    v.structure.push_bare_signature(sig);
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
                self.structure.push_signature(sig);
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
                while let PacketParserResult::Some(pp) = ppr {
                    // The literal data packet was already inspected.
                    if first {
                        assert_eq!(pp.packet.tag(), packet::Tag::Literal);
                        first = false;
                    } else {
                        self.helper.inspect(&pp)?;
                    }

                    if let Err(err) = pp.possible_message() {
                        return Err(err.context(
                            "Malformed OpenPGP message").into());
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

                self.verify_signatures()
            } else {
                self.oppr = Some(PacketParserResult::Some(pp));
                Ok(())
            }
        } else {
            panic!("No ppr.");
        }
    }

    /// Verifies the signatures.
    fn verify_signatures(&mut self) -> Result<()> {
        let mut results = MessageStructure::new();
        for layer in ::std::mem::replace(&mut self.structure,
                                         IMessageStructure::new())
            .layers.into_iter()
        {
            match layer {
                IMessageLayer::Compression { algo } =>
                    results.new_compression_layer(algo),
                IMessageLayer::Encryption { sym_algo, aead_algo } =>
                    results.new_encryption_layer(sym_algo, aead_algo),
                IMessageLayer::SignatureGroup { sigs, .. } => {
                    results.new_signature_group();
                    for sig in sigs.into_iter() {
                        results.push_verification_result(
                            if let Some(issuer) = sig.get_issuer() {
                                if let Some((i, j)) = self.keys.get(&issuer) {
                                    let tpk = &self.tpks[*i];
                                    let (binding, revocation, key)
                                        = tpk.keys_all().nth(*j).unwrap();
                                    if sig.verify(key).unwrap_or(false) &&
                                        sig.signature_alive(self.time, None)
                                    {
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
                                                    (sig, tpk,
                                                     key,
                                                     binding,
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
            }
        }

        self.helper.check(&results)
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
    use super::*;
    use crate::parse::Parse;

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

        fn check(&mut self, structure: &MessageStructure) -> Result<()> {
            use self::VerificationResult::*;
            for layer in structure.iter() {
                match layer {
                    MessageLayer::SignatureGroup { ref results } =>
                        for result in results {
                            match result {
                                GoodChecksum(..) => self.good += 1,
                                MissingKey(_) => self.unknown += 1,
                                NotAlive(_) => self.bad += 1,
                                BadChecksum(_) => self.bad += 1,
                            }
                        }
                    MessageLayer::Compression { .. } => (),
                    _ => unreachable!(),
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
         .map(|f| TPK::from_bytes(crate::tests::key(f)).unwrap())
         .collect::<Vec<_>>();
        let tests = &[
            ("messages/signed-1.gpg",                      VHelper::new(1, 0, 0, 0, keys.clone())),
            ("messages/signed-1-sha256-testy.gpg",         VHelper::new(0, 1, 0, 0, keys.clone())),
            ("messages/signed-1-notarized-by-ed25519.pgp", VHelper::new(2, 0, 0, 0, keys.clone())),
            ("keys/neal.pgp",                              VHelper::new(0, 0, 0, 1, keys.clone())),
        ];

        let reference = crate::tests::manifesto();

        for (f, r) in tests {
            // Test Verifier.
            let h = VHelper::new(0, 0, 0, 0, keys.clone());
            let mut v =
                match Verifier::from_bytes(crate::tests::file(f), h,
                                           crate::frozen_time()) {
                    Ok(v) => v,
                    Err(e) => if r.error > 0 || r.unknown > 0 {
                        // Expected error.  No point in trying to read
                        // something.
                        continue;
                    } else {
                        panic!("{}: {}", f, e);
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
            assert_eq!(reference, &content[..]);

            // Test Decryptor.
            let h = VHelper::new(0, 0, 0, 0, keys.clone());
            let mut v =
                match Decryptor::from_bytes(crate::tests::file(f), h,
                                            crate::frozen_time()) {
                    Ok(v) => v,
                    Err(e) => if r.error > 0 || r.unknown > 0 {
                        // Expected error.  No point in trying to read
                        // something.
                        continue;
                    } else {
                        panic!("{}: {}", f, e);
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
            assert_eq!(reference, &content[..]);
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

            fn check(&mut self, structure: &MessageStructure) -> Result<()> {
                assert_eq!(structure.iter().count(), 2);
                for (i, layer) in structure.iter().enumerate() {
                    match layer {
                        MessageLayer::SignatureGroup { ref results } => {
                            assert_eq!(results.len(), 1);
                            if let VerificationResult::MissingKey(ref sig) =
                                results[0]
                            {
                                assert_eq!(
                                    &sig.issuer_fingerprint().unwrap()
                                        .to_string(),
                                    match i {
                                        0 => "8E8C 33FA 4626 3379 76D9  7978 069C 0C34 8DD8 2C19",
                                        1 => "C03F A641 1B03 AE12 5764  6118 7223 B566 78E0 2528",
                                        _ => unreachable!(),
                                    }
                                );
                            }
                        },
                        _ => unreachable!(),
                    }
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
        let v = Verifier::from_bytes(
            crate::tests::message("signed-1-notarized-by-ed25519.pgp"),
            VHelper(()), crate::frozen_time()).unwrap();
        assert!(v.message_processed());

        // Test decryptor.
        let v = Decryptor::from_bytes(
            crate::tests::message("signed-1-notarized-by-ed25519.pgp"),
            VHelper(()), crate::frozen_time()).unwrap();
        assert!(v.message_processed());
    }

    // This test is relatively long running in debug mode.  Split it
    // up.
    fn detached_verifier_read_size(l: usize) {
        use crate::conversions::Time;

        struct Test<'a> {
            sig: &'a [u8],
            content: &'a [u8],
            reference: time::SystemTime,
        };
        let tests = [
            Test {
                sig: crate::tests::message(
                    "a-cypherpunks-manifesto.txt.ed25519.sig"),
                content: crate::tests::manifesto(),
                reference: crate::frozen_time(),
            },
            Test {
                sig: crate::tests::message(
                    "emmelie-dorothea-dina-samantha-awina-detached-signature-of-100MB-of-zeros.sig"),
                content: &vec![ 0; 100 * 1024 * 1024 ][..],
                reference: time::SystemTime::from_pgp(1572602018),
            },
        ];

        let keys = [
            "emmelie-dorothea-dina-samantha-awina-ed25519.pgp"
        ].iter()
            .map(|f| TPK::from_bytes(crate::tests::key(f)).unwrap())
            .collect::<Vec<_>>();

        let mut buffer = Vec::with_capacity(104 * 1024 * 1024);
        buffer.resize(buffer.capacity(), 0);

        let read_to_end = |v: &mut Verifier<_>, l, buffer: &mut Vec<_>| {
            let mut offset = 0;
            loop {
                if offset + l > buffer.len() {
                    if buffer.len() < buffer.capacity() {
                        // Use the available capacity.
                        buffer.resize(buffer.capacity(), 0);
                    } else {
                        // Double the capacity and size.
                        buffer.resize(buffer.capacity() * 2, 0);
                    }
                }
                match v.read(&mut buffer[offset..offset + l]) {
                    Ok(0) => break,
                    Ok(l) => offset += l,
                    Err(err) => panic!("Error reading data: {:?}", err),
                }
            }

            offset
        };

        for test in tests.iter() {
            let sig = test.sig;
            let content = test.content;
            let reference = test.reference;

            let h = VHelper::new(0, 0, 0, 0, keys.clone());
            let mut v = DetachedVerifier::from_bytes(
                sig, content, h, reference).unwrap();

            let got = read_to_end(&mut v, l, &mut buffer);
            assert!(v.message_processed());
            let got = &buffer[..got];
            assert_eq!(got.len(), content.len());
            assert_eq!(got, &content[..]);

            let h = v.into_helper();
            assert_eq!(h.good, 1);
            assert_eq!(h.bad, 0);

            // Same, but with readers.
            use std::io::Cursor;
            let h = VHelper::new(0, 0, 0, 0, keys.clone());
            let mut v = DetachedVerifier::from_reader(
                Cursor::new(sig), Cursor::new(content),
                h, reference).unwrap();

            let got = read_to_end(&mut v, l, &mut buffer);
            let got = &buffer[..got];
            assert!(v.message_processed());
            assert_eq!(got.len(), content.len());
            assert_eq!(got, &content[..]);
        }
    }

    #[test]
    fn detached_verifier1() {
        // Transformer::read_helper rounds up to 4 MB chunks try
        // chunk sizes around that size.
        detached_verifier_read_size(4 * 1024 * 1024 - 1);
    }
    #[test]
    fn detached_verifier2() {
        detached_verifier_read_size(4 * 1024 * 1024);
    }
    #[test]
    fn detached_verifier3() {
        detached_verifier_read_size(4 * 1024 * 1024 + 1);
    }

    #[test]
    fn verify_long_message() {
        use crate::tpk::{TPKBuilder, CipherSuite};
        use crate::serialize::stream::{LiteralWriter, Signer, Message};
        use std::io::Write;

        let (tpk, _) = TPKBuilder::new()
            .set_cipher_suite(CipherSuite::Cv25519)
            .add_signing_subkey()
            .generate().unwrap();

        // sign 30MiB message
        let mut buf = vec![];
        {
            let key = tpk.keys_all().signing_capable().nth(0).unwrap().2;
            let keypair =
                key.clone().mark_parts_secret().unwrap()
                .into_keypair().unwrap();

            let m = Message::new(&mut buf);
            let signer = Signer::new(m, keypair).build().unwrap();
            let mut ls = LiteralWriter::new(signer).build().unwrap();

            ls.write_all(&mut vec![42u8; 30 * 1024 * 1024]).unwrap();
            ls.finalize().unwrap();
        }

        // Test Verifier.
        let h = VHelper::new(0, 0, 0, 0, vec![tpk.clone()]);
        let mut v = Verifier::from_bytes(&buf, h, None).unwrap();

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
        let mut v = Verifier::from_bytes(&buf, h, None).unwrap();

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
        let mut v = Decryptor::from_bytes(&buf, h, None).unwrap();

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
        let mut v = Decryptor::from_bytes(&buf, h, None).unwrap();

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
