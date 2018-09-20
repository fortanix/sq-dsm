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
    packet::Key,
    KeyID,
    Packet,
    Result,
    packet::Signature,
    TPK,
};
use parse::{
    Cookie,
    PacketParser,
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
///     fn result(&mut self, result: VerificationResult) -> Result<()> {
///         if let VerificationResult::Unknown(_) = result {
///             // We didn't supply the key, hence unknown.
///         } else {
///             panic!("unexpected result: {:?}", result);
///         }
///         Ok(())
///     }
///     fn check(&mut self) -> Result<()> {
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
    buffer: Vec<u8>,
    seen_eof: bool,
    oppr: Option<PacketParserResult<'a>>,
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
    Good(Signature),
    /// Unable to verify the signature because the key is missing.
    Unknown(Signature),
    /// The signature is bad.
    Bad(Signature),
}

/// Helper for signature verification.
pub trait VerificationHelper {
    /// Retrieves the TPKs containing the specified keys.
    fn get_public_keys(&mut self, &[KeyID]) -> Result<Vec<TPK>>;

    /// Conveys the result of a signature verification.
    ///
    /// This callback is only called before all data is returned.
    /// That is, once `io::Read` returns EOF, this callback will not
    /// be called again.  As such, any error returned by this function
    /// will abort reading, and the error will be propagated via the
    /// `io::Read` operation.
    fn result(&mut self, VerificationResult) -> Result<()>;

    /// Signals that the last signature has been verified.
    ///
    /// This is the place to implement your verification policy.
    /// Check that the required number of signatures or notarizations
    /// were confirmed as valid.
    ///
    /// This callback is only called before all data is returned.
    /// That is, once `io::Read` returns EOF, this callback will not
    /// be called again.  As such, any error returned by this function
    /// will abort reading, and the error will be propagated via the
    /// `io::Read` operation.
    fn check(&mut self) -> Result<()>;
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
        self.seen_eof
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
            buffer: Vec::new(),
            seen_eof: false,
            oppr: None,
        };

        let mut issuers = Vec::new();
        while let PacketParserResult::Some(mut pp) = ppr {
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

                    // Start to buffer the data.
                    v.fill_buffer(&mut pp, BUFFER_SIZE)?;
                },
                _ => (),
            }

            if ! v.buffer.is_empty() && ! v.seen_eof {
                // We started buffering, but we are not done with the
                // literal data packet.
                ppr = PacketParserResult::Some(pp);
                break;
            }

            let ((p, _), (ppr_tmp, _)) = pp.recurse()?;
            v.verify(p)?;
            ppr = ppr_tmp;
        }

        match ppr {
            PacketParserResult::EOF(eof) =>
                if ! eof.is_message() {
                    Err(Error::MalformedMessage(
                        "Malformed OpenPGP message".into()).into())
                } else {
                    v.helper.check()?;
                    Ok(v)
                },
            PacketParserResult::Some(pp) => {
                v.oppr = Some(PacketParserResult::Some(pp));
                Ok(v)
            },
        }
    }

    fn fill_buffer(&mut self, pp: &mut PacketParser, amount: usize)
                   -> Result<()> {
        let mut buffer = vec![0; 4096];
        while self.buffer.len() < amount {
            let l = pp.read(&mut buffer)?;
            if l == 0 {
                self.seen_eof = true;
                break;
            }

            self.buffer.extend_from_slice(&buffer[..l]);
        }
        Ok(())
    }


    /// Verifies the given Signature (if it is one), and stores the
    /// result.
    fn verify(&mut self, p: Packet) -> Result<()> {
        match p {
            Packet::Signature(sig) => {
                if let Some(issuer) = sig.get_issuer() {
                    if let Some((i, j)) = self.keys.get(&issuer) {
                        let (_, key) = self.tpks[*i].keys().nth(*j).unwrap();
                        if sig.verify(key).unwrap_or(false) {
                            self.helper.result(
                                VerificationResult::Good(sig))?;
                        } else {
                            self.helper.result(
                                VerificationResult::Bad(sig))?;
                        }
                    } else {
                        self.helper.result(
                            VerificationResult::Unknown(sig))?;
                    }
                } else {
                    self.helper.result(
                        VerificationResult::Bad(sig))?;
                }
            },
            _ => (),
        }
        Ok(())
    }

    /// Like `io::Read::read()`, but returns our `Result`.
    fn read_helper(&mut self, buf: &mut [u8]) -> Result<usize> {
        // We never return more than BUFFER_SIZE bytes.
        let n = cmp::min(buf.len(), BUFFER_SIZE);
        let buf = &mut buf[..n];

        // Make sure we have BUFFER_SIZE bytes more than requested.
        let want = buf.len() + BUFFER_SIZE;
        if self.buffer.len() < want && ! self.seen_eof {
            if let Some(mut ppr) = self.oppr.take() {
                while let PacketParserResult::Some(mut pp) = ppr {
                    if ! pp.possible_message() {
                        return Err(Error::MalformedMessage(
                            "Malformed OpenPGP message".into()).into());
                    }

                    match pp.packet {
                        Packet::Literal(_) => {
                            // Start to buffer the data.
                            self.fill_buffer(&mut pp, want)?;
                        },
                        _ => (),
                    }

                    if ! self.buffer.is_empty() && ! self.seen_eof {
                        // We started buffering, but we are not done with the
                        // literal data packet.
                        ppr = PacketParserResult::Some(pp);
                        break;
                    }

                    let ((p, _), (ppr_tmp, _)) = pp.recurse()?;
                    self.verify(p)?;
                    ppr = ppr_tmp;
                }

                match ppr {
                    PacketParserResult::EOF(eof) =>
                        if ! eof.is_message() {
                            return Err(Error::MalformedMessage(
                                "Malformed OpenPGP message".into()).into());
                        } else {
                            self.helper.check()?;
                        },
                    PacketParserResult::Some(pp) => {
                        self.oppr = Some(PacketParserResult::Some(pp));
                    },
                }
            }
        }

        let n = cmp::min(buf.len(), self.buffer.len());
        &mut buf[..n].copy_from_slice(&self.buffer[..n]);
        self.buffer.drain(..n);
        Ok(n)
    }
}

impl<'a, H: VerificationHelper> io::Read for Verifier<'a, H> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.seen_eof && self.buffer.is_empty() {
            return Ok(0);
        }

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

        fn result(&mut self, result: VerificationResult) -> Result<()> {
            use self::VerificationResult::*;
            match result {
                Good(_) => self.good += 1,
                Unknown(_) => self.unknown += 1,
                Bad(_) => self.bad += 1,
            }
            Ok(())
        }

        fn check(&mut self) -> Result<()> {
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
