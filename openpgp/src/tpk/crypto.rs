use std::io::{Read, Write, Cursor, copy};

use {Error, tpk::TPK, armor, Result, KeyID, Fingerprint};
use constants::DataFormat;
use serialize::stream::{wrap, Encryptor, EncryptionMode, LiteralWriter};
use parse::stream::{Verifier, VerificationHelper, VerificationResult};
use failure;

/// Governs how the `senders` argument for `verify_from_senders` and `verify_stream_from_senders`
/// is interpreted. In all cases at least one signature must be valid.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum VerificationMode {
    /// The message must be signed by all key mentioned in `senders`. No other signature can be
    /// present.
    Exact,
    /// All signatures attached to the message must be by keys in `senders`. Not all keys in
    /// `senders` must sign the message.
    IgnoreSuperflouosSenders,
    /// All keys in `senders` must have signed the message. Signatures from other keys are ignored.
    IgnoreUnknownSignatures,
}

impl TPK {
    /// Encrypts message read from `input` to all keys in `recipients`.
    pub fn encrypt_stream_to_recipients<R, W>(recipients: &[&TPK], input: &mut R,
                                       mode: EncryptionMode, armor: bool, output: W)
        -> Result<()> where R: Read, W: Write
    {
        let sink = if armor {
            wrap(armor::Writer::new(output, armor::Kind::Message, &[][..])?)
        } else {
            wrap(output)
        };
        let seip = Encryptor::new(sink, &[], recipients, mode)?;
        let mut lit = LiteralWriter::new(seip, DataFormat::Binary, None, None)?;

        copy(input, &mut lit)?;
        lit.finalize()?;

        Ok(())
    }

    /// Encrypts the message read from `input` to this public key, writing the result to `output`.
    /// The message will be ascii armored if `armor` is true.
    pub fn encrypt_stream<R: Read, W: Write>(&self, input: &mut R, mode: EncryptionMode, armor: bool,
                          output: W) -> Result<()> {
        Self::encrypt_stream_to_recipients(&[self], input, mode, armor, output)
    }

    /// Encrypts the message read from `input` to all keys in `recipiens`, writing the result to `output`.
    /// The message will be ascii armored if `armor` is true.
    pub fn encrypt_to_recipients(recipients: &[&TPK], data: &[u8], mode: EncryptionMode,
                                 armor: bool) -> Result<Box<[u8]>> {
        let mut output = Cursor::new(Vec::with_capacity((data.len() as f32 * 1.3).ceil() as usize));
        let mut input = Cursor::new(data);

        Self::encrypt_stream_to_recipients(recipients, &mut input, mode, armor, &mut output)?;

        Ok(output.into_inner().into_boxed_slice())
    }

    /// Encrypts `message` to this public key, returning the ciphertext.
    /// The message will be ascii armored if `armor` is true.
    pub fn encrypt(&self, message: &[u8], mode: EncryptionMode, armor: bool)
        -> Result<Box<[u8]>>
    {
        Self::encrypt_to_recipients(&[&self], message, mode, armor)
    }

    /// Verifies the signed `message` using this key. Returns the verified potion.
    pub fn verify(&self, message: &[u8]) -> Result<Option<Box<[u8]>>> {
        Self::verify_from_senders(&[&self], message, VerificationMode::Exact)
    }

    /// Verifies the signed message read from `input` using this key. Writes the verified potion
    /// into `output`. The functin returns true if all signatures where correct, false otherwise.
    ///
    /// This function is somwhat unsafe as its only buffering up to 25MiB before
    /// writing to `output`. If the message is larger than that, unverified data in written into
    /// `output`. Make sure you check the return value before processing the data!
    pub fn verify_stream<R,W>(&self, input: R, output: W) -> Result<bool>
        where R: Read, W: Write
    {
        Self::verify_stream_from_senders(&[&self], input, VerificationMode::Exact, output)
    }

    /// Verifies the signed `message` against keys in `senders` and accoring to `mode`. Returns the
    /// verified message if signature(s) are (were) correct and None otherwise.
    pub fn verify_from_senders(senders: &[&TPK], message: &[u8], mode: VerificationMode)
        -> Result<Option<Box<[u8]>>>
    {
        let mut buf = Vec::default();
        let is_valid = Self::verify_stream_from_senders(senders, message, mode,
                                                        &mut buf)?;

        if is_valid {
            Ok(Some(buf.into_boxed_slice()))
        } else {
            Ok(None)
        }
    }

    /// Verifies a signed message read from `input` against keys in `senders` and accoring to `mode`.
    /// Writes the signed data into `output` and returns true if signature(s) are (were) correct and
    /// false otherwise.
    ///
    /// This function is somwhat unsafe as its only buffering up to 25MiB before
    /// writing to `output`. If the message is larger than that, unverified data in written into
    /// `output`. Make sure you check the return value before processing the data!
    pub fn verify_stream_from_senders<R,W>(senders: &[&TPK], input: R,
                                           mode: VerificationMode, mut output: W)
        -> Result<bool> where R: Read, W: Write
    {
        let hlp = Helper{
            good: Vec::default(),
            unknown: Vec::default(),
            bad: Vec::default(),
            errors: Vec::default(),
            keys: senders,
        };
        let mut verifier = Verifier::from_reader(input, hlp)?;

        while !verifier.message_processed()
            && verifier.helper_ref().errors.is_empty()
            && verifier.helper_ref().bad.is_empty()
        {
            copy(&mut verifier, &mut output)?;
        }

        let is_good = {
            use std::collections::HashSet;
            use std::iter::FromIterator;

            let hlp = verifier.helper_ref();
            let signers = HashSet::<Fingerprint>::from_iter(hlp.good.iter().cloned());

            if !hlp.errors.is_empty() {
                return Err(
                    Error::BadSignature(format!("Internal error: {:?}", hlp.errors))
                    .into());
            }

            (match mode {
                VerificationMode::Exact =>
                    senders.iter().all(|tpk| {
                        signers.contains(&tpk.fingerprint()) || tpk.subkeys().any(|sk| {
                            signers.contains(&sk.subkey().fingerprint())
                        })
                    }) && hlp.unknown.len() == 0,
                VerificationMode::IgnoreUnknownSignatures =>
                    hlp.good.len() >= 1,
                VerificationMode::IgnoreSuperflouosSenders =>
                    hlp.good.len() >= 1 && hlp.unknown.len() == 0,
            }) && (hlp.bad.len() == 0)
        };

        if is_good {
            copy(&mut verifier, &mut output)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

#[derive(Debug)]
struct Helper<'a> {
    good: Vec<Fingerprint>,
    bad: Vec<Fingerprint>,
    unknown: Vec<Fingerprint>,
    errors: Vec<failure::Error>,
    keys: &'a [&'a TPK],
}

impl<'a> VerificationHelper for Helper<'a> {
    fn get_public_keys(&mut self, ids: &[KeyID]) -> Result<Vec<TPK>> {
        Ok(self.keys.iter().filter(|key| {
            let my_kid = key.primary().fingerprint().to_keyid();

            ids.iter().any(|id| *id == my_kid)
        }).cloned().cloned().collect())
    }

    fn result(&mut self, result: VerificationResult) -> Result<()> {
        match result {
            VerificationResult::Good(ref sig) => {
                self.good.push(sig.issuer_fingerprint()
                    .ok_or(Error::BadSignature("No issuer".into()))?);
            }
            VerificationResult::Unknown(ref sig) => {
                self.unknown.push(sig.issuer_fingerprint()
                    .ok_or(Error::BadSignature("No issuer".into()))?);
            }
            VerificationResult::Bad(ref sig) => {
                self.bad.push(sig.issuer_fingerprint()
                    .ok_or(Error::BadSignature("No issuer".into()))?);
            }
        }
        Ok(())
    }

    fn error(&mut self, error: failure::Error) {
        self.errors.push(error);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpk::{TPKBuilder, TPK};
    use std::io::Write;
    use constants::DataFormat;
    use serialize::stream::{
        wrap, EncryptionMode, LiteralWriter,
    };

    #[test]
   fn encrypt() {
       let tpk = TPKBuilder::autocrypt().generate().unwrap();
       let _ = tpk.encrypt(&b"Hello, World"[..], EncryptionMode::AtRest, false).unwrap();

       // XXX: try decryption when implemented
   }

    #[test]
   fn encrypt_to_multiple() {
       let tpk1 = TPKBuilder::autocrypt().generate().unwrap();
       let tpk2 = TPKBuilder::autocrypt().generate().unwrap();
       let tpk3 = TPKBuilder::autocrypt().generate().unwrap();
       let _ = TPK::encrypt_to_recipients(
           &[&tpk1,&tpk2,&tpk3],
           &b"Hello, World"[..],
           EncryptionMode::AtRest, false).unwrap();

       // XXX: try decryption when implemented
   }

   #[test]
   fn verify_single() {
       use serialize::stream::Signer;

       let tsk = TPKBuilder::autocrypt().generate().unwrap();
       let msg = vec![42u8; 30 * 1024 * 1024];
       let mut o = vec![];
       {
           let signer = Signer::new(wrap(&mut o), &[&tsk]).unwrap();
           let mut ls = LiteralWriter::new(signer, DataFormat::Binary, None, None).unwrap();
           ls.write_all(&msg).unwrap();
           ls.finalize().unwrap();
       }

       let my_msg = tsk.verify(&o).unwrap().unwrap();
       assert_eq!(&my_msg[..], &msg[..]);
   }

   #[test]
   fn verify_multiple() {
       use serialize::stream::Signer;

       let tsk1 = TPKBuilder::autocrypt().generate().unwrap();
       let tsk2 = TPKBuilder::autocrypt().generate().unwrap();
       let tsk3 = TPKBuilder::autocrypt().generate().unwrap();
       let msg = vec![42u8; 30 * 1024 * 1024];
       let mut o = vec![];
       {
           let signer = Signer::new(wrap(&mut o), &[&tsk1,&tsk2]).unwrap();
           let mut ls = LiteralWriter::new(signer, DataFormat::Binary, None, None).unwrap();
           ls.write_all(&msg).unwrap();
           ls.finalize().unwrap();
       }

       let my_msg = TPK::verify_from_senders(&[&tsk1, &tsk2, &tsk1], &o, VerificationMode::Exact).unwrap().unwrap();
       assert_eq!(&my_msg[..], &msg[..]);

       assert!(TPK::verify_from_senders(&[&tsk1, &tsk2, &tsk3], &o, VerificationMode::IgnoreSuperflouosSenders).unwrap().is_some());
       assert!(TPK::verify_from_senders(&[&tsk2, &tsk3], &o, VerificationMode::IgnoreSuperflouosSenders).unwrap().is_none());
       assert!(TPK::verify_from_senders(&[&tsk3], &o, VerificationMode::IgnoreSuperflouosSenders).unwrap().is_none());

       assert!(TPK::verify_from_senders(&[&tsk1, &tsk2, &tsk3], &o, VerificationMode::IgnoreUnknownSignatures).unwrap().is_some());
       assert!(TPK::verify_from_senders(&[&tsk2], &o, VerificationMode::IgnoreUnknownSignatures).unwrap().is_some());
       assert!(TPK::verify_from_senders(&[&tsk3], &o, VerificationMode::IgnoreUnknownSignatures).unwrap().is_none());

       assert!(TPK::verify_from_senders(&[&tsk1, &tsk2, &tsk3], &o, VerificationMode::Exact).unwrap().is_none());
   }
}
