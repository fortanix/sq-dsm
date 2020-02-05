use failure::{self, ResultExt};
use std::fs;
use std::io;
use std::path::PathBuf;
use std::time::SystemTime;
use tempfile::NamedTempFile;

extern crate sequoia_openpgp as openpgp;
use crate::openpgp::armor;
use crate::openpgp::{Packet, Result};
use crate::openpgp::packet::Signature;
use crate::openpgp::parse::{
    Parse,
    PacketParserResult,
};
use crate::openpgp::serialize::Serialize;
use crate::openpgp::serialize::stream::{
    Message, Signer, LiteralWriter,
};
use crate::openpgp::policy::Policy;
use crate::{
    create_or_stdout,
    create_or_stdout_pgp,
    Writer,
};

pub fn sign(policy: &dyn Policy,
            input: &mut dyn io::Read, output_path: Option<&str>,
            secrets: Vec<openpgp::Cert>, detached: bool, binary: bool,
            append: bool, notarize: bool, time: Option<SystemTime>,
            force: bool)
            -> Result<()> {
    match (detached, append|notarize) {
        (_, false) | (true, true) =>
            sign_data(policy, input, output_path, secrets, detached, binary,
                      append, time, force),
        (false, true) =>
            sign_message(policy, input, output_path, secrets, binary, notarize,
                         time, force),
    }
}

fn sign_data(policy: &dyn Policy,
             input: &mut dyn io::Read, output_path: Option<&str>,
             secrets: Vec<openpgp::Cert>, detached: bool, binary: bool,
             append: bool, time: Option<SystemTime>, force: bool)
             -> Result<()> {
    let (output, prepend_sigs, tmp_path):
    (Box<dyn io::Write>, Vec<Signature>, Option<PathBuf>) =
        if detached && append && output_path.is_some() {
            // First, read the existing signatures.
            let mut sigs = Vec::new();
            let mut ppr =
                openpgp::parse::PacketParser::from_file(output_path.unwrap())?;

            while let PacketParserResult::Some(pp) = ppr {
                let (packet, ppr_tmp) = pp.recurse()?;
                ppr = ppr_tmp;

                match packet {
                    Packet::Signature(sig) => sigs.push(sig),
                    p => return Err(
                        failure::err_msg(
                            format!("{} in detached signature", p.tag()))
                            .context("Invalid detached signature").into()),
                }
            }

            // Then, create a temporary file to write to.  If we are
            // successful with adding our signature(s), we rename the
            // file replacing the old one.
            let tmp_file = NamedTempFile::new_in(
                PathBuf::from(output_path.unwrap()).parent()
                    .unwrap_or(&PathBuf::from(".")))?;
            let tmp_path = tmp_file.path().into();
            (Box::new(tmp_file), sigs, Some(tmp_path))
        } else {
            (create_or_stdout(output_path, force)?, Vec::new(), None)
        };

    let mut output = Writer::from(output);
    if ! binary {
        output = output.armor(
            if detached {
                armor::Kind::Signature
            } else {
                armor::Kind::Message
            },
            &[])?;
    }

    let mut keypairs = super::get_signing_keys(&secrets, policy, time)?;
    if keypairs.is_empty() {
        return Err(failure::format_err!("No signing keys found"));
    }

    // When extending a detached signature, prepend any existing
    // signatures first.
    for sig in prepend_sigs.into_iter() {
        Packet::Signature(sig).serialize(&mut output)?;
    }

    // Stream an OpenPGP message.
    let sink = Message::new(&mut output);

    let mut signer = Signer::new(sink, keypairs.pop().unwrap());
    for s in keypairs {
        signer = signer.add_signer(s);
        if let Some(time) = time {
            signer = signer.creation_time(time);
        }
    }
    if detached {
        signer = signer.detached();
    }
    let signer = signer.build().context("Failed to create signer")?;

    let mut writer = if detached {
        // Detached signatures do not need a literal data packet, just
        // hash the data as is.
        signer
    } else {
        // We want to wrap the data in a literal data packet.
        LiteralWriter::new(signer).build()
            .context("Failed to create literal writer")?
    };

    // Finally, copy stdin to our writer stack to sign the data.
    io::copy(input, &mut writer)
        .context("Failed to sign")?;

    writer.finalize()
        .context("Failed to sign")?;
    // The sink may be a NamedTempFile.  Carefully keep a reference so
    // that we can rename it.
    let tmp = output.finalize()?;

    if let Some(path) = tmp_path {
        // Atomically replace the old file.
        fs::rename(path,
                   output_path.expect("must be Some if tmp_path is Some"))?;
    }
    drop(tmp);
    Ok(())
}

fn sign_message(policy: &dyn Policy,
                input: &mut dyn io::Read, output_path: Option<&str>,
                secrets: Vec<openpgp::Cert>, binary: bool, notarize: bool,
                time: Option<SystemTime>, force: bool)
             -> Result<()> {
    let mut output =
        create_or_stdout_pgp(output_path, force,
                             binary,
                             armor::Kind::Message)?;
    sign_message_(policy, input, &mut output, secrets, notarize, time)?;
    output.finalize()?;
    Ok(())
}

fn sign_message_(policy: &dyn Policy,
                 input: &mut dyn io::Read, output: &mut dyn io::Write,
                 secrets: Vec<openpgp::Cert>, notarize: bool,
                 time: Option<SystemTime>)
                 -> Result<()>
{
    let mut keypairs = super::get_signing_keys(&secrets, policy, time)?;
    if keypairs.is_empty() {
        return Err(failure::format_err!("No signing keys found"));
    }

    let mut sink = Message::new(output);

    // Create a parser for the message to be notarized.
    let mut ppr
        = openpgp::parse::PacketParser::from_reader(input)
        .context("Failed to build parser")?;

    // Once we see a signature, we can no longer strip compression.
    let mut seen_signature = false;
    #[derive(PartialEq, Eq, Debug)]
    enum State {
        InFirstSigGroup,
        AfterFirstSigGroup,
        Signing {
            // Counts how many signatures are being notarized.  If
            // this drops to zero, we pop the signer from the stack.
            signature_count: isize,
        },
        Done,
    };
    let mut state =
        if ! notarize {
            State::InFirstSigGroup
        } else {
            // Pretend we have passed the first signature group so
            // that we put our signature first.
            State::AfterFirstSigGroup
        };

    while let PacketParserResult::Some(mut pp) = ppr {
        if let Err(err) = pp.possible_message() {
            return Err(err.context("Malformed OpenPGP message").into());
        }

        match pp.packet {
            Packet::PKESK(_) | Packet::SKESK(_) =>
                return Err(failure::err_msg(
                    "Signing encrypted data is not implemented")),

            Packet::Literal(_) =>
                if let State::InFirstSigGroup = state {
                    // Cope with messages that have no signatures, or
                    // with a ops packet without the last flag.
                    state = State::AfterFirstSigGroup;
                },

            // To implement this, we'd need to stream the
            // compressed data packet inclusive framing, but
            // currently the partial body filter transparently
            // removes the framing.
            //
            // If you do implement this, there is a half-disabled test
            // in tests/sq-sign.rs.
            Packet::CompressedData(_) if seen_signature =>
                return Err(failure::err_msg(
                    "Signing a compress-then-sign message is not implemented")),

            _ => (),
        }

        match state {
            State::AfterFirstSigGroup => {
                // After the first signature group, we push the signer
                // onto the writer stack.
                let mut signer = Signer::new(sink, keypairs.pop().unwrap());
                for s in keypairs.drain(..) {
                    signer = signer.add_signer(s);
                    if let Some(time) = time {
                        signer = signer.creation_time(time);
                    }
                }
                sink = signer.build().context("Failed to create signer")?;
                state = State::Signing { signature_count: 0, };
            },

            State::Signing { signature_count } if signature_count == 0 => {
                // All signatures that are being notarized are
                // written, pop the signer from the writer stack.
                sink = sink.finalize_one()
                    .context("Failed to sign data")?
                    .unwrap();
                state = State::Done;
            },

            _ => (),
        }

        if let Packet::Literal(_) = pp.packet {
            let l = if let Packet::Literal(l) = pp.packet.clone() {
                l
            } else {
                unreachable!()
            };
            // Create a literal writer to wrap the data in a literal
            // message packet.
            let mut literal = LiteralWriter::new(sink).format(l.format());
            if let Some(f) = l.filename() {
                literal = literal.filename(f)?;
            }
            if let Some(d) = l.date() {
                literal = literal.date(d)?;
            }

            let mut literal = literal.build()
                .context("Failed to create literal writer")?;

            // Finally, just copy all the data.
            io::copy(&mut pp, &mut literal)
                .context("Failed to sign data")?;

            // Pop the literal writer.
            sink = literal.finalize_one()
                .context("Failed to sign data")?
                .unwrap();
        }

        let (packet, ppr_tmp) = if seen_signature {
            // Once we see a signature, we can no longer strip
            // compression.
            pp.next()
        } else {
            pp.recurse()
        }.context("Parsing failed")?;
        ppr = ppr_tmp;

        match packet {
            Packet::OnePassSig(mut ops) => {
                let was_last = ops.last();
                match state {
                    State::InFirstSigGroup => {
                        // We want to append our signature here, hence
                        // we set last to false.
                        ops.set_last(false);

                        if was_last {
                            // The signature group ends here.
                            state = State::AfterFirstSigGroup;
                        }
                    },

                    State::Signing { ref mut signature_count } =>
                        *signature_count += 1,

                    _ => (),
                }

                Packet::OnePassSig(ops).serialize(&mut sink)?;
                seen_signature = true;
            },

            Packet::Signature(sig) => {
                Packet::Signature(sig).serialize(&mut sink)
                    .context("Failed to serialize")?;
                if let State::Signing { ref mut signature_count } = state {
                    *signature_count -= 1;
                }
            },
            _ => (),
        }
    }

    if let PacketParserResult::EOF(eof) = ppr {
        if let Err(err) = eof.is_message() {
            return Err(err.context("Malformed OpenPGP message").into());
        }
    } else {
        unreachable!()
    }

    match state {
        State::Signing { signature_count } => {
            assert_eq!(signature_count, 0);
            sink.finalize()
                .context("Failed to sign data")?;
        },
        State::Done => (),
        _ => panic!("Unexpected state: {:?}", state),
    }

    Ok(())
}
