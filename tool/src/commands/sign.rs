use failure::{self, ResultExt};
use std::fs;
use std::io;
use std::path::PathBuf;
use tempfile::NamedTempFile;

extern crate sequoia_openpgp as openpgp;
use crate::openpgp::armor;
use crate::openpgp::constants::DataFormat;
use crate::openpgp::crypto;
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
use crate::create_or_stdout;

pub fn sign(input: &mut io::Read, output_path: Option<&str>,
            secrets: Vec<openpgp::TPK>, detached: bool, binary: bool,
            append: bool, notarize: bool, force: bool)
            -> Result<()> {
    match (detached, append|notarize) {
        (_, false) | (true, true) =>
            sign_data(input, output_path, secrets, detached, binary, append,
                      force),
        (false, true) =>
            sign_message(input, output_path, secrets, binary, notarize, force),
    }
}

fn sign_data(input: &mut io::Read, output_path: Option<&str>,
             secrets: Vec<openpgp::TPK>, detached: bool, binary: bool,
             append: bool, force: bool)
             -> Result<()> {
    let (mut output, prepend_sigs, tmp_path):
    (Box<io::Write>, Vec<Signature>, Option<PathBuf>) =
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

    let mut output = if ! binary {
        Box::new(armor::Writer::new(&mut output,
                                    if detached {
                                        armor::Kind::Signature
                                    } else {
                                        armor::Kind::Message
                                    },
                                    &[])?)
    } else {
        output
    };

    let mut keypairs = super::get_signing_keys(&secrets)?;
    let signers = keypairs.iter_mut()
        .map(|s| -> &mut dyn crypto::Signer<_> { s })
        .collect();

    // When extending a detached signature, prepend any existing
    // signatures first.
    for sig in prepend_sigs.into_iter() {
        Packet::Signature(sig).serialize(&mut output)?;
    }

    // Stream an OpenPGP message.
    let sink = Message::new(output);

    let signer = if detached {
        Signer::detached(sink, signers, None)
    } else {
        Signer::new(sink, signers, None)
    }.context("Failed to create signer")?;

    let mut writer = if detached {
        // Detached signatures do not need a literal data packet, just
        // hash the data as is.
        signer
    } else {
        // We want to wrap the data in a literal data packet.
        LiteralWriter::new(signer, DataFormat::Binary, None, None)
            .context("Failed to create literal writer")?
    };

    // Finally, copy stdin to our writer stack to sign the data.
    io::copy(input, &mut writer)
        .context("Failed to sign")?;

    writer.finalize()
        .context("Failed to sign")?;

    if let Some(path) = tmp_path {
        // Atomically replace the old file.
        fs::rename(path,
                   output_path.expect("must be Some if tmp_path is Some"))?;
    }
    Ok(())
}

fn sign_message(input: &mut io::Read, output_path: Option<&str>,
                secrets: Vec<openpgp::TPK>, binary: bool, notarize: bool,
                force: bool)
             -> Result<()> {
    let mut output = create_or_stdout(output_path, force)?;
    let output = if ! binary {
        Box::new(armor::Writer::new(&mut output,
                                    armor::Kind::Message,
                                    &[])?)
    } else {
        output
    };

    let mut keypairs = super::get_signing_keys(&secrets)?;
    // We need to create the signers here, so that we can take() them
    // once in the parsing loop.  We cannot create the references in
    // the loop, because the borrow checker does not understand that
    // it happens only once.
    let mut signers = Some(keypairs.iter_mut()
                           .map(|s| -> &mut dyn crypto::Signer<_> { s })
                           .collect::<Vec<&mut dyn crypto::Signer<_>>>());

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
                let signers = signers.take().expect("only happens once");
                sink = Signer::new(sink, signers, None)
                    .context("Failed to create signer")?;
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
            let mut literal =
                LiteralWriter::new(sink, l.format(), l.filename(),
                                   l.date().map(|d| *d))
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
            sink.finalize_one()
                .context("Failed to sign data")?
                .unwrap();
        },
        State::Done => (),
        _ => panic!("Unexpected state: {:?}", state),
    }

    Ok(())
}
