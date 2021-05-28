use anyhow::Context as _;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::time::SystemTime;
use tempfile::NamedTempFile;

use sequoia_openpgp as openpgp;
use crate::openpgp::armor;
use crate::openpgp::{Packet, Result};
use crate::openpgp::packet::prelude::*;
use crate::openpgp::packet::signature::subpacket::NotationData;
use crate::openpgp::parse::{
    Parse,
    PacketParserResult,
};
use crate::openpgp::serialize::Serialize;
use crate::openpgp::serialize::stream::{
    Message, Armorer, Signer, LiteralWriter,
};
use crate::openpgp::types::SignatureType;

use crate::secrets::PreSecret;

use crate::Config;

pub struct SignOpts<'a> {
    pub config: Config<'a>,
    pub private_key_store: Option<&'a str>,
    pub input: &'a mut (dyn io::Read + Sync + Send),
    pub output_path: Option<&'a str>,
    pub presecrets: Vec<PreSecret>,
    pub detached: bool,
    pub binary: bool,
    pub append: bool,
    pub notarize: bool,
    pub time: Option<SystemTime>,
    pub notations: &'a [(bool, NotationData)]
}

pub fn sign(opts: SignOpts) -> Result<()> {
    match (opts.detached, opts.append|opts.notarize) {
        (_, false) | (true, true) =>
            sign_data(opts),
        (false, true) =>
            sign_message(opts),
    }
}

fn sign_data(opts: SignOpts) -> Result<()> {
    let SignOpts {
        config,
        private_key_store,
        input,
        output_path,
        presecrets,
        detached,
        binary,
        append,
        time,
        notations, ..} = opts;
    let (mut output, prepend_sigs, tmp_path):
    (Box<dyn io::Write + Sync + Send>, Vec<Signature>, Option<PathBuf>) =
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
                        anyhow::anyhow!(
                            format!("{} in detached signature", p.tag()))
                            .context("Invalid detached signature")),
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
            (config.create_or_stdout_safe(output_path)?, Vec::new(), None)
        };

    let keypairs = super::get_signing_keys(&presecrets, &config.policy, private_key_store, time)?;
    if keypairs.is_empty() {
        return Err(anyhow::anyhow!("No signing keys found"));
    }

    // Stream an OpenPGP message.
    // The sink may be a NamedTempFile.  Carefully keep a reference so
    // that we can rename it.
    let mut message = Message::new(&mut output);
    if ! binary {
        message = Armorer::new(message)
            .kind(if detached {
                armor::Kind::Signature
            } else {
                armor::Kind::Message
            })
            .build()?;
    }

    // When extending a detached signature, prepend any existing
    // signatures first.
    for sig in prepend_sigs.into_iter() {
        Packet::Signature(sig).serialize(&mut message)?;
    }

    let mut builder = SignatureBuilder::new(SignatureType::Binary);
    for (critical, n) in notations.iter() {
        builder = builder.add_notation(
            n.name(),
            n.value(),
            Some(n.flags().clone()),
            *critical)?;
    }

    let mut signing_keys = super::get_signing_keys(&presecrets,
                                               &config.policy,
                                               private_key_store,
                                               time)?;
    let crypto_signer = if let Some(key) = signing_keys.pop() {
        key
    } else {
        return Err(anyhow::anyhow!("No signing keys found"));
    };

    let mut signer = Signer::with_template(message, crypto_signer, builder);

    for s in signing_keys {
        signer = signer.add_signer(s);
    }

    if let Some(time) = time {
        signer = signer.creation_time(time);
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

    if let Some(path) = tmp_path {
        // Atomically replace the old file.
        fs::rename(path,
                   output_path.expect("must be Some if tmp_path is Some"))?;
    }
    Ok(())
}

fn sign_message(opts: SignOpts) -> Result<()> {
    let mut output =
        opts.config.create_or_stdout_pgp(opts.output_path,
                                    opts.binary,
                                    armor::Kind::Message)?;
    sign_message_(opts, &mut output)?;
    output.finalize()?;
    Ok(())
}

fn sign_message_(opts: SignOpts, output: &mut (dyn io::Write + Sync + Send)) -> Result<()>
{
    let SignOpts {
        config,
        private_key_store,
        input,
        presecrets: secrets,
        notarize,
        time,
        notations, ..
    } = opts;
    let mut keypairs = super::get_signing_keys(&secrets, &config.policy, private_key_store, time)?;
    if keypairs.is_empty() {
        return Err(anyhow::anyhow!("No signing keys found"));
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
    }
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
            return Err(err.context("Malformed OpenPGP message"));
        }

        match pp.packet {
            Packet::PKESK(_) | Packet::SKESK(_) =>
                return Err(anyhow::anyhow!(
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
                return Err(anyhow::anyhow!(
                    "Signing a compress-then-sign message is not implemented")),

            _ => (),
        }

        match state {
            State::AfterFirstSigGroup => {
                // After the first signature group, we push the signer
                // onto the writer stack.
                let mut builder = SignatureBuilder::new(SignatureType::Binary);
                for (critical, n) in notations.iter() {
                    builder = builder.add_notation(
                        n.name(),
                        n.value(),
                        Some(n.flags().clone()),
                        *critical)?;
                }

                let crypto_signer = if let Some(key) = keypairs.pop() {
                    key
                } else {
                    return Err(anyhow::anyhow!("No signing keys found"));
                };
                let mut signer = Signer::with_template(
                    sink, crypto_signer, builder);
                if let Some(time) = time {
                    signer = signer.creation_time(time);
                }
                for s in keypairs.drain(..) {
                    signer = signer.add_signer(s);
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
            return Err(err.context("Malformed OpenPGP message"));
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

pub fn clearsign(config: Config,
                 private_key_store: Option<&str>,
                 mut input: impl io::Read + Sync + Send,
                 mut output: impl io::Write + Sync + Send,
                 presecrets: Vec<PreSecret>,
                 time: Option<SystemTime>,
                 notations: &[(bool, NotationData)])
                 -> Result<()>
{
    let keypairs = super::get_signing_keys(&presecrets, &config.policy, private_key_store, time)?;
    if keypairs.is_empty() {
        return Err(anyhow::anyhow!("No signing keys found"));
    };

    // Prepare a signature template.
    let mut builder = SignatureBuilder::new(SignatureType::Text);
    for (critical, n) in notations.iter() {
        builder = builder.add_notation(
            n.name(),
            n.value(),
            Some(n.flags().clone()),
            *critical)?;
    }

    let message = Message::new(&mut output);

    let mut signing_keys = super::get_signing_keys(&presecrets,
                                               &config.policy,
                                               private_key_store,
                                               time)?;
    let crypto_signer = if let Some(key) = signing_keys.pop() {
        key
    } else {
        return Err(anyhow::anyhow!("No signing keys found"));
    };
    let mut signer = Signer::with_template(message, crypto_signer, builder)
        .cleartext();
    if let Some(time) = time {
        signer = signer.creation_time(time);
    }
    for s in signing_keys {
        signer = signer.add_signer(s);
    }
    let mut message = signer.build().context("Failed to create signer")?;

    // Finally, copy stdin to our writer stack to sign the data.
    io::copy(&mut input, &mut message)
        .context("Failed to sign")?;

    message.finalize()
        .context("Failed to sign")?;

    Ok(())
}
