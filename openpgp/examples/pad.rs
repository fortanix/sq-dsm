/// Asymmetrically encrypts and pads OpenPGP messages using the
/// openpgp crate, Sequoia's low-level API.

use std::env;
use std::io;

use anyhow::Context;

extern crate sequoia_openpgp as openpgp;
use crate::openpgp::armor;
use crate::openpgp::KeyID;
use crate::openpgp::types::KeyFlags;
use crate::openpgp::parse::Parse;
use crate::openpgp::serialize::stream::{
    Message, LiteralWriter, Encryptor, Recipient, padding::*,
};
use crate::openpgp::policy::StandardPolicy as P;

fn main() -> openpgp::Result<()> {
    let p = &P::new();
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        return Err(anyhow::anyhow!("A simple encryption filter.\n\n\
                Usage: {} [at-rest|for-transport] <keyfile> [<keyfile>...] \
                <input >output\n", args[0]));
    }

    let mode = match args[1].as_ref() {
        "at-rest" => KeyFlags::empty().set_storage_encryption(),
        "for-transport" => KeyFlags::empty().set_transport_encryption(),
        x => return Err(anyhow::anyhow!("invalid mode: {:?}, \
                     must be either 'at-rest' or 'for-transport'",
                    x)),
    };

    // Read the certificates from the given files.
    let certs: Vec<openpgp::Cert> = args[2..].iter().map(|f| {
        openpgp::Cert::from_file(f)
    }).collect::<openpgp::Result<Vec<_>>>().context("Failed to read key")?;

    // Build a vector of recipients to hand to Encryptor.
    let recipients = certs
        .iter()
        .flat_map(|cert| {
            cert.keys()
                .with_policy(p, None).alive().revoked(false).key_flags(&mode)
        })
        .map(|ka| Recipient::new(KeyID::wildcard(), ka.key()))
        .collect::<Vec<_>>();

    // Compose a writer stack corresponding to the output format and
    // packet structure we want.  First, we want the output to be
    // ASCII armored.
    let mut sink = armor::Writer::new(io::stdout(), armor::Kind::Message)
        .context("Failed to create an armored writer")?;

    // Stream an OpenPGP message.
    let message = Message::new(&mut sink);

    // We want to encrypt a literal data packet.
    let encryptor = Encryptor::for_recipients(message, recipients)
        .build().context("Failed to create encryptor")?;

    let padder = Padder::new(encryptor, padme)
        .context("Failed to create padder")?;

    let mut literal_writer = LiteralWriter::new(padder).build()
        .context("Failed to create literal writer")?;

    // Copy stdin to our writer stack to encrypt the data.
    io::copy(&mut io::stdin(), &mut literal_writer)
        .context("Failed to encrypt")?;

    // Finally, finalize the OpenPGP message by tearing down the
    // writer stack.
    literal_writer.finalize()?;

    // Finalize the armor writer.
    sink.finalize()
        .context("Failed to write data")?;

    Ok(())
}
