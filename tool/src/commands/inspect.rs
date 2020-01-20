use std::io::{self, Read};

use clap;

extern crate sequoia_openpgp as openpgp;
use crate::openpgp::{Packet, Result};
use crate::openpgp::parse::{Parse, PacketParserResult};

use super::dump::Convert;

pub fn inspect(m: &clap::ArgMatches, output: &mut dyn io::Write)
               -> Result<()> {
    let print_keygrips = m.is_present("keygrips");
    let print_certifications = m.is_present("certifications");

    let input = m.value_of("input");
    let input_name = input.unwrap_or("-");
    write!(output, "{}: ", input_name)?;

    let mut type_called = false;  // Did we print the type yet?
    let mut encrypted = false;    // Is it an encrypted message?
    let mut packets = Vec::new(); // Accumulator for packets.
    let mut pkesks = Vec::new();  // Accumulator for PKESKs.
    let mut n_skesks = 0;         // Number of SKESKs.
    let mut sigs = Vec::new();    // Accumulator for signatures.
    let mut literal_prefix = Vec::new();

    let mut ppr =
        openpgp::parse::PacketParser::from_reader(crate::open_or_stdin(input)?)?;
    while let PacketParserResult::Some(mut pp) = ppr {
        match pp.packet {
            Packet::PublicKey(_) | Packet::SecretKey(_) => {
                if pp.possible_cert().is_err()
                    && pp.possible_keyring().is_ok()
                {
                    if ! type_called {
                        writeln!(output, "OpenPGP Keyring.")?;
                        writeln!(output)?;
                        type_called = true;
                    }
                    let pp = openpgp::PacketPile::from(
                        ::std::mem::replace(&mut packets, Vec::new()));
                    let cert = openpgp::Cert::from_packet_pile(pp)?;
                    inspect_cert(output, &cert, print_keygrips,
                                print_certifications)?;
                }
            },
            Packet::Literal(_) => {
                pp.by_ref().take(40).read_to_end(&mut literal_prefix)?;
            },
            Packet::SEIP(_) | Packet::AED(_) => {
                encrypted = true;
            },
            _ => (),
        }

        let possible_keyring = pp.possible_keyring().is_ok();
        let (packet, ppr_) = pp.recurse()?;
        ppr = ppr_;

        match packet {
            Packet::PKESK(p) => pkesks.push(p),
            Packet::SKESK(_) => n_skesks += 1,
            Packet::Signature(s) => if possible_keyring {
                packets.push(Packet::Signature(s))
            } else {
                sigs.push(s)
            },
            _ => packets.push(packet),
        }
    }

    if let PacketParserResult::EOF(eof) = ppr {
        let is_message = eof.is_message();
        let is_cert = eof.is_cert();
        let is_keyring = eof.is_keyring();

        if is_message.is_ok() {
            writeln!(output, "{}OpenPGP Message.",
                     match (encrypted, ! sigs.is_empty()) {
                         (false, false) => "",
                         (false, true) => "Signed ",
                         (true, false) => "Encrypted ",
                         (true, true) => "Encrypted and signed ",
                     })?;
            writeln!(output)?;
            if n_skesks > 0 {
                writeln!(output, "      Passwords: {}", n_skesks)?;
            }
            for pkesk in pkesks.iter() {
                writeln!(output, "      Recipient: {}", pkesk.recipient())?;
            }
            inspect_signatures(output, &sigs)?;
            if ! literal_prefix.is_empty() {
                writeln!(output, "           Data: {:?}{}",
                         String::from_utf8_lossy(&literal_prefix),
                         if literal_prefix.len() == 40 { "..." } else { "" })?;
            }

        } else if is_cert.is_ok() || is_keyring.is_ok() {
            let pp = openpgp::PacketPile::from(packets);
            let cert = openpgp::Cert::from_packet_pile(pp)?;
            inspect_cert(output, &cert, print_keygrips, print_certifications)?;
        } else if packets.is_empty() && ! sigs.is_empty() {
            writeln!(output, "Detached signature{}.",
                     if sigs.len() > 1 { "s" } else { "" })?;
            writeln!(output)?;
            inspect_signatures(output, &sigs)?;
        } else if packets.is_empty() {
            writeln!(output, "No OpenPGP data.")?;
        } else {
            writeln!(output, "Unknown sequence of OpenPGP packets.")?;
            writeln!(output, "  Message: {}", is_message.unwrap_err())?;
            writeln!(output, "  Cert: {}", is_cert.unwrap_err())?;
            writeln!(output, "  Keyring: {}", is_keyring.unwrap_err())?;
            writeln!(output)?;
            writeln!(output, "Hint: Try 'sq packet dump {}'", input_name)?;
        }
    } else {
        unreachable!()
    }

    Ok(())
}

fn inspect_cert(output: &mut dyn io::Write, cert: &openpgp::Cert,
               print_keygrips: bool, print_certifications: bool) -> Result<()> {
    if cert.is_tsk() {
        writeln!(output, "Transferable Secret Key.")?;
    } else {
        writeln!(output, "OpenPGP Certificate.")?;
    }
    writeln!(output)?;
    writeln!(output, "    Fingerprint: {}", cert.fingerprint())?;
    inspect_revocation(output, "", cert.revoked(None))?;
    let primary = cert.primary().binding();
    inspect_key(output, "", primary.key(), cert.primary_key_signature(None),
                primary.certifications(),
                print_keygrips, print_certifications)?;
    writeln!(output)?;

    for ka in cert.keys().skip(1) {
        writeln!(output, "         Subkey: {}", ka.key().fingerprint())?;
        match ka.policy(None) {
            Ok(ka) => {
                inspect_revocation(output, "", ka.revoked())?;
                inspect_key(output, "", ka.key(), Some(ka.binding_signature()),
                            ka.binding().certifications(),
                            print_keygrips, print_certifications)?;
            }
            Err(err) =>
                writeln!(output, "             Not valid: {}", err)?,
        }
        writeln!(output)?;
    }

    for uidb in cert.userids().bindings() {
        writeln!(output, "         UserID: {}", uidb.userid())?;
        inspect_revocation(output, "", uidb.revoked(None))?;
        if let Some(sig) = uidb.binding_signature(None) {
            if let Err(e) =
                sig.signature_alive(None, std::time::Duration::new(0, 0))
            {
                writeln!(output, "                 Invalid: {}", e)?;
            }
        }
        inspect_certifications(output,
                               uidb.certifications(),
                               print_certifications)?;
        writeln!(output)?;
    }

    Ok(())
}

fn inspect_key<P, R>(output: &mut dyn io::Write,
                     indent: &str,
                     key: &openpgp::packet::Key<P, R>,
                     binding_signature: Option<&openpgp::packet::Signature>,
                     certs: &[openpgp::packet::Signature],
                     print_keygrips: bool,
                     print_certifications: bool)
        -> Result<()>
        where P: openpgp::packet::key::KeyParts,
              R: openpgp::packet::key::KeyRole
{
    if let Some(sig) = binding_signature {
        if let Err(e) = sig.key_alive(key, None) {
            writeln!(output, "{}                 Invalid: {}", indent, e)?;
        }
    }

    if print_keygrips {
        writeln!(output, "{}        Keygrip: {}", indent,
                 key.mpis().keygrip()?)?;
    }
    writeln!(output, "{}Public-key algo: {}", indent, key.pk_algo())?;
    if let Some(bits) = key.mpis().bits() {
        writeln!(output, "{}Public-key size: {} bits", indent, bits)?;
    }
    writeln!(output, "{}  Creation time: {}", indent,
             key.creation_time().convert())?;
    if let Some(sig) = binding_signature {
        if let Some(expires) = sig.key_expiration_time() {
            let expiration_time = key.creation_time() + expires;
            writeln!(output, "{}Expiration time: {} (creation time + {})",
                     indent,
                     expiration_time.convert(),
                     expires.convert())?;
        }

        if let Some(flags) = sig.key_flags().and_then(inspect_key_flags) {
            writeln!(output, "{}       Key flags: {}", indent, flags)?;
        }
    }
    inspect_certifications(output, certs, print_certifications)?;

    Ok(())
}

fn inspect_revocation(output: &mut dyn io::Write,
                      indent: &str,
                      revoked: openpgp::RevocationStatus)
                      -> Result<()> {
    use crate::openpgp::RevocationStatus::*;
    match revoked {
        Revoked(_) =>
            writeln!(output, "{}                 Revoked", indent)?,
        CouldBe(_) =>
            writeln!(output, "{}                 Possibly revoked", indent)?,
        NotAsFarAsWeKnow => (),
    }

    Ok(())
}

fn inspect_key_flags(flags: openpgp::types::KeyFlags) -> Option<String> {
    let mut capabilities = Vec::new();
    if flags.for_certification() {
        capabilities.push("certification")
    }
    if flags.for_signing() {
        capabilities.push("signing")
    }
    if flags.for_authentication() {
        capabilities.push("authentication")
    }
    if flags.for_transport_encryption() {
        capabilities.push("transport encryption")
    }
    if flags.for_storage_encryption() {
        capabilities.push("data-at-rest encryption")
    }

    if capabilities.len() > 0 {
        Some(capabilities.join(", "))
    } else {
        None
    }
}

fn inspect_signatures(output: &mut dyn io::Write,
                      sigs: &[openpgp::packet::Signature]) -> Result<()> {
    use crate::openpgp::types::SignatureType::*;
    for sig in sigs {
        match sig.typ() {
            Binary | Text => (),
            signature_type @ _ =>
                writeln!(output, "           Kind: {}", signature_type)?,
        }

        if let Some(fp) = sig.issuer_fingerprint() {
            writeln!(output, "      Signed by: {}", fp)?;
        } else if let Some(kid) = sig.issuer() {
            writeln!(output, "      Signed by: {}", kid)?;
        }
    }
    if ! sigs.is_empty() {
        writeln!(output, "                 \
                          Signatures have NOT been verified!")?;
    }

    Ok(())
}

fn inspect_certifications(output: &mut dyn io::Write,
                          certs: &[openpgp::packet::Signature],
                          print_certifications: bool) -> Result<()> {
    if print_certifications {
        for sig in certs {
            if let Some(fp) = sig.issuer_fingerprint() {
                writeln!(output, "   Certified by: {}", fp)?;
            } else if let Some(kid) = sig.issuer() {
                writeln!(output, "   Certified by: {}", kid)?;
            }
        }
        if ! certs.is_empty() {
            writeln!(output, "                 \
                              Certifications have NOT been verified!")?;
        }
    } else {
        if ! certs.is_empty() {
            writeln!(output, " Certifications: {}, \
                              use --certifications to list", certs.len())?;
        }
    }

    Ok(())
}
