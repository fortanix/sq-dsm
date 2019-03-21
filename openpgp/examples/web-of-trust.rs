/// Extracts the Web-Of-Trust, i.e. the certification relation, from
/// SKS packet dump using the openpgp crate, Sequoia's low-level API.
///
/// Note that to achieve reasonable performance, you need to compile
/// Sequoia and this program with optimizations:
///
///     % cargo run -p sequoia-openpgp --example web-of-trust --release \
///           -- <packet-dump> [<packet-dump> ...]

use std::env;

extern crate sequoia_openpgp as openpgp;
use openpgp::tpk::TPKParser;
use openpgp::parse::Parse;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        panic!("Extracts the certification relation from OpenPGP packet dumps.\
                \n\nUsage: {} <packet-dump> [<packet-dump> ...]\n", args[0]);
    }

    // The issuer refers to a (sub)key, but we want to use the primary
    // keys as identifiers.  But, because there are no tools besides
    // Sequoia that support certification-capable subkeys, we will
    // assume for now that the issuer is always a primary key.

    eprintln!("Format: certifier, user-id, key");

    // For each input file, create a parser.
    for input in &args[1..] {
        eprintln!("Parsing {}...", input);
        let mut parser = TPKParser::from_file(input)
            .expect("Failed to create reader");

        for tpk in parser {
            match tpk {
                Ok(tpk) => {
                    let keyid = tpk.fingerprint().to_keyid();
                    for uidb in tpk.userids() {
                        for tps in uidb.certifications() {
                            if let Some(issuer) = tps.get_issuer() {
                                println!("{}, {:?}, {}",
                                         issuer.as_u64().unwrap(),
                                         String::from_utf8_lossy(
                                             uidb.userid().value()),
                                         keyid.as_u64().unwrap());
                            } else {
                                eprintln!("No issuer!?");
                            }
                        }
                    }
                },
                Err(e) =>
                    eprintln!("Parsing TPK failed: {}", e),
            }
        }
    }
}
