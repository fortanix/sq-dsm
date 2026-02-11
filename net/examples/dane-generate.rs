//! Demonstrates how to generate DANE records.

use std::env;

use sequoia_openpgp::{
    Cert,
    Result,
    parse::Parse,
    policy::StandardPolicy,
};

use sequoia_net::dane;

fn main() -> Result<()> {
    let domain = env::args()
        .nth(1).expect("Usage: dane-get <DOMAIN> <CERT-FILE>");
    let cert_file = env::args()
        .nth(2).expect("Usage: dane-get <DOMAIN> <CERT-FILE>");

    let p = StandardPolicy::new();
    let cert = Cert::from_file(cert_file)?;
    let vcert = cert.with_policy(&p, None)?;
    for record in dane::generate(&vcert, domain, None, None)? {
        println!("{}", record);
    }

    Ok(())
}
