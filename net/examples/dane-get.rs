//! Demonstrates how retrieve certs via DANE.

use std::{
    env,
    io,
};

use sequoia_openpgp::{
    Result,
    serialize::Serialize,
};

use sequoia_net::dane;

#[tokio::main]
async fn main() -> Result<()> {
    let address = env::args()
        .nth(1).expect("Usage: dane-get <EMAIL-ADDRESS>");

    for cert in dane::get(address).await? {
        cert?.armored().serialize(&mut io::stdout())?;
    }

    Ok(())
}
