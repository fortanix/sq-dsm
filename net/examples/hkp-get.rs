use std::{
    env,
    io,
};

use sequoia_openpgp::{
    Fingerprint,
    Result,
    serialize::Serialize,
};

use sequoia_net::KeyServer;

#[tokio::main]
async fn main() -> Result<()> {
    let url = env::args()
        .nth(1).expect("Usage: tor-hkp-get <URL> <FINGERPRINT>");
    let handle: Fingerprint = env::args()
        .nth(2).expect("Usage: tor-hkp-get <SERVER> <FINGERPRINT>")
        .parse()?;

    let keyserver = KeyServer::new(&url)?;
    for cert in keyserver.get(handle).await? {
        cert?.armored().serialize(&mut io::stdout())?;
    }
    Ok(())
}
