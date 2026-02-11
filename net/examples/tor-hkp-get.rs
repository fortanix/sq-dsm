use std::{
    env,
    io,
    time::Duration,
};

use sequoia_openpgp::{
    self as openpgp,
    Fingerprint,
    Result,
    serialize::Serialize,
};

use sequoia_net::KeyServer;

#[tokio::main]
async fn main() -> Result<()> {
    let handle: Fingerprint = env::args()
        .nth(1).expect("Usage: tor-hkp-get <FINGERPRINT>")
        .parse()?;

    // Select a fresh circuit by providing a random username/password
    // combination to Tor.
    let mut nonce = [0; 4];
    openpgp::crypto::random(&mut nonce[..])?;
    let nonce = openpgp::fmt::hex::encode(&nonce);
    let proxy_url = format!("socks5h://anonymous:{}@127.0.0.1:9050", nonce);

    // Create a reqwest::Client with appropriate timeouts for Tor, and
    // set the local Tor client as SOCKS5 proxy.
    let client = reqwest::Client::builder()
	.connect_timeout(Duration::new(10, 0))
	.timeout(Duration::new(10, 0))
        .proxy(reqwest::Proxy::all(proxy_url)?)
        .build()?;

    // Connect to keys.openpgp.org over Tor.
    let keyserver = KeyServer::with_client(
        "hkp://zkaan2xfbuxia2wpf7ofnkbz6r5zdbbvxbunvp5g2iebopbfc4iqmbad.onion",
        client)?;

    // Finally, get the requested certificate.
    for cert in keyserver.get(handle).await? {
        cert?.armored().serialize(&mut io::stdout())?;
    }
    Ok(())
}
