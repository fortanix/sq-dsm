use sequoia_openpgp as openpgp;
use openpgp::{
    Cert,
    Result,
    armor,
    parse::Parse,
    serialize::Serialize,
};
use sequoia_autocrypt as autocrypt;

use crate::{
    Config,
    open_or_stdin,
};

pub fn dispatch(config: Config, m: &clap::ArgMatches) -> Result<()> {
    match m.subcommand() {
        ("decode",  Some(m)) => {
            let input = open_or_stdin(m.value_of("input"))?;
            let mut output =
                config.create_or_stdout_pgp(m.value_of("output"),
                                            m.is_present("binary"),
                                            armor::Kind::PublicKey)?;
            let ac = autocrypt::AutocryptHeaders::from_reader(input)?;
            for h in &ac.headers {
                if let Some(ref cert) = h.key {
                    cert.serialize(&mut output)?;
                }
            }
            output.finalize()?;
        },
        ("encode-sender",  Some(m)) => {
            let input = open_or_stdin(m.value_of("input"))?;
            let mut output =
                config.create_or_stdout_safe(m.value_of("output"))?;
            let cert = Cert::from_reader(input)?;
            let addr = m.value_of("address").map(|a| a.to_string())
                .or_else(|| {
                    cert.with_policy(&config.policy, None)
                        .and_then(|vcert| vcert.primary_userid()).ok()
                        .map(|ca| ca.userid().to_string())
                });
            let ac = autocrypt::AutocryptHeader::new_sender(
                &config.policy,
                &cert,
                &addr.ok_or(anyhow::anyhow!(
                    "No well-formed primary userid found, use \
                     --address to specify one"))?,
                m.value_of("prefer-encrypt").expect("has default"))?;
            write!(&mut output, "Autocrypt: ")?;
            ac.serialize(&mut output)?;
        },
        _ => unreachable!(),
    }

    Ok(())
}
