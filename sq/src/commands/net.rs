//! Network services.

use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::{
    Result,
    KeyHandle,
    KeyID,
    Fingerprint,
    cert::{
        Cert,
        CertParser,
    },
    packet::{
        UserID,
    },
    parse::Parse,
    serialize::Serialize,
};
use sequoia_net as net;
use net::{
    KeyServer,
    wkd,
};

use crate::{
    Config,
    open_or_stdin,
    serialize_keyring,
};


fn parse_network_policy(m: &clap::ArgMatches) -> net::Policy {
    match m.value_of("policy").expect("has default value") {
        "offline" => net::Policy::Offline,
        "anonymized" => net::Policy::Anonymized,
        "encrypted" => net::Policy::Encrypted,
        "insecure" => net::Policy::Insecure,
        _ => unreachable!(),
    }
}

pub fn dispatch_keyserver(config: Config, m: &clap::ArgMatches) -> Result<()> {
    let network_policy = parse_network_policy(m);
    let mut ks = if let Some(uri) = m.value_of("server") {
        KeyServer::new(network_policy, &uri)
    } else {
        KeyServer::keys_openpgp_org(network_policy)
    }.context("Malformed keyserver URI")?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?;

    match m.subcommand() {
        ("get",  Some(m)) => {
            let query = m.value_of("query").unwrap();

            let handle: Option<KeyHandle> = {
                let q_fp = query.parse::<Fingerprint>();
                let q_id = query.parse::<KeyID>();
                if let Ok(Fingerprint::V4(_)) = q_fp {
                    q_fp.ok().map(Into::into)
                } else if let Ok(KeyID::V4(_)) = q_id {
                    q_fp.ok().map(Into::into)
                } else {
                    None
                }
            };

            if let Some(handle) = handle {
                let cert = rt.block_on(ks.get(handle))
                    .context("Failed to retrieve cert")?;

                let mut output =
                    config.create_or_stdout_safe(m.value_of("output"))?;
                if ! m.is_present("binary") {
                    cert.armored().serialize(&mut output)
                } else {
                    cert.serialize(&mut output)
                }.context("Failed to serialize cert")?;
            } else if let Ok(Some(addr)) = UserID::from(query).email() {
                let certs = rt.block_on(ks.search(addr))
                    .context("Failed to retrieve certs")?;

                let mut output =
                    config.create_or_stdout_safe(m.value_of("output"))?;
                serialize_keyring(&mut output, &certs,
                                  m.is_present("binary"))?;
            } else {
                return Err(anyhow::anyhow!(
                    "Query must be a fingerprint, a keyid, \
                     or an email address: {:?}", query));
            }
        },
        ("send",  Some(m)) => {
            let mut input = open_or_stdin(m.value_of("input"))?;
            let cert = Cert::from_reader(&mut input).
                context("Malformed key")?;

            rt.block_on(ks.send(&cert))
                .context("Failed to send key to server")?;
        },
        _ => unreachable!(),
    }

    Ok(())
}

pub fn dispatch_wkd(config: Config, m: &clap::ArgMatches) -> Result<()> {
    let network_policy = parse_network_policy(m);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?;

    match m.subcommand() {
        ("url",  Some(m)) => {
            let email_address = m.value_of("input").unwrap();
            let wkd_url = wkd::Url::from(email_address)?;
            // XXX: Add other subcomand to specify whether it should be
            // created with the advanced or the direct method.
            let url = wkd_url.to_url(None)?;
            println!("{}", url);
        },
        ("get",  Some(m)) => {
            // Check that the policy allows https.
            network_policy.assert(net::Policy::Encrypted)?;

            let email_address = m.value_of("input").unwrap();
            // XXX: EmailAddress could be created here to
            // check it's a valid email address, print the error to
            // stderr and exit.
            // Because it might be created a WkdServer struct, not
            // doing it for now.
            let certs = rt.block_on(wkd::get(&email_address))?;
            // ```text
            //     The HTTP GET method MUST return the binary representation of the
            //     OpenPGP key for the given mail address.
            // [draft-koch]: https://datatracker.ietf.org/doc/html/draft-koch-openpgp-webkey-service-07
            // ```
            // But to keep the parallelism with `store export` and `keyserver get`,
            // The output is armored if not `--binary` option is given.
            let mut output =
                config.create_or_stdout_safe(m.value_of("output"))?;
            serialize_keyring(&mut output, &certs,
                              m.is_present("binary"))?;
        },
        ("generate", Some(m)) => {
            let domain = m.value_of("domain").unwrap();
            let f = open_or_stdin(m.value_of("input"))?;
            let base_path =
                m.value_of("base_directory").expect("required");
            let variant = if m.is_present("direct_method") {
                wkd::Variant::Direct
            } else {
                wkd::Variant::Advanced
            };
            let parser = CertParser::from_reader(f)?;
            let certs: Vec<Cert> = parser.filter_map(|cert| cert.ok())
                .collect();
            for cert in certs {
                wkd::insert(&base_path, domain, variant, &cert)
                    .context(format!("Failed to generate the WKD in \
                                      {}.", base_path))?;
            }
        },
        _ => unreachable!(),
    }

    Ok(())
}
