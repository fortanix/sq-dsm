use anyhow::Context as _;
use clap::ArgMatches;
use itertools::Itertools;
use std::time::{SystemTime, Duration};

use crate::openpgp::KeyHandle;
use crate::openpgp::Packet;
use crate::openpgp::Result;
use crate::openpgp::armor::{Writer, Kind};
use crate::openpgp::cert::prelude::*;
use crate::openpgp::packet::prelude::*;
use crate::openpgp::packet::signature::subpacket::SubpacketTag;
use crate::openpgp::parse::Parse;
use crate::openpgp::policy::Policy;
use crate::openpgp::serialize::Serialize;
use crate::openpgp::types::KeyFlags;
use crate::openpgp::types::SignatureType;

use crate::{
    open_or_stdin,
};
use crate::Config;
use crate::SECONDS_IN_YEAR;
use crate::parse_duration;
use crate::decrypt_key;

pub fn dispatch(config: Config, m: &clap::ArgMatches) -> Result<()> {
    match m.subcommand() {
        ("generate", Some(m)) => generate(config, m)?,
        ("extract-cert", Some(m)) => extract_cert(config, m)?,
        ("adopt", Some(m)) => adopt(config, m)?,
        ("attest-certifications", Some(m)) =>
            attest_certifications(config, m)?,
        _ => unreachable!(),
        }
    Ok(())
}

fn generate(config: Config, m: &ArgMatches) -> Result<()> {
    let mut builder = CertBuilder::new();

    // User ID
    match m.values_of("userid") {
        Some(uids) => for uid in uids {
            builder = builder.add_userid(uid);
        },
        None => {
            eprintln!("No user ID given, using direct key signature");
        }
    }

    // Expiration.
    match (m.value_of("expires"), m.value_of("expires-in")) {
        (None, None) => // Default expiration.
            builder = builder.set_validity_period(
                Some(Duration::new(3 * SECONDS_IN_YEAR, 0))),
        (Some(t), None) if t == "never" =>
            builder = builder.set_validity_period(None),
        (Some(t), None) => {
            let now = builder.creation_time()
                .unwrap_or_else(std::time::SystemTime::now);
            let expiration = SystemTime::from(
                crate::parse_iso8601(t, chrono::NaiveTime::from_hms(0, 0, 0))?);
            let validity = expiration.duration_since(now)?;
            builder = builder.set_creation_time(now)
                .set_validity_period(validity);
        },
        (None, Some(d)) if d == "never" =>
            builder = builder.set_validity_period(None),
        (None, Some(d)) => {
            let d = parse_duration(d)?;
            builder = builder.set_validity_period(Some(d));
        },
        (Some(_), Some(_)) => unreachable!("conflicting args"),
    }

    // Cipher Suite
    match m.value_of("cipher-suite") {
        Some("rsa3k") => {
            builder = builder.set_cipher_suite(CipherSuite::RSA3k);
        }
        Some("rsa4k") => {
            builder = builder.set_cipher_suite(CipherSuite::RSA4k);
        }
        Some("cv25519") => {
            builder = builder.set_cipher_suite(CipherSuite::Cv25519);
        }
        Some(ref cs) => {
            return Err(anyhow::anyhow!("Unknown cipher suite '{}'", cs));
        }
        None => panic!("argument has a default value"),
    }

    // Signing Capability
    match (m.is_present("can-sign"), m.is_present("cannot-sign")) {
        (false, false) | (true, false) => {
            builder = builder.add_signing_subkey();
        }
        (false, true) => { /* no signing subkey */ }
        (true, true) => {
            return Err(
                anyhow::anyhow!("Conflicting arguments --can-sign and --cannot-sign"));
        }
    }

    // Encryption Capability
    match (m.value_of("can-encrypt"), m.is_present("cannot-encrypt")) {
        (Some("universal"), false) | (None, false) => {
            builder = builder.add_subkey(KeyFlags::empty()
                                         .set_transport_encryption()
                                         .set_storage_encryption(),
                                         None,
                                         None);
        }
        (Some("storage"), false) => {
            builder = builder.add_storage_encryption_subkey();
        }
        (Some("transport"), false) => {
            builder = builder.add_transport_encryption_subkey();
        }
        (None, true) => { /* no encryption subkey */ }
        (Some(_), true) => {
            return Err(
                anyhow::anyhow!("Conflicting arguments --can-encrypt and \
                             --cannot-encrypt"));
        }
        (Some(ref cap), false) => {
            return Err(
                anyhow::anyhow!("Unknown encryption capability '{}'", cap));
        }
    }

    if m.is_present("with-password") {
        let p0 = rpassword::read_password_from_tty(Some(
            "Enter password to protect the key: "))?.into();
        let p1 = rpassword::read_password_from_tty(Some(
            "Repeat the password once more: "))?.into();

        if p0 == p1 {
            builder = builder.set_password(Some(p0));
        } else {
            return Err(anyhow::anyhow!("Passwords do not match."));
        }
    }

    // Generate the key
    let (cert, rev) = builder.generate()?;

    // Export
    if m.is_present("export") {
        let (key_path, rev_path) =
            match (m.value_of("export"), m.value_of("rev-cert")) {
                (Some("-"), Some("-")) =>
                    ("-".to_string(), "-".to_string()),
                (Some("-"), Some(ref rp)) =>
                    ("-".to_string(), rp.to_string()),
                (Some("-"), None) =>
                    return Err(
                        anyhow::anyhow!("Missing arguments: --rev-cert is mandatory \
                                     if --export is '-'.")),
                (Some(ref kp), None) =>
                    (kp.to_string(), format!("{}.rev", kp)),
                (Some(ref kp), Some("-")) =>
                    (kp.to_string(), "-".to_string()),
                (Some(ref kp), Some(ref rp)) =>
                    (kp.to_string(), rp.to_string()),
                _ =>
                    return Err(
                        anyhow::anyhow!("Conflicting arguments --rev-cert and \
                                     --export")),
            };

        let headers = cert.armor_headers();

        // write out key
        {
            let headers: Vec<_> = headers.iter()
                .map(|value| ("Comment", value.as_str()))
                .collect();

            let w = config.create_or_stdout_safe(Some(&key_path))?;
            let mut w = Writer::with_headers(w, Kind::SecretKey, headers)?;
            cert.as_tsk().serialize(&mut w)?;
            w.finalize()?;
        }

        // write out rev cert
        {
            let mut headers: Vec<_> = headers.iter()
                .map(|value| ("Comment", value.as_str()))
                .collect();
            headers.insert(0, ("Comment", "Revocation certificate for"));

            let w = config.create_or_stdout_safe(Some(&rev_path))?;
            let mut w = Writer::with_headers(w, Kind::Signature, headers)?;
            Packet::Signature(rev).serialize(&mut w)?;
            w.finalize()?;
        }
    } else {
        return Err(
            anyhow::anyhow!("Saving generated key to the store isn't implemented \
                         yet."));
    }

    Ok(())
}

fn extract_cert(config: Config, m: &ArgMatches) -> Result<()> {
    let input = open_or_stdin(m.value_of("input"))?;
    let mut output = config.create_or_stdout_safe(m.value_of("output"))?;

    let cert = Cert::from_reader(input)?;
    if m.is_present("binary") {
        cert.serialize(&mut output)?;
    } else {
        cert.armored().serialize(&mut output)?;
    }
    Ok(())
}

fn adopt(config: Config, m: &ArgMatches) -> Result<()> {
    let input = open_or_stdin(m.value_of("certificate"))?;
    let cert = Cert::from_reader(input)?;
    let mut wanted: Vec<(KeyHandle,
                         Option<(Key<key::PublicParts, key::SubordinateRole>,
                                 SignatureBuilder)>)>
        = vec![];

    // Gather the Key IDs / Fingerprints and make sure they are valid.
    for id in m.values_of("key").unwrap_or_default() {
        let h = id.parse::<KeyHandle>()?;
        if h.is_invalid() {
            return Err(anyhow::anyhow!(
                "Invalid Fingerprint or KeyID ('{:?}')", id));
        }
        wanted.push((h, None));
    }

    let null_policy = &crate::openpgp::policy::NullPolicy::new();
    let adoptee_policy: &dyn Policy =
        if m.values_of("allow-broken-crypto").is_some() {
            null_policy
        } else {
            &config.policy
        };

    // Find the corresponding keys.
    for keyring in m.values_of("keyring").unwrap_or_default() {
        for cert in CertParser::from_file(keyring)
            .context(format!("Parsing: {}", keyring))?
        {
            let cert = cert.context(format!("Parsing {}", keyring))?;

            let vc = match cert.with_policy(adoptee_policy, None) {
                Ok(vc) => vc,
                Err(err) => {
                    eprintln!("Ignoring {} from '{}': {}",
                              cert.keyid().to_hex(), keyring, err);
                    continue;
                }
            };

            for key in vc.keys() {
                for (id, ref mut keyo) in wanted.iter_mut() {
                    if id.aliases(key.key_handle()) {
                        match keyo {
                            Some((_, _)) =>
                                // We already saw this key.
                                (),
                            None => {
                                let sig = key.binding_signature();
                                let builder: SignatureBuilder = match sig.typ() {
                                    SignatureType::SubkeyBinding =>
                                        sig.clone().into(),
                                    SignatureType::DirectKey
                                        | SignatureType::PositiveCertification
                                        | SignatureType::CasualCertification
                                        | SignatureType::PersonaCertification
                                        | SignatureType::GenericCertification =>
                                    {
                                        // Convert to a binding
                                        // signature.
                                        let kf = sig.key_flags()
                                            .context("Missing required \
                                                      subpacket, KeyFlags")?;
                                        SignatureBuilder::new(
                                            SignatureType::SubkeyBinding)
                                            .set_key_flags(kf)?
                                    },
                                    _ => panic!("Unsupported binding \
                                                 signature: {:?}",
                                                sig),
                                };

                                *keyo = Some(
                                    (key.key().clone().role_into_subordinate(),
                                     builder));
                            }
                        }
                    }
                }
            }
        }
    }


    // If we are missing any keys, stop now.
    let missing: Vec<&KeyHandle> = wanted
        .iter()
        .filter_map(|(id, keyo)| {
            match keyo {
                Some(_) => None,
                None => Some(id),
            }
        })
        .collect();
    if missing.len() > 0 {
        return Err(anyhow::anyhow!(
            "Keys not found: {}",
            missing.iter().map(|&h| h.to_hex()).join(", ")));
    }


    let passwords = &mut Vec::new();

    // Get a signer.
    let pk = cert.primary_key().key();
    let mut pk_signer =
        decrypt_key(
            pk.clone().parts_into_secret()?,
            passwords)?
        .into_keypair()?;


    // Add the keys and signatues to cert.
    let mut packets: Vec<Packet> = vec![];
    for (_, ka) in wanted.into_iter() {
        let (key, builder) = ka.expect("Checked for missing keys above.");
        let mut builder = builder;

        // If there is a valid backsig, recreate it.
        let need_backsig = builder.key_flags()
            .map(|kf| kf.for_signing() || kf.for_certification())
            .expect("Missing keyflags");

        if need_backsig {
            // Derive a signer.
            let mut subkey_signer
                = decrypt_key(
                    key.clone().parts_into_secret()?,
                    passwords)?
                .into_keypair()?;

            let backsig = builder.embedded_signatures()
                .filter(|backsig| {
                    (*backsig).clone().verify_primary_key_binding(
                        &cert.primary_key(),
                        &key).is_ok()
                })
                .nth(0)
                .map(|sig| SignatureBuilder::from(sig.clone()))
                .unwrap_or_else(|| {
                    SignatureBuilder::new(SignatureType::PrimaryKeyBinding)
                })
                .sign_primary_key_binding(&mut subkey_signer, pk, &key)?;

            builder = builder.set_embedded_signature(backsig)?;
        } else {
            builder = builder.modify_hashed_area(|mut a| {
                a.remove_all(SubpacketTag::EmbeddedSignature);
                Ok(a)
            })?;
        }

        let mut sig = builder.sign_subkey_binding(&mut pk_signer, pk, &key)?;

        // Verify it.
        assert!(sig.verify_subkey_binding(pk_signer.public(), pk, &key)
                .is_ok());

        packets.push(key.into());
        packets.push(sig.into());
    }

    let cert = cert.clone().insert_packets(packets.clone())?;

    let mut sink = config.create_or_stdout_safe(m.value_of("output"))?;
    if m.is_present("binary") {
        cert.as_tsk().serialize(&mut sink)?;
    } else {
        cert.as_tsk().armored().serialize(&mut sink)?;
    }

    let vc = cert.with_policy(&config.policy, None).expect("still valid");
    for pair in packets[..].chunks(2) {
        let newkey: &Key<key::PublicParts, key::UnspecifiedRole> = match pair[0] {
            Packet::PublicKey(ref k) => k.into(),
            Packet::PublicSubkey(ref k) => k.into(),
            Packet::SecretKey(ref k) => k.into(),
            Packet::SecretSubkey(ref k) => k.into(),
            ref p => panic!("Expected a key, got: {:?}", p),
        };
        let newsig: &Signature = match pair[1] {
            Packet::Signature(ref s) => s,
            ref p => panic!("Expected a sig, got: {:?}", p),
        };

        let mut found = false;
        for key in vc.keys() {
            if key.fingerprint() == newkey.fingerprint() {
                for sig in key.self_signatures() {
                    if sig == newsig {
                        found = true;
                        break;
                    }
                }
            }
        }
        assert!(found, "Subkey: {:?}\nSignature: {:?}", newkey, newsig);
    }

    Ok(())
}

fn attest_certifications(config: Config, m: &ArgMatches)
                         -> Result<()> {
    // XXX: This function has to do some steps manually, because
    // Sequoia does not expose this functionality because it has not
    // been standardized yet.
    use sequoia_openpgp::{
        crypto::hash::{Hash, Digest},
        packet::signature::subpacket::*,
        types::HashAlgorithm,
    };
    #[allow(non_upper_case_globals)]
    const SignatureType__AttestedKey: SignatureType =
        SignatureType::Unknown(0x16);
    #[allow(non_upper_case_globals)]
    const SubpacketTag__AttestedCertifications: SubpacketTag =
        SubpacketTag::Unknown(37);

    // Attest to all certifications?
    let all = ! m.is_present("none"); // All is the default.

    // Some configuration.
    let hash_algo = HashAlgorithm::default();
    let digest_size = hash_algo.context()?.digest_size();
    let reserve_area_space = 256; // For the other subpackets.
    let digests_per_sig = ((1usize << 16) - reserve_area_space) / digest_size;

    let input = open_or_stdin(m.value_of("key"))?;
    let key = Cert::from_reader(input)?;

    // First, remove all attestations.
    let key = Cert::from_packets(
        key.into_packets().filter(|p| match p {
            Packet::Signature(s) if s.typ() == SignatureType__AttestedKey =>
                false,
            _ => true,
        }))?;


    // Get a signer.
    let mut passwords = Vec::new();
    let pk = key.primary_key().key();
    let mut pk_signer =
        decrypt_key(
            pk.clone().parts_into_secret()?,
            &mut passwords)?
        .into_keypair()?;

    // Now, create new attestation signatures.
    let mut attestation_signatures = Vec::new();
    for uid in key.userids() {
        let mut attestations = Vec::new();

        if all {
            for certification in uid.certifications() {
                let mut h = hash_algo.context()?;
                certification.hash_for_confirmation(&mut h);
                attestations.push(h.into_digest()?);
            }
        }

        // Hashes SHOULD be sorted.
        attestations.sort();

        // All attestation signatures we generate for this component
        // should have the same creation time.  Fix it now.
        let t = std::time::SystemTime::now();

        // Hash the components like in a binding signature.
        let mut hash = hash_algo.context()?;
        key.primary_key().hash(&mut hash);
        uid.hash(&mut hash);

        for digests in attestations.chunks(digests_per_sig) {
            let mut body = Vec::with_capacity(digest_size * digests.len());
            digests.iter().for_each(|d| body.extend(d));

            attestation_signatures.push(
                SignatureBuilder::new(SignatureType__AttestedKey)
                    .set_signature_creation_time(t)?
                    .modify_hashed_area(|mut a| {
                        a.add(Subpacket::new(
                            SubpacketValue::Unknown {
                                tag: SubpacketTag__AttestedCertifications,
                                body,
                            },
                            true)?)?;
                        Ok(a)
                    })?
                    .sign_hash(&mut pk_signer, hash.clone())?);
        }
    }

    for ua in key.user_attributes() {
        let mut attestations = Vec::new();

        if all {
            for certification in ua.certifications() {
                let mut h = hash_algo.context()?;
                certification.hash_for_confirmation(&mut h);
                attestations.push(h.into_digest()?);
            }
        }

        // Hashes SHOULD be sorted.
        attestations.sort();

        // All attestation signatures we generate for this component
        // should have the same creation time.  Fix it now.
        let t = std::time::SystemTime::now();

        // Hash the components like in a binding signature.
        let mut hash = hash_algo.context()?;
        key.primary_key().hash(&mut hash);
        ua.hash(&mut hash);

        for digests in attestations.chunks(digests_per_sig) {
            let mut body = Vec::with_capacity(digest_size * digests.len());
            digests.iter().for_each(|d| body.extend(d));

            attestation_signatures.push(
                SignatureBuilder::new(SignatureType__AttestedKey)
                    .set_signature_creation_time(t)?
                    .modify_hashed_area(|mut a| {
                        a.add(Subpacket::new(
                            SubpacketValue::Unknown {
                                tag: SubpacketTag__AttestedCertifications,
                                body,
                            },
                            true)?)?;
                        Ok(a)
                    })?
                    .sign_hash(&mut pk_signer, hash.clone())?);
        }
    }

    // Finally, add the new signatures.
    let key = key.insert_packets(attestation_signatures)?;

    let mut sink = config.create_or_stdout_safe(m.value_of("output"))?;
    if m.is_present("binary") {
        key.as_tsk().serialize(&mut sink)?;
    } else {
        key.as_tsk().armored().serialize(&mut sink)?;
    }

    Ok(())
}
