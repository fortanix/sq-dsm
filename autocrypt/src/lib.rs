//! This crate deals with Autocrypt encoded data (see the [Autocrypt
//! Spec]).
//!
//!   [Autocrypt Spec]: https://autocrypt.org/level1.html#openpgp-based-key-data
//!
//! # Scope
//!
//! This implements low-level functionality like encoding and decoding
//! of Autocrypt headers and setup messages.  Note: Autocrypt is more
//! than just headers; it requires tight integration with the MUA.

#![doc(html_favicon_url = "https://docs.sequoia-pgp.org/favicon.png")]
#![doc(html_logo_url = "https://docs.sequoia-pgp.org/logo.svg")]
#![warn(missing_docs)]

use base64;

use std::convert::TryFrom;
use std::io;
use std::io::prelude::*;
use std::io::BufReader;
use std::path::Path;
use std::fs::File;
use std::str;

use sequoia_openpgp as openpgp;
use openpgp::armor;
use openpgp::Error;
pub use openpgp::Result;
use openpgp::Packet;
use openpgp::packet::SKESK;
use openpgp::cert::prelude::*;
use openpgp::parse::{
    Parse,
    PacketParserResult, PacketParser,
};
use openpgp::serialize::Serialize;
use openpgp::serialize::stream::{
    Message, LiteralWriter, Encryptor,
};
use openpgp::crypto::Password;
use openpgp::policy::Policy;
use openpgp::types::RevocationStatus;

mod cert;
pub use cert::cert_builder;

/// Version of Autocrypt to use. `Autocrypt::default()` always returns the
/// latest version.
pub enum Autocrypt {
    /// Autocrypt <= 1.0.1
    V1,
    /// Autocrypt version 1.1 (January 2019)
    V1_1,
}

impl Default for Autocrypt {
    fn default() -> Self { Autocrypt::V1_1 }
}

/// An autocrypt header attribute.
#[derive(Debug, PartialEq)]
pub struct Attribute {
    /// Whether the attribute is critical.
    pub critical: bool,
    /// The attribute's name.
    ///
    /// If the attribute is not critical, the leading underscore has
    /// been stripped.
    pub key: String,
    /// The attribute's value.
    pub value: String,
}

/// Whether the data comes from an "Autocrypt" or "Autocrypt-Gossip"
/// header.
#[derive(Debug, PartialEq)]
pub enum AutocryptHeaderType {
    /// An "Autocrypt" header.
    Sender,
    /// An "Autocrypt-Gossip" header.
    Gossip,
}

/// A parsed Autocrypt header.
#[derive(Debug, PartialEq)]
pub struct AutocryptHeader {
    /// Whether this is an "Autocrypt" or "Autocrypt-Gossip" header.
    pub header_type: AutocryptHeaderType,

    /// The parsed key data.
    pub key: Option<Cert>,

    /// All attributes.
    pub attributes: Vec<Attribute>,
}

impl AutocryptHeader {
    fn empty(header_type: AutocryptHeaderType) -> Self {
        AutocryptHeader {
            header_type: header_type,
            key: None,
            attributes: Vec::new(),
        }
    }

    /// Creates a new "Autocrypt" header.
    pub fn new_sender<'a, P>(policy: &dyn Policy,
                             cert: &Cert, addr: &str, prefer_encrypt: P)
                             -> Result<Self>
        where P: Into<Option<&'a str>>
    {
        // Minimize Cert.
        let mut acc = Vec::new();

        // The primary key and the most recent selfsig.
        let primary = cert.primary_key().with_policy(policy, None)?;
        acc.push(primary.key().clone().into());
        primary.self_signatures().take(1)
            .for_each(|s| acc.push(s.clone().into()));

        // The subkeys and the most recent selfsig.
        for skb in cert.keys().with_policy(policy, None).subkeys() {
            // Skip if revoked.
            if let RevocationStatus::Revoked(_) = skb.revocation_status() {
                continue;
            }
            if skb.for_signing() || skb.for_transport_encryption() {
                let k = skb.key().clone();
                acc.push(k.into());
                acc.push(skb.binding_signature().clone().into());
            }
        }

        // The UserIDs matching ADDR.
        let mut found_one = false;
        for uidb in cert.userids().with_policy(policy, None) {
            // XXX: Fix match once we have the rfc2822-name-addr.
            if let Ok(Some(a)) = uidb.userid().email() {
                if &a == addr {
                    acc.push(uidb.userid().clone().into());
                    acc.push(uidb.binding_signature().clone().into());
                    found_one = true;
                } else {
                    // Address is not matching.
                    continue;
                }
            } else {
                // Malformed UserID.
                continue;
            }
        }

        // User ids are only decorative in Autocrypt.  By convention,
        // the cert should include a user id matching the sender's
        // address, but we should include at least one user id.
        if ! found_one {
            if let Ok(uidb) = cert.with_policy(policy, None)?.primary_userid() {
                acc.push(uidb.userid().clone().into());
                acc.push(uidb.binding_signature().clone().into());
            }
        }

        let cleaned_cert = Cert::try_from(acc)?;

        Ok(AutocryptHeader {
            header_type: AutocryptHeaderType::Sender,
            key: Some(cleaned_cert),
            attributes: vec![
                Attribute {
                    critical: true,
                    key: "addr".into(),
                    value: addr.into(),
                },
                Attribute {
                    critical: true,
                    key: "prefer-encrypt".into(),
                    value: prefer_encrypt.into()
                        .unwrap_or("nopreference").into(),
                },
            ],
        })
    }

    /// Looks up an attribute.
    pub fn get(&self, key: &str) -> Option<&Attribute> {
        for a in &self.attributes {
            if a.key == key {
                return Some(a);
            }
        }

        None
    }

    /// Writes a serialized version of the object to `o`.
    pub fn serialize(&self, o: &mut dyn std::io::Write) -> Result<()> {
        if self.key.is_none() {
            return Err(Error::InvalidOperation("No key".into()).into());
        }

        for attr in self.attributes.iter() {
            write!(o, "{}={}; ", attr.key, attr.value)?;
        }

        let mut buf = Vec::new();
        self.key.as_ref().unwrap().serialize(&mut buf)?;
        write!(o, "keydata={} ", base64::encode(&buf))?;
        Ok(())
    }

}

/// A set of parsed Autocrypt headers.
#[derive(Debug, PartialEq)]
pub struct AutocryptHeaders {
    /// The value in the from header.
    pub from: Option<String>,

    /// Any autocrypt headers.
    pub headers: Vec<AutocryptHeader>,
}

impl AutocryptHeaders {
    fn empty() -> Self {
        AutocryptHeaders {
            from: None,
            headers: Vec::new(),
        }
    }

    fn from_lines<I: Iterator<Item = io::Result<String>>>(mut lines: I)
        -> Result<Self>
    {
        let mut headers = AutocryptHeaders::empty();

        let mut next_line = lines.next();
        while let Some(line) = next_line {
            // Return any error.
            let mut line = line?;

            if line.is_empty() {
                // End of headers.
                break;
            }

            next_line = lines.next();

            // If the line is folded (a line break was inserted in
            // front of whitespace (either a space (0x20) or a
            // horizontal tab (0x09)), then unfold it.
            //
            // See https://tools.ietf.org/html/rfc5322#section-2.2.3
            while let Some(Ok(nl)) = next_line {
                if !nl.is_empty() && (&nl[0..1] == " " || &nl[0..1] == "\t") {
                    line.push_str(&nl[..]);
                    next_line = lines.next();
                } else {
                    // Put it back.
                    next_line = Some(Ok(nl));
                    break;
                }
            }

            const AUTOCRYPT : &str = "Autocrypt: ";
            const AUTOCRYPT_GOSSIP : &str = "Autocrypt-Gossip: ";
            const FROM : &str = "From: ";

            if line.starts_with(FROM) {
                headers.from
                    = Some(line[FROM.len()..].trim_matches(' ').into());
            } else if line.starts_with(AUTOCRYPT) || line.starts_with(AUTOCRYPT_GOSSIP) {
                headers.headers.push(Self::decode_autocrypt_like_header(&line));
            }
        }

        Ok(headers)
    }

    /// Decode header that has the same format as the Autocrypt header.
    /// This function should be called only on "Autocrypt" or "Autocrypt-Gossip"
    /// headers.
    fn decode_autocrypt_like_header(line: &str) -> AutocryptHeader {
        let mut parts = line.splitn(2, ": ");
        let header_name = parts.next().unwrap();
        let ac_value = parts.next().unwrap();

        let header_type = match header_name {
            "Autocrypt" => AutocryptHeaderType::Sender,
            "Autocrypt-Gossip" => AutocryptHeaderType::Gossip,
            other => panic!("Expected Autocrypt header but found: {}", other)
        };

        let mut header = AutocryptHeader::empty(header_type);

        for pair in ac_value.split(';') {
            let pair = pair
                .splitn(2, |c| c == '=')
                .collect::<Vec<&str>>();

            let (key, value) : (String, String) = if pair.len() == 1 {
                // No value...
                (pair[0].trim_matches(' ').into(), "".into())
            } else {
                (pair[0].trim_matches(' ').into(),
                 pair[1].trim_matches(' ').into())
            };

            if key == "keydata" {
                if let Ok(decoded) = base64::decode(
                    &value.replace(" ", "")[..]) {
                    if let Ok(cert) = Cert::from_bytes(&decoded[..]) {
                        header.key = Some(cert);
                    }
                }
            }

            let critical = !key.is_empty() && &key[0..1] == "_";
            header.attributes.push(Attribute {
                critical,
                key: if critical {
                    key[1..].to_string()
                } else {
                    key
                },
                value,
            });
        }
        header
    }

    /// Parses an autocrypt header.
    ///
    /// `data` should be all of a mail's headers.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let lines = BufReader::new(io::Cursor::new(data)).lines();
        Self::from_lines(lines)
    }

    /// Parses an autocrypt header.
    ///
    /// `path` should name a file containing a single mail.  If the
    /// file is in mbox format, then only the first mail is
    /// considered.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::from_reader(File::open(path)?)
    }

    /// Parses an autocrypt header.
    ///
    /// `reader` contain a single mail.  If it contains multiple
    /// emails, then only the first mail is considered.
    pub fn from_reader<R: io::Read>(reader: R) -> Result<Self> {
        Self::from_lines(BufReader::new(reader).lines())
    }
}

/// Holds an Autocrypt Setup Message.
///
/// An [Autocrypt Setup Message] is used to transfer a private key from
/// one device to another.
///
/// [Autocrypt Setup Message]:
///   https://autocrypt.org/level1.html#autocrypt-setup-message
#[derive(Debug, PartialEq)]
pub struct AutocryptSetupMessage {
    prefer_encrypt: Option<String>,
    passcode_format: Option<String>,
    passcode: Option<Password>,
    // We only emit a "Passcode-Begin" header if this is set.  Note:
    // we don't check if this actually matches the start of the
    // passcode.
    passcode_begin: Option<String>,

    cert: Cert,
}

impl AutocryptSetupMessage {
    /// Creates a new Autocrypt Setup Message for the specified `Cert`.
    ///
    /// You can set the `prefer_encrypt` setting, which defaults to
    /// "nopreference", using `set_prefer_encrypt`.
    ///
    /// Note: this generates a random passcode.  To retrieve the
    /// passcode, use the `passcode` method.
    ///
    /// To decode an Autocrypt Setup Message, use the `from_bytes` or
    /// `from_reader` methods.
    pub fn new(cert: Cert) -> Self {
        AutocryptSetupMessage {
            prefer_encrypt: None,
            passcode: None,
            passcode_format: None,
            passcode_begin: None,
            cert,
        }
    }

    /// Sets the prefer encrypt header.
    pub fn set_prefer_encrypt(mut self, value: &str) -> Self {
        self.prefer_encrypt = Some(value.into());
        self
    }

    /// Returns the prefer encrypt header.
    pub fn prefer_encrypt(&self) -> Option<&str> {
        self.prefer_encrypt.as_ref().map(|v| &v[..])
    }


    /// Sets the "Passcode-Format" header.
    pub fn set_passcode_format(mut self, value: &str) -> Self {
        self.passcode_format = Some(value.into());
        self
    }

    /// Returns the "Passcode-Format" header.
    pub fn passcode_format(&self) -> Option<&str> {
        self.passcode_format.as_ref().map(|v| &v[..])
    }


    /// Sets the passcode.
    pub fn set_passcode(mut self, passcode: Password) -> Self {
        self.passcode = Some(passcode);
        self
    }

    /// Returns the ASM's passcode.
    ///
    /// If the passcode has not yet been generated, this returns
    /// `None`.
    pub fn passcode(&self) -> Option<&Password> {
        self.passcode.as_ref()
    }


    /// Sets the "Passcode-Begin" header.
    pub fn set_passcode_begin(mut self, value: &str) -> Self {
        self.passcode_begin = Some(value.into());
        self
    }

    /// Returns the "Passcode-Begin" header.
    pub fn passcode_begin(&self) -> Option<&str> {
        self.passcode_begin.as_ref().map(|v| &v[..])
    }


    // Generates a new passcode in "numeric9x4" format.
    fn passcode_gen() -> Password {
        use openpgp::crypto::mem;
        // Generate a random passcode.

        // The passcode consists of 36 digits, which encode
        // approximately 119 bits of information.  120 bits = 15
        // bytes.
        let mut p_as_vec = mem::Protected::from(vec![0; 15]);
        openpgp::crypto::random(&mut p_as_vec[..]);

        // Turn it into a 128-bit number.
        let mut p_as_u128 = 0u128;
        for v in p_as_vec.iter() {
            p_as_u128 = (p_as_u128 << 8) + *v as u128;
        }

        // Turn it into ASCII.
        let mut p : Vec<u8> = Vec::new();
        for i in 0..36 {
            if i > 0 && i % 4 == 0 {
                p.push(b'-');
            }

            p.push(b'0' + ((p_as_u128 as u8) % 10));
            p_as_u128 = p_as_u128 / 10;
        }

        p.into()
    }

    /// If there is no passcode, generates one.
    fn passcode_ensure(&mut self) {
        if self.passcode.is_some() {
            return;
        }

        let passcode = Self::passcode_gen();
        self.passcode_format = Some("numeric9x4".into());
        self.passcode_begin = passcode.map(|p| {
            Some(str::from_utf8(&p[..2]).unwrap().into())
        });
        self.passcode = Some(passcode);
    }

    /// Generates the Autocrypt Setup Message.
    ///
    /// The message is written to `w`.
    pub fn serialize<W>(&mut self, w: &mut W) -> Result<()>
        where W: io::Write + Send + Sync,
    {
        // The outer message is an ASCII-armored encoded message
        // containing a single SK-ESK and a single SEIP packet.  The
        // SEIP packet contains a literal data packet whose content is
        // the inner message.

        self.passcode_ensure();

        let mut headers : Vec<(&str, &str)> = Vec::new();
        if let Some(ref format) = self.passcode_format {
            headers.push(
                (&"Passphrase-Format"[..], &format[..]));
        }
        if let Some(ref begin) = self.passcode_begin {
            headers.push(
                (&"Passphrase-Begin"[..], &begin[..]));
        }

        let mut armor_writer =
            armor::Writer::with_headers(w, armor::Kind::Message, headers)?;

        {
            // Passphrase-Format header with value numeric9x4
            let m = Message::new(&mut armor_writer);
            let m = Encryptor::with_passwords(
                m, vec![self.passcode.clone().unwrap()]).build()?;

            let m = LiteralWriter::new(m).build()?;

            // The inner message is an ASCII-armored encoded Cert.
            let mut w = armor::Writer::with_headers(
                m, armor::Kind::SecretKey,
                vec![("Autocrypt-Prefer-Encrypt",
                      self.prefer_encrypt().unwrap_or(&"nopreference"[..]))])?;

            self.cert.as_tsk().serialize(&mut w)?;
            let m = w.finalize()?;
            m.finalize()?;
        }
        armor_writer.finalize()?;
        Ok(())
    }


    /// Parses the autocrypt setup message in `r`.
    ///
    /// `passcode` is the passcode used to protect the message.
    pub fn from_bytes<'a>(bytes: &'a [u8])
        -> Result<AutocryptSetupMessageParser<'a>>
    {
        Self::from_reader(bytes)
    }

    /// Parses the autocrypt setup message in `r`.
    ///
    /// `passcode` is the passcode used to protect the message.
    pub fn from_reader<'a, R: io::Read + Send + Sync + 'a>(r: R)
        -> Result<AutocryptSetupMessageParser<'a>> {
        // The outer message uses ASCII-armor.  It includes a password
        // hint.  Hence, we need to parse it aggressively.
        let mut r = armor::Reader::new(
            r, armor::ReaderMode::Tolerant(Some(armor::Kind::Message)));

        // Note, it is essential that we call r.headers here so that
        // we can return any error now and not in
        // AutocryptSetupMessageParser::header.
        let (format, begin) = {
            let headers = r.headers()?;

            let format = headers.iter()
                .filter_map(|(k, v)| {
                    if k == "Passphrase-Format" { Some(v) } else { None }
                })
                .collect::<Vec<&String>>();
            let format = if !format.is_empty() {
                // If there are multiple headers, then just silently take
                // the first one.
                Some(format[0].clone())
            } else {
                None
            };

            let begin = headers.iter()
                .filter_map(|(k, v)| {
                    if k == "Passphrase-Begin" { Some(v) } else { None }
                })
                .collect::<Vec<&String>>();
            let begin = if !begin.is_empty() {
                // If there are multiple headers, then just silently take
                // the first one.
                Some(begin[0].clone())
            } else {
                None
            };

            (format, begin)
        };

        // Get the first packet, which is the SK-ESK packet.

        let mut ppr = PacketParser::from_reader(r)?;

        // The outer message consists of exactly three packets: a
        // SK-ESK and a SEIP packet, which contains a Literal data
        // packet.

        let pp = if let PacketParserResult::Some(pp) = ppr {
            pp
        } else {
            return Err(
                Error::MalformedMessage(
                    "Premature EOF: expected an SK-ESK, encountered EOF".into())
                .into());
        };

        let (packet, ppr_) = pp.next()?;
        ppr = ppr_;

        let skesk = match packet {
            Packet::SKESK(skesk) => skesk,
            p => return Err(
                Error::MalformedMessage(
                    format!("Expected a SKESK packet, found a {}", p.tag()))
                .into()),
        };

        let pp = match ppr {
            PacketParserResult::EOF(_) =>
                return Err(
                    Error::MalformedMessage(
                        "Pre-mature EOF after reading SK-ESK packet".into())
                    .into()),
            PacketParserResult::Some(pp) => {
                match pp.packet {
                    Packet::SEIP(_) => (),
                    ref p => return Err(
                        Error::MalformedMessage(
                            format!("Expected a SEIP packet, found a {}",
                                    p.tag()))
                        .into()),
                }

                pp
            }
        };

        Ok(AutocryptSetupMessageParser {
            passcode_format: format,
            passcode_begin: begin,
            skesk: skesk,
            pp: pp,
            passcode: None,
        })
    }

    /// Returns the Cert consuming the `AutocryptSetupMessage` in the
    /// process.
    pub fn into_cert(self) -> Cert {
        self.cert
    }
}

/// A Parser for an `AutocryptSetupMessage`.
pub struct AutocryptSetupMessageParser<'a> {
    passcode_format: Option<String>,
    passcode_begin: Option<String>,
    skesk: SKESK,
    pp: PacketParser<'a>,
    passcode: Option<Password>,
}

impl<'a> AutocryptSetupMessageParser<'a> {
    /// Returns the "Passcode-Format" header.
    pub fn passcode_format(&self) -> Option<&str> {
        self.passcode_format.as_ref().map(|v| &v[..])
    }

    /// Returns the "Passcode-Begin" header.
    pub fn passcode_begin(&self) -> Option<&str> {
        self.passcode_begin.as_ref().map(|v| &v[..])
    }

    /// Tries to decrypt the message.
    ///
    /// On success, follow up with
    /// `AutocryptSetupMessageParser::parse()` to extract the
    /// `AutocryptSetupMessage`.
    pub fn decrypt(&mut self, passcode: &Password) -> Result<()> {
        if ! self.pp.encrypted() {
            return Err(
                Error::InvalidOperation("Already decrypted".into()).into());
        }

        let (algo, key) = self.skesk.decrypt(passcode)?;
        self.pp.decrypt(algo, &key)?;

        self.passcode = Some(passcode.clone());

        Ok(())
    }

    /// Finishes parsing the `AutocryptSetupMessage`.
    ///
    /// Before calling this, you must decrypt the payload using
    /// `decrypt`.
    ///
    /// If the payload has not been decrypted, returns
    /// `Error::InvalidOperation`.
    ///
    /// If the payload is malformed, returns
    /// `Error::MalformedMessage`.
    pub fn parse(self) -> Result<AutocryptSetupMessage> {
        if self.pp.encrypted() {
            return Err(
                Error::InvalidOperation("Not decrypted".into()).into());
        }

        // Recurse into the SEIP packet.
        let mut ppr = self.pp.recurse()?.1;
        if ppr.as_ref().map(|pp| pp.recursion_depth()).ok() != Some(1) {
            return Err(
                Error::MalformedMessage(
                    "SEIP container empty, but expected a Literal Data packet"
                    .into())
                .into());
        }

        // Get the literal data packet.
        let (prefer_encrypt, cert) = if let PacketParserResult::Some(mut pp) = ppr {
            match pp.packet {
                Packet::Literal(_) => (),
                p => return Err(Error::MalformedMessage(
                    format!("SEIP container contains a {}, \
                             expected a Literal Data packet",
                            p.tag())).into()),
            }

            // The inner message consists of an ASCII-armored encoded
            // Cert.
            let (prefer_encrypt, cert) = {
                let mut r = armor::Reader::new(
                    &mut pp,
                    armor::ReaderMode::Tolerant(
                        Some(armor::Kind::SecretKey)));

                let prefer_encrypt = {
                    let headers = r.headers()?;
                    let prefer_encrypt = headers.iter()
                        .filter_map(|(k, v)| {
                            if k == "Autocrypt-Prefer-Encrypt" {
                                Some(v)
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<&String>>();

                    if !prefer_encrypt.is_empty() {
                        // If there are multiple headers, then just
                        // silently take the first one.
                        Some(prefer_encrypt[0].clone())
                    } else {
                        None
                    }
                };

                let cert = Cert::from_reader(r)?;

                (prefer_encrypt, cert)
            };

            ppr = pp.recurse()?.1;

            (prefer_encrypt, cert)
        } else {
            return Err(
                Error::MalformedMessage(
                    "Pre-mature EOF after reading SEIP packet".into())
                    .into());
        };

        // Get the MDC packet.
        if let PacketParserResult::Some(pp) = ppr {
            match pp.packet {
                Packet::MDC(_) => (),
                ref p => return
                    Err(Error::MalformedMessage(
                        format!("Expected an MDC packet, got a {}",
                                p.tag()))
                        .into()),
            }

            ppr = pp.recurse()?.1;
        }

        // Make sure we reached the end of the outer message.
        match ppr {
            PacketParserResult::EOF(pp) => {
                // If we've gotten this far, then the outer message
                // has the right sequence of packets, but we haven't
                // carefully checked the nesting.  We do that now.
                if let Err(err) = pp.is_message() {
                    return Err(err.context("Invalid OpenPGP Message"));
                }
            }
            PacketParserResult::Some(pp) =>
                return Err(Error::MalformedMessage(
                    format!("Extraneous packet: {}.", pp.packet.tag()))
                           .into()),
        }

        // We're done!
        Ok(AutocryptSetupMessage {
            prefer_encrypt: prefer_encrypt,
            passcode: self.passcode,
            passcode_format: self.passcode_format,
            passcode_begin: self.passcode_begin,
            cert,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use openpgp::policy::StandardPolicy as P;

    #[test]
    fn decode_test() {
        let ac = AutocryptHeaders::from_bytes(
            &include_bytes!("../tests/data/hpk.txt")[..]
        )
        .unwrap();
        //eprintln!("ac: {:#?}", ac);

        // We expect exactly one Autocrypt header.
        assert_eq!(ac.headers.len(), 1);

        assert_eq!(ac.headers[0].header_type, AutocryptHeaderType::Sender);
        assert_eq!(ac.headers[0].get("addr").unwrap().value,
                   "holger@merlinux.eu");

        assert_eq!(ac.headers[0].get("prefer-encrypt").unwrap().value,
                   "mutual");

        let cert = ac.headers[0].key.as_ref()
            .expect("Failed to parse key material.");
        assert_eq!(cert.fingerprint(),
                   "156962B0F3115069ACA970C68E3B03A279B772D6".parse().unwrap());
        assert_eq!(cert.userids().next().unwrap().value(),
                   &b"holger krekel <holger@merlinux.eu>"[..]);


        let ac = AutocryptHeaders::from_bytes(
            &include_bytes!("../tests/data/vincent.txt")[..]
        )
        .unwrap();
        //eprintln!("ac: {:#?}", ac);

        assert_eq!(ac.from,
                   Some("Vincent Breitmoser <look@my.amazin.horse>".into()));

        // We expect exactly one Autocrypt header.
        assert_eq!(ac.headers.len(), 1);

        assert_eq!(ac.headers[0].get("addr").unwrap().value,
                   "look@my.amazin.horse");

        assert!(ac.headers[0].get("prefer_encrypt").is_none());

        let cert = ac.headers[0].key.as_ref()
            .expect("Failed to parse key material.");
        assert_eq!(cert.fingerprint(),
                   "D4AB192964F76A7F8F8A9B357BD18320DEADFA11".parse().unwrap());
        assert_eq!(cert.userids().next().unwrap().value(),
                   &b"Vincent Breitmoser <look@my.amazin.horse>"[..]);


        let ac = AutocryptHeaders::from_bytes(
            &include_bytes!("../tests/data/patrick.txt")[..]
        )
        .unwrap();
        //eprintln!("ac: {:#?}", ac);

        assert_eq!(ac.from,
                   Some("Patrick Brunschwig <patrick@enigmail.net>".into()));

        // We expect exactly one Autocrypt header.
        assert_eq!(ac.headers.len(), 1);

        assert_eq!(ac.headers[0].get("addr").unwrap().value,
                   "patrick@enigmail.net");

        assert!(ac.headers[0].get("prefer_encrypt").is_none());

        let cert = ac.headers[0].key.as_ref()
            .expect("Failed to parse key material.");
        assert_eq!(cert.fingerprint(),
                   "4F9F89F5505AC1D1A260631CDB1187B9DD5F693B".parse().unwrap());
        assert_eq!(cert.userids().next().unwrap().value(),
                   &b"Patrick Brunschwig <patrick@enigmail.net>"[..]);

        let ac2 = AutocryptHeaders::from_bytes(
            &include_bytes!("../tests/data/patrick_unfolded.txt")[..]
        )
        .unwrap();
        assert_eq!(ac, ac2);
    }


    #[test]
    fn decode_gossip() {
        let ac = AutocryptHeaders::from_bytes(
            &include_bytes!("../tests/data/gossip.txt")[..]
        )
        .unwrap();
        //eprintln!("ac: {:#?}", ac);

        // We expect exactly two Autocrypt headers.
        assert_eq!(ac.headers.len(), 2);

        assert_eq!(ac.headers[0].header_type, AutocryptHeaderType::Gossip);
        assert_eq!(ac.headers[0].get("addr").unwrap().value,
                "dkg@fifthhorseman.net");

        assert_eq!(ac.headers[1].get("addr").unwrap().value,
                "neal@walfield.org");

        let cert = ac.headers[0].key.as_ref()
            .expect("Failed to parse key material.");
        assert_eq!(cert.fingerprint(),
                   "C4BC2DDB38CCE96485EBE9C2F20691179038E5C6".parse().unwrap());
        assert_eq!(cert.userids().next().unwrap().value(),
                &b"Daniel Kahn Gillmor <dkg@fifthhorseman.net>"[..]);

    }

    #[test]
    fn passcode_gen_test() {
        let mut dist = [0usize; 10];

        let samples = 8 * 1024;

        // 36 digits grouped into four digits, each group
        // separated by a dash.
        let digits = 36;
        let passcode_len = 36 + (36 / 4 - 1);

        for _ in 0..samples {
            let p = AutocryptSetupMessage::passcode_gen();
            p.map(|p| {
                assert_eq!(p.len(), passcode_len);

                for c in p.iter() {
                    match *c as char {
                        '0'|'1'|'2'|'3'|'4'|'5'|'6'|'7'|'8'|'9' => {
                            let i = *c as usize - ('0' as usize);
                            dist[i] = dist[i] + 1
                        },
                        '-' => (),
                        _ => panic!("Unexpected character in passcode: {}", c),
                    }
                }
            });
        }

        // Make sure the distribution is reasonable.  If this runs
        // long enough, then of course, this test will eventually
        // fail.  But, it is extremely unlikely and suggests a failure
        // in the random number generator or the code.

        let expected_value = (samples * digits) as f32 / 10.;
        // We expect each digit to occur within 10% of its expected
        // value.
        let lower = (expected_value * 0.9) as usize;
        let upper = (expected_value * 1.1) as usize;
        let expected_value = expected_value as usize;

        eprintln!("Distribution (expected value: {}, bounds: {}..{}):",
                  expected_value, lower, upper);
        let mut bad = 0;
        for (i, count) in dist.iter()
            .map(|x| *x)
            .enumerate()
            .collect::<Vec<(usize, usize)>>()
        {
            let is_good = lower < count && count < upper;
            eprintln!("{}: {} occurrences{}.",
                      i, count, if is_good { "" } else { " UNLIKELY" });

            if !is_good {
                bad = bad + 1;
            }
        }

        // Allow one digit to be out of the bounds.
        //
        // Dear developer: if this test has failed more than once for
        // you over years of development, then there is almost
        // certainly a bug!  Report it, please!
        assert!(bad <= 1);
    }

    #[test]
    fn autocrypt_setup_message() {
        // Try the example autocrypt setup message.
        let mut asm = AutocryptSetupMessage::from_bytes(
            &include_bytes!("../tests/data/setup-message.txt")[..]).unwrap();

        // A bad passcode.
        assert!(asm.decrypt(&"123".into()).is_err());
        // Now the right one.
        assert!(asm.decrypt(
            &"1742-0185-6197-1303-7016-8412-3581-4441-0597".into()
        ).is_ok());
        let asm = asm.parse().unwrap();

        // A basic check to make sure we got the key.
        assert_eq!(asm.into_cert().fingerprint(),
                   "E604 68CE 44D7 7C3F CE9F  D072 71DB C565 7FDE 65A7".parse()
                       .unwrap());


        // Create an ASM for testy-private.  Then decrypt it and make
        // sure the Cert, etc. survived the round trip.
        let cert =
            Cert::from_bytes(&include_bytes!("../tests/data/testy-private.pgp")[..])
            .unwrap();

        let mut asm = AutocryptSetupMessage::new(cert)
            .set_prefer_encrypt("mutual");
        let mut buffer = Vec::new();
        asm.serialize(&mut buffer).unwrap();

        let mut asm2 = AutocryptSetupMessage::from_bytes(&buffer[..]).unwrap();
        asm2.decrypt(asm.passcode().unwrap()).unwrap();
        let asm2 = asm2.parse().unwrap();
        assert_eq!(asm, asm2);
    }

    #[test]
    fn autocrypt_header_new() {
        let p = &P::new();

        let cert = Cert::from_bytes(&include_bytes!("../tests/data/testy.pgp")[..])
            .unwrap();
        let header = AutocryptHeader::new_sender(p, &cert, "testy@example.org",
                                                 "mutual").unwrap();
        let mut buf = Vec::new();
        write!(&mut buf, "Autocrypt: ").unwrap();
        header.serialize(&mut buf).unwrap();

        let ac = AutocryptHeaders::from_bytes(&buf).unwrap();

        // We expect exactly one Autocrypt header.
        assert_eq!(ac.headers.len(), 1);

        assert_eq!(ac.headers[0].get("addr").unwrap().value,
                   "testy@example.org");

        assert_eq!(ac.headers[0].get("prefer-encrypt").unwrap().value,
                   "mutual");

        let cert = ac.headers[0].key.as_ref()
            .expect("Failed to parse key material.");
        assert_eq!(&cert.fingerprint().to_hex(),
                   "3E8877C877274692975189F5D03F6F865226FE8B");
        assert_eq!(cert.userids().len(), 1);
        assert_eq!(cert.keys().subkeys().count(), 1);
        assert_eq!(cert.userids().next().unwrap().userid().value(),
                   &b"Testy McTestface <testy@example.org>"[..]);
    }

    #[test]
    fn autocrypt_header_new_address_mismatch() -> Result<()> {
        let p = &P::new();

        let cert =
            Cert::from_bytes(&include_bytes!("../tests/data/testy.pgp")[..])?;
        let header = AutocryptHeader::new_sender(p, &cert,
                                                 "anna-lena@example.org",
                                                 "mutual")?;
        let mut buf = Vec::new();
        write!(&mut buf, "Autocrypt: ")?;
        header.serialize(&mut buf)?;

        let ac = AutocryptHeaders::from_bytes(&buf)?;

        // We expect exactly one Autocrypt header.
        assert_eq!(ac.headers.len(), 1);

        assert_eq!(ac.headers[0].get("addr").unwrap().value,
                   "anna-lena@example.org");

        assert_eq!(ac.headers[0].get("prefer-encrypt").unwrap().value,
                   "mutual");

        let cert = ac.headers[0].key.as_ref()
            .expect("Failed to parse key material.");
        assert_eq!(&cert.fingerprint().to_hex(),
                   "3E8877C877274692975189F5D03F6F865226FE8B");
        assert_eq!(cert.userids().len(), 1);
        assert_eq!(cert.keys().subkeys().count(), 1);
        assert_eq!(cert.userids().next().unwrap().userid().value(),
                   &b"Testy McTestface <testy@example.org>"[..]);
        Ok(())
    }
}
