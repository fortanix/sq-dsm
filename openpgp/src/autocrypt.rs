//! Autocrypt.
//!
//! This module deals with Autocrypt encoded (see the [Autocrypt Spec]).
//!
//! [Autocrypt Spec]: https://autocrypt.org/level1.html#openpgp-based-key-data
//!
//! # Scope
//!
//! This implements encoding and decoding of Autocrypt headers.  Note:
//! Autocrypt is more than just headers; it requires tight integration
//! with the MUA.

extern crate base64;

use std::io;
use std::io::prelude::*;
use std::io::BufReader;
use std::path::Path;
use std::fs::File;

use Result;
use TPK;

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
    pub key: Option<TPK>,

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

    /// Looks up an attribute.
    pub fn get(&self, key: &str) -> Option<&Attribute> {
        for a in &self.attributes {
            if a.key == key {
                return Some(a);
            }
        }

        None
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

            if line == "" {
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
                if nl.len() > 0 && (&nl[0..1] == " " || &nl[0..1] == "\t") {
                    line.push_str(&nl[..]);
                    next_line = lines.next();
                } else {
                    // Put it back.
                    next_line = Some(Ok(nl));
                    break;
                }
            }

            const AUTOCRYPT : &str = "Autocrypt: ";
            const FROM : &str = "From: ";

            if line.starts_with(FROM) {
                headers.from
                    = Some(line[FROM.len()..].trim_matches(' ').into());
            } else if line.starts_with(AUTOCRYPT) {
                let ac_value = &line[AUTOCRYPT.len()..];

                let mut header = AutocryptHeader::empty(
                    AutocryptHeaderType::Sender);

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
                            if let Ok(tpk) = TPK::from_bytes(&decoded[..]) {
                                header.key = Some(tpk);
                            }
                        }
                    }

                    let critical = key.len() >= 1 && &key[0..1] == "_";
                    header.attributes.push(Attribute {
                        critical: critical,
                        key: if critical {
                            key[1..].to_string()
                        } else {
                            key
                        },
                        value: value,
                    });
                }

                headers.headers.push(header);
            }
        }

        return Ok(headers)
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

#[cfg(test)]
mod test {
    use super::*;

    use Fingerprint;

    #[test]
    fn decode_test() {
        const HPK : &'static [u8] = b"\
Cc: autocrypt@lists.mayfirst.org, delta@codespeak.net
Subject: Re: [Autocrypt] [delta-chat] DeltaX gathering 16-24th july ongoings
From: holger krekel <holger@merlinux.eu>
Delivery-date: Mon, 18 Jun 2018 19:21:24 +0200
DMARC-Filter: OpenDMARC Filter v1.2.0 mail.merlinux.eu 3E7561006EB
Date: Mon, 18 Jun 2018 19:21:10 +0200
Message-ID: <20180618172110.GB21885@beto>
Autocrypt: addr=holger@merlinux.eu; prefer-encrypt=mutual; keydata= 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 1CvHBWNRmnPMaFMeSpgJ
List-Archive: <http://lists.mayfirst.org/pipermail/autocrypt/>
Errors-To: autocrypt-bounces+neal=walfield.org@lists.mayfirst.org

On Mon, Jun 18, 2018 at 10:11 -0700, Karissa McKelvey wrote:
...
"
;

        const VINCENT : &'static [u8] = b"\
To: gnupg-devel <gnupg-devel@gnupg.org>, sks-devel@nongnu.org,
 Autocrypt <autocrypt@lists.mayfirst.org>, openpgp-email <openpgp-email@enigmail.net>
Subject: Keyservers and GDPR
From: Vincent Breitmoser <look@my.amazin.horse>
Delivery-date: Tue, 22 May 2018 21:45:08 +0200
Date: Tue, 22 May 2018 21:44:09 +0200
Message-ID: <20180522194409.tmrteipcsoorisns@calamity>
Autocrypt: addr=look@my.amazin.horse; keydata=mQINBFAB3UABEADCyB/vbIBA3m1Bwc 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 lJcO6TtHWnElS3pACbTQM0RHJox3zqU3q6K3c=
User-Agent: NeoMutt/20180323
List-Archive: <https://lists.gnupg.org/pipermail/gnupg-devel/>
Errors-To: gnupg-devel-bounces@gnupg.org

";

        const PATRICK : &'static [u8] = b"\
To: GnuPG Users List <gnupg-users@gnupg.org>, openpgp-email@enigmail.net
Subject: [openpgp-email] Efail - Possible Measures?
From: Patrick Brunschwig <patrick@enigmail.net>
Delivery-date: Sat, 19 May 2018 18:47:34 +0200
X-Authenticated-Sender-Id: patrick@enigmail.net
Openpgp: id=4F9F89F5505AC1D1A260631CDB1187B9DD5F693B
Autocrypt: addr=patrick@enigmail.net; prefer-encrypt=mutual; keydata= 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
Message-ID: <f45adfe2-7d2b-50d1-f88d-5efbe878cf7f@enigmail.net>
Date: Sat, 19 May 2018 18:47:08 +0200
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:60.0)
 Gecko/20100101 Thunderbird/60.0
List-Archive: <https://lists.enigmail.net/pipermail/openpgp-email_enigmail.net/>
Reply-To: OpenPGP-based Email Encryption <openpgp-email@enigmail.net>
Errors-To: openpgp-email-bounces@enigmail.net

In the light of the Efail vulnerability I am asking myself if it's
...
";

        const PATRICK_UNFOLDED : &'static [u8] = b"\
To: GnuPG Users List <gnupg-users@gnupg.org>, openpgp-email@enigmail.net
Subject: [openpgp-email] Efail - Possible Measures?
From: Patrick Brunschwig <patrick@enigmail.net>
Delivery-date: Sat, 19 May 2018 18:47:34 +0200
X-Authenticated-Sender-Id: patrick@enigmail.net
Openpgp: id=4F9F89F5505AC1D1A260631CDB1187B9DD5F693B
Autocrypt: addr=patrick@enigmail.net;
 prefer-encrypt=mutual;
 keydata=
 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
Message-ID: <f45adfe2-7d2b-50d1-f88d-5efbe878cf7f@enigmail.net>
Date: Sat, 19 May 2018 18:47:08 +0200
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:60.0)
 Gecko/20100101 Thunderbird/60.0
List-Archive: <https://lists.enigmail.net/pipermail/openpgp-email_enigmail.net/>
Reply-To: OpenPGP-based Email Encryption <openpgp-email@enigmail.net>
Errors-To: openpgp-email-bounces@enigmail.net

In the light of the Efail vulnerability I am asking myself if it's
...
";

        let ac = AutocryptHeaders::from_bytes(&HPK[..]).unwrap();
        //eprintln!("ac: {:#?}", ac);

        // We expect exactly one Autocrypt header.
        assert_eq!(ac.headers.len(), 1);

        assert_eq!(ac.headers[0].get("addr").unwrap().value,
                   "holger@merlinux.eu");

        assert_eq!(ac.headers[0].get("prefer-encrypt").unwrap().value,
                   "mutual");

        let tpk = ac.headers[0].key.as_ref()
            .expect("Failed to parse key material.");
        assert_eq!(tpk.primary().fingerprint(),
                   Fingerprint::from_hex(
                       &"156962B0F3115069ACA970C68E3B03A279B772D6"[..]).unwrap());
        assert_eq!(&tpk.userids().next().unwrap().userid().value[..],
                   &b"holger krekel <holger@merlinux.eu>"[..]);


        let ac = AutocryptHeaders::from_bytes(&VINCENT[..]).unwrap();
        //eprintln!("ac: {:#?}", ac);

        assert_eq!(ac.from,
                   Some("Vincent Breitmoser <look@my.amazin.horse>".into()));

        // We expect exactly one Autocrypt header.
        assert_eq!(ac.headers.len(), 1);

        assert_eq!(ac.headers[0].get("addr").unwrap().value,
                   "look@my.amazin.horse");

        assert!(ac.headers[0].get("prefer_encrypt").is_none());

        let tpk = ac.headers[0].key.as_ref()
            .expect("Failed to parse key material.");
        assert_eq!(tpk.primary().fingerprint(),
                   Fingerprint::from_hex(
                       &"D4AB192964F76A7F8F8A9B357BD18320DEADFA11"[..]).unwrap());
        assert_eq!(&tpk.userids().next().unwrap().userid().value[..],
                   &b"Vincent Breitmoser <look@my.amazin.horse>"[..]);


        let ac = AutocryptHeaders::from_bytes(&PATRICK[..]).unwrap();
        //eprintln!("ac: {:#?}", ac);

        assert_eq!(ac.from,
                   Some("Patrick Brunschwig <patrick@enigmail.net>".into()));

        // We expect exactly one Autocrypt header.
        assert_eq!(ac.headers.len(), 1);

        assert_eq!(ac.headers[0].get("addr").unwrap().value,
                   "patrick@enigmail.net");

        assert!(ac.headers[0].get("prefer_encrypt").is_none());

        let tpk = ac.headers[0].key.as_ref()
            .expect("Failed to parse key material.");
        assert_eq!(tpk.primary().fingerprint(),
                   Fingerprint::from_hex(
                       &"4F9F89F5505AC1D1A260631CDB1187B9DD5F693B"[..]).unwrap());
        assert_eq!(&tpk.userids().next().unwrap().userid().value[..],
                   &b"Patrick Brunschwig <patrick@enigmail.net>"[..]);

        let ac2 = AutocryptHeaders::from_bytes(&PATRICK_UNFOLDED[..]).unwrap();
        assert_eq!(ac, ac2);
    }
}
