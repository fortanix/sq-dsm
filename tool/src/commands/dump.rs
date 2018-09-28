use std::io::{self, Read};
use time;

extern crate openpgp;
use openpgp::{Packet, Result};
use openpgp::ctb::CTB;
use openpgp::packet::{Header, BodyLength};
use openpgp::packet::signature::subpacket::{Subpacket, SubpacketValue};
use openpgp::s2k::S2K;
use openpgp::parse::{Map, PacketParserResult};

use super::TIMEFMT;

// Indent packets according to their recursion level.
const INDENT: &'static str
    // 64 spaces = max recursion depth (16) * 4 spaces
    = "                                                                ";

pub fn dump(input: &mut io::Read, output: &mut io::Write, mpis: bool, hex: bool)
        -> Result<()> {
    let mut ppr
        = openpgp::parse::PacketParserBuilder::from_reader(input)?
        .map(hex).finalize()?;
    let mut dumper = PacketDumper::new(mpis);

    while let PacketParserResult::Some(mut pp) = ppr {
        let additional_fields = match pp.packet {
            Packet::Literal(_) if ! hex => {
                let mut prefix = vec![0; 40];
                let n = pp.read(&mut prefix)?;
                Some(vec![
                    format!("Content: {:?}{}",
                            String::from_utf8_lossy(&prefix[..n]),
                            if n == prefix.len() { "..." } else { "" }),
                ])
            },
            _ => None,
        };

        dumper.packet(output, 2 * pp.recursion_depth as usize,
                      Some(&pp.header), &pp.packet, pp.map.take(),
                      additional_fields)?;

        let (_, (ppr_, _)) = pp.recurse()?;
        ppr = ppr_;
    }
    Ok(())
}

pub struct PacketDumper {
    mpis: bool,
}

impl PacketDumper {
    pub fn new(mpis: bool) -> Self {
        PacketDumper {
            mpis: mpis,
        }
    }

    pub fn packet(&mut self, output: &mut io::Write, depth: usize,
                  header: Option<&Header>, p: &Packet, map: Option<Map>,
                  additional_fields: Option<Vec<String>>)
                  -> Result<()> {
        use self::openpgp::Packet::*;
        let i = &INDENT[0..2 * depth as usize];

        if let Some(h) = header {
            write!(output, "{}{} CTB, {}: ", i,
                   if let CTB::Old(_) = h.ctb { "Old" } else { "New" },
                   match h.length {
                       BodyLength::Full(n) =>
                           format!("{} bytes", n),
                       BodyLength::Partial(n) =>
                           format!("partial length, {} bytes in first chunk", n),
                       BodyLength::Indeterminate =>
                           "indeterminate length".into(),
                   })?;
        } else {
            write!(output, "{}", i)?;
        }

        match p {
            Unknown(ref u) => {
                writeln!(output, "Unknown Packet")?;
                writeln!(output, "{}  Tag: {}", i, u.tag())?;
            },

            Signature(ref s) => {
                writeln!(output, "Signature Packet")?;
                writeln!(output, "{}  Version: {}", i, s.version())?;
                writeln!(output, "{}  Type: {}", i, s.sigtype())?;
                writeln!(output, "{}  Pk algo: {}", i, s.pk_algo())?;
                writeln!(output, "{}  Hash algo: {}", i, s.hash_algo())?;
                if s.hashed_area().iter().count() > 0 {
                    writeln!(output, "{}  Hashed area:", i)?;
                    for (_, _, pkt) in s.hashed_area().iter() {
                        self.dump_subpacket(output, depth, pkt)?;
                    }
                }
                if s.unhashed_area().iter().count() > 0 {
                    writeln!(output, "{}  Unhashed area:", i)?;
                    for (_, _, pkt) in s.unhashed_area().iter() {
                        self.dump_subpacket(output, depth, pkt)?;
                    }
                }
                writeln!(output, "{}  Hash prefix: {}", i,
                         to_hex(s.hash_prefix(), false))?;
                write!(output, "{}  Level: {} ", i, s.level())?;
                match s.level() {
                    0 => writeln!(output, "(signature over data)")?,
                    1 => writeln!(output, "(notarization over signatures \
                                           level 0 and data)")?,
                    n => writeln!(output, "(notarization over signatures \
                                           level <= {} and data)", n - 1)?,
                }
                if self.mpis {
                    writeln!(output, "{}  MPIs: {:?}", i, s.mpis())?;
                }
            },

            OnePassSig(ref o) => {
                writeln!(output, "One-Pass Signature Packet")?;
                writeln!(output, "{}  Version: {}", i, o.version())?;
                writeln!(output, "{}  Type: {}", i, o.sigtype())?;
                writeln!(output, "{}  Pk algo: {}", i, o.pk_algo())?;
                writeln!(output, "{}  Hash algo: {}", i, o.hash_algo())?;
                writeln!(output, "{}  Issuer: {}", i, o.issuer())?;
                writeln!(output, "{}  Last: {}", i, o.last())?;
            },

            PublicKey(ref k) | PublicSubkey(ref k)
                | SecretKey(ref k) | SecretSubkey(ref k) =>
            {
                writeln!(output, "{}", p.tag())?;
                writeln!(output, "{}  Version: {}", i, k.version())?;
                writeln!(output, "{}  Creation time: {}", i,
                         time::strftime(TIMEFMT, k.creation_time()).unwrap())?;
                writeln!(output, "{}  Pk algo: {}", i, k.pk_algo())?;
                if self.mpis {
                    writeln!(output, "{}  MPIs: {:?}", i, k.mpis())?;
                    if let Some(secrets) = k.secret() {
                        writeln!(output, "{}  Secrets: {:?}", i, secrets)?;
                    }
                }
            },

            UserID(ref u) => {
                writeln!(output, "User ID Packet")?;
                writeln!(output, "{}  Value: {}", i,
                         String::from_utf8_lossy(u.userid()))?;
            },

            UserAttribute(ref u) => {
                writeln!(output, "User Attribute Packet")?;
                writeln!(output, "{}  Value: {} bytes", i,
                         u.user_attribute().len())?;
            },

            Literal(ref l) => {
                writeln!(output, "Literal Data Packet")?;
                writeln!(output, "{}  Format: {}", i, l.format())?;
                if let Some(filename) = l.filename() {
                    writeln!(output, "{}  Filename: {}", i,
                             String::from_utf8_lossy(filename))?;
                }
                if let Some(timestamp) = l.date() {
                    writeln!(output, "{}  Timestamp: {}", i,
                             time::strftime(TIMEFMT, timestamp).unwrap())?;
                }
            },

            CompressedData(ref c) => {
                writeln!(output, "Compressed Data Packet")?;
                writeln!(output, "{}  Algorithm: {}", i, c.algorithm())?;
            },

            PKESK(ref p) => {
                writeln!(output, "Public-key Encrypted Session Key Packet")?;
                writeln!(output, "{}  Version: {}", i, p.version())?;
                writeln!(output, "{}  Recipient: {}", i, p.recipient())?;
                writeln!(output, "{}  Pk algo: {}", i, p.pk_algo())?;
                if self.mpis {
                    writeln!(output, "{}  ESK: {:?}", i, p.esk())?;
                }
            },

            SKESK(ref s) => {
                writeln!(output, "Symmetric-key Encrypted Session Key Packet")?;
                writeln!(output, "{}  Version: {}", i, s.version())?;
                writeln!(output, "{}  Cipher: {}", i, s.symmetric_algo())?;
                write!(output, "{}  S2K: ", i)?;
                self.dump_s2k(output, i, s.s2k())?;
                if let Some(esk) = s.esk() {
                    writeln!(output, "{}  ESK: {}", i, to_hex(esk, false))?;
                }
            },

            SEIP(ref s) => {
                writeln!(output, "Encrypted and Integrity Protected Data Packet")?;
                writeln!(output, "{}  Version: {}", i, s.version())?;
            },

            MDC(ref m) => {
                writeln!(output, "Modification Detection Code Packet")?;
                writeln!(output, "{}  Hash: {}", i, to_hex(m.hash(), false))?;
            },
        }

        if let Some(fields) = additional_fields {
            for field in fields {
                writeln!(output, "{}  {}", i, field)?;
            }
        }

        if let Some(map) = map {
            writeln!(output)?;
            let mut hd = HexDumper::new();
            for (field, bytes) in map.iter() {
                hd.write(output, bytes, field)?;
            }
        }
        writeln!(output)?;

        Ok(())
    }

    fn dump_subpacket(&mut self, output: &mut io::Write, depth: usize,
                      s: Subpacket)
                      -> Result<()> {
        use self::SubpacketValue::*;
        let i = &INDENT[0..2 * depth as usize];

        match s.value {
            Unknown(ref b) =>
                write!(output, "{}    Unknown: {:?}", i, b)?,
            Invalid(ref b) =>
                write!(output, "{}    Invalid: {:?}", i, b)?,
            SignatureCreationTime(ref t) =>
                write!(output, "{}    Signature creation time: {}", i,
                       time::strftime(TIMEFMT, t).unwrap())?,
            SignatureExpirationTime(ref t) =>
                write!(output, "{}    Signature expiration time: {}", i, t)?,
            ExportableCertification(e) =>
                write!(output, "{}    Exportable certification: {}", i, e)?,
            TrustSignature{level, trust} =>
                write!(output, "{}    Trust signature: level {} trust {}", i,
                       level, trust)?,
            RegularExpression(ref r) =>
                write!(output, "{}    Regular expression: {}", i,
                       String::from_utf8_lossy(r))?,
            Revocable(r) =>
                write!(output, "{}    Revocable: {}", i, r)?,
            KeyExpirationTime(ref t) =>
                write!(output, "{}    Signature expiration time: {}", i, t)?,
            PreferredSymmetricAlgorithms(ref c) =>
                write!(output, "{}    Cipher preference: {}", i,
                       c.iter().map(|c| format!("{:?}", c))
                       .collect::<Vec<String>>().join(", "))?,
            RevocationKey{class, pk_algo, ref fp} =>
                write!(output,
                       "{}    Revocation key: class {} algo {} fingerprint {}", i,
                       class, pk_algo, fp)?,
            Issuer(ref is) =>
                write!(output, "{}    Issuer: {}", i, is)?,
            NotationData(ref n) =>
                write!(output, "{}    Notation: {:?}", i, n)?,
            PreferredHashAlgorithms(ref h) =>
                write!(output, "{}    Hash preference: {}", i,
                       h.iter().map(|h| format!("{:?}", h))
                       .collect::<Vec<String>>().join(", "))?,
            PreferredCompressionAlgorithms(ref c) =>
                write!(output, "{}    Compression preference: {}", i,
                       c.iter().map(|c| format!("{:?}", c))
                       .collect::<Vec<String>>().join(", "))?,
            KeyServerPreferences(ref p) =>
                write!(output, "{}    Keyserver preferences: {:?}", i, p)?,
            PreferredKeyServer(ref k) =>
                write!(output, "{}    Preferred keyserver: {}", i,
                       String::from_utf8_lossy(k))?,
            PrimaryUserID(p) =>
                write!(output, "{}    Primary User ID: {}", i, p)?,
            PolicyURI(ref p) =>
                write!(output, "{}    Policy URI: {}", i,
                       String::from_utf8_lossy(p))?,
            KeyFlags(ref k) =>
                write!(output, "{}    Key flags: {:?}", i, k)?,
            SignersUserID(ref u) =>
                write!(output, "{}    Signers User ID: {}", i,
                       String::from_utf8_lossy(u))?,
            ReasonForRevocation{code, ref reason} => {
                let reason = String::from_utf8_lossy(reason);
                write!(output, "{}    Reason for revocation: {}{}{}", i, code,
                       if reason.len() > 0 { ", " } else { "" }, reason)?
            }
            Features(ref f) =>
                write!(output, "{}    Features: {:?}", i, f)?,
            SignatureTarget{pk_algo, hash_algo, ref digest} =>
                write!(output, "{}    Signature target: {}, {}, {}", i,
                       pk_algo, hash_algo, to_hex(digest, false))?,
            EmbeddedSignature(_) =>
            // Embedded signature is dumped below.
                write!(output, "{}    Embedded signature: ", i)?,
            IssuerFingerprint(ref fp) =>
                write!(output, "{}    Issuer Fingerprint: {}", i, fp)?,
            IntendedRecipient(ref fp) =>
                write!(output, "{}    Intended Recipient: {}", i, fp)?,
        }

        if s.critical {
            write!(output, " (critical)")?;
        }
        writeln!(output)?;

        match s.value {
            EmbeddedSignature(ref sig) => {
                self.packet(output, depth + 3, None, sig, None, None)?;
            },
            _ => (),
        }

        Ok(())
    }

    fn dump_s2k(&self, output: &mut io::Write, i: &str, s2k: &S2K)
                -> Result<()> {
        use self::S2K::*;
        match s2k {
            Simple { hash } => {
                writeln!(output, "Simple")?;
                writeln!(output, "{}    Hash: {}", i, hash)?;
            },
            Salted { hash, ref salt } => {
                writeln!(output, "Salted")?;
                writeln!(output, "{}    Hash: {}", i, hash)?;
                writeln!(output, "{}    Salt: {}", i, to_hex(salt, false))?;
            },
            Iterated { hash, ref salt, iterations } => {
                writeln!(output, "Iterated")?;
                writeln!(output, "{}    Hash: {}", i, hash)?;
                writeln!(output, "{}    Salt: {}", i, to_hex(salt, false))?;
                writeln!(output, "{}    Iterations: {}", i, iterations)?;
            },
            Private(n) =>
                writeln!(output, "Private({})", n)?,
            Unknown(n) =>
                writeln!(output, "Unknown({})", n)?,
        }
        Ok(())
    }
}

pub struct HexDumper {
    offset: usize,
}

impl HexDumper {
    pub fn new() -> Self {
        HexDumper {
            offset: 0,
        }
    }

    pub fn write(&mut self, sink: &mut io::Write, buf: &[u8], msg: &str)
             -> Result<()> {
        let mut msg_printed = false;
        write!(sink, "{:08x}  ", self.offset)?;
        for i in 0 .. self.offset % 16 {
            if i != 7 {
                write!(sink, "   ")?;
            } else {
                write!(sink, "    ")?;
            }
        }

        for c in buf {
            write!(sink, "{:02x} ", c)?;
            self.offset += 1;
            match self.offset % 16 {
                0 => {
                    if ! msg_printed {
                        write!(sink, "  {}", msg)?;
                        msg_printed = true;
                    }

                    write!(sink, "\n{:08x}  ", self.offset)?;
                },
                8 => write!(sink, " ")?,
                _ => (),
            }
        }

        for i in self.offset % 16 .. 16 {
            if i != 7 {
                write!(sink, "   ")?;
            } else {
                write!(sink, "    ")?;
            }
        }

        if ! msg_printed {
            write!(sink, "  {}", msg)?;
        }
        writeln!(sink)?;
        Ok(())
    }
}

fn to_hex(s: &[u8], pretty: bool) -> String {
    use std::fmt::Write;

    let mut result = String::new();
    for (i, b) in s.iter().enumerate() {
        // Add spaces every four digits to make the output more
        // readable.
        if pretty && i > 0 && i % 2 == 0 {
            write!(&mut result, " ").unwrap();
        }
        write!(&mut result, "{:02X}", b).unwrap();
    }
    result
}
