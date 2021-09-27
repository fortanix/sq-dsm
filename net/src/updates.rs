//! OpenPGP Keystore Update Manifests.
//!
//! This implements an efficient and privacy preserving mechanism that
//! OpenPGP clients can use to update their certificates.  For
//! details, please see [the draft].
//!
//! [the draft]: https://gitlab.com/hagrid-keyserver/keystore-updates

use std::{
    collections::BTreeSet,
    convert::{TryFrom, TryInto},
    fmt,
    io,
    ops,
};

use sequoia_openpgp as openpgp;
use openpgp::{
    Fingerprint,
};

/// The number of seconds in one epoch.
pub const SECONDS_PER_EPOCH: u64 = 1 << 15;

/// Set of certificate updates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    start: Epoch,
    end: Epoch,
    prefixes: BTreeSet<u32>,
}

impl Manifest {
    /// Magic string for Update Manifests.
    pub const MAGIC: &'static [u8] = b"\xE4\x2B\xAF\xBD\xD5\x75\x77\x0A";

    /// Creates a new Update Manifest
    pub fn new<S, E>(start: S, end: E)
        -> anyhow::Result<Manifest>
    where
        S: Into<Epoch>,
        E: Into<Epoch>,
    {
        let start = start.into();
        let end = end.into();
        if start <= end {
            Ok(Manifest {
                start,
                end,
                prefixes: Default::default(),
            })
        } else {
            Err(anyhow::anyhow!("End epoch predates start epoch"))
        }
    }

    /// Computes the prefix of the given Fingerprint.
    fn prefix(fingerprint: &Fingerprint) -> u32 {
        let mut prefix = [0u8; 4];
        prefix.copy_from_slice(&fingerprint.as_bytes()[..4]);
        u32::from_be_bytes(prefix)
    }

    /// Tests whether a cert is included in the Update Manifest.
    ///
    /// Note: Due to the privacy-preserving nature of Update Manifests
    /// that store only fingerprint prefixes, this may return false
    /// positives.
    pub fn contains(&self, fingerprint: &Fingerprint) -> bool {
        self.prefixes.contains(&Self::prefix(fingerprint))
    }

    /// Tests whether an epoch is included in the Update Manifest.
    pub fn contains_epoch(&self, epoch: Epoch) -> bool {
        // Both start and end are inclusive, therefore:
        self.start <= epoch && epoch <= self.end
    }

    /// Iterates over all epochs contained in this Update Manifest.
    pub fn epochs(&self) -> impl Iterator<Item = Epoch> {
        (self.start.0..self.end.0 + 1).into_iter()
            .map(Epoch)
    }

    /// Returns the start epoch.
    pub fn start(&self) -> Epoch {
        self.start
    }

    /// Returns the end epoch.
    pub fn end(&self) -> Epoch {
        self.end
    }

    /// Returns the number of fingerprint prefixes in this Update
    /// Manifest.
    pub fn len(&self) -> usize {
        self.prefixes.len()
    }

    /// Inserts a fingerprint into the Update Manifest.
    pub fn insert(&mut self, fingerprint: &Fingerprint) {
        self.prefixes.insert(Self::prefix(fingerprint));
    }

    /// Merges two Update Manifests into one.
    pub fn merge(&self, other: &Self) -> Manifest {
        Manifest {
            start: self.start.min(other.start),
            end: self.end.max(other.end),
            prefixes: self.prefixes.iter().cloned()
                .chain(other.prefixes.iter().cloned())
                .collect(),
          }
    }

    /// Writes the Update Manifest to the given `io::Write`r.
    pub fn serialize(&self, sink: &mut dyn io::Write) -> io::Result<()> {
        sink.write_all(Self::MAGIC)?;

        self.start.serialize(sink)?;
        self.end.serialize(sink)?;

        for prefix in &self.prefixes {
            sink.write_all(&prefix.to_be_bytes())?;
        }

        Ok(())
    }

    /// Reads the Update Manifest from the given `io::Read`er.
    pub fn parse(source: &mut dyn io::Read) -> io::Result<Self> {
        let mut magic = [0; 8];
        source.read_exact(&mut magic)?;
        if &magic[..] != Self::MAGIC {
            return Err(io::Error::new(io::ErrorKind::Other,
                                      anyhow::anyhow!("Bad magic string")));
        }

        let start = Epoch::parse(source)?;
        let end = Epoch::parse(source)?;
        if start > end {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                anyhow::anyhow!("End epoch predates start epoch")));
        }

        let mut prefixes = BTreeSet::default();
        let mut prefix = [0; 4];
        'parse: loop {
            let mut read = 0;
            loop {
                let n = source.read(&mut prefix[read..])?;
                if n == 0 {
                    match read {
                        0 => break 'parse,
                        _ => return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "Truncated fingerprint prefix")),
                    }
                }

                read += n;
                if read == 4 {
                    prefixes.insert(u32::from_be_bytes(prefix));
                    continue 'parse;
                }
            }
        }

        Ok(Manifest {
            start,
            end,
            prefixes,
        })
    }
}

/// Granularity of updates.
///
/// For the purposes of this update mechanism, the updates cycle in
/// blocks of 2^15 seconds, or about 9 hours.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Epoch(u32);

impl fmt::Display for Epoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u32> for Epoch {
    fn from(e: u32) -> Self {
        Epoch(e)
    }
}

impl TryFrom<std::time::SystemTime> for Epoch {
    type Error = anyhow::Error;

    fn try_from(t: std::time::SystemTime) -> anyhow::Result<Self> {
        use std::time::*;
        let unix_epoch = t.duration_since(UNIX_EPOCH)?;
        Self::try_from_unix(unix_epoch.as_secs())
    }
}

impl Epoch {
    /// Returns the currently active Epoch.
    pub fn current() -> anyhow::Result<Epoch> {
        std::time::SystemTime::now().try_into()
    }

    /// Returns the epoch for the given UNIX epoch.
    pub fn try_from_unix(t: u64) -> anyhow::Result<Self> {
        Ok(Epoch((t / SECONDS_PER_EPOCH).try_into()?))
    }

    /// Returns the previous Epoch, if any.
    pub fn pred(&self) -> Option<Epoch> {
        self.0.checked_sub(1).map(Epoch)
    }

    /// Returns the next Epoch, if any.
    pub fn succ(&self) -> Option<Epoch> {
        self.0.checked_add(1).map(Epoch)
    }

    /// Returns an iterator over all epochs starting from this one to
    /// `other`, in descending order, excluding `other`.
    pub fn since(&self, other: Epoch)
                 -> anyhow::Result<impl Iterator<Item = Epoch>> {
        if other <= *self {
            Ok((other.0 + 1..self.0).into_iter().rev().map(Epoch))
        } else {
            Err(anyhow::anyhow!("other is later than self"))
        }
    }

    /// Writes the Epoch to the given `io::Write`r.
    pub fn serialize(&self, sink: &mut dyn io::Write) -> io::Result<()> {
        sink.write_all(&self.0.to_be_bytes())
    }

    /// Reads the Epoch from the given `io::Read`er.
    pub fn parse(source: &mut dyn io::Read) -> io::Result<Self> {
        let mut be_bytes = [0; 4];
        source.read_exact(&mut be_bytes)?;
        Ok(Self(u32::from_be_bytes(be_bytes)))
    }
}

impl std::str::FromStr for Epoch {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if s == "current" {
            Ok(Epoch::current()?)
        } else {
            Ok(Epoch(s.parse()?))
        }
    }
}

impl ops::Add<Epoch> for Epoch {
    type Output = Self;

    fn add(self, other: Epoch) -> Self {
        Self(self.0 + other.0)
    }
}

impl ops::Sub<Epoch> for Epoch {
    type Output = Self;

    fn sub(self, other: Epoch) -> Self {
        Self(self.0 - other.0)
    }
}

impl ops::Add<u32> for Epoch {
    type Output = Self;

    fn add(self, other: u32) -> Self {
        Self(self.0 + other)
    }
}

impl ops::Sub<u32> for Epoch {
    type Output = Self;

    fn sub(self, other: u32) -> Self {
        Self(self.0 - other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_epoch() -> crate::Result<()> {
        let _ = Epoch::current()?;
        Ok(())
    }

    #[test]
    fn merge() -> crate::Result<()> {
        let c = Epoch::current()?;

        // End predates start.
        assert!(Manifest::new(c - 1, c - 2).is_err());

        let mut u_0 = Manifest::new(c - 1, c)?;
        let mut u_1 = Manifest::new(c - 2, c - 1)?;

        let neal: Fingerprint =
            "8F17777118A33DDA9BA48E62AACB3243630052D9".parse()?;
        let justus: Fingerprint =
            "CBCD8F030588653EEDD7E2659B7DD433F254904A".parse()?;
        let vincent: Fingerprint =
            "D4AB192964F76A7F8F8A9B357BD18320DEADFA11".parse()?;

        u_0.insert(&neal);
        u_1.insert(&neal);
        u_0.insert(&justus);
        u_1.insert(&vincent);

        let u_01 = u_0.merge(&u_1);

        assert_eq!(u_01.start, c - 2);
        assert_eq!(u_01.end, c);
        assert_eq!(u_01.len(), 3);
        assert!(u_01.contains(&neal));
        assert!(u_01.contains(&justus));
        assert!(u_01.contains(&vincent));

        Ok(())
    }

    /// Checks serialization using the sample Update Manifest.
    ///
    /// ```text
    /// Below is a hexdump of an update manifest that covers epochs from 15296
    /// to 15322 (inclusive).  This corresponds to the time range from
    /// 1985-11-18T22:35:28 through 1985-11-29T04:21:03 (inclusive).  The
    /// observed updated certificates had five primary key fingerprint
    /// prefixes:
    ///
    /// 32144D9D, 65FB1218, 7E91F402, 9ED85A5E, EA71546A
    ///
    /// 00000000  e4 2b af bd d5 75 77 0a  00 00 3b c0 00 00 3b da
    /// 00000010  32 14 4d 9d 65 fb 12 18  7e 91 f4 02 9e d8 5a 5e
    /// 00000020  ea 71 54 6a
    /// ```
    fn sample_manifest() -> crate::Result<(Epoch, Epoch,
                                           Vec<Fingerprint>,
                                           &'static[u8])> {
        let start = Epoch(15296);
        let end = Epoch(15322);
        let fp0: Fingerprint =
            "32144D9DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".parse()?;
        let fp1: Fingerprint =
            "65FB1218AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".parse()?;
        let fp2: Fingerprint =
            "7E91F402AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".parse()?;
        let fp3: Fingerprint =
            "9ED85A5EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".parse()?;
        let fp4: Fingerprint =
            "EA71546AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".parse()?;
        let bytes = b"\
            \xe4\x2b\xaf\xbd\xd5\x75\x77\x0a\x00\x00\x3b\xc0\x00\x00\x3b\xda\
            \x32\x14\x4d\x9d\x65\xfb\x12\x18\x7e\x91\xf4\x02\x9e\xd8\x5a\x5e\
            \xea\x71\x54\x6a";

        Ok((start, end, vec![fp0, fp1, fp2, fp3, fp4], bytes))
    }

    #[test]
    fn serialize() -> crate::Result<()> {
        let (start, end, fingerprints, bytes) = sample_manifest()?;

        let mut manifest = Manifest::new(start, end)?;
        manifest.insert(&fingerprints[3]);
        manifest.insert(&fingerprints[1]);
        manifest.insert(&fingerprints[0]);
        manifest.insert(&fingerprints[4]);
        manifest.insert(&fingerprints[2]);

        let mut buf = Vec::new();
        manifest.serialize(&mut buf)?;
        assert_eq!(&buf[..], bytes);

        Ok(())
    }

    #[test]
    fn parse() -> crate::Result<()> {
        let (start, end, fingerprints, bytes) = sample_manifest()?;

        let manifest = Manifest::parse(&mut io::Cursor::new(bytes))?;
        assert_eq!(manifest.start, start);
        assert_eq!(manifest.end, end);
        assert!(manifest.contains(&fingerprints[3]));
        assert!(manifest.contains(&fingerprints[1]));
        assert!(manifest.contains(&fingerprints[0]));
        assert!(manifest.contains(&fingerprints[4]));
        assert!(manifest.contains(&fingerprints[2]));
        assert_eq!(manifest.len(), 5);

        Ok(())
    }
}
