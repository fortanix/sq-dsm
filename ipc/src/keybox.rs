//! Support for the GnuPG keybox format.
//!
//! This implementation is based on keybox files created by GnuPG 2.2.23 and
//! the way they are handled by the `kbxutil` program from that version of GnuPG.

use anyhow::Context;

use openpgp::parse::buffered_reader::{self, BufferedReader};

use openpgp::cert::Cert;
use openpgp::parse::{Cookie, Parse};
use openpgp::types::HashAlgorithm::SHA1;
use openpgp::Result;
use sequoia_openpgp as openpgp;

use std::convert::TryInto;
use std::fmt::Display;

/// GnuPG Keybox
///
/// This implementation is based on keybox files created by GnuPG 2.2.23 and
/// the way they are handled by the `kbxutil` program from that version of GnuPG.
///
/// For example, to extract all certs from a keybox while ignoring all other
/// records:
///
/// ```rust
/// # use sequoia_openpgp::parse::buffered_reader;
/// # fn parse_keybox(reader: &mut dyn buffered_reader::BufferedReader<()>)
/// #    -> sequoia_openpgp::Result<Vec<sequoia_openpgp::Cert>> {
/// use sequoia_ipc::keybox::{Keybox, KeyboxRecord};
/// use sequoia_openpgp::{Cert, Result};
/// use sequoia_openpgp::parse::Parse;
///
/// let kbx = Keybox::from_reader(reader)?;
/// let certs = kbx
///     // Keep only records which were parsed successfully.
///     .filter_map(|kbx_record| kbx_record.ok())
///     // Map the OpenPGP records to the contained certs.
///     .filter_map(|kbx_record| {
///         match kbx_record {
///             KeyboxRecord::OpenPGP(r) => Some(r.cert()),
///             _ => None,
///         }
///     }).collect::<Result<Vec<Cert>>>();
/// certs
/// # }
/// ```
pub struct Keybox<'a> {
    /// Offset into the Keybox file.
    offset: usize,

    reader: Box<dyn BufferedReader<()> + 'a>,
}

impl<'a> Keybox<'a> {
    fn read_next_record(&mut self) -> Result<KeyboxRecord> {
        // The first 4 bytes contain the record's length,
        // bytes 5 and 6 the type and version.
        let input = self
            .reader
            .data_hard(6)
            .map_err(|e| Error::NotEnoughData(e.to_string()))?;
        // input holds at least 4 bytes, so this cannot fail.
        let len = u32::from_be_bytes(input[..4].try_into().unwrap()) as usize;

        let content = self.reader.data_consume_hard(len)?;

        // The length includes the four byte length itself.
        let offset = self.offset;
        self.offset += len;

        let kbx_record = KeyboxRecord::new(offset, (&content[..len]).to_vec())?;
        Ok(kbx_record)
    }

    /// Reads from the given buffered reader.
    ///
    /// Implementations of this function should be short.  Ideally,
    /// they should hand of the reader to a private function erasing
    /// the readers type by invoking [`BufferedReader::into_boxed`].
    pub fn from_buffered_reader<R>(reader: R) -> Result<Self>
    where
        R: BufferedReader<Cookie> + 'a,
    {
        Ok(Keybox {
            offset: 0,
            reader: buffered_reader::Adapter::new(reader).into_boxed(),
        })
    }

    /// Reads from the given reader.
    ///
    /// The default implementation just uses
    /// [`Parse::from_buffered_reader`], but implementations can
    /// provide their own specialized version.
    pub fn from_reader<R: 'a + std::io::Read + Send + Sync>(reader: R) -> Result<Self> {
        Self::from_buffered_reader(
            buffered_reader::Generic::with_cookie(reader,
                                                  None,
                                                  Default::default())
                .into_boxed())
    }

    /// Reads from the given file.
    ///
    /// The default implementation just uses
    /// [`Parse::from_buffered_reader`], but implementations can
    /// provide their own specialized version.
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self>
    {
        Self::from_buffered_reader(
            buffered_reader::File::with_cookie(path.as_ref(),
                                               Default::default())?
                .into_boxed())
    }

    /// Reads from the given slice.
    ///
    /// The default implementation just uses
    /// [`Parse::from_buffered_reader`], but implementations can
    /// provide their own specialized version.
    pub fn from_bytes<D: AsRef<[u8]> + ?Sized + Send + Sync>(data: &'a D) -> Result<Self> {
        Self::from_buffered_reader(
            buffered_reader::Memory::with_cookie(data.as_ref(), Default::default())
                .into_boxed())
    }
}

impl<'a> Iterator for Keybox<'a> {
    type Item = Result<KeyboxRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.reader.eof() {
            None
        } else {
            Some(self.read_next_record())
        }
    }
}

/// Types of keybox records.
///
/// Note: This enum cannot be exhaustively matched to allow future extensions.
#[non_exhaustive]
#[derive(PartialEq, Eq, Debug)]
pub enum KeyboxRecordType {
    /// Header record type.
    Header,
    /// OpenPGP record type.
    OpenPGP,
    /// X.509 record type.
    X509,
    /// Catchall.
    Unknown(u8),
}

impl From<u8> for KeyboxRecordType {
    fn from(value: u8) -> Self {
        match value {
            1 => KeyboxRecordType::Header,
            2 => KeyboxRecordType::OpenPGP,
            3 => KeyboxRecordType::X509,
            v => KeyboxRecordType::Unknown(v),
        }
    }
}

impl Display for KeyboxRecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyboxRecordType::Header => write!(f, "Header"),
            KeyboxRecordType::OpenPGP => write!(f, "OpenPGP"),
            KeyboxRecordType::X509 => write!(f, "X509"),
            KeyboxRecordType::Unknown(v) => write!(f, "Unknown: {}", v),
        }
    }
}

/// Provides access to the fields shared by all keybox record types.
impl KeyboxRecord {
    fn bytes(&self) -> &[u8] {
        match self {
            KeyboxRecord::Header(h) => &h.bytes,
            KeyboxRecord::OpenPGP(o) => &o.bytes,
            KeyboxRecord::X509(x) => &x.bytes,
            KeyboxRecord::Unknown(_, bytes) => bytes,
        }
    }

    /// Returns the offset in the Keybox file.
    pub fn offset(&self) -> usize {
        match self {
            KeyboxRecord::Header(h) => h.offset(),
            KeyboxRecord::OpenPGP(o) => o.offset(),
            KeyboxRecord::X509(x) => x.offset(),
            KeyboxRecord::Unknown(offset, _bytes) => *offset,
        }
    }

    /// The first 4 bytes contain the record's length.
    pub fn length_field(&self) -> u32 {
        u32::from_be_bytes((&self.bytes()[..4]).try_into().unwrap())
    }

    /// The 5th byte contains the record's type.
    pub fn typ(&self) -> KeyboxRecordType {
        KeyboxRecordType::from(self.bytes()[4])
    }

    /// The 6th byte contains the record type's version.
    pub fn version(&self) -> u8 {
        self.bytes()[5]
    }

    fn new(offset: usize, bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() < 6 {
            return Err(Error::NotEnoughData(
                "A keybox record requires at least 6 bytes.".to_string(),
            )
            .into());
        }

        let record = KeyboxRecord::Unknown(offset, bytes.clone());
        match record.typ() {
            KeyboxRecordType::Header => {
                HeaderRecord::new(offset, bytes).map(KeyboxRecord::Header)
            }
            KeyboxRecordType::OpenPGP => {
                OpenPGPRecordV1::new(offset, &record).map(KeyboxRecord::OpenPGP)
            }
            KeyboxRecordType::X509 => {
                X509Record::new(offset, bytes).map(KeyboxRecord::X509)
            }
            KeyboxRecordType::Unknown(_) => Ok(record),
        }
    }
}

/// Keybox record
///
/// Holds the record's data and provides access to the fields shared by all
/// record types.
///
/// Note: This enum cannot be exhaustively matched to allow future extensions.
#[non_exhaustive]
#[derive(PartialEq, Eq, Debug)]
pub enum KeyboxRecord {
    /// Header record.
    Header(HeaderRecord),
    /// OpenPGP record.
    OpenPGP(OpenPGPRecordV1),
    /// X.509 record.
    X509(X509Record),
    /// Catchall.
    Unknown(usize, Vec<u8>),
}

/// Keybox header record.
///
/// Contains general metadata of the keybox.
#[derive(PartialEq, Eq, Debug)]
pub struct HeaderRecord {
    /// Offset into the Keybox file.
    offset: usize,

    bytes: Vec<u8>,
}

impl HeaderRecord {
    fn new(offset: usize, bytes: Vec<u8>) -> Result<Self> {
        //TODO at least check length?
        Ok(Self { offset, bytes })
    }

    /// Returns the offset in the Keybox file.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// Flags field.
    // Semantics unknown.
    pub fn flags(&self) -> [u8; 2] {
        self.bytes[0x6..=0x7].try_into().unwrap()
    }

    /// Checks that the magic number is correctly "KBXf".
    pub fn check_magic(&self) -> bool {
        let magic = &self.bytes[0x08..=0x0B];
        magic == b"KBXf"
    }

    /// The unix timestamp when this keybox file was created.
    pub fn created_at(&self) -> u32 {
        u32::from_be_bytes((self.bytes[0x10..=0x13]).try_into().unwrap())
    }

    /// The unix timestamp when this keybox file was last maintained.
    // Unsure what "last maintained" means. Not last modified, adding a key
    // through gpg --import does not change it
    pub fn last_maintained(&self) -> u32 {
        u32::from_be_bytes((self.bytes[0x14..=0x17]).try_into().unwrap())
    }
}

/// Keybox X.509 record
///
/// Unhandled, only exists for completeness.
#[derive(PartialEq, Eq, Debug)]
pub struct X509Record {
    /// Offset into the Keybox file.
    offset: usize,

    bytes: Vec<u8>,
}

impl X509Record {
    fn new(offset: usize, bytes: Vec<u8>) -> Result<Self> {
        //TODO at least check length?
        Ok(Self { offset, bytes })
    }

    /// Returns the offset in the Keybox file.
    pub fn offset(&self) -> usize {
        self.offset
    }
}

/// Keybox OpenPGP record
#[derive(PartialEq, Eq, Debug)]
pub struct OpenPGPRecordV1 {
    /// Offset into the Keybox file.
    offset: usize,

    bytes: Vec<u8>,
}

impl OpenPGPRecordV1 {
    fn new(offset: usize, record: &KeyboxRecord) -> Result<Self> {
        // Check type and version
        if record.typ() != KeyboxRecordType::OpenPGP || record.version() != 1 {
            return Err(
                Error::UnhandledRecord(record.typ(), record.version()).into()
            );
        }

        // Check record header length
        if record.bytes().len() < 0x10 {
            return Err(Error::NotEnoughData(format!(
                "OpenPGP record header is 16 bytes, got {}",
                record.bytes().len()
            ))
            .into());
        };

        let record = OpenPGPRecordV1 {
            offset,
            bytes: record.bytes().to_vec(),
        };

        // Check checksum
        if record.checksum_field()[..] != record.compute_checksum()? {
            return Err(Error::InvalidData("wrong checksum".to_string()).into());
        }

        Ok(record)
    }

    /// Returns the offset in the Keybox file.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// Flags field.
    // Semantics unknown.
    pub fn flags(&self) -> [u8; 2] {
        self.bytes[0x6..=0x7].try_into().unwrap()
    }

    /// Data offset field.
    pub fn data_offset(&self) -> usize {
        u32::from_be_bytes((self.bytes[0x8..=0xB]).try_into().unwrap()) as usize
    }

    /// Data length field.
    pub fn data_length(&self) -> usize {
        u32::from_be_bytes((self.bytes[0xC..=0xF]).try_into().unwrap()) as usize
    }

    /// The record's contained raw data.
    pub fn data_section(&self) -> Result<&[u8]> {
        let data_end = self.data_offset() + self.data_length();
        // Check if data length is correct
        if self.bytes.len() < data_end {
            return Err(Error::NotEnoughData(
                "data section truncated".to_string(),
            )
            .into());
        };
        Ok(&self.bytes[self.data_offset()..data_end])
    }

    /// Metadata section, unhandled.
    // Not handled, contains:
    // Redundant data (fingerprints, keyids, userids) of the
    // following cert,
    // management fields (ownertrust, all-validity?)
    // timestamps (recheck?, latest change?, creation date)
    pub fn metadata_section(&self) -> &[u8] {
        &self.bytes[0x10..self.data_offset()]
    }

    /// Checksum field.
    ///
    /// Contains a there's a SHA1 hash over the whole record.
    pub fn checksum_field(&self) -> [u8; 20] {
        let hash_offset = self.data_offset() + self.data_length();
        self.bytes[hash_offset..hash_offset + 20]
            .try_into()
            .unwrap()
    }

    /// Compute the checksum
    ///
    /// Computes a SHA1 hash over the whole record.
    pub fn compute_checksum(&self) -> Result<Vec<u8>> {
        let hash_offset = self.data_offset() + self.data_length();
        let (hashed_data, _hash) = &self.bytes.split_at(hash_offset);
        let mut ctx = SHA1.context()?.for_digest();
        ctx.update(hashed_data);
        ctx.into_digest()
    }

    /// Extract the cert from a keybox openpgp version 1 record.
    /// Ignores metadata and flags stored in the record, but
    /// checks the checksum.
    pub fn cert(&self) -> Result<Cert> {
        let cert_data = &self.data_section()?;
        Cert::from_bytes(cert_data)
            .with_context(
                || format!("Parsing keybox record at offset {}",
                           self.offset()))
    }
}

#[derive(thiserror::Error, Debug)]
/// Errors used in this module.
pub enum Error {
    /// Not enough data
    #[error("Not enough data: {0}")]
    NotEnoughData(String),
    /// Unhandled record
    #[error("Unhandled record type: {0}, version {1}")]
    UnhandledRecord(KeyboxRecordType, u8),
    /// Invalid data
    #[error("Invalid data: {0}")]
    InvalidData(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(test)]
    // Extract all certs from a keybox. Ignore other records.
    fn parse_keybox(reader: &mut dyn BufferedReader<()>) -> Result<Vec<Cert>> {
        let kbx = Keybox::from_reader(reader)?;
        let certs = kbx
            // Keep only records which were parsed successfully.
            .filter_map(|kbx_record| kbx_record.ok())
            // Map the OpenPGP records to the contained certs.
            .filter_map(|kbx_record| match kbx_record {
                KeyboxRecord::OpenPGP(r) => Some(r.cert()),
                _ => None,
            })
            .collect::<Result<Vec<Cert>>>();
        certs
    }

    #[test]
    fn keybox_record() -> Result<()> {
        let header_bytes = crate::tests::keybox("header_sample");
        let header_kbx = KeyboxRecord::new(0, header_bytes.to_vec())?;
        assert_eq!(header_kbx.typ(), header_bytes[4].into());

        let openpgp_bytes = crate::tests::keybox("testy_openpgp");
        let openpgp_kbx = KeyboxRecord::new(0, openpgp_bytes.to_vec())?;
        assert_eq!(openpgp_kbx.typ(), openpgp_bytes[4].into());

        let x509_bytes = crate::tests::keybox("testy_x509");
        let x509_kbx = KeyboxRecord::new(0, x509_bytes.to_vec())?;
        assert_eq!(x509_kbx.typ(), x509_bytes[4].into());

        let too_short = &[1u8; 5];
        assert!(KeyboxRecord::new(0, too_short.to_vec()).is_err());
        Ok(())
    }

    #[test]
    fn cert_from_openpgp_record() -> Result<()> {
        let openpgp_bytes = crate::tests::keybox("testy_openpgp");
        let kbx_record = KeyboxRecord::new(0, openpgp_bytes.to_vec())?;
        let openpgp_record = match kbx_record {
            KeyboxRecord::OpenPGP(r) => r,
            _ => unreachable!(),
        };
        let cert = openpgp_record.cert().unwrap();
        let testy = Cert::from_bytes(crate::tests::key("testy.pgp")).unwrap();
        assert_eq!(cert, testy);
        Ok(())
    }

    #[test]
    fn cert_from_keybox() -> Result<()> {
        let bytes = crate::tests::keybox("keybox.kbx");
        let mut br = buffered_reader::Memory::new(bytes);
        let certs = parse_keybox(&mut br)?;
        let testy = Cert::from_bytes(crate::tests::key("testy.pgp"))?;
        assert_eq!(certs[0], testy);
        Ok(())
    }

    #[test]
    fn openpgp_record() -> Result<()> {
        let openpgp_bytes = crate::tests::keybox("testy_openpgp");
        let kbx_record = KeyboxRecord::new(0, openpgp_bytes.to_vec())?;
        assert_eq!(kbx_record.length_field(), 1428u32);
        assert_eq!(kbx_record.typ(), KeyboxRecordType::OpenPGP);
        assert_eq!(kbx_record.version(), 1u8);
        let openpgp_record = match kbx_record {
            KeyboxRecord::OpenPGP(r) => r,
            _ => unreachable!(),
        };
        assert_eq!(openpgp_record.flags(), [0u8, 0u8]);
        assert_eq!(openpgp_record.data_offset(), 126usize);
        assert_eq!(openpgp_record.data_length(), 1282usize);
        assert_eq!(
            openpgp_record.metadata_section(),
            [
                0, 2, 0, 28, 62, 136, 119, 200, 119, 39, 70, 146, 151, 81, 137,
                245, 208, 63, 111, 134, 82, 38, 254, 139, 0, 0, 0, 32, 0, 0, 0,
                0, 1, 241, 135, 87, 91, 212, 86, 68, 4, 101, 100, 193, 73, 226,
                17, 129, 102, 201, 38, 50, 0, 0, 0, 60, 0, 0, 0, 0, 0, 0, 0, 1,
                0, 12, 0, 0, 1, 158, 0, 0, 0, 36, 0, 0, 0, 0, 0, 2, 0, 4, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 96, 129,
                142, 142, 0, 0, 0, 0
            ]
        );
        Ok(())
    }

    #[test]
    fn openpgp_errors() -> Result<()> {
        let openpgp_too_short = [0u8, 7u8, 1u8, 1u8, 2u8, 1u8, 1u8];
        assert!(KeyboxRecord::new(0, openpgp_too_short.to_vec()).is_err());

        let openpgp_unknown_version = [0u8, 7u8, 1u8, 1u8, 2u8, 7u8, 1u8];
        assert!(KeyboxRecord::new(0, openpgp_unknown_version.to_vec()).is_err());

        let mut openpgp_wrong_checksum = crate::tests::keybox("testy_openpgp").to_vec();
        // set last byte (= last byte of checksum) to 0
        if let Some(last) = openpgp_wrong_checksum.last_mut() {
            *last = 0u8;
        };
        assert!(KeyboxRecord::new(0, openpgp_wrong_checksum.to_vec()).is_err());
        Ok(())
    }

    #[test]
    fn header_record() -> Result<()> {
        let header_bytes = crate::tests::keybox("header_sample");
        let kbx_record = KeyboxRecord::new(0, header_bytes.to_vec())?;
        assert_eq!(kbx_record.length_field(), 32u32);
        assert_eq!(kbx_record.typ(), KeyboxRecordType::Header);
        assert_eq!(kbx_record.version(), 1u8);
        let header_record = match kbx_record {
            KeyboxRecord::Header(r) => r,
            _ => unreachable!(),
        };
        assert!(header_record.check_magic());
        assert_eq!(header_record.flags(), [0x00u8, 0x02u8]);
        assert_eq!(header_record.created_at(), 0x6081_8e8eu32);
        assert_eq!(header_record.last_maintained(), 0x6081_8e8eu32);
        Ok(())
    }

    #[test]
    fn x509_record() -> Result<()> {
        let x509_bytes = crate::tests::keybox("testy_x509");
        let kbx_record = KeyboxRecord::new(0, x509_bytes.to_vec())?;
        assert_eq!(kbx_record.length_field(), 1704u32);
        assert_eq!(kbx_record.typ(), KeyboxRecordType::X509);
        assert_eq!(kbx_record.version(), 1u8);
        Ok(())
    }
}
