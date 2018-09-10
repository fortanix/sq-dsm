use buffered_reader::{
    BufferedReader, BufferedReaderGeneric, BufferedReaderMemory,
    BufferedReaderFile,
};
use std::io;
use std::path::Path;

use CTB;
use Result;
use armor;

/// Transparently strips ASCII Armor.
///
/// This reader detects and strips ASCII Armor.
pub struct Reader<'a>(Box<'a + BufferedReader<()>>);

impl<'a> Reader<'a> {
    fn from_buffered_reader(mut br: Box<'a + BufferedReader<()>>)
                            -> Result<Self> {
        let ptag = br.data_hard(1)?[0];
        if let Ok(_) = CTB::from_ptag(ptag) {
            Ok(Reader(br))
        } else {
            Ok(Reader(Box::new(BufferedReaderGeneric::new(
                armor::Reader::from_buffered_reader(br, None),
                None))))
        }
    }

    /// Creates a `Reader` from an `io::Read`er.
    pub fn from_reader<R>(reader: R) -> Result<Self>
        where R: io::Read + 'a
    {
        Self::from_buffered_reader(
            Box::new(BufferedReaderGeneric::new(reader, None)))
    }

    /// Creates a `Reader` from a file.
    pub fn from_file<P>(path: P) -> Result<Self>
        where P: AsRef<Path>
    {
        Self::from_buffered_reader(Box::new(BufferedReaderFile::open(path)?))
    }

    /// Creates a `Reader` from a buffer.
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self> {
        Self::from_buffered_reader(
            Box::new(BufferedReaderMemory::new(bytes)))
    }
}

impl<'a> io::Read for Reader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}
