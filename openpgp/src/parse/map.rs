//! Packet maps.
//!
//! If configured to do so, a `PacketParser` will create a map that
//! charts the byte-stream, describing where the information was
//! extracted from.

use std::iter;
use std::cmp;

/// Map created during parsing.
#[derive(Clone, Debug)]
pub struct Map {
    length: usize,
    entries: Vec<Entry>,
    header: Vec<u8>,
    data: Vec<u8>,
}

/// Represents an entry in the map.
#[derive(Clone, Debug)]
struct Entry {
    offset: usize,
    length: usize,
    field: &'static str,
}

impl Map {
    /// Creates a new map.
    pub(crate) fn new(header: Vec<u8>) -> Self {
        Map {
            length: 0,
            entries: Vec::new(),
            header: header,
            data: Vec::new(),
        }
    }

    /// Adds a field to the map.
    pub(crate) fn add(&mut self, field: &'static str, length: usize) {
        self.entries.push(Entry {
            offset: self.length, length: length, field: field
        });
        self.length += length;
    }

    /// Finalizes the map providing the actual data.
    pub(crate) fn finalize(&mut self, data: Vec<u8>) {
        self.data = data;
    }

    /// Creates an iterator over the map.
    ///
    /// Items returned are a small string indicating what kind of
    /// information is extracted (e.g. "header", or "version"), and a
    /// slice containing the actual bytes.
    ///
    /// # Example
    ///
    /// ```
    /// # use openpgp::Result;
    /// # use openpgp::parse::{PacketParser, PacketParserBuilder};
    /// # f();
    /// #
    /// # fn f() -> Result<()> {
    /// let msg = b"\xcb\x12t\x00\x00\x00\x00\x00Hello world.";
    /// let ppo = PacketParserBuilder::from_bytes(msg)?
    ///     .map(true).finalize()?;
    /// let map = ppo.unwrap().map.unwrap();
    /// assert_eq!(map.iter().collect::<Vec<(&str, &[u8])>>(),
    ///            [("header", &b"\xcb\x12"[..]),
    ///             ("format", b"t"),
    ///             ("filename_len", b"\x00"),
    ///             ("date", b"\x00\x00\x00\x00"),
    ///             ("body", b"Hello world.")]);
    /// # Ok(())
    /// # }
    /// ```
    pub fn iter<'a>(&'a self)
                    -> Box<'a + iter::Iterator<Item=(&'static str, &'a [u8])>> {
        let len = self.data.len();
        Box::new(
            iter::once(("header", self.header.as_slice()))
                .chain(self.entries.iter().map(move |e| {
                    let start = cmp::min(len, e.offset);
                    let end = cmp::min(len, e.offset + e.length);
                    (e.field, &self.data[start..end])
                })))
    }
}
