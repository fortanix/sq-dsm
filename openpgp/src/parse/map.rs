//! Packet maps.
//!
//! If configured to do so, a `PacketParser` will create a map that
//! charts the byte-stream, describing where the information was
//! extracted from.

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
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::Result;
    /// # use openpgp::parse::{PacketParser, PacketParserBuilder};
    /// # f();
    /// #
    /// # fn f() -> Result<()> {
    /// let msg = b"\xcb\x12t\x00\x00\x00\x00\x00Hello world.";
    /// let ppo = PacketParserBuilder::from_bytes(msg)?
    ///     .map(true).finalize()?;
    /// assert_eq!(ppo.unwrap().map().unwrap().iter()
    ///            .map(|f| (f.name, f.data)).collect::<Vec<(&str, &[u8])>>(),
    ///            [("frame", &b"\xcb\x12"[..]),
    ///             ("format", b"t"),
    ///             ("filename_len", b"\x00"),
    ///             ("date", b"\x00\x00\x00\x00"),
    ///             ("body", b"Hello world.")]);
    /// # Ok(())
    /// # }
    /// ```
    pub fn iter<'a>(&'a self) -> Iter<'a> {
        Iter::new(self)
    }
}

/// Represents an entry in the map.
#[derive(Clone, Debug)]
pub struct Field<'a> {
    /// Name of the field.
    pub name: &'static str,
    /// Offset of the field in the packet.
    pub offset: usize,
    /// Length of the field.
    pub length: usize,
    /// Value of the field.
    pub data: &'a [u8],
}

impl<'a> Field<'a> {
    fn new(map: &'a Map, i: usize) -> Field<'a> {
        if i == 0 {
            Field {
                offset: 0,
                length: map.header.len(),
                name: "frame",
                data: map.header.as_slice()
            }
        } else {
            let len = map.data.len();
            let e = &map.entries[i - 1];
            let start = cmp::min(len, e.offset);
            let end = cmp::min(len, e.offset + e.length);
            Field {
                offset: map.header.len() + e.offset,
                length: e.length,
                name: e.field,
                data: &map.data[start..end],
            }
        }
    }
}

/// An iterator over the map.
pub struct Iter<'a> {
    map: &'a Map,
    i: usize,
}

impl<'a> Iter<'a> {
    fn new(map: &'a Map) -> Iter<'a> {
        Iter {
            map: map,
            i: 0,
        }
    }
}

impl<'a> Iterator for Iter<'a> {
    type Item = Field<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.i < self.map.entries.len() + 1 {
            self.i += 1;
            Some(Field::new(self.map, self.i - 1))
        } else {
            None
        }
    }
}
