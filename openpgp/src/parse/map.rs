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
    pub(super) fn new(header: Vec<u8>) -> Self {
        Map {
            length: 0,
            entries: Vec::new(),
            header: header,
            data: Vec::new(),
        }
    }

    /// Adds a field to the map.
    pub(super) fn add(&mut self, field: &'static str, length: usize) {
        self.entries.push(Entry {
            offset: self.length, length, field
        });
        self.length += length;
    }

    /// Finalizes the map providing the actual data.
    pub(super) fn finalize(&mut self, data: Vec<u8>) {
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
    /// # use openpgp::parse::{Parse, PacketParser, PacketParserBuilder};
    /// # f();
    /// #
    /// # fn f() -> Result<()> {
    /// let msg = b"\xcb\x12t\x00\x00\x00\x00\x00Hello world.";
    /// let ppo = PacketParserBuilder::from_bytes(msg)?
    ///     .map(true).finalize()?;
    /// assert_eq!(ppo.unwrap().map().unwrap().iter()
    ///            .map(|f| (f.name(), f.data()))
    ///            .collect::<Vec<(&str, &[u8])>>(),
    ///            [("CTB", &b"\xcb"[..]),
    ///             ("length", &b"\x12"[..]),
    ///             ("format", b"t"),
    ///             ("filename_len", b"\x00"),
    ///             ("date", b"\x00\x00\x00\x00"),
    ///             ("body", b"Hello world.")]);
    /// # Ok(())
    /// # }
    /// ```
    pub fn iter<'a>(&'a self) -> impl Iterator<Item = Field<'a>> {
        Iter::new(self)
    }
}

/// Represents an entry in the map.
#[derive(Clone, Debug)]
pub struct Field<'a> {
    /// Name of the field.
    name: &'static str,
    /// Offset of the field in the packet.
    offset: usize,
    /// Value of the field.
    data: &'a [u8],
}

impl<'a> Field<'a> {
    fn new(map: &'a Map, i: usize) -> Option<Field<'a>> {
        // Old-style CTB with indeterminate length emits no length
        // field.
        let has_length = map.header.len() > 1;
        if i == 0 {
            Some(Field {
                offset: 0,
                name: "CTB",
                data: &map.header.as_slice()[..1],
            })
        } else if i == 1 && has_length {
            Some(Field {
                offset: 1,
                name: "length",
                data: &map.header.as_slice()[1..]
            })
        } else {
            let offset_length = if has_length { 1 } else { 0 };
            map.entries.get(i - 1 - offset_length).map(|e| {
                let len = map.data.len();
                let start = cmp::min(len, e.offset);
                let end = cmp::min(len, e.offset + e.length);
                Field {
                    offset: map.header.len() + e.offset,
                    name: e.field,
                    data: &map.data[start..end],
                }
            })
        }
    }

    /// Returns the name of the field.
    ///
    /// Note: The returned names are for display purposes only and may
    /// change in the future.
    pub fn name(&self) -> &'a str {
        self.name
    }

    /// Returns the offset of the field in the packet.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// Returns the value of the field.
    pub fn data(&self) -> &'a [u8] {
        self.data
    }
}

/// An iterator over the map.
struct Iter<'a> {
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
        let field = Field::new(self.map, self.i);
        if field.is_some() {
            self.i += 1;
        }
        field
    }
}
