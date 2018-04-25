use std::fmt;
use std::cell::RefCell;
use std::cmp;

use Error;
use Result;

use buffered_reader::BufferedReader;
use buffered_reader::BufferedReaderMemory;

const TRACE: bool = false;

#[derive(Clone)]
pub struct MPIs {
    pub raw: Vec<u8>,

    // A vector of (start, length) tuples into `raw`, one for each
    // MPI.
    parsed: RefCell<Option<Vec<(usize, usize)>>>,
}

impl fmt::Debug for MPIs {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.values() {
            Ok(values) => {
                f.debug_list()
                    .entries(values.iter().map(
                        |v| format!("{} bits: {}",
                                    v.len() * 8
                                    - if v.len() > 0 {
                                          v[0].leading_zeros() as usize
                                      } else {
                                          0
                                      },
                                    ::to_hex(v, true))))
                    .finish()
            },
            Err(error) => {
                f.write_str(&format!("Invalid MPI ({})", error))
            }
        }
    }
}

impl PartialEq for MPIs {
    fn eq(&self, other: &MPIs) -> bool {
        self.raw == other.raw
    }
}

impl Eq for MPIs {}

impl PartialOrd for MPIs {
    fn partial_cmp(&self, other: &MPIs) -> Option<cmp::Ordering> {
        // We use a lexographical ordering, not a numerical one.  A
        // numerical ordering would be more natural, but it's not
        // clear how to order two MPI arrays that have a different
        // number of elements, for instance.  A lexicographical
        // ordering is enough for a stable sort, however, which is our
        // primary concern.
        self.raw.partial_cmp(&other.raw)
    }
}

impl Ord for MPIs {
    fn cmp(&self, other: &MPIs) -> cmp::Ordering {
        // See PartialOrd::partial_cmp for why we use lexographical
        // ordering.
        self.raw.cmp(&other.raw)
    }
}

impl MPIs {
    /// Returns a new MPIs object contain no MPIs.
    pub fn new() -> MPIs {
        MPIs::parse(Vec::new())
    }

    /// Parses an OpenPGP formatted array of MPIs.
    ///
    /// See [Section 3.2 of RFC 4880] for details.
    ///
    ///   [Section 3.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-3.2
    pub fn parse(raw: Vec<u8>) -> MPIs {
        MPIs {
            raw: raw,
            parsed: RefCell::new(None)
        }
    }

    // Parses self.raw and caches the result in self.parsed, if
    // necessary.
    fn do_parse(&self) -> Result<()> {
        if self.parsed.borrow().is_some() {
            // Already parsed.  We're done.
            return Ok(());
        }

        let mut raw = BufferedReaderMemory::new(&self.raw[..]);
        let mut parsed = Vec::new();

        while raw.data(1)?.len() > 0 {
            let bits = raw.read_be_u16()? as usize;

            let start_offset = raw.total_out();

            let bytes = (bits + 7) / 8;
            let value = &raw.data_consume_hard(bytes)?[..bytes];

            if TRACE {
                eprintln!("bits: {}, value: {}",
                          bits, ::to_hex(value, true));
            }

            parsed.push((start_offset, bytes));

            let unused_bits = bytes * 8 - bits;
            assert_eq!(bytes * 8 - unused_bits, bits);

            if TRACE {
                eprintln!("unused bits: {}", unused_bits);
            }

            // Make sure the unused bits are zeroed.
            if unused_bits > 0 {
                let mask = !((1 << (8 - unused_bits)) - 1);
                let unused_value = value[0] & mask;

                if TRACE {
                    eprintln!("mask: {:08b} & first byte: {:08b} \
                               = unused value: {:08b}",
                              mask, value[0], unused_value);
                }

                if unused_value != 0 {
                    return Err(Error::MalformedMPI(
                        format!("{} unused bits not zeroed: ({:x})",
                                unused_bits, unused_value)).into());
                }
            }

            let first_used_bit = 8 - unused_bits;
            if value[0] & (1 << (first_used_bit - 1)) == 0 {
                return Err(Error::MalformedMPI(
                    format!("leading bit is not set: \
                             expected bit {} to be set in {:8b} ({:x})",
                            first_used_bit, value[0], value[0])).into());
            }
        }

        *self.parsed.borrow_mut() = Some(parsed);

        return Ok(());
    }

    /// Returns the MPIs.
    ///
    /// If an error occurs while parsing the MPIs, that is returned.
    pub fn values(&self) -> Result<Vec<&[u8]>> {
        self.do_parse()?;

        if let Some(parsed) = self.parsed.borrow().as_ref() {
            let mut mpis = Vec::new();
            for &(start, len) in parsed {
                mpis.push(&self.raw[start..start + len]);
            }

            return Ok(mpis);
        } else {
            return Err(
                Error::MalformedMPI("parsing error".to_string()).into());
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn mpis_parse_test() {
        // The number 1.
        let mpis = MPIs::parse(b"\x00\x01\x01".to_vec());
        let mpis = mpis.values().unwrap();
        assert_eq!(mpis.len(), 1);
        assert_eq!(mpis[0].len(), 1);
        assert_eq!(mpis[0][0], 1);

        // The number 511.
        let mpis = MPIs::parse(b"\x00\x09\x01\xff".to_vec());
        let mpis = mpis.values().unwrap();
        assert_eq!(mpis.len(), 1);
        assert_eq!(mpis[0].len(), 2);
        assert_eq!(mpis[0][0], 1);
        assert_eq!(mpis[0][1], 0xff);

        // The number 1, incorrectly encoded (the length should be 1,
        // not 2).
        assert!(MPIs::parse(b"\x00\x02\x01".to_vec()).values().is_err());
    }
}
