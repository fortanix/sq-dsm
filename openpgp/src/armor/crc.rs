//! Computes the CRC-24, (see [RFC 4880, section 6.1]).
//!
//! [RFC 4880, section 6.1]: https://tools.ietf.org/html/rfc4880#section-6.1

const CRC24_INIT: u32 = 0xB704CE;
const CRC24_POLY: u32 = 0x864CFB;

#[derive(Debug)]
pub struct CRC {
    n: u32,
}

/// Computes the CRC-24, (see [RFC 4880, section 6.1]).
///
/// [RFC 4880, section 6.1]: https://tools.ietf.org/html/rfc4880#section-6.1
impl CRC {
    pub fn new() -> Self {
        CRC { n: CRC24_INIT }
    }

    pub fn update(&mut self, buf: &[u8]) -> &Self {
        for octet in buf {
            self.n ^= (*octet as u32) << 16;
            for _ in 0..8 {
                self.n <<= 1;
                if self.n & 0x1000000 > 0 {
                    self.n ^= CRC24_POLY;
                }
            }
        }
        self
    }

    pub fn finalize(&self) -> u32 {
        self.n & 0xFFFFFF
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn foobarbaz() {
        let b = b"foobarbaz";
        let crcs = [
            0xb704ce,
            0x6d2804,
            0xa2d10d,
            0x4fc255,
            0x7aafca,
            0xc79c46,
            0x7334de,
            0x77dc72,
            0x000f65,
            0xf40d86,
        ];

        for len in 0..b.len() + 1 {
            assert_eq!(CRC::new().update(&b[..len]).finalize(), crcs[len]);
        }
    }

    /// Reference implementation of the iterative CRC24 computation.
    fn iterative(buf: &[u8]) -> u32 {
        let mut n = CRC24_INIT;
        for octet in buf {
            n ^= (*octet as u32) << 16;
            for _ in 0..8 {
                n <<= 1;
                if n & 0x1000000 > 0 {
                    n ^= CRC24_POLY;
                }
            }
        }
        n & 0xFFFFFF
    }

    quickcheck! {
        fn compare(b: Vec<u8>) -> bool {
            let mut c = CRC::new();
            c.update(&b);
            assert_eq!(c.finalize(), iterative(&b));
            true
        }
    }
}
