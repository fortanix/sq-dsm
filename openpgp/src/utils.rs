//! Utility functions that don't fit anywhere else.

pub fn read_be_u64(b: &[u8]) -> u64 {
    assert_eq!(b.len(), 8);
    ((b[0] as u64) << 56) as u64
        | ((b[1] as u64) << 48)
        | ((b[2] as u64) << 40)
        | ((b[3] as u64) << 32)
        | ((b[4] as u64) << 24)
        | ((b[5] as u64) << 16)
        | ((b[6] as u64) <<  8)
        | ((b[7] as u64) <<  0)
}

pub fn write_be_u64(b: &mut [u8], n: u64) {
    assert_eq!(b.len(), 8);
    b[0] = (n >> 56) as u8;
    b[1] = (n >> 48) as u8;
    b[2] = (n >> 40) as u8;
    b[3] = (n >> 32) as u8;
    b[4] = (n >> 24) as u8;
    b[5] = (n >> 16) as u8;
    b[6] = (n >>  8) as u8;
    b[7] = (n >>  0) as u8;
}

#[cfg(test)]
mod test {
    use super::*;

    quickcheck! {
        fn be_u64_roundtrip(n: u64) -> bool {
            let mut b = [0; 8];
            write_be_u64(&mut b, n);
            n == read_be_u64(&b)
        }
    }
}
