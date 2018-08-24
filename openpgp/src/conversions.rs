//! Conversions for primitive OpenPGP types.

use time;

use Error;
use Result;

/// Conversions for OpenPGP time stamps.
pub trait Time {
    /// Converts an OpenPGP time stamp to broken-down time.
    fn from_pgp(u32) -> Self;
    /// Converts broken-down time to an OpenPGP time stamp.
    fn to_pgp(&self) -> Result<u32>;
}

impl Time for time::Tm {
    fn from_pgp(timestamp: u32) -> Self {
        time::at_utc(time::Timespec::new(timestamp as i64, 0))
    }

    fn to_pgp(&self) -> Result<u32> {
        let epoch = self.to_timespec().sec;
        if epoch > ::std::u32::MAX as i64 {
            return Err(Error::InvalidArgument(
                format!("Time exceeds u32 epoch: {:?}", self))
                       .into());
        }
        Ok(epoch as u32)
    }
}

/// Conversions for OpenPGP durations.
pub trait Duration {
    /// Converts an OpenPGP duration to ISO 8601 time duration.
    fn from_pgp(u32) -> Self;
    /// Converts ISO 8601 time duration to an OpenPGP duration.
    fn to_pgp(&self) -> Result<u32>;
}

impl Duration for time::Duration {
    fn from_pgp(duration: u32) -> Self {
        time::Duration::seconds(duration as i64)
    }

    fn to_pgp(&self) -> Result<u32> {
        let secs = self.num_seconds();
        if secs > ::std::u32::MAX as i64 {
            return Err(Error::InvalidArgument(
                format!("Duration exceeds u32: {:?}", self))
                       .into());
        }
        Ok(secs as u32)
    }
}


/// A helpful debugging function.
#[allow(dead_code)]
pub(crate) fn to_hex(s: &[u8], pretty: bool) -> String {
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

/// A helpful function for converting a hexadecimal string to binary.
/// This function skips whitespace if `pretty` is set.
pub(crate) fn from_hex(hex: &str, pretty: bool) -> Result<Vec<u8>> {
    const BAD: u8 = 255u8;
    const X: u8 = 'x' as u8;

    let mut nibbles = hex.as_bytes().iter().filter_map(|x| {
        match *x as char {
            '0' => Some(0u8),
            '1' => Some(1u8),
            '2' => Some(2u8),
            '3' => Some(3u8),
            '4' => Some(4u8),
            '5' => Some(5u8),
            '6' => Some(6u8),
            '7' => Some(7u8),
            '8' => Some(8u8),
            '9' => Some(9u8),
            'a' | 'A' => Some(10u8),
            'b' | 'B' => Some(11u8),
            'c' | 'C' => Some(12u8),
            'd' | 'D' => Some(13u8),
            'e' | 'E' => Some(14u8),
            'f' | 'F' => Some(15u8),
            'x' | 'X' if pretty => Some(X),
            _ if pretty && x.is_ascii_whitespace() => None,
            _ => Some(BAD),
        }
    }).collect::<Vec<u8>>();

    if pretty && nibbles.len() >= 2 && nibbles[0] == 0 && nibbles[1] == X {
        // Drop '0x' prefix.
        nibbles.remove(0);
        nibbles.remove(0);
    }

    if nibbles.iter().any(|&b| b == BAD || b == X) {
        // Not a hex character.
        return
            Err(Error::InvalidArgument("Invalid characters".into()).into());
    }

    // We need an even number of nibbles.
    if nibbles.len() % 2 != 0 {
        return
            Err(Error::InvalidArgument("Odd number of nibbles".into()).into());
    }

    let bytes = nibbles.chunks(2).map(|nibbles| {
        (nibbles[0] << 4) | nibbles[1]
    }).collect::<Vec<u8>>();

    Ok(bytes)
}

#[cfg(test)]
mod test {
    #[test]
    fn from_hex() {
        use super::from_hex as fh;
        assert_eq!(fh("", false).ok(), Some(vec![]));
        assert_eq!(fh("0", false).ok(), None);
        assert_eq!(fh("00", false).ok(), Some(vec![0x00]));
        assert_eq!(fh("09", false).ok(), Some(vec![0x09]));
        assert_eq!(fh("0f", false).ok(), Some(vec![0x0f]));
        assert_eq!(fh("99", false).ok(), Some(vec![0x99]));
        assert_eq!(fh("ff", false).ok(), Some(vec![0xff]));
        assert_eq!(fh("000", false).ok(), None);
        assert_eq!(fh("0000", false).ok(), Some(vec![0x00, 0x00]));
        assert_eq!(fh("0009", false).ok(), Some(vec![0x00, 0x09]));
        assert_eq!(fh("000f", false).ok(), Some(vec![0x00, 0x0f]));
        assert_eq!(fh("0099", false).ok(), Some(vec![0x00, 0x99]));
        assert_eq!(fh("00ff", false).ok(), Some(vec![0x00, 0xff]));
        assert_eq!(fh("\t\n\x0c\r ", false).ok(), None);
        assert_eq!(fh("a", false).ok(), None);
        assert_eq!(fh("0x", false).ok(), None);
        assert_eq!(fh("0x0", false).ok(), None);
        assert_eq!(fh("0x00", false).ok(), None);
    }

    #[test]
    fn from_pretty_hex() {
        use super::from_hex as fh;
        assert_eq!(fh(" ", true).ok(), Some(vec![]));
        assert_eq!(fh(" 0", true).ok(), None);
        assert_eq!(fh(" 00", true).ok(), Some(vec![0x00]));
        assert_eq!(fh(" 09", true).ok(), Some(vec![0x09]));
        assert_eq!(fh(" 0f", true).ok(), Some(vec![0x0f]));
        assert_eq!(fh(" 99", true).ok(), Some(vec![0x99]));
        assert_eq!(fh(" ff", true).ok(), Some(vec![0xff]));
        assert_eq!(fh(" 00 0", true).ok(), None);
        assert_eq!(fh(" 00 00", true).ok(), Some(vec![0x00, 0x00]));
        assert_eq!(fh(" 00 09", true).ok(), Some(vec![0x00, 0x09]));
        assert_eq!(fh(" 00 0f", true).ok(), Some(vec![0x00, 0x0f]));
        assert_eq!(fh(" 00 99", true).ok(), Some(vec![0x00, 0x99]));
        assert_eq!(fh(" 00 ff", true).ok(), Some(vec![0x00, 0xff]));
        assert_eq!(fh("\t\n\x0c\r ", true).ok(), Some(vec![]));
        assert_eq!(fh("a", true).ok(), None);
        assert_eq!(fh(" 0x", true).ok(), Some(vec![]));
        assert_eq!(fh(" 0x0", true).ok(), None);
        assert_eq!(fh(" 0x00", true).ok(), Some(vec![0x00]));
    }

    quickcheck! {
        fn hex_roundtrip(data: Vec<u8>) -> bool {
            let hex = super::to_hex(&data, false);
            data == super::from_hex(&hex, false).unwrap()
        }
    }

    quickcheck! {
        fn pretty_hex_roundtrip(data: Vec<u8>) -> bool {
            let hex = super::to_hex(&data, true);
            data == super::from_hex(&hex, true).unwrap()
        }
    }
}
