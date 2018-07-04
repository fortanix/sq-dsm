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
