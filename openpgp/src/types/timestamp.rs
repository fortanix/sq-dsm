use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::time::{SystemTime, Duration as SystemDuration, UNIX_EPOCH};
use quickcheck::{Arbitrary, Gen};

use crate::{
    Error,
    Result,
};

/// A timestamp representable by OpenPGP.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(u32);

impl From<Timestamp> for u32 {
    fn from(t: Timestamp) -> Self {
        t.0
    }
}

impl From<u32> for Timestamp {
    fn from(t: u32) -> Self {
        Timestamp(t)
    }
}

impl TryFrom<SystemTime> for Timestamp {
    type Error = failure::Error;

    fn try_from(t: SystemTime) -> Result<Self> {
        match t.duration_since(std::time::UNIX_EPOCH) {
            Ok(d) if d.as_secs() <= std::u32::MAX as u64 =>
                Ok(Timestamp(d.as_secs() as u32)),
            _ => Err(Error::InvalidArgument(
                format!("Time exceeds u32 epoch: {:?}", t))
                     .into()),
        }
    }
}

impl From<Timestamp> for SystemTime {
    fn from(t: Timestamp) -> Self {
        UNIX_EPOCH + SystemDuration::new(t.0 as u64, 0)
    }
}

impl fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", SystemTime::from(*self))
    }
}

impl Timestamp {
    /// Returns the current time.
    pub fn now() -> Timestamp {
        SystemTime::now().try_into()
            .expect("representable for the next hundred years")
    }
}

impl Arbitrary for Timestamp {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        Timestamp(u32::arbitrary(g))
    }
}

/// A duration representable by OpenPGP.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Duration(u32);

impl From<Duration> for u32 {
    fn from(d: Duration) -> Self {
        d.0
    }
}

impl From<u32> for Duration {
    fn from(d: u32) -> Self {
        Duration(d)
    }
}

impl TryFrom<SystemDuration> for Duration {
    type Error = failure::Error;

    fn try_from(d: SystemDuration) -> Result<Self> {
        if d.as_secs() <= std::u32::MAX as u64 {
            Ok(Duration(d.as_secs() as u32))
        } else {
            Err(Error::InvalidArgument(
                format!("Duration exceeds u32: {:?}", d))
                     .into())
        }
    }
}

impl From<Duration> for SystemDuration {
    fn from(d: Duration) -> Self {
        SystemDuration::new(d.0 as u64, 0)
    }
}

impl fmt::Debug for Duration {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", SystemDuration::from(*self))
    }
}

impl Duration {
    /// Returns a `Duration` with the given number of seconds.
    pub fn seconds(n: u32) -> Duration {
        n.into()
    }

    /// Returns a `Duration` with the given number of minutes, if
    /// representable.
    pub fn minutes(n: u32) -> Result<Duration> {
        60u32.checked_mul(n).ok_or(())
            .map(Self::seconds)
            .map_err(|_| Error::InvalidArgument(
                format!("Not representable: {} minutes in seconds exceeds u32",
                        n)).into())
    }

    /// Returns a `Duration` with the given number of hours, if
    /// representable.
    pub fn hours(n: u32) -> Result<Duration> {
        60u32.checked_mul(n)
            .ok_or(Error::InvalidArgument("".into()).into())
            .and_then(Self::minutes)
            .map_err(|_| Error::InvalidArgument(
                format!("Not representable: {} hours in seconds exceeds u32",
                        n)).into())
    }

    /// Returns a `Duration` with the given number of days, if
    /// representable.
    pub fn days(n: u32) -> Result<Duration> {
        24u32.checked_mul(n)
            .ok_or(Error::InvalidArgument("".into()).into())
            .and_then(Self::hours)
            .map_err(|_| Error::InvalidArgument(
                format!("Not representable: {} days in seconds exceeds u32",
                        n)).into())
    }

    /// Returns a `Duration` with the given number of weeks, if
    /// representable.
    pub fn weeks(n: u32) -> Result<Duration> {
        7u32.checked_mul(n)
            .ok_or(Error::InvalidArgument("".into()).into())
            .and_then(Self::days)
            .map_err(|_| Error::InvalidArgument(
                format!("Not representable: {} weeks in seconds exceeds u32",
                        n)).into())
    }

    /// Returns the duration as seconds.
    pub fn as_secs(self) -> u64 {
        self.0 as u64
    }
}

impl Arbitrary for Duration {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        Duration(u32::arbitrary(g))
    }
}
