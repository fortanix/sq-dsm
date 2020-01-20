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

    /// Adds a duration to this timestamp.
    ///
    /// Returns `None` if the resulting timestamp is not
    /// representable.
    pub fn checked_add(&self, d: Duration) -> Option<Timestamp> {
        self.0.checked_add(d.0).map(|v| Self(v))
    }

    /// Subtracts a duration from this timestamp.
    ///
    /// Returns `None` if the resulting timestamp is not
    /// representable.
    pub fn checked_sub(&self, d: Duration) -> Option<Timestamp> {
        self.0.checked_sub(d.0).map(|v| Self(v))
    }

    /// Rounds down to the given level of precision.
    ///
    /// This can be used to reduce the metadata leak resulting from
    /// time stamps.  For example, a group of people attending a key
    /// signing event could be identified by comparing the time stamps
    /// of resulting certifications.  By rounding the creation time of
    /// these signatures down, all of them, and others, fall into the
    /// same bucket.
    ///
    /// The given level `p` determines the resulting resolution of
    /// `2^p` seconds.  The default is `21`, which results in a
    /// resolution of 24 days, or roughly a month.  `p` must be lower
    /// than 32.
    ///
    /// See [`Duration::round_up`](struct.Duration.html#method.round_up).
    ///
    /// # Important note
    ///
    /// If we create a signature, it is important that the signature's
    /// creation time does not predate the signing keys creation time,
    /// or otherwise violate the key's validity constraints.  The
    /// correct way to use this interface is to round the time down,
    /// lookup all keys and other objects like userids using this
    /// time, and on success create the signature:
    ///
    /// ```rust
    /// # use sequoia_openpgp::{*, packet::prelude::*, types::*, cert::*};
    /// # f().unwrap();
    /// # fn f() -> Result<()> {
    /// // Let's fix a time.
    /// let now = Timestamp::from(1583436160);
    ///
    /// // Generate a Cert for Alice.
    /// let (alice, _) = CertBuilder::new()
    ///     .set_creation_time(now.checked_sub(Duration::weeks(2)?).unwrap())
    ///     .primary_key_flags(KeyFlags::default().set_certification(true))
    ///     .add_userid("alice@example.org")
    ///     .generate()?;
    ///
    /// // Generate a Cert for Bob.
    /// let (bob, _) = CertBuilder::new()
    ///     .set_creation_time(now.checked_sub(Duration::weeks(1)?).unwrap())
    ///     .primary_key_flags(KeyFlags::default().set_certification(true))
    ///     .add_userid("bob@example.org")
    ///     .generate()?;
    ///
    /// let sign_with_p = |p| -> Result<Signature> {
    ///     // Round `now` down, then use `t` for all lookups.
    ///     let t: std::time::SystemTime = now.round_down(p)?.into();
    ///
    ///     /// First, get the certification key.
    ///     let mut keypair =
    ///         alice.keys().policy(t).secret().for_certification()
    ///         .nth(0).ok_or_else(|| failure::err_msg("no valid key at"))?
    ///         .key().clone().into_keypair()?;
    ///
    ///     // Then, lookup the binding between `bob@example.org` and
    ///     // `bob` at `t`.
    ///     let ca = bob.userids().policy(t)
    ///         .filter(|ca| ca.userid().value() == b"bob@example.org")
    ///         .nth(0).ok_or_else(|| failure::err_msg("no valid userid"))?;
    ///
    ///     // Finally, Alice certifies the binding between
    ///     // `bob@example.org` and `bob` at `t`.
    ///     ca.userid().certify(&mut keypair, &bob,
    ///                         SignatureType::PositiveCertification, None, t)
    /// };
    ///
    /// assert!(sign_with_p(21).is_ok());
    /// assert!(sign_with_p(22).is_err()); // Rounded-down t predates key, uid.
    /// # Ok(()) }
    /// ```
    ///
    /// There are two possible policies that can be implemented using
    /// this mechanism.  If protecting the timestamp is more important
    /// than the signature, the process must fail.  Otherwise,
    /// increasing the precision until all constraints are satisfied
    /// will find a timestamp approximating `now`, assuming that the
    /// constraints are satisfied at `now`.
    pub fn round_down<P>(&self, precision: P) -> Result<Timestamp>
        where P: Into<Option<u8>>
    {
        let p = precision.into().unwrap_or(21) as u32;
        if p < 32 {
            Ok(Self(self.0 & !((1 << p) - 1)))
        } else {
            Err(Error::InvalidArgument(
                format!("Invalid precision {}", p)).into())
        }
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

    /// Rounds up to the given level of precision.
    ///
    /// If [`Timestamp::round_down`] is used to round the creation
    /// timestamp of a key or signature down, then this function may
    /// be used to round the corresponding expiration time up.  This
    /// ensures validity during the originally intended lifetime,
    /// while avoiding the metadata leak associated with preserving
    /// the originally intended expiration time.
    ///
    ///   [`Timestamp::round_down`]: struct.Timestamp.html#method.round_down
    ///
    /// The given level `p` determines the resulting resolution of
    /// `2^p` seconds.  The default is `21`, which results in a
    /// resolution of 24 days, or roughly a month.  `p` must be lower
    /// than 32.
    pub fn round_up<P>(&self, precision: P) -> Result<Duration>
        where P: Into<Option<u8>>
    {
        let p = precision.into().unwrap_or(21) as u32;
        if p < 32 {
            if let Some(sum) = self.0.checked_add((1 << p) - 1) {
                Ok(Self(sum & !((1 << p) - 1)))
            } else {
                Ok(Self(std::u32::MAX))
            }
        } else {
            Err(Error::InvalidArgument(
                format!("Invalid precision {}", p)).into())
        }
    }
}

impl Arbitrary for Duration {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        Duration(u32::arbitrary(g))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    quickcheck! {
        fn timestamp_round_down(t: Timestamp) -> bool {
            let u = t.round_down(None).unwrap();
            assert!(u <= t);
            assert_eq!(u32::from(u) & 0b1_1111_1111_1111_1111, 0);
            assert!(u32::from(t) - u32::from(u) < 2097152);
            true
        }
    }

    quickcheck! {
        fn duration_round_up(t: Duration) -> bool {
            let u = t.round_up(None).unwrap();
            assert!(t <= u);
            assert_eq!(u32::from(u) & 0b1_1111_1111_1111_1111, 0);
            assert!(u32::from(u) - u32::from(t) < 2097152);
            true
        }
    }
}
