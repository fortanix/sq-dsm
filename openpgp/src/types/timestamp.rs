use std::cmp;
use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::time::{SystemTime, Duration as SystemDuration, UNIX_EPOCH};
use std::u32;

#[cfg(test)]
use quickcheck::{Arbitrary, Gen};

use crate::{
    Error,
    Result,
};

/// A timestamp representable by OpenPGP.
///
/// OpenPGP timestamps are represented as `u32` containing the number of seconds
/// elapsed since midnight, 1 January 1970 UTC ([Section 3.5 of RFC 4880]).
///
/// They cannot express dates further than 7th February of 2106 or earlier than
/// the [UNIX epoch]. Unlike Unix's `time_t`, OpenPGP's timestamp is unsigned so
/// it rollsover in 2106, not 2038.
///
/// # Examples
///
/// Signature creation time is internally stored as a `Timestamp`:
///
/// Note that this example retrieves raw packet value.
/// Use [`SubpacketArea::signature_creation_time`] to get the signature creation time.
///
/// [`SubpacketArea::signature_creation_time`]: ../packet/signature/subpacket/struct.SubpacketArea.html#method.signature_creation_time
///
/// ```
/// use sequoia_openpgp as openpgp;
/// # use openpgp::Result;
/// use std::convert::From;
/// use std::time::SystemTime;
/// use openpgp::cert::prelude::*;
/// use openpgp::policy::StandardPolicy;
/// use openpgp::packet::signature::subpacket::{SubpacketTag, SubpacketValue};
///
/// # fn main() -> Result<()> {
/// let (cert, _) =
///     CertBuilder::general_purpose(None, Some("alice@example.org"))
///     .generate()?;
///
/// let subkey = cert.keys().subkeys().next().unwrap();
/// let packets = subkey.bundle().self_signatures()[0].hashed_area();
///
/// match packets.subpacket(SubpacketTag::SignatureCreationTime).unwrap().value() {
///     SubpacketValue::SignatureCreationTime(ts) => assert!(u32::from(*ts) > 0),
///     v => panic!("Unexpected subpacket: {:?}", v),
/// }
///
/// let p = &StandardPolicy::new();
/// let now = SystemTime::now();
/// assert!(subkey.binding_signature(p, now)?.signature_creation_time().is_some());
/// # Ok(()) }
/// ```
///
/// [Section 3.5 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-3.5
/// [UNIX epoch]: https://en.wikipedia.org/wiki/Unix_time
/// [`Timestamp::round_down`]: ../types/struct.Timestamp.html#method.round_down
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(u32);
assert_send_and_sync!{Timestamp}

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
    type Error = anyhow::Error;

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

impl From<Timestamp> for Option<SystemTime> {
    fn from(t: Timestamp) -> Self {
        Some(t.into())
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", crate::fmt::time(&SystemTime::from(*self)))
    }
}

impl fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
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
    /// The lower limit `floor` represents the earliest time the timestamp will be
    /// rounded down to.
    ///
    /// See also [`Duration::round_up`](struct.Duration.html#method.round_up).
    ///
    /// # Important note
    ///
    /// If we create a signature, it is important that the signature's
    /// creation time does not predate the signing keys creation time,
    /// or otherwise violate the key's validity constraints.
    /// This can be achieved by using the `floor` parameter.
    ///
    /// To ensure validity, use this function to round the time down,
    /// using the latest known relevant timestamp as a floor.
    /// Then, lookup all keys and other objects like userids using this
    /// timestamp, and on success create the signature:
    ///
    /// ```rust
    /// # use sequoia_openpgp::{*, packet::prelude::*, types::*, cert::*};
    /// use sequoia_openpgp::policy::StandardPolicy;
    ///
    /// # f().unwrap();
    /// # fn f() -> Result<()> {
    /// let policy = &StandardPolicy::new();
    ///
    /// // Let's fix a time.
    /// let now = Timestamp::from(1583436160);
    ///
    /// let cert_creation_alice = now.checked_sub(Duration::weeks(2)?).unwrap();
    /// let cert_creation_bob = now.checked_sub(Duration::weeks(1)?).unwrap();
    ///
    /// // Generate a Cert for Alice.
    /// let (alice, _) = CertBuilder::new()
    ///     .set_creation_time(cert_creation_alice)
    ///     .set_primary_key_flags(KeyFlags::empty().set_certification())
    ///     .add_userid("alice@example.org")
    ///     .generate()?;
    ///
    /// // Generate a Cert for Bob.
    /// let (bob, _) = CertBuilder::new()
    ///     .set_creation_time(cert_creation_bob)
    ///     .set_primary_key_flags(KeyFlags::empty().set_certification())
    ///     .add_userid("bob@example.org")
    ///     .generate()?;
    ///
    /// let sign_with_p = |p| -> Result<Signature> {
    ///     // Round `now` down, then use `t` for all lookups.
    ///     // Use the creation time of Bob's Cert as lower bound for rounding.
    ///     let t: std::time::SystemTime = now.round_down(p, cert_creation_bob)?.into();
    ///
    ///     // First, get the certification key.
    ///     let mut keypair =
    ///         alice.keys().with_policy(policy, t).secret().for_certification()
    ///         .nth(0).ok_or_else(|| anyhow::anyhow!("no valid key at"))?
    ///         .key().clone().into_keypair()?;
    ///
    ///     // Then, lookup the binding between `bob@example.org` and
    ///     // `bob` at `t`.
    ///     let ca = bob.userids().with_policy(policy, t)
    ///         .filter(|ca| ca.userid().value() == b"bob@example.org")
    ///         .nth(0).ok_or_else(|| anyhow::anyhow!("no valid userid"))?;
    ///
    ///     // Finally, Alice certifies the binding between
    ///     // `bob@example.org` and `bob` at `t`.
    ///     ca.userid().certify(&mut keypair, &bob,
    ///                         SignatureType::PositiveCertification, None, t)
    /// };
    ///
    /// assert!(sign_with_p(21).is_ok());
    /// assert!(sign_with_p(22).is_ok());  // Rounded to bob's cert's creation time.
    /// assert!(sign_with_p(32).is_err()); // Invalid precision
    /// # Ok(()) }
    /// ```
    pub fn round_down<P, F>(&self, precision: P, floor: F) -> Result<Timestamp>
        where P: Into<Option<u8>>,
              F: Into<Option<SystemTime>>
    {
        let p = precision.into().unwrap_or(21) as u32;
        if p < 32 {
            let rounded = Self(self.0 & !((1 << p) - 1));
            match floor.into() {
                Some(floor) => {
                    Ok(cmp::max(rounded, floor.try_into()?))
                }
                None => { Ok(rounded) }
            }
        } else {
            Err(Error::InvalidArgument(
                format!("Invalid precision {}", p)).into())
        }
    }
}

#[cfg(test)]
impl Arbitrary for Timestamp {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        Timestamp(u32::arbitrary(g))
    }
}

/// A duration representable by OpenPGP.
///
/// # Examples
///
/// ```
/// use sequoia_openpgp as openpgp;
/// # use openpgp::Result;
/// use openpgp::cert::prelude::*;
/// use openpgp::policy::StandardPolicy;
/// use openpgp::packet::signature::subpacket::{SubpacketTag, SubpacketValue};
/// use openpgp::types::{Timestamp, Duration};
///
/// # fn main() -> Result<()> {
/// let p = &StandardPolicy::new();
///
/// let now = Timestamp::now();
/// let validity_period = Duration::days(365)?;
///
/// let (cert,_) = CertBuilder::new()
///     .set_creation_time(now)
///     .set_validity_period(validity_period)
///     .generate()?;
///
/// let vc = cert.with_policy(p, now)?;
/// assert!(vc.alive().is_ok());
/// # Ok(()) }
/// ```
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Duration(u32);
assert_send_and_sync!{Duration}

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
    type Error = anyhow::Error;

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

impl From<Duration> for Option<SystemDuration> {
    fn from(d: Duration) -> Self {
        Some(d.into())
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
    ///
    /// The upper limit `ceil` represents the maximum time to round up to.
    pub fn round_up<P, C>(&self, precision: P, ceil: C) -> Result<Duration>
        where P: Into<Option<u8>>,
              C: Into<Option<SystemDuration>>
    {
        let p = precision.into().unwrap_or(21) as u32;
        if p < 32 {
            if let Some(sum) = self.0.checked_add((1 << p) - 1) {
                let rounded = Self(sum & !((1 << p) - 1));
                match ceil.into() {
                    Some(ceil) => {
                        Ok(cmp::min(rounded, ceil.try_into()?))
                    },
                    None => Ok(rounded)
                }
            } else {
                Ok(Self(std::u32::MAX))
            }
        } else {
            Err(Error::InvalidArgument(
                format!("Invalid precision {}", p)).into())
        }
    }
}

#[allow(unused)]
impl Timestamp {
    pub(crate) const UNIX_EPOCH : Timestamp = Timestamp(0);
    pub(crate) const MAX : Timestamp = Timestamp(u32::MAX);

    // for y in $(seq 1970 2106); do echo "    const Y$y : Timestamp = Timestamp($(date -u --date="Jan. 1, $y" '+%s'));"; done
    pub(crate) const Y1970 : Timestamp = Timestamp(0);
    pub(crate) const Y1971 : Timestamp = Timestamp(31536000);
    pub(crate) const Y1972 : Timestamp = Timestamp(63072000);
    pub(crate) const Y1973 : Timestamp = Timestamp(94694400);
    pub(crate) const Y1974 : Timestamp = Timestamp(126230400);
    pub(crate) const Y1975 : Timestamp = Timestamp(157766400);
    pub(crate) const Y1976 : Timestamp = Timestamp(189302400);
    pub(crate) const Y1977 : Timestamp = Timestamp(220924800);
    pub(crate) const Y1978 : Timestamp = Timestamp(252460800);
    pub(crate) const Y1979 : Timestamp = Timestamp(283996800);
    pub(crate) const Y1980 : Timestamp = Timestamp(315532800);
    pub(crate) const Y1981 : Timestamp = Timestamp(347155200);
    pub(crate) const Y1982 : Timestamp = Timestamp(378691200);
    pub(crate) const Y1983 : Timestamp = Timestamp(410227200);
    pub(crate) const Y1984 : Timestamp = Timestamp(441763200);
    pub(crate) const Y1985 : Timestamp = Timestamp(473385600);
    pub(crate) const Y1986 : Timestamp = Timestamp(504921600);
    pub(crate) const Y1987 : Timestamp = Timestamp(536457600);
    pub(crate) const Y1988 : Timestamp = Timestamp(567993600);
    pub(crate) const Y1989 : Timestamp = Timestamp(599616000);
    pub(crate) const Y1990 : Timestamp = Timestamp(631152000);
    pub(crate) const Y1991 : Timestamp = Timestamp(662688000);
    pub(crate) const Y1992 : Timestamp = Timestamp(694224000);
    pub(crate) const Y1993 : Timestamp = Timestamp(725846400);
    pub(crate) const Y1994 : Timestamp = Timestamp(757382400);
    pub(crate) const Y1995 : Timestamp = Timestamp(788918400);
    pub(crate) const Y1996 : Timestamp = Timestamp(820454400);
    pub(crate) const Y1997 : Timestamp = Timestamp(852076800);
    pub(crate) const Y1998 : Timestamp = Timestamp(883612800);
    pub(crate) const Y1999 : Timestamp = Timestamp(915148800);
    pub(crate) const Y2000 : Timestamp = Timestamp(946684800);
    pub(crate) const Y2001 : Timestamp = Timestamp(978307200);
    pub(crate) const Y2002 : Timestamp = Timestamp(1009843200);
    pub(crate) const Y2003 : Timestamp = Timestamp(1041379200);
    pub(crate) const Y2004 : Timestamp = Timestamp(1072915200);
    pub(crate) const Y2005 : Timestamp = Timestamp(1104537600);
    pub(crate) const Y2006 : Timestamp = Timestamp(1136073600);
    pub(crate) const Y2007 : Timestamp = Timestamp(1167609600);
    pub(crate) const Y2008 : Timestamp = Timestamp(1199145600);
    pub(crate) const Y2009 : Timestamp = Timestamp(1230768000);
    pub(crate) const Y2010 : Timestamp = Timestamp(1262304000);
    pub(crate) const Y2011 : Timestamp = Timestamp(1293840000);
    pub(crate) const Y2012 : Timestamp = Timestamp(1325376000);
    pub(crate) const Y2013 : Timestamp = Timestamp(1356998400);
    pub(crate) const Y2014 : Timestamp = Timestamp(1388534400);
    pub(crate) const Y2015 : Timestamp = Timestamp(1420070400);
    pub(crate) const Y2016 : Timestamp = Timestamp(1451606400);
    pub(crate) const Y2017 : Timestamp = Timestamp(1483228800);
    pub(crate) const Y2018 : Timestamp = Timestamp(1514764800);
    pub(crate) const Y2019 : Timestamp = Timestamp(1546300800);
    pub(crate) const Y2020 : Timestamp = Timestamp(1577836800);
    pub(crate) const Y2021 : Timestamp = Timestamp(1609459200);
    pub(crate) const Y2022 : Timestamp = Timestamp(1640995200);
    pub(crate) const Y2023 : Timestamp = Timestamp(1672531200);
    pub(crate) const Y2024 : Timestamp = Timestamp(1704067200);
    pub(crate) const Y2025 : Timestamp = Timestamp(1735689600);
    pub(crate) const Y2026 : Timestamp = Timestamp(1767225600);
    pub(crate) const Y2027 : Timestamp = Timestamp(1798761600);
    pub(crate) const Y2028 : Timestamp = Timestamp(1830297600);
    pub(crate) const Y2029 : Timestamp = Timestamp(1861920000);
    pub(crate) const Y2030 : Timestamp = Timestamp(1893456000);
    pub(crate) const Y2031 : Timestamp = Timestamp(1924992000);
    pub(crate) const Y2032 : Timestamp = Timestamp(1956528000);
    pub(crate) const Y2033 : Timestamp = Timestamp(1988150400);
    pub(crate) const Y2034 : Timestamp = Timestamp(2019686400);
    pub(crate) const Y2035 : Timestamp = Timestamp(2051222400);
    pub(crate) const Y2036 : Timestamp = Timestamp(2082758400);
    pub(crate) const Y2037 : Timestamp = Timestamp(2114380800);
    pub(crate) const Y2038 : Timestamp = Timestamp(2145916800);
    pub(crate) const Y2039 : Timestamp = Timestamp(2177452800);
    pub(crate) const Y2040 : Timestamp = Timestamp(2208988800);
    pub(crate) const Y2041 : Timestamp = Timestamp(2240611200);
    pub(crate) const Y2042 : Timestamp = Timestamp(2272147200);
    pub(crate) const Y2043 : Timestamp = Timestamp(2303683200);
    pub(crate) const Y2044 : Timestamp = Timestamp(2335219200);
    pub(crate) const Y2045 : Timestamp = Timestamp(2366841600);
    pub(crate) const Y2046 : Timestamp = Timestamp(2398377600);
    pub(crate) const Y2047 : Timestamp = Timestamp(2429913600);
    pub(crate) const Y2048 : Timestamp = Timestamp(2461449600);
    pub(crate) const Y2049 : Timestamp = Timestamp(2493072000);
    pub(crate) const Y2050 : Timestamp = Timestamp(2524608000);
    pub(crate) const Y2051 : Timestamp = Timestamp(2556144000);
    pub(crate) const Y2052 : Timestamp = Timestamp(2587680000);
    pub(crate) const Y2053 : Timestamp = Timestamp(2619302400);
    pub(crate) const Y2054 : Timestamp = Timestamp(2650838400);
    pub(crate) const Y2055 : Timestamp = Timestamp(2682374400);
    pub(crate) const Y2056 : Timestamp = Timestamp(2713910400);
    pub(crate) const Y2057 : Timestamp = Timestamp(2745532800);
    pub(crate) const Y2058 : Timestamp = Timestamp(2777068800);
    pub(crate) const Y2059 : Timestamp = Timestamp(2808604800);
    pub(crate) const Y2060 : Timestamp = Timestamp(2840140800);
    pub(crate) const Y2061 : Timestamp = Timestamp(2871763200);
    pub(crate) const Y2062 : Timestamp = Timestamp(2903299200);
    pub(crate) const Y2063 : Timestamp = Timestamp(2934835200);
    pub(crate) const Y2064 : Timestamp = Timestamp(2966371200);
    pub(crate) const Y2065 : Timestamp = Timestamp(2997993600);
    pub(crate) const Y2066 : Timestamp = Timestamp(3029529600);
    pub(crate) const Y2067 : Timestamp = Timestamp(3061065600);
    pub(crate) const Y2068 : Timestamp = Timestamp(3092601600);
    pub(crate) const Y2069 : Timestamp = Timestamp(3124224000);
    pub(crate) const Y2070 : Timestamp = Timestamp(3155760000);
    pub(crate) const Y2071 : Timestamp = Timestamp(3187296000);
    pub(crate) const Y2072 : Timestamp = Timestamp(3218832000);
    pub(crate) const Y2073 : Timestamp = Timestamp(3250454400);
    pub(crate) const Y2074 : Timestamp = Timestamp(3281990400);
    pub(crate) const Y2075 : Timestamp = Timestamp(3313526400);
    pub(crate) const Y2076 : Timestamp = Timestamp(3345062400);
    pub(crate) const Y2077 : Timestamp = Timestamp(3376684800);
    pub(crate) const Y2078 : Timestamp = Timestamp(3408220800);
    pub(crate) const Y2079 : Timestamp = Timestamp(3439756800);
    pub(crate) const Y2080 : Timestamp = Timestamp(3471292800);
    pub(crate) const Y2081 : Timestamp = Timestamp(3502915200);
    pub(crate) const Y2082 : Timestamp = Timestamp(3534451200);
    pub(crate) const Y2083 : Timestamp = Timestamp(3565987200);
    pub(crate) const Y2084 : Timestamp = Timestamp(3597523200);
    pub(crate) const Y2085 : Timestamp = Timestamp(3629145600);
    pub(crate) const Y2086 : Timestamp = Timestamp(3660681600);
    pub(crate) const Y2087 : Timestamp = Timestamp(3692217600);
    pub(crate) const Y2088 : Timestamp = Timestamp(3723753600);
    pub(crate) const Y2089 : Timestamp = Timestamp(3755376000);
    pub(crate) const Y2090 : Timestamp = Timestamp(3786912000);
    pub(crate) const Y2091 : Timestamp = Timestamp(3818448000);
    pub(crate) const Y2092 : Timestamp = Timestamp(3849984000);
    pub(crate) const Y2093 : Timestamp = Timestamp(3881606400);
    pub(crate) const Y2094 : Timestamp = Timestamp(3913142400);
    pub(crate) const Y2095 : Timestamp = Timestamp(3944678400);
    pub(crate) const Y2096 : Timestamp = Timestamp(3976214400);
    pub(crate) const Y2097 : Timestamp = Timestamp(4007836800);
    pub(crate) const Y2098 : Timestamp = Timestamp(4039372800);
    pub(crate) const Y2099 : Timestamp = Timestamp(4070908800);
    pub(crate) const Y2100 : Timestamp = Timestamp(4102444800);
    pub(crate) const Y2101 : Timestamp = Timestamp(4133980800);
    pub(crate) const Y2102 : Timestamp = Timestamp(4165516800);
    pub(crate) const Y2103 : Timestamp = Timestamp(4197052800);
    pub(crate) const Y2104 : Timestamp = Timestamp(4228588800);
    pub(crate) const Y2105 : Timestamp = Timestamp(4260211200);
    pub(crate) const Y2106 : Timestamp = Timestamp(4291747200);
}

#[cfg(test)]
impl Arbitrary for Duration {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        Duration(u32::arbitrary(g))
    }
}

/// Normalizes the given SystemTime to the resolution OpenPGP
/// supports.
pub(crate) fn normalize_systemtime(t: SystemTime) -> SystemTime {
    UNIX_EPOCH + SystemDuration::new(
        t.duration_since(UNIX_EPOCH).unwrap().as_secs(), 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    quickcheck! {
        fn timestamp_round_down(t: Timestamp) -> bool {
            let u = t.round_down(None, None).unwrap();
            assert!(u <= t);
            assert_eq!(u32::from(u) & 0b1_1111_1111_1111_1111_1111, 0);
            assert!(u32::from(t) - u32::from(u) < 2_u32.pow(21));
            true
        }
    }

    #[test]
    fn timestamp_round_down_floor() -> Result<()> {
        let t = Timestamp(1585753307);
        let floor = t.checked_sub(Duration::weeks(1).unwrap()).unwrap();

        let u = t.round_down(21, floor).unwrap();
        assert!(u < t);
        assert!(floor < u);
        assert_eq!(u32::from(u) & 0b1_1111_1111_1111_1111_1111, 0);

        let floor = t.checked_sub(Duration::days(1).unwrap()).unwrap();

        let u = t.round_down(21, floor).unwrap();
        assert_eq!(u, floor);
        Ok(())
    }

    quickcheck! {
        fn duration_round_up(d: Duration) -> bool {
            let u = d.round_up(None, None).unwrap();
            assert!(d <= u);
            assert_eq!(u32::from(u) & 0b1_1111_1111_1111_1111_1111, 0);
            assert!(u32::from(u) - u32::from(d) < 2_u32.pow(21));
            true
        }
    }

    #[test]
    fn duration_round_up_ceil() -> Result<()> {
        let d = Duration(123);

        let ceil = Duration(2_u32.pow(23));

        let u = d.round_up(21, ceil)?;
        assert!(d < u);
        assert!(u < ceil);
        assert_eq!(u32::from(u) & 0b1_1111_1111_1111_1111_1111, 0);

        let ceil = Duration::days(1).unwrap();

        let u = d.round_up(21, ceil)?;
        assert!(d < u);
        assert_eq!(u, ceil);

        Ok(())
    }
}
