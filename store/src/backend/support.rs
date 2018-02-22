//! Data types for working with `rusqlite`.

use rusqlite;
use rusqlite::types::{ToSql, ToSqlOutput, FromSql, FromSqlResult, ValueRef};
use std::fmt;
use std::ops::{Add, Sub};
use time::{Timespec, Duration, now_utc};

/// Represents a row id.
///
/// This is used to represent handles to stored objects.
#[derive(Copy, Clone, PartialEq)]
pub struct ID(i64);

impl fmt::Display for ID {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl ID {
    /// Returns ID(0).
    ///
    /// This is smaller than all valid ids.
    pub fn null() -> Self {
        ID(0)
    }

    /// Returns the largest id.
    pub fn max() -> Self {
        ID(::std::i64::MAX)
    }
}

impl From<i64> for ID {
    fn from(id: i64) -> Self {
        ID(id)
    }
}

impl ToSql for ID {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput> {
        Ok(ToSqlOutput::from(self.0))
    }
}

impl FromSql for ID {
    fn column_result(value: ValueRef) -> FromSqlResult<Self> {
        value.as_i64().map(|id| id.into())
    }
}


/// A serializable system time.
#[derive(Clone, Copy, PartialEq, PartialOrd)]
pub struct Timestamp(Timespec);

impl Timestamp {
    pub fn now() -> Self {
        Timestamp(now_utc().to_timespec())
    }

    /// Converts to unix time.
    pub fn unix(&self) -> i64 {
        self.0.sec
    }
}

impl ToSql for Timestamp {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput> {
        Ok(ToSqlOutput::from(self.0.sec))
    }
}

impl FromSql for Timestamp {
    fn column_result(value: ValueRef) -> FromSqlResult<Self> {
        value.as_i64().map(|t| Timestamp(Timespec::new(t, 0)))
    }
}

impl Add<Duration> for Timestamp {
    type Output = Timestamp;

    fn add(self, other: Duration) -> Timestamp {
        Timestamp(self.0 + other)
    }
}

impl Sub<Timestamp> for Timestamp {
    type Output = Duration;

    fn sub(self, other: Self) -> Self::Output {
        self.0 - other.0
    }
}
