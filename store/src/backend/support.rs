//! Data types for working with `rusqlite`.

use rusqlite;
use rusqlite::types::{ToSql, ToSqlOutput, FromSql, FromSqlResult, ValueRef};
use std::fmt;
use std::ops::Add;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::{
    Result,
};

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
///
/// XXX: Drop this.  Instead, use chrono::DateTime which implements
/// ToSql and FromSql.
#[derive(Clone, Copy, PartialEq, PartialOrd)]
pub struct Timestamp(SystemTime);

impl Timestamp {
    pub fn now() -> Self {
        Timestamp(SystemTime::now())
    }

    /// Converts to unix time.
    pub fn unix(&self) -> i64 {
        match self.0.duration_since(UNIX_EPOCH) {
            Ok(d) if d.as_secs() < std::i64::MAX as u64 =>
                d.as_secs() as i64,
            _ => 0, // Not representable.
        }
    }

    pub fn duration_since(&self, earlier: Timestamp) -> Result<Duration> {
        Ok(self.0.duration_since(earlier.0)?)
    }
}

impl ToSql for Timestamp {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput> {
        Ok(ToSqlOutput::from(self.unix()))
    }
}

impl FromSql for Timestamp {
    fn column_result(value: ValueRef) -> FromSqlResult<Self> {
        value.as_i64()
            .map(|t| Timestamp(UNIX_EPOCH + Duration::new(t as u64, 0)))
    }
}

impl Add<Duration> for Timestamp {
    type Output = Timestamp;

    fn add(self, other: Duration) -> Timestamp {
        Timestamp(self.0 + other)
    }
}
