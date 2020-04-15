use chrono::{DateTime, offset::Utc};

use crate::Result;

/// Parses the given string depicting a ISO 8601 timestamp, rounding down.
pub fn parse_bound_round_down(s: &str) -> Result<DateTime<Utc>> {
    match s {
        // XXX: parse "-" to None once we figure out how to do that
        // with structopt.
        "now" => Ok(Utc::now()),
        _ => parse_iso8601(s, chrono::NaiveTime::from_hms(0, 0, 0)),
    }
}

/// Parses the given string depicting a ISO 8601 timestamp, rounding up.
pub fn parse_bound_round_up(s: &str) -> Result<DateTime<Utc>> {
    match s {
        // XXX: parse "-" to None once we figure out how to do that
        // with structopt.
        "now" => Ok(Utc::now()),
        _ => parse_iso8601(s, chrono::NaiveTime::from_hms(23, 59, 59)),
    }
}

/// Parses the given string depicting a ISO 8601 timestamp.
fn parse_iso8601(s: &str, pad_date_with: chrono::NaiveTime)
                 -> Result<DateTime<Utc>>
{
    // If you modify this function this function, synchronize the
    // changes with the copy in sqv.rs!
    for f in &[
        "%Y-%m-%dT%H:%M:%S%#z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M%#z",
        "%Y-%m-%dT%H:%M",
        "%Y-%m-%dT%H%#z",
        "%Y-%m-%dT%H",
        "%Y%m%dT%H%M%S%#z",
        "%Y%m%dT%H%M%S",
        "%Y%m%dT%H%M%#z",
        "%Y%m%dT%H%M",
        "%Y%m%dT%H%#z",
        "%Y%m%dT%H",
    ] {
        if f.ends_with("%#z") {
            if let Ok(d) = DateTime::parse_from_str(s, *f) {
                return Ok(d.into());
            }
        } else {
            if let Ok(d) = chrono::NaiveDateTime::parse_from_str(s, *f) {
                return Ok(DateTime::from_utc(d, Utc));
            }
        }
    }
    for f in &[
        "%Y-%m-%d",
        "%Y-%m",
        "%Y-%j",
        "%Y%m%d",
        "%Y%m",
        "%Y%j",
        "%Y",
    ] {
        if let Ok(d) = chrono::NaiveDate::parse_from_str(s, *f) {
            return Ok(DateTime::from_utc(d.and_time(pad_date_with), Utc));
        }
    }
    Err(anyhow::anyhow!("Malformed ISO8601 timestamp: {}", s))
}

#[test]
fn test_parse_iso8601() {
    let z = chrono::NaiveTime::from_hms(0, 0, 0);
    parse_iso8601("2017-03-04T13:25:35Z", z).unwrap();
    parse_iso8601("2017-03-04T13:25:35+08:30", z).unwrap();
    parse_iso8601("2017-03-04T13:25:35", z).unwrap();
    parse_iso8601("2017-03-04T13:25Z", z).unwrap();
    parse_iso8601("2017-03-04T13:25", z).unwrap();
    // parse_iso8601("2017-03-04T13Z", z).unwrap(); // XXX: chrono doesn't like
    // parse_iso8601("2017-03-04T13", z).unwrap(); // ditto
    parse_iso8601("2017-03-04", z).unwrap();
    // parse_iso8601("2017-03", z).unwrap(); // ditto
    parse_iso8601("2017-031", z).unwrap();
    parse_iso8601("20170304T132535Z", z).unwrap();
    parse_iso8601("20170304T132535+0830", z).unwrap();
    parse_iso8601("20170304T132535", z).unwrap();
    parse_iso8601("20170304T1325Z", z).unwrap();
    parse_iso8601("20170304T1325", z).unwrap();
    // parse_iso8601("20170304T13Z", z).unwrap(); // ditto
    // parse_iso8601("20170304T13", z).unwrap(); // ditto
    parse_iso8601("20170304", z).unwrap();
    // parse_iso8601("201703", z).unwrap(); // ditto
    parse_iso8601("2017031", z).unwrap();
    // parse_iso8601("2017", z).unwrap(); // ditto
}
