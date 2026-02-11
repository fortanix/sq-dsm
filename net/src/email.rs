//! Provides e-mail parsing functions.

use std::fmt;
use super::{Result, Error};

/// Stores the local_part and domain of an email address.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct EmailAddress {
    pub(crate) local_part: String,
    pub(crate) domain: String,
}

impl fmt::Display for EmailAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.local_part, self.domain)
    }
}

impl EmailAddress {
    /// Returns an EmailAddress from an email address string.
    ///
    /// From [draft-koch]:
    ///
    ///```text
    /// To help with the common pattern of using capitalized names
    /// (e.g. "Joe.Doe@example.org") for mail addresses, and under the
    /// premise that almost all MTAs treat the local-part case-insensitive
    /// and that the domain-part is required to be compared
    /// case-insensitive anyway, all upper-case ASCII characters in a User
    /// ID are mapped to lowercase.  Non-ASCII characters are not changed.
    ///```
    pub(crate) fn from<S: AsRef<str>>(email_address: S) -> Result<Self> {
        // Ensure that is a valid email address by parsing it and return the
        // errors that it returns.
        // This is also done in hagrid.
        let email_address = email_address.as_ref();
        let v: Vec<&str> = email_address.split('@').collect();
        if v.len() != 2 {
            return Err(Error::MalformedEmail(email_address.into()).into())
        };

        // Convert domain to lowercase without tailoring, i.e. without taking any
        // locale into account. See:
        // https://doc.rust-lang.org/std/primitive.str.html#method.to_lowercase
        //
        // Keep the local part as-is as we'll need that to generate WKD URLs.
        let email = EmailAddress {
            local_part: v[0].to_string(),
            domain: v[1].to_lowercase()
        };
        Ok(email)
    }
}
