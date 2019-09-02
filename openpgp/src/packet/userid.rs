use std::fmt;
use std::str;
use std::hash::{Hash, Hasher};
use std::cell::RefCell;
use quickcheck::{Arbitrary, Gen};
use crate::rfc2822::{
    AddrSpec,
    AddrSpecOrOther,
    Name,
    NameAddr,
    NameAddrOrOther,
};
use failure::ResultExt;

use crate::Result;
use crate::packet;
use crate::Packet;

struct ParsedUserID {
    name: Option<String>,
    comment: Option<String>,
    address: Result<String>,
    // Handles invalid email addresses.  For instance:
    //
    //     Hostname <ssh://server@example.net>
    //
    // would have no address, but other would be
    // "ssh://server@example.net".
    other: Option<String>,
}

/// Holds a UserID packet.
///
/// See [Section 5.11 of RFC 4880] for details.
///
///   [Section 5.11 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.11
pub struct UserID {
    /// CTB packet header fields.
    pub(crate) common: packet::Common,
    /// The user id.
    ///
    /// According to [RFC 4880], the text is by convention UTF-8 encoded
    /// and in "mail name-addr" form, i.e., "Name (Comment)
    /// <email@example.com>".
    ///
    ///   [RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.11
    ///
    /// Use `UserID::default()` to get a UserID with a default settings.
    value: Vec<u8>,

    parsed: RefCell<Option<ParsedUserID>>,
}

impl From<Vec<u8>> for UserID {
    fn from(u: Vec<u8>) -> Self {
        UserID {
            common: Default::default(),
            value: u,
            parsed: RefCell::new(None),
        }
    }
}

impl From<&[u8]> for UserID {
    fn from(u: &[u8]) -> Self {
        UserID {
            common: Default::default(),
            value: u.to_vec(),
            parsed: RefCell::new(None),
        }
    }
}

impl<'a> From<&'a str> for UserID {
    fn from(u: &'a str) -> Self {
        let b = u.as_bytes();
        let mut v = Vec::with_capacity(b.len());
        v.extend_from_slice(b);
        v.into()
    }
}

impl From<String> for UserID {
    fn from(u: String) -> Self {
        let u = &u[..];
        u.into()
    }
}

impl<'a> From<::std::borrow::Cow<'a, str>> for UserID {
    fn from(u: ::std::borrow::Cow<'a, str>) -> Self {
        let b = u.as_bytes();
        let mut v = Vec::with_capacity(b.len());
        v.extend_from_slice(b);
        v.into()
    }
}

impl fmt::Display for UserID {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let userid = String::from_utf8_lossy(&self.value[..]);
        write!(f, "{}", userid)
    }
}

impl fmt::Debug for UserID {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let userid = String::from_utf8_lossy(&self.value[..]);

        f.debug_struct("UserID")
            .field("value", &userid)
            .finish()
    }
}

impl PartialEq for UserID {
    fn eq(&self, other: &UserID) -> bool {
        self.value == other.value
    }
}

impl Eq for UserID {
}


impl Hash for UserID {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // We hash only the data; the cache does not implement hash.
        self.common.hash(state);
        self.value.hash(state);
    }
}

impl Clone for UserID {
    fn clone(&self) -> Self {
        UserID {
            common: self.common.clone(),
            value: self.value.clone(),
            parsed: RefCell::new(None),
        }
    }
}

impl UserID {
    /// Constructs a User ID.
    ///
    /// This escapes the name.  The comment and address must be well
    /// formed according to RFC 2822.  Only the address is required.
    ///
    /// If you already have a full RFC 2822 mailbox, then you can just
    /// use `UserID::from()`.
    ///
    /// ```
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::packet::UserID;
    /// assert_eq!(UserID::from_address(
    ///                "John \"the Boat\" Smith".into(),
    ///                None, "boat@example.org").unwrap().value(),
    ///            &b"\"John \\\"the Boat\\\" Smith\" <boat@example.org>"[..]);
    /// ```
    pub fn from_address<O, S>(name: O, comment: O, address: S)
        -> Result<Self>
        where S: AsRef<str>,
              O: Into<Option<S>>
    {
        let name = name.into();
        let comment = comment.into();
        let address = address.as_ref();

        // Make sure the address is valid.
        AddrSpec::parse(address)
            .context(format!("Invalid address: {:?}", address))?;

        // XXX: Currently we don't have an interface to just parse a
        // comment, but we check it's validity below.

        let is_name_addr = name.is_some() || comment.is_some();

        let combined = match (name, comment) {
            (Some(name), Some(comment)) => {
                let name = name.as_ref();

                format!("{} ({}) <{}>",
                        Name::escaped(name)
                            .context(format!("Invalid display name: {:?}",
                                             name))?,
                        comment.as_ref(), address)
            }
            (Some(name), None) => {
                let name = name.as_ref();

                format!("{} <{}>",
                        Name::escaped(name)
                            .context(format!("Invalid display name: {:?}",
                                             name))?,
                        address)
            }
            (None, Some(comment)) =>
                // A comment can't exist without a display name.
                format!("\"\" {} <{}>",
                        comment.as_ref(), address),
            (None, None) =>
                address.into(),
        };

        if is_name_addr {
            // Make sure the whole thing is valid (this also checks the
            // comment).
            NameAddr::parse(&combined)?;
        }

        Ok(combined.into())
    }

    /// Constructs a User ID.
    ///
    /// This escapes the name.  The comment must be well formed, the
    /// address can be arbitrary.
    ///
    /// This is useful when you want to specify a URI instead of an
    /// email address.
    ///
    /// If you have a full RFC 2822 mailbox, then you can just use
    /// `UserID::from()`.
    ///
    /// ```
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::packet::UserID;
    /// assert_eq!(UserID::from_unchecked_address(
    ///                "NAS".into(),
    ///                None, "ssh://host.example.org").unwrap().value(),
    ///            &b"NAS <ssh://host.example.org>"[..]);
    /// ```
    pub fn from_unchecked_address<O, S>(name: O, comment: O, address: S)
        -> Result<Self>
        where S: AsRef<str>,
              O: Into<Option<S>>
    {
        let name = name.into();
        let comment = comment.into();
        let address = address.as_ref();

        // XXX: Currently we don't have an interface to just parse a
        // comment, but we check it's validity below.

        let is_name_addr = name.is_some() || comment.is_some();

        let combined = match (name, comment) {
            (Some(name), Some(comment)) => {
                let name = name.as_ref();

                format!("{} ({}) <{}>",
                        Name::escaped(name)
                            .context(format!("Invalid display name: {:?}",
                                             name))?,
                        comment.as_ref(), address)
            }
            (Some(name), None) => {
                let name = name.as_ref();

                format!("{} <{}>",
                        Name::escaped(name)
                            .context(format!("Invalid display name: {:?}",
                                             name))?,
                        address)
            }
            (None, Some(comment)) =>
                // A comment can't exist without a display name.
                format!("\"\" {} <{}>",
                        comment.as_ref(), address),
            (None, None) =>
                address.into(),
        };

        // Make sure the whole thing is valid (this also checks the
        // comment).
        if is_name_addr {
            // Make sure the whole thing is valid (this also checks the
            // comment).
            NameAddrOrOther::parse(&combined)?;
        }

        Ok(combined.into())
    }

    /// Gets the user ID packet's value.
    pub fn value(&self) -> &[u8] {
        self.value.as_slice()
    }

    fn do_parse(&self) -> Result<()> {
        if self.parsed.borrow().is_none() {
            let s = str::from_utf8(&self.value)?;

            *self.parsed.borrow_mut() = Some(match NameAddrOrOther::parse(s) {
                Ok(na) => ParsedUserID {
                    name: na.name().map(|s| s.to_string()),
                    comment: na.comment().map(|s| s.to_string()),
                    address: na.address().map(|s| s.to_string()),
                    other: na.other().map(|s| s.to_string()),
                },
                Err(err) => {
                    // Try with the addr-spec parser.
                    if let Ok(a) = AddrSpecOrOther::parse(s) {
                        ParsedUserID {
                            name: None,
                            comment: None,
                            address: a.address().map(|s| s.to_string()),
                            other: a.other().map(|s| s.to_string()),
                        }
                    } else {
                        // Return the error from the NameAddrOrOther parser.
                        let err : failure::Error = err.into();
                        return Err(err).context(format!(
                            "Not a valid RFC 2822 mailbox: {:?}", s))?;
                    }
                }
            });
        }
        Ok(())
    }

    /// Treats the user ID as an RFC 2822 name-addr and extracts the
    /// display name, if any.
    ///
    /// Note: if the email address is invalid, but the rest of the
    /// input is okay, this still returns the display name.
    pub fn name(&self) -> Result<Option<String>> {
        self.do_parse()?;
        match *self.parsed.borrow() {
            Some(ParsedUserID { ref name, .. }) =>
                Ok(name.as_ref().map(|s| s.clone())),
            None => unreachable!(),
        }
    }

    /// Treats the user ID as an RFC 2822 name-addr and extracts the
    /// first comment, if any.
    ///
    /// Note: if the email address is invalid, but the rest of the
    /// input is okay, this still returns the first comment.
    pub fn comment(&self) -> Result<Option<String>> {
        self.do_parse()?;
        match *self.parsed.borrow() {
            Some(ParsedUserID { ref comment, .. }) =>
                Ok(comment.as_ref().map(|s| s.clone())),
            None => unreachable!(),
        }
    }

    /// Treats the user ID as an RFC 2822 name-addr and extracts the
    /// address, if valid.
    ///
    /// If the email address is invalid, returns `Ok(None)`.  In this
    /// case, the invalid email address can be returned using
    /// `UserID::other_address()`.
    pub fn address(&self) -> Result<Option<String>> {
        self.do_parse()?;
        match *self.parsed.borrow() {
            Some(ParsedUserID { address: Ok(ref address), .. }) =>
                Ok(Some(address.clone())),
            Some(ParsedUserID { address: Err(_), .. }) =>
                Ok(None),
            None => unreachable!(),
        }
    }

    /// Treats the user ID as an RFC 2822 name-addr and, if the
    /// address is invalid, returns that.
    ///
    /// If the address is valid, this returns None.
    ///
    /// This is particularly useful with the following types of User
    /// IDs:
    ///
    /// ```text
    /// First Last (Comment) <ssh://server.example.net>
    /// ```
    ///
    /// will be successfully parsed.  In this case,
    /// `NameAddrOrOther::address()` will return the parse error, and the
    /// invalid address can be obtained using `NameAddrOrOther::other()`.
    pub fn other(&self) -> Result<Option<String>> {
        self.do_parse()?;
        match *self.parsed.borrow() {
            Some(ParsedUserID { ref other, .. }) =>
                Ok(other.as_ref().map(|s| s.clone())),
            None => unreachable!(),
        }
    }

    /// Treats the user ID as an RFC 2822 name-addr and returns the
    /// address.
    ///
    /// If the address is invalid, that is returned.  For instance:
    ///
    /// ```text
    /// First Last (Comment) <ssh://server.example.net>
    /// ```
    ///
    /// will be successfully parsed and this function will return
    /// `ssh://server.example.net`.
    pub fn other_or_address(&self) -> Result<Option<String>> {
        self.do_parse()?;
        match *self.parsed.borrow() {
            Some(ParsedUserID { address: Ok(ref address), .. }) =>
                Ok(Some(address.clone())),
            Some(ParsedUserID { ref other, .. }) =>
                Ok(other.as_ref().map(|s| s.clone())),
            None => unreachable!(),
        }
    }

    /// Returns a normalized version of the UserID's email address.
    ///
    /// Normalized email addresses are primarily needed when email
    /// addresses are compared.
    ///
    /// Note: normalized email addresses are still valid email
    /// addresses.
    ///
    /// This function normalizes an email address by doing [puny-code
    /// normalization] on the domain, and lowercasing the local part in
    /// the so-called [empty locale].
    ///
    /// Note: this normalization procedure is the same as the
    /// normalization procedure recommended by [Autocrypt].
    ///
    ///   [puny-code normalization]: https://tools.ietf.org/html/rfc5891.html#section-4.4
    ///   [empty locale]: https://www.w3.org/International/wiki/Case_folding
    ///   [Autocrypt]: https://autocrypt.org/level1.html#e-mail-address-canonicalization
    pub fn address_normalized(&self) -> Result<Option<String>> {
        match self.address() {
            e @ Err(_) => e,
            Ok(None) => Ok(None),
            Ok(Some(address)) => {
                let mut iter = address.split('@');
                let localpart = iter.next().expect("Invalid email address");
                let domain = iter.next().expect("Invalid email address");
                assert!(iter.next().is_none(), "Invalid email address");

                // Normalize Unicode in domains.
                let domain = idna::domain_to_ascii(domain)
                    .map_err(|e| failure::format_err!(
                        "punycode conversion failed: {:?}", e))?;

                // Join.
                let address = format!("{}@{}", localpart, domain);

                // Convert to lowercase without tailoring, i.e. without taking
                // any locale into account.  See:
                //
                //  - https://www.w3.org/International/wiki/Case_folding
                //  - https://doc.rust-lang.org/std/primitive.str.html#method.to_lowercase
                //  - http://www.unicode.org/versions/Unicode7.0.0/ch03.pdf#G33992
                let address = address.to_lowercase();

                Ok(Some(address))
            }
        }
    }
}

impl From<UserID> for Packet {
    fn from(s: UserID) -> Self {
        Packet::UserID(s)
    }
}

impl Arbitrary for UserID {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        Vec::<u8>::arbitrary(g).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::Parse;
    use crate::serialize::SerializeInto;

    quickcheck! {
        fn roundtrip(p: UserID) -> bool {
            let q = UserID::from_bytes(&p.to_vec().unwrap()).unwrap();
            assert_eq!(p, q);
            true
        }
    }

    #[test]
    fn name_addr() {
        fn c(value: &str, ok: bool,
             name: Option<&str>, comment: Option<&str>,
             address: Option<&str>, other: Option<&str>)
        {
            let name = name.map(|s| s.to_string());
            let comment = comment.map(|s| s.to_string());
            let address = address.map(|s| s.to_string());
            let other = other.map(|s| s.to_string());

            let u = UserID::from(value);
            for _ in 0..2 {
                let name_got = u.name();
                let comment_got = u.comment();
                let address_got = u.address();
                let other_got = u.other();

                eprintln!("Parsing {:?}", value);
                eprintln!("name: expected: {:?}, got: {:?}",
                          name, name_got);
                eprintln!("comment: expected: {:?}, got: {:?}",
                          comment, comment_got);
                eprintln!("address: expected: {:?}, got: {:?}",
                          address, address_got);
                eprintln!("other: expected: {:?}, got: {:?}",
                          other, other_got);

                match name_got {
                    Ok(ref v) if ok =>
                        assert_eq!(v, &name),
                    Ok(_) if !ok =>
                        panic!("Expected parse to fail."),
                    Err(ref err) if ok =>
                        panic!("Expected parse to succeed: {:?}", err),
                    Err(_) if !ok =>
                        (),
                    _ => unreachable!(),
                };
                match comment_got {
                    Ok(ref v) if ok =>
                        assert_eq!(v, &comment),
                    Ok(_) if !ok =>
                        panic!("Expected parse to fail."),
                    Err(ref err) if ok =>
                        panic!("Expected parse to succeed: {:?}", err),
                    Err(_) if !ok =>
                        (),
                    _ => unreachable!(),
                };
                match address_got {
                    Ok(ref v) if ok =>
                        assert_eq!(v, &address),
                    Ok(_) if !ok =>
                        panic!("Expected parse to fail."),
                    Err(ref err) if ok =>
                        panic!("Expected parse to succeed: {:?}", err),
                    Err(_) if !ok =>
                        (),
                    _ => unreachable!(),
                };
                match other_got {
                    Ok(ref v) if ok =>
                        assert_eq!(v, &other),
                    Ok(_) if !ok =>
                        panic!("Expected parse to fail."),
                    Err(ref err) if ok =>
                        panic!("Expected parse to succeed: {:?}", err),
                    Err(_) if !ok =>
                        (),
                    _ => unreachable!(),
                };
            }
        }

        c("Henry Ford (CEO) <henry@ford.com>", true,
          Some("Henry Ford"), Some("CEO"), Some("henry@ford.com"), None);

        // The quotes disappear.  Unexpected, but true.
        c("Thomas \"Tomakin\" (DHC) <thomas@clh.co.uk>", true,
          Some("Thomas Tomakin"), Some("DHC"),
          Some("thomas@clh.co.uk"), None);

        c("Aldous L. Huxley <huxley@old-world.org>", true,
          Some("Aldous L. Huxley"), None,
          Some("huxley@old-world.org"), None);

        // Make sure bare email addresses work.  This is an extension
        // to 2822 where addresses normally have to be in angle
        // brackets.
        c("huxley@old-world.org", true,
          None, None, Some("huxley@old-world.org"), None);

        // Tricky...
        c("\"<loki@bar.com>\" <foo@bar.com>", true,
          Some("<loki@bar.com>"), None, Some("foo@bar.com"), None);

        // Invalid.
        c("<huxley@@old-world.org>", true,
          None, None, None, Some("huxley@@old-world.org"));
        c("huxley@@old-world.org", true,
          None, None, None, Some("huxley@@old-world.org"));
        c("huxley@old-world.org.", true,
          None, None, None, Some("huxley@old-world.org."));
        c("@old-world.org", true,
          None, None, None, Some("@old-world.org"));
    }

    #[test]
    fn address_normalized() {
        fn c(value: &str, expected: &str) {
            let u = UserID::from(value);
            let got = u.address_normalized().unwrap().unwrap();
            assert_eq!(expected, got);
        }

        c("Henry Ford (CEO) <henry@ford.com>", "henry@ford.com");
        c("Henry Ford (CEO) <Henry@Ford.com>", "henry@ford.com");
        c("Henry Ford (CEO) <Henry@Ford.com>", "henry@ford.com");
        c("hans@bücher.tld", "hans@xn--bcher-kva.tld");
        c("hANS@bücher.tld", "hans@xn--bcher-kva.tld");
    }

    #[test]
    fn from_address() {
        assert_eq!(UserID::from_address(None, None, "foo@bar.com")
                       .unwrap().value(),
                   b"foo@bar.com");
        assert!(UserID::from_address(None, None, "foo@@bar.com").is_err());
        assert_eq!(UserID::from_address("Foo Q. Bar".into(), None, "foo@bar.com")
                      .unwrap().value(),
                   b"\"Foo Q. Bar\" <foo@bar.com>");
    }
}
