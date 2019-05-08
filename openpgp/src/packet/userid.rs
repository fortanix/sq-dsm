use std::fmt;
use std::str;
use std::hash::{Hash, Hasher};
use std::cell::RefCell;
use quickcheck::{Arbitrary, Gen};
use rfc2822::{NameAddr, AddrSpec};

use Result;
use packet;
use Packet;

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

    parsed: RefCell<Option<(Option<String>, Option<String>, Option<String>)>>,
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
        self.common == other.common
            && self.value == other.value
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
    /// Gets the user ID packet's value.
    pub fn value(&self) -> &[u8] {
        self.value.as_slice()
    }

    fn do_parse(&self) -> Result<()> {
        if self.parsed.borrow().is_none() {
            let s = str::from_utf8(&self.value)?;

            *self.parsed.borrow_mut() = Some(match NameAddr::parse(s) {
                Ok(na) => (na.name().map(|s| s.to_string()),
                           na.comment().map(|s| s.to_string()),
                           na.address().map(|s| s.to_string())),
                Err(err) => {
                    // Try with the addr-spec parser.
                    if let Ok(a) = AddrSpec::parse(s) {
                        (None, None, Some(a.address().to_string()))
                    } else {
                        // Return the error from the NameAddr parser.
                        return Err(err.into());
                    }
                }
            });
        }
        Ok(())
    }

    /// Treats the user ID as an RFC 2822 name-addr and extracts the
    /// display name, if any.
    pub fn name(&self) -> Result<Option<String>> {
        self.do_parse()?;
        match *self.parsed.borrow() {
            Some((ref name, ref _comment, ref _address)) =>
                Ok(name.as_ref().map(|s| s.clone())),
            None => unreachable!(),
        }
    }

    /// Treats the user ID as an RFC 2822 name-addr and extracts the
    /// first comment, if any.
    pub fn comment(&self) -> Result<Option<String>> {
        self.do_parse()?;
        match *self.parsed.borrow() {
            Some((ref _name, ref comment, ref _address)) =>
                Ok(comment.as_ref().map(|s| s.clone())),
            None => unreachable!(),
        }
    }

    /// Treats the user ID as an RFC 2822 name-addr and extracts the
    /// address, if any.
    pub fn address(&self) -> Result<Option<String>> {
        self.do_parse()?;
        match *self.parsed.borrow() {
            Some((ref _name, ref _comment, ref address)) =>
                Ok(address.as_ref().map(|s| s.clone())),
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
    use parse::Parse;
    use serialize::SerializeInto;

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
             name: Option<&str>, comment: Option<&str>, address: Option<&str>)
        {
            let name = name.map(|s| s.to_string());
            let comment = comment.map(|s| s.to_string());
            let address = address.map(|s| s.to_string());

            let u = UserID::from(value);
            for _ in 0..2 {
                match u.name() {
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
                match u.comment() {
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
                match u.address() {
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
            }
        }

        c("Henry Ford (CEO) <henry@ford.com>", true,
          Some("Henry Ford"), Some("CEO"), Some("henry@ford.com"));

        // The quotes disappear.  Unexpected, but true.
        c("Thomas \"Tomakin\" (DHC) <thomas@clh.co.uk>", true,
          Some("Thomas Tomakin"), Some("DHC"), Some("thomas@clh.co.uk"));

        c("Aldous L. Huxley <huxley@old-world.org>", true,
          Some("Aldous L. Huxley"), None, Some("huxley@old-world.org"));

        // Make sure bare email addresses work.  This is an extension
        // to 2822 where addresses normally have to be in angle
        // brackets.
        c("huxley@old-world.org", true,
          None, None, Some("huxley@old-world.org"));

        // Tricky...
        c("\"<loki@bar.com>\" <foo@bar.com>", true,
          Some("<loki@bar.com>"), None, Some("foo@bar.com"));

        // Invalid.
        c("<huxley@@old-world.org>", false, None, None, None);
        c("huxley@@old-world.org", false, None, None, None);
        c("huxley@old-world.org.", false, None, None, None);
        c("@old-world.org", false, None, None, None);
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
}
