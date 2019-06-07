//! *S-Expressions* for communicating cryptographic primitives.
//!
//! *S-Expressions* as described in the internet draft [S-Expressions],
//! are a way to communicate cryptographic primitives like keys,
//! signatures, and ciphertexts between agents or implementations.
//!
//! [S-Expressions]: https://people.csail.mit.edu/rivest/Sexp.txt

use std::fmt;
use std::ops::Deref;
use quickcheck::{Arbitrary, Gen};

/// An *S-Expression*.
///
/// An *S-Expression* is either a string, or a list of *S-Expressions*.
#[derive(Clone, PartialEq, Eq)]
pub enum Sexp {
    /// Just a string.
    String(String_),
    /// A list of *S-Expressions*.
    List(Vec<Sexp>),
}

impl fmt::Debug for Sexp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Sexp::String(ref s) => s.fmt(f),
            Sexp::List(ref l) => l.fmt(f),
        }
    }
}

impl Arbitrary for Sexp {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        if f32::arbitrary(g) < 0.7 {
            Sexp::String(String_::arbitrary(g))
        } else {
            let mut v = Vec::new();
            for _ in 0..usize::arbitrary(g) % 3 {
                v.push(Sexp::arbitrary(g));
            }
            Sexp::List(v)
        }
    }
}

/// A string.
///
/// A string can optionally have a display hint.
#[derive(Clone, PartialEq, Eq)]
pub struct String_(Box<[u8]>, Option<Box<[u8]>>);

impl fmt::Debug for String_ {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fn bstring(f: &mut fmt::Formatter, buf: &[u8]) -> fmt::Result {
            write!(f, "b\"")?;
            for &b in buf {
                match b {
                    0...31 | 128...255 =>
                        write!(f, "\\x{:02x}", b)?,
                    0x22 => // "
                        write!(f, "\\\"")?,
                    0x5c => // \
                        write!(f, "\\\\")?,
                    _ =>
                        write!(f, "{}", b as char)?,
                }
            }
            write!(f, "\"")
        }

        if let Some(hint) = self.display_hint() {
            write!(f, "[")?;
            bstring(f, hint)?;
            write!(f, "]")?;
        }
        bstring(f, &self.0)
    }
}

impl String_ {
    /// Constructs a new *Simple String*.
    pub fn new<S>(s: S) -> Self
        where S: Into<Box<[u8]>>
    {
        Self(s.into(), None)
    }

    /// Constructs a new *String*.
    pub fn with_display_hint<S, T>(s: S, display_hint: T) -> Self
        where S: Into<Box<[u8]>>, T: Into<Box<[u8]>>
    {
        Self(s.into(), Some(display_hint.into()))
    }

    /// Gets a reference to this *String*'s display hint, if any.
    pub fn display_hint(&self) -> Option<&[u8]> {
        self.1.as_ref().map(|b| b.as_ref())
    }
}

impl From<&[u8]> for String_ {
    fn from(b: &[u8]) -> Self {
        Self::new(b.to_vec())
    }
}

impl Deref for String_ {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Arbitrary for String_ {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        if bool::arbitrary(g) {
            Self::new(Vec::arbitrary(g).into_boxed_slice())
        } else {
            Self::with_display_hint(Vec::arbitrary(g).into_boxed_slice(),
                                    Vec::arbitrary(g).into_boxed_slice())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parse::Parse;
    use serialize::Serialize;

    quickcheck! {
        fn roundtrip(s: Sexp) -> bool {
            let mut buf = Vec::new();
            s.serialize(&mut buf).unwrap();
            let t = Sexp::from_bytes(&buf).unwrap();
            assert_eq!(s, t);
            true
        }
    }
}
