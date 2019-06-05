//! This crates provides support for parsing a subset of [RFC 2822].
//! In particular, it exports functions that parse a string according
//! to the [`name-addr`] production, and the [`addr-spec`] production.
//!
//! This crate does not yet parse [RFC 2822] [`dates and times`] or
//! [`message headers`].  Given the infrastructure, adding support for
//! these productions should be straightforward.  However, the main
//! user of this crate is [Sequoia], an [OpenPGP implementation], and
//! it only uses this crate to parse [User IDs], which usually include
//! an [RFC 2822] mail [`name-addr`].  If you require this
//! functionality, please feel free to open an [issue].
//!
//!   [RFC 2822]: https://tools.ietf.org/html/rfc2822
//!   [`name-addr`]: https://tools.ietf.org/html/rfc2822#section-3.4
//!   [`addr-spec`]: https://tools.ietf.org/html/rfc2822#section-3.4.1
//!   [`dates and times`]: https://tools.ietf.org/html/rfc2822#section-3.3
//!   [`message headers`]: https://tools.ietf.org/html/rfc2822#section-3.6
//!   [Sequoia]: https://sequoia-pgp.org/
//!   [OpenPGP implementation]: https://tools.ietf.org/html/rfc4880
//!   [User IDs]: https://tools.ietf.org/html/rfc4880#section-5.11
//!   [issue]: https://gitlab.com/sequoia-pgp/sequoia/issues
//!
//! # Examples
//!
//! Parsing a [`name-addr`]:
//!
//! ```
//! use sequoia_rfc2822::NameAddr;
//!
//! let nameaddr = NameAddr::parse(
//!     "Professor Pippy P. Poopypants <pippy@jerome-horwitz.k12.oh.us>")
//!     .expect("Valid name-addr");
//! assert_eq!(nameaddr.name(), Some("Professor Pippy P. Poopypants"));
//! assert_eq!(nameaddr.comment(), None);
//! assert_eq!(nameaddr.address(), Some("pippy@jerome-horwitz.k12.oh.us"));
//!
//! // Extra angle brackets.
//! assert!(NameAddr::parse("Invalid <<pippy@jerome-horwitz.k12.oh.us>>")
//!        .is_err());
//!
//! // No angle brackets.
//! assert!(NameAddr::parse("pippy@jerome-horwitz.k12.oh.us")
//!        .is_err());
//! ```
//!
//! Parsing an [`addr-spec`]:
//!
//! ```
//! use sequoia_rfc2822::AddrSpec;
//!
//! let addrspec = AddrSpec::parse(
//!     "pippy@jerome-horwitz.k12.oh.us")
//!     .expect("Valid addr-spec");
//! assert_eq!(addrspec.address(), "pippy@jerome-horwitz.k12.oh.us");
//!
//! // Angle brackets are not allowed.
//! assert!(AddrSpec::parse("<pippy@jerome-horwitz.k12.oh.us>")
//!        .is_err());
//! ```

extern crate failure;
extern crate lalrpop_util;

#[cfg(test)] #[macro_use] extern crate lazy_static;
#[cfg(test)] #[macro_use] extern crate quickcheck;
#[cfg(test)] extern crate rand;

use lalrpop_util::ParseError;

#[macro_use] mod macros;
#[macro_use] mod trace;
mod strings;
#[macro_use] mod component;
use component::{
    Component
};
mod lexer;
use lexer::LexicalError;

// We expose a number of productions for testing purposes.
// Unfortunately, lalrpop doesn't understand the #[cfg(test)]
// attribute.  So, to avoid warnings, we allow unused imports and dead
// code when not testing.
#[cfg(test)]
mod grammar;
#[cfg(not(test))]
#[allow(unused_imports, dead_code)]
mod grammar;

#[cfg(test)]
mod roundtrip;

const TRACE : bool = false;

pub type Result<T> = ::std::result::Result<T, failure::Error>;

// A failure needs to have a 'static life time.  lexer::Tokens don't.
// Convert tokens into strings.
//
// Unfortunately, we can't implement From, because we don't define the
// ParseError in this crate.
fn parse_error_downcast<'a>(e: ParseError<usize, lexer::Token<'a>, LexicalError>)
    -> ParseError<usize, String, LexicalError>
{
    match e {
        ParseError::UnrecognizedToken {
            token: (start, t, end),
            expected,
        } => ParseError::UnrecognizedToken {
            token: (start, t.into(), end),
            expected,
        },

        ParseError::ExtraToken {
            token: (start, t, end),
        } => ParseError::ExtraToken {
            token: (start, t.into(), end),
        },

        ParseError::InvalidToken { location }
        => ParseError::InvalidToken { location },

        ParseError::User { error }
        => ParseError::User { error },

        ParseError::UnrecognizedEOF { location, expected }
        => ParseError::UnrecognizedEOF { location, expected },
    }
}

/// A `DisplayName`.
pub struct Name {
}

impl Name {
    /// Returns an escaped version of `name`, which is appropriate for
    /// use in a `name-addr`.
    ///
    /// Returns an error if `name` contains characters that cannot be
    /// escaped (NUL, CR and LF).
    pub fn escaped<S>(name: S) -> Result<String>
        where S: AsRef<str>
    {
        let name = name.as_ref();

        let lexer = lexer::Lexer::new(name);
        grammar::EscapedDisplayNameParser::new().parse(name, lexer)
            .map_err(|e| parse_error_downcast(e).into())
    }
}

/// A parsed RFC 2822 `addr-spec`.
///
/// The address must not include angle brackets.  That is, this parser
/// recognizes addresses of the form:
///
/// ```text
/// email@example.org
/// ```
///
/// But not:
///
/// ```text
/// <email@example.org>
/// ```
///
/// RFC 2822 comments are ignored.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AddrSpec {
    components: Vec<Component>,
}

impl AddrSpec {
    /// Create an RFC 2822 `addr-spec`.
    ///
    /// Not yet exported as this function does *not* do any escaping.
    #[allow(dead_code)]
    fn new<S>(address: S)
        -> Result<Self>
        where S: AsRef<str> + Eq + std::fmt::Debug,
    {
        let address = address.as_ref();

        // Make sure the input is valid.
        let a = match Self::parse(address) {
            Err(err) => return Err(err.into()),
            Ok(a) => a,
        };

        assert_eq!(a.address(), address);

        Ok(a)
    }

    /// Parses a string that allegedly contains an [RFC 2822
    /// `addr-spec`].
    ///
    /// [RFC 2822 `addr-spec`]: https://tools.ietf.org/html/rfc2822#section-3.4
    pub fn parse<S>(input: S) -> Result<Self>
        where S: AsRef<str>
    {
        let input = input.as_ref();
        let lexer = lexer::Lexer::new(input);
        let components = match grammar::AddrSpecParser::new().parse(input, lexer) {
            Ok(components) => components,
            Err(err) => return Err(parse_error_downcast(err).into()),
        };

        Ok(Self {
            components,
        })
    }

    /// Returns the address.
    pub fn address(&self) -> &str {
        for c in self.components.iter() {
            if let Component::Address(t) = c {
                return &t[..];
            }
        }
        // An addr-spec always has an Address.
        unreachable!();
    }
}

/// A parsed RFC 2822 `addr-spec`, which also recognizes invalid email
/// addresses.
///
/// For this parser to recognize an email address, the input must not
/// include angle brackets.  That is, this parser recognizes addresses
/// of the form:
///
/// ```text
/// email@example.org
/// ```
///
/// But not:
///
/// ```text
/// <email@example.org>
/// ```
///
/// When parsing valid email addresses, RFC 2822 comments are ignored.
///
/// If the input is not a valid email address, no error is returned by
/// `AddrSpecOrOther::parse()` (unlike `AddrSpec::parse()`).  Instead,
/// the invalid email address can be obtained using
/// `AddrSpecOrOther::other()`.  Consider:
///
/// ```text
/// ssh://server.example.net
/// ```
///
/// In this case, `AddrSpecOrOther::other()` returns
/// `ssh://server.example.net`.  The parse error can still be obtained
/// using `AddrSpecOrOther::address()`.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AddrSpecOrOther {
    components: Vec<Component>,
}

impl AddrSpecOrOther {
    /// Creates an RFC 2822 `addr-spec` or other.
    ///
    /// Not yet exported as this function does *not* do any escaping.
    #[allow(dead_code)]
    fn new<S>(address: S)
        -> Result<Self>
        where S: AsRef<str> + Eq + std::fmt::Debug,
    {
        let address = address.as_ref();

        // Make sure the input is valid.
        let a = match Self::parse(address) {
            Err(err) => return Err(err.into()),
            Ok(a) => a,
        };

        Ok(a)
    }

    /// Parses a string that allegedly contains an [RFC 2822
    /// `addr-spec`] or other.
    ///
    /// [RFC 2822 `addr-spec`]: https://tools.ietf.org/html/rfc2822#section-3.4
    pub fn parse<S>(input: S) -> Result<Self>
        where S: AsRef<str>
    {
        let input = input.as_ref();
        let lexer = lexer::Lexer::new(input);
        let components = match grammar::AddrSpecOrOtherParser::new().parse(input, lexer) {
            Ok(components) => components,
            Err(err) => return Err(parse_error_downcast(err).into()),
        };

        Ok(Self {
            components,
        })
    }

    /// Returns the address, if any.
    ///
    /// If the address is invalid, then the parse error is returned.
    pub fn address(&self) -> Result<&str> {
        for c in self.components.iter() {
            if let Component::Address(t) = c {
                return Ok(&t[..]);
            }
            if let Component::InvalidAddress(e, _) = c {
                return Err(e.clone().into());
            }
        }

        unreachable!();
    }

    /// Returns the invalid address, if any.
    ///
    /// If the address is valid, then this returns None.
    pub fn other(&self) -> Option<&str> {
        for c in self.components.iter() {
            if let Component::Address(_) = c {
                return None;
            }
            if let Component::InvalidAddress(_, t) = c {
                return Some(&t[..]);
            }
        }

        unreachable!();
    }
}

/// A parsed [RFC 2822 `name-addr`].
///
/// `name-addr`s are typically of the form:
///
/// ```text
/// First Last (Comment) <email@example.org>
/// ```
///
/// The name and comment are optional, but the comment is only allowed
/// if there is also a name.
///
/// Note: this does not recognize bare addresses.  That is the angle
/// brackets are required and the following is not recognized as a
/// `name-addr`:
///
/// ```text
/// email@example.org
/// ```
///
/// [RFC 2822 `name-addr`]: https://tools.ietf.org/html/rfc2822#section-3.4
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NameAddr {
    components: Vec<Component>,
}

impl NameAddr {
    /// Create an RFC 2822 `name-addr`.
    ///
    /// Not yet exported as this function does *not* do any escaping.
    #[allow(dead_code)]
    fn new<S>(name: Option<S>, comment: Option<S>, address: Option<S>)
        -> Result<Self>
        where S: AsRef<str> + Eq + std::fmt::Debug,
    {
        let mut s = if let Some(ref name) = name {
            String::from(name.as_ref())
        } else {
            String::new()
        };

        if let Some(ref comment) = comment {
            if name.is_some() {
                s.push(' ');
            }
            s.push_str(&format!("({})", comment.as_ref())[..]);
        }

        if let Some(ref address) = address {
            if name.is_some() || comment.is_some() {
                s.push(' ');
            }
            s.push_str(&format!("<{}>", address.as_ref())[..]);
        }

        // Make sure the input is valid.
        let na = match Self::parse(s) {
            Err(err) => return Err(err.into()),
            Ok(na) => na,
        };

        if let Some(name_reparsed) = na.name() {
            assert!(name.is_some());
            assert_eq!(name_reparsed, name.unwrap().as_ref());
        } else {
            assert!(name.is_none());
        }
        if let Some(comment_reparsed) = na.comment() {
            assert!(comment.is_some());
            assert_eq!(comment_reparsed, comment.unwrap().as_ref());
        } else {
            assert!(comment.is_none());
        }
        if let Some(address_reparsed) = na.address() {
            assert!(address.is_some());
            assert_eq!(address_reparsed, address.unwrap().as_ref());
        } else {
            assert!(address.is_none());
        }

        Ok(na)
    }

    /// Parses a string that allegedly contains an [RFC 2822
    /// `name-addr`].
    ///
    /// [RFC 2822 `name-addr`]: https://tools.ietf.org/html/rfc2822#section-3.4
    pub fn parse<S>(input: S) -> Result<Self>
        where S: AsRef<str>
    {
        let input = input.as_ref();
        let lexer = lexer::Lexer::new(input);
        let components = match grammar::NameAddrParser::new().parse(input, lexer) {
            Ok(components) => components,
            Err(err) => return Err(parse_error_downcast(err).into()),
        };

        Ok(Self {
            components,
        })
    }

    /// Returns the [display name].
    ///
    /// [display name]: https://tools.ietf.org/html/rfc2822#section-3.4
    pub fn name(&self) -> Option<&str> {
        for c in self.components.iter() {
            if let Component::Text(t) = c {
                return Some(&t[..]);
            }
        }
        None
    }

    /// Returns the first comment.
    pub fn comment(&self) -> Option<&str> {
        for c in self.components.iter() {
            if let Component::Comment(t) = c {
                return Some(&t[..]);
            }
        }
        None
    }

    /// Returns the address.
    pub fn address(&self) -> Option<&str> {
        for c in self.components.iter() {
            if let Component::Address(t) = c {
                return Some(&t[..]);
            }
        }
        None
    }
}

/// A parsed [RFC 2822 `name-addr`], which also recognizes invalid
/// email addresses.
///
/// `name-addr`s are typically of the form:
///
/// ```text
/// First Last (Comment) <email@example.org>
/// ```
///
/// The name and comment are optional, but the comment is only allowed
/// if there is also a name.
///
/// Note: this does not recognize bare addresses.  That is, the angle
/// brackets are required and the following is not recognized (even as
/// an invalid address) as a `name-addr`:
///
/// ```text
/// email@example.org
/// ```
///
/// [RFC 2822 `name-addr`]: https://tools.ietf.org/html/rfc2822#section-3.4
///
/// This version of the `name-addr` parser also recognizes invalid
/// email addresses.  For instance:
///
/// ```text
/// First Last (Comment) <ssh://server.example.net>
/// ```
///
/// will be successfully parsed.  In this case,
/// `NameAddrOrOther::address()` will return the parse error, and the
/// invalid address can be obtained using `NameAddrOrOther::other()`.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NameAddrOrOther {
    components: Vec<Component>,
}

impl NameAddrOrOther {
    /// Creates an RFC 2822 `name-addr` with an optionally invalid
    /// email address.
    ///
    /// Not yet exported as this function does *not* do any escaping.
    #[allow(dead_code)]
    fn new<S>(name: Option<S>, comment: Option<S>, address: Option<S>)
        -> Result<Self>
        where S: AsRef<str> + Eq + std::fmt::Debug,
    {
        let mut s = if let Some(ref name) = name {
            String::from(name.as_ref())
        } else {
            String::new()
        };

        if let Some(ref comment) = comment {
            if name.is_some() {
                s.push(' ');
            }
            s.push_str(&format!("({})", comment.as_ref())[..]);
        }

        if let Some(ref address) = address {
            if name.is_some() || comment.is_some() {
                s.push(' ');
            }
            s.push_str(&format!("<{}>", address.as_ref())[..]);
        }

        // Make sure the input is valid.
        let na = match Self::parse(s) {
            Err(err) => return Err(err.into()),
            Ok(na) => na,
        };

        if let Some(name_reparsed) = na.name() {
            assert!(name.is_some());
            assert_eq!(name_reparsed, name.unwrap().as_ref());
        } else {
            assert!(name.is_none());
        }
        if let Some(comment_reparsed) = na.comment() {
            assert!(comment.is_some());
            assert_eq!(comment_reparsed, comment.unwrap().as_ref());
        } else {
            assert!(comment.is_none());
        }

        Ok(na)
    }

    /// Parses a string that allegedly contains an [RFC 2822
    /// `name-addr`] with an optionally invalid email address.
    ///
    /// [RFC 2822 `name-addr`]: https://tools.ietf.org/html/rfc2822#section-3.4
    pub fn parse<S>(input: S) -> Result<Self>
        where S: AsRef<str>
    {
        let input = input.as_ref();
        let lexer = lexer::Lexer::new(input);
        let components = match grammar::NameAddrOrOtherParser::new().parse(input, lexer) {
            Ok(components) => components,
            Err(err) => return Err(parse_error_downcast(err).into()),
        };

        Ok(Self {
            components,
        })
    }

    /// Returns the [display name].
    ///
    /// [display name]: https://tools.ietf.org/html/rfc2822#section-3.4
    pub fn name(&self) -> Option<&str> {
        for c in self.components.iter() {
            if let Component::Text(t) = c {
                return Some(&t[..]);
            }
        }
        None
    }

    /// Returns the first comment.
    pub fn comment(&self) -> Option<&str> {
        for c in self.components.iter() {
            if let Component::Comment(t) = c {
                return Some(&t[..]);
            }
        }
        None
    }

    /// Returns the address, if any.
    ///
    /// If the address is invalid, then the parse error is returned.
    pub fn address(&self) -> Result<&str> {
        for c in self.components.iter() {
            if let Component::Address(t) = c {
                return Ok(&t[..]);
            }
            if let Component::InvalidAddress(e, _) = c {
                return Err(e.clone().into());
            }
        }

        unreachable!()
    }

    /// Returns the invalid address, if any.
    ///
    /// If the address is valid, then this returns None.
    pub fn other(&self) -> Option<&str> {
        for c in self.components.iter() {
            if let Component::Address(_) = c {
                return None;
            }
            if let Component::InvalidAddress(_, t) = c {
                return Some(&t[..]);
            }
        }

        unreachable!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! c {
        ( $parser:expr, $t:ty) => {
            fn c<S>(input: S, expected: Option<$t>)
                where S: AsRef<str>
            {
                let input = input.as_ref();
                eprintln!("\n\ninput: '{:?}'", input);

                let lexer = lexer::Lexer::new(&input[..]);
                let result = $parser.parse(input, lexer);

                if let Some(expected) = expected {
                    if let Ok(result) = result {
                        assert_eq!(result, expected,
                                   "Parsing: '{:?}'\n     got: '{:?}'\nexpected: '{:?}'",
                                   input, result, expected);
                    } else {
                        panic!("Parsing: '{:?}': {:?}", input, result);
                    }
                } else {
                    assert!(result.is_err(), "Parsing '{:?}'\n     got: '{:?}'\nexpected: '{:?}'",
                            input, result, expected);
                }
            }
        };
    }

    // comment         =       "(" *([FWS] ccontent) [FWS] ")"
    // ccontent        =       ctext / quoted-pair / comment
    // ctext           =       NO-WS-CTL /     ; Non white space controls
    //                         %d33-39 /       ; The rest of the US-ASCII
    //                         %d42-91 /       ;  characters not including "(",
    //                         %d93-126        ;  ")", or "\"
    // quoted-pair     =       ("\" text) / obs-qp
    // text            =       %d1-9 /         ; Characters excluding CR and LF
    //                         %d11 /
    //                         %d12 /
    //                         %d14-127 /
    //                         obs-text

    // The comment production parses a single comment.
    //
    // A comment can contain pretty much anything, but any parenthesis
    // need to be balanced (or escaped).
    #[test]
    fn comment_parser() {
        c!(grammar::CommentParser::new(), Component);

        // A comment must be surrounded by ().
        c("foobar", None);
        c("(foobar)",
          Some(Component::Comment("foobar".into())));
        c("(foo bar)",
          Some(Component::Comment("foo bar".into())));
        // Unbalanced parenthesis are not allowed.
        c("((foobar)", None);
        // Unless they are escaped.
        c("(\\(foobar)",
          Some(Component::Comment("(foobar".into())));
        c("((foobar))",
          Some(Component::Comment("(foobar)".into())));
        c("((fo()ob()ar))",
          Some(Component::Comment("(fo()ob()ar)".into())));

        // The comment parser doesn't remove leading or trailing
        // whitespace.
        c("  \r\n   ((abc))", None);
        c("((abc))  ", None);

        // Folding whitespace is compressed to a single space.
        c("(   a)",
          Some(Component::Comment(" a".into())));
        c("(a      )",
          Some(Component::Comment("a ".into())));
        c("(      a        )",
          Some(Component::Comment(" a ".into())));
        c("(   a  b    )",
          Some(Component::Comment(" a b ".into())));

        c("( \r\n  a  b)",
          Some(Component::Comment(" a b".into())));
        c("(a    \r\n b )",
          Some(Component::Comment("a b ".into())));
        c("(a  b  \r\n  )",
          Some(Component::Comment("a b ".into())));
        c("(      a   b     )",
          Some(Component::Comment(" a b ".into())));
        c("(  \r\n    a    \r\n  b   \r\n  )",
          Some(Component::Comment(" a b ".into())));

        c("(   a  \r\n   bc      \r\n       d   )",
          Some(Component::Comment(" a bc d ".into())));
        c("((     a  \r\n   bc      \r\n       d ))",
          Some(Component::Comment("( a bc d )".into())));

        // The crlf in folding white space must be followed by a
        // space.
        c("(foo\r\n)", None);
        c("(foo\r\n )",
          Some(Component::Comment("foo ".into())));

        // Multiple folding white spaces in a row are not allowed.
        c("(( \r\n  \r\n    a ))", None);
        c("(( abcd \r\n  \r\n    a ))", None);
        c("(( abcd \r\n  \r\n    ))", None);
    }

    // CFWS            =       *([FWS] comment) (([FWS] comment) / FWS)
    //
    // The CFWS production allows for multiple comments preceded,
    // separated and followed by folding whitespace.
    #[test]
    fn cfws_parser() {
        c!(grammar::CfwsParser::new(), Vec<Component>);

        // A comment must be surrounded by ().
        c("foobar", None);
        c("(foobar)",
          Some(vec![Component::Comment("foobar".into())]));
        // Unbalanced parenthesis are not allowed.
        c("((foobar)", None);
        c("((foobar))",
          Some(vec![Component::Comment("(foobar)".into())]));
        c("((fo()ob()ar))",
          Some(vec![Component::Comment("(fo()ob()ar)".into())]));

        // Folding white space before and after is okay.  It appears
        // as a single space character.
        c("  \r\n   ((abc))",
          Some(vec![
              Component::WS,
              Component::Comment("(abc)".into()),
          ]));
        c("((abc)) \r\n  ",
          Some(vec![
              Component::Comment("(abc)".into()),
              Component::WS,
          ]));

        c("((a  \r\n   bc      \r\n       d))",
          Some(vec![Component::Comment("(a bc d)".into())]));

        // Multiple comments are also allowed.
        c("((foobar   buz)) (bam)\r\n (quuz)  \r\n   ",
          Some(vec![
              Component::Comment("(foobar buz)".into()),
              Component::WS,
              Component::Comment("bam".into()),
              Component::WS,
              Component::Comment("quuz".into()),
              Component::WS,
          ]));
        c("(xy(z)zy)   ((foobar))      (bam)",
          Some(vec![
              Component::Comment("xy(z)zy".into()),
              Component::WS,
              Component::Comment("(foobar)".into()),
              Component::WS,
              Component::Comment("bam".into())
          ]));

        // Adjacent comments don't have any spaces between them.
        c("((foobar   buz))(bam)(quuz)",
          Some(vec![
              Component::Comment("(foobar buz)".into()),
              Component::Comment("bam".into()),
              Component::Comment("quuz".into()),
          ]));

    }

    // atom            =       [CFWS] 1*atext [CFWS]
    //
    // Note: our atom parser also allows for dots.
    //
    // An atom is a sequence of characters.
    //
    // They may be preceded or followed by a CFWS (zero or more
    // comments and folding white space).
    //
    // Note: no spaces are allowed in the atext!  They can't even be
    // escaped.
    #[test]
    fn atom_parser() {
        c!(grammar::AtomParser::new(), Vec<Component>);

        c("foobar", Some(vec![Component::Text("foobar".into())]));

        // "Any character except controls, SP, and specials."
        for &s in ["a", "1", "ß", "ü", "é", "あ", "fooゔヲ", "ℝ💣東京",
                  "!", "#", "$", "%", "&", "'", "*", "+", "-",
                   "/", "=", "?", "^", "_", "`", "{", "|", "}", "~",
                   // Extension:
                   "."]
            .into_iter()
        {
            c(s, Some(vec![Component::Text(s.to_string())]))
        }

        for &s in ["\x02", " ",
                  "(", ")", "<", ">", "[", "]", ":", ";",
                  "@", "\\", ",", "\""]
            .into_iter()
        {
            c(s, None)
        }

        // No internal white space.
        c("foo bar", None);

        // If a CFWS precedes an atom, any comments are retained, but
        // trailing white space is removed.
        c("\r\n foobar  \r\n ",
          Some(vec![
              Component::WS,
              Component::Text("foobar".into()),
              Component::WS,
          ]));
        c("  \r\n foobar  ",
          Some(vec![
              Component::WS,
              Component::Text("foobar".into()),
              Component::WS,
          ]));

        c("(some comment)foobar",
          Some(vec![
              Component::Comment("some comment".into()),
              Component::Text("foobar".into())
          ]));
        c("(some comment) foobar",
          Some(vec![
              Component::Comment("some comment".into()),
              Component::WS,
              Component::Text("foobar".into())
          ]));
        c("(so\r\n m   \r\n e co\r\n   mme  \r\n   nt\r\n ) \r\n    foobar",
          Some(vec![
              Component::Comment("so m e co mme nt ".into()),
              Component::WS,
              Component::Text("foobar".into())
          ]));

        c("(a)(b)(c)foobar(d)(e)",
          Some(vec![
              Component::Comment("a".into()),
              Component::Comment("b".into()),
              Component::Comment("c".into()),
              Component::Text("foobar".into()),
              Component::Comment("d".into()),
              Component::Comment("e".into())
          ]));
        c(" \r\n  (a)\r\n (b)\r\n   (c)\r\n    foobar \r\n (d)(e) \r\n ",
          Some(vec![
              Component::WS,
              Component::Comment("a".into()),
              Component::WS,
              Component::Comment("b".into()),
              Component::WS,
              Component::Comment("c".into()),
              Component::WS,
              Component::Text("foobar".into()),
              Component::WS,
              Component::Comment("d".into()),
              Component::Comment("e".into()),
              Component::WS,
          ]));
    }

    // quoted-string   =       [CFWS]
    //                         DQUOTE *([FWS] qcontent) [FWS] DQUOTE
    //                         [CFWS]
    //
    // qcontent        =       qtext / quoted-pair
    //
    // qtext           =       NO-WS-CTL /     ; Non white space controls
    //                         %d33 /          ; The rest of the US-ASCII
    //                         %d35-91 /       ;  characters not including "\"
    //                         %d93-126        ;  or the quote character
    //
    // quoted-pair     =       ("\" text) / obs-qp
    #[test]
    fn quoted_string_parser() {
        c!(grammar::QuotedStringParser::new(), Vec<Component>);

        c("\"foobar\"", Some(vec![Component::Text("foobar".into())]));
        c("\"   foobar\"", Some(vec![Component::Text(" foobar".into())]));
        c("\"foobar  \"", Some(vec![Component::Text("foobar ".into())]));
        c("\"foo  bar bam \"",
          Some(vec![Component::Text("foo bar bam ".into())]));
        c("\"   foo  bar bam \"",
          Some(vec![Component::Text(" foo bar bam ".into())]));
        c("\r\n \"(some comment)\"",
          Some(vec![
              Component::WS,
              Component::Text("(some comment)".into()),
          ]));
        c("\"(some comment)\" \r\n ",
          Some(vec![
              Component::Text("(some comment)".into()),
              Component::WS,
          ]));


        c("\"\\f\\o\\o\\b\\a\\r\"",
          Some(vec![Component::Text("foobar".into())]));

        // comments in a quoted string aren't.
        c("(not a comment)\"foobar\"",
          Some(vec![
              Component::Comment("not a comment".into()),
              Component::Text("foobar".into())
          ]));
        c("\"(not a comment)foobar\"",
          Some(vec![Component::Text("(not a comment)foobar".into())]));
        c("\"))((((not a comment)foobar\"",
          Some(vec![Component::Text("))((((not a comment)foobar".into())]));
    }

    // word            =       atom / quoted-string
    #[test]
    fn word_parser() {
        c!(grammar::WordParser::new(), Vec<Component>);

        c("foobar", Some(vec![Component::Text("foobar".into())]));
        c("\"foobar\"", Some(vec![Component::Text("foobar".into())]));
        c("\"\\f\\o\\o\\b\\a\\r\"", Some(vec![Component::Text("foobar".into())]));
    }

    // phrase          =       1*word / obs-phrase
    #[test]
    fn phrase_parser() {
        c!(grammar::PhraseParser::new(), Vec<Component>);

        c("foobar", Some(vec![Component::Text("foobar".into())]));
        c("foobar bam", Some(vec![Component::Text("foobar bam".into())]));
        c("foobar  bam", Some(vec![Component::Text("foobar bam".into())]));
        c(" foobar  bam ",
          Some(vec![
              Component::WS,
              Component::Text("foobar bam".into()),
              Component::WS,
          ]));

        c("\"foobar\"", Some(vec![Component::Text("foobar".into())]));
        c("\"foobar\" \"bam\"", Some(vec![Component::Text("foobar bam".into())]));
        c("\"foobar\"  \"bam\"", Some(vec![Component::Text("foobar bam".into())]));
        c(" \"foobar\"  \"bam\" ",
          Some(vec![
              Component::WS,
              Component::Text("foobar bam".into()),
              Component::WS,
          ]));

        c("\"foobar\"\"bam\"",
          Some(vec![Component::Text("foobarbam".into())]));
        c("\"foobar\"quuz\"bam\"",
          Some(vec![Component::Text("foobarquuzbam".into())]));
        c("\"foobar\"quuz \"bam\"",
          Some(vec![Component::Text("foobarquuz bam".into())]));
        c("\"foobar\"quuz  \"bam\"",
          Some(vec![Component::Text("foobarquuz bam".into())]));

        c("\"foobar\"", Some(vec![Component::Text("foobar".into())]));
        // Just a comment is not allowed.
        c("(foobar)", None);
        c("(foobar) quux",
          Some(vec![
              Component::Comment("foobar".into()),
              Component::WS,
              Component::Text("quux".into())
          ]));
        c("xyzzy (foobar) quux",
          Some(vec![Component::Text("xyzzy".into()),
                    Component::WS,
                    Component::Comment("foobar".into()),
                    Component::WS,
                    Component::Text("quux".into())]));
        c("foobar (comment) \"quoted string\"",
          Some(vec![
              Component::Text("foobar".into()),
              Component::WS,
              Component::Comment("comment".into()),
              Component::WS,
              Component::Text("quoted string".into())]));
        c("foobar (comment) \"   quoted string\"",
          Some(vec![
              Component::Text("foobar".into()),
              Component::WS,
              Component::Comment("comment".into()),
              Component::WS,
              Component::Text(" quoted string".into())]));
        c("foobar bam   quuz",
          Some(vec![Component::Text("foobar bam quuz".into())]));
    }

    // dot-atom        =       [CFWS] dot-atom-text [CFWS]
    // dot-atom-text   =       1*atext *("." 1*atext)
    #[test]
    fn dot_atom_parser() {
        c!(grammar::DotAtomParser::new(), Vec<Component>);

        c("f",
          Some(vec![Component::Text("f".into())]));
        c("foo",
          Some(vec![Component::Text("foo".into())]));
        c("f.o",
          Some(vec![Component::Text("f.o".into())]));
        c("foo.bar",
          Some(vec![Component::Text("foo.bar".into())]));

        c("foo.", None);
        c("foo.bar.", None);
        c("foo..bar", None);
        c(".foo.bar", None);
        c(".", None);
        c("..", None);

        // Internal space is not allowed.
        c("foo bar", None);

        // But leading and trailing space is okay.
        c(" f",
          Some(vec![
              Component::WS,
              Component::Text("f".into()),
          ]));
        c("  f",
          Some(vec![
              Component::WS,
              Component::Text("f".into()),
          ]));
        c("f ",
          Some(vec![
              Component::Text("f".into()),
              Component::WS,
          ]));
        c("f  ",
          Some(vec![
              Component::Text("f".into()),
              Component::WS,
          ]));

        // Comments are also okay.
        c("(comment) f",
          Some(vec![
              Component::Comment("comment".into()),
              Component::WS,
              Component::Text("f".into()),
          ]));
        c(" (comment) f",
          Some(vec![
              Component::WS,
              Component::Comment("comment".into()),
              Component::WS,
              Component::Text("f".into()),
          ]));
        c(" f (comment) ",
          Some(vec![
              Component::WS,
              Component::Text("f".into()),
              Component::WS,
              Component::Comment("comment".into()),
              Component::WS,
          ]));
        c(" f (comment)",
          Some(vec![
              Component::WS,
              Component::Text("f".into()),
              Component::WS,
              Component::Comment("comment".into()),
          ]));
    }


    // domain-literal  =       [CFWS] "[" *([FWS] dcontent) [FWS] "]" [CFWS]
    #[test]
    fn domain_literal_parser() {
        c!(grammar::DomainLiteralParser::new(), Vec<Component>);

        c("[foo]",
          Some(vec![Component::Text("[foo]".into())]));
        c("[\\[foo\\[]",
          Some(vec![Component::Text("[[foo[]".into())]));
        c("[foo.bar.com quux:biz]",
          Some(vec![Component::Text("[foo.bar.com quux:biz]".into())]));
        c(" \r\n   [\r\n   foo.bar.com \r\n   quux:biz\r\n   ]\r\n   ",
          Some(vec![
              Component::WS,
              Component::Text("[ foo.bar.com quux:biz ]".into()),
              Component::WS,
          ]));
    }

    // addr-spec-or-other     =       local-part "@" domain
    //                        |       anything
    #[test]
    fn or_other_parsers() {
        fn e() -> ParseError<usize, String, LexicalError> {
            ParseError::User { error: LexicalError::NoError }
        }

        struct Test<'a> {
            input: &'a str,
            output: Option<Vec<Component>>,
        };

        let tests : &[Test] = &[
            // First, some normal, valid email addresses.
            Test {
                input: "foo@bar.com",
                output: Some(vec![Component::Address("foo@bar.com".into())])
            },
            Test {
                input: "foo@bar",
                output: Some(vec![Component::Address("foo@bar".into())])
            },
            Test {
                input: "foo.bar@x",
                output: Some(vec![Component::Address("foo.bar@x".into())])
            },
            // Last character is a multibyte character.
            Test {
                input: "foo.bar@ß",
                output: Some(vec![Component::Address("foo.bar@ß".into())])
            },

            // Then some invalid email addresses...

            // [ is not a valid localpart.
            Test {
                input: "[@x",
                output: Some(vec![
                    Component::InvalidAddress(e(), "[@x".into())
                ])
            },
            Test {
                input: "[ß@x",
                output: Some(vec![
                    Component::InvalidAddress(e(), "[ß@x".into())
                ])
            },
            // Last character is a multibyte character.
            Test {
                input: "[@xß",
                output: Some(vec![
                    Component::InvalidAddress(e(), "[@xß".into())
                ])
            },
            Test {
                input: "[@xßℝ",
                output: Some(vec![
                    Component::InvalidAddress(e(), "[@xßℝ".into())
                ])
            },
            Test {
                input: "foo[@x",
                output: Some(vec![
                    Component::InvalidAddress(e(), "foo[@x".into())
                ])
            },

            // What happens with comments?
            Test {
                input: "(c)[@x",
                output: Some(vec![
                    Component::InvalidAddress(e(), "(c)[@x".into())
                ])
            },
            Test {
                input: "[(c)@x",
                output: Some(vec![
                    Component::InvalidAddress(e(), "[(c)@x".into())
                ])
            },
            Test {
                input: "[@(c)x",
                output: Some(vec![
                    Component::InvalidAddress(e(), "[@(c)x".into())
                ])
            },

            Test {
                input: "foo(c)[@x",
                output: Some(vec![
                    Component::InvalidAddress(e(), "foo(c)[@x".into())
                ])
            },
            Test {
                input: "foo[(c)@x",
                output: Some(vec![
                    Component::InvalidAddress(e(), "foo[(c)@x".into())
                ])
            },
            Test {
                input: "foo[@(c)x",
                output: Some(vec![
                    Component::InvalidAddress(e(), "foo[@(c)x".into())
                ])
            },

            Test {
                input: "[@x (c)",
                output: Some(vec![
                    Component::InvalidAddress(e(), "[@x (c)".into())
                ])
            },

            Test {
                input: "(c) foo[@x",
                output: Some(vec![
                    Component::InvalidAddress(e(), "(c) foo[@x".into())
                ])
            },
            Test {
                input: "foo[ (c)@x",
                output: Some(vec![
                    Component::InvalidAddress(e(), "foo[ (c)@x".into())
                ])
            },

            // @ is not a valid domain part.
            Test {
                input: "foo.bar@@dings",
                output: Some(vec![
                    Component::InvalidAddress(e(), "foo.bar@@dings".into())
                ])
            },
            Test {
                input: "foo.bar@x@dings",
                output: Some(vec![
                    Component::InvalidAddress(e(), "foo.bar@x@dings".into())
                ])
            },

            // Again, what happens with comments?
            Test {
                input: "foo.bar  (1)@@(2)dings",
                output: Some(vec![
                    Component::InvalidAddress(e(), "foo.bar  (1)@@(2)dings".into())
                ])
            },
            Test {
                input: "foo.bar  (1) @@ (2)dings",
                output: Some(vec![
                    Component::InvalidAddress(e(), "foo.bar  (1) @@ (2)dings".into())
                ])
            },

            Test {
                input: "foo.bar(1)@x@dings",
                output: Some(vec![
                    Component::InvalidAddress(e(), "foo.bar(1)@x@dings".into())
                ])
            },
            Test {
                input: "foo.bar@(1)x@dings",
                output: Some(vec![
                    Component::InvalidAddress(e(), "foo.bar@(1)x@dings".into())
                ])
            },
            Test {
                input: "foo.bar@x(1)@dings",
                output: Some(vec![
                    Component::InvalidAddress(e(), "foo.bar@x(1)@dings".into())
                ])
            },
            Test {
                input: "foo.bar@x@(1)dings",
                output: Some(vec![
                    Component::InvalidAddress(e(), "foo.bar@x@(1)dings".into())
                ])
            },
            Test {
                input: "foo.bar@x@  (1)  dings",
                output: Some(vec![
                    Component::InvalidAddress(e(), "foo.bar@x@  (1)  dings".into())
                ])
            },



            // Try some URIs for completeness.
            Test {
                input: "ssh://user:pasword@example.org/resource",
                output: Some(vec![
                    Component::InvalidAddress(
                        e(), "ssh://user:pasword@example.org/resource".into())
                ])
            },

            Test {
                input: "(not a comment)   ssh://user:pasword@example.org/resource",
                output: Some(vec![
                    Component::InvalidAddress(
                        e(), "(not a comment)   ssh://user:pasword@example.org/resource".into())
                ])
            },

            Test {
                input: "shark://grrrr/39874293847092837443987492834",
                output: Some(vec![
                    Component::InvalidAddress(
                        e(), "shark://grrrr/39874293847092837443987492834".into())
                ])
            },

            Test {
                input: "shark://bait/8uyoi3lu4hl2..dfoif983j4b@%",
                output: Some(vec![
                    Component::InvalidAddress(
                        e(), "shark://bait/8uyoi3lu4hl2..dfoif983j4b@%".into())
                ])
            },
        ][..];

        for t in tests.iter() {
            {
                c!(grammar::AddrSpecOrOtherParser::new(), Vec<Component>);
                c(t.input.to_string(), t.output.clone())
            }

            {
                c!(grammar::AngleAddrOrOtherParser::new(), Vec<Component>);
                c(format!("<{}>", t.input), t.output.clone())
            }

            {
                c!(grammar::NameAddrOrOtherParser::new(), Vec<Component>);
                c(format!("Foo Bar <{}>", t.input),
                  t.output.clone().map(|mut x| {
                      x.insert(0, Component::WS);
                      x.insert(0, Component::Text("Foo Bar".into()));
                      x
                  }))
            }
        }
    }

    // angle-addr      =       [CFWS] "<" addr-spec ">" [CFWS] / obs-angle-addr
    // addr-spec       =       local-part "@" domain
    // local-part      =       dot-atom / quoted-string / obs-local-part
    // dot-atom        =       [CFWS] dot-atom-text [CFWS]
    // dot-atom-text   =       1*atext *("." 1*atext)
    // domain          =       dot-atom / domain-literal / obs-domain
    // domain-literal  =       [CFWS] "[" *([FWS] dcontent) [FWS] "]" [CFWS]
    #[test]
    fn angle_addr_parser() {
        c!(grammar::AngleAddrParser::new(), Vec<Component>);

        c("[foo]", None);

        // Normal email addresses.
        c("<foo@bar.com>", Some(vec![Component::Address("foo@bar.com".into())]));
        c("<foo@bar>", Some(vec![Component::Address("foo@bar".into())]));
        c("<foo.bar@x>", Some(vec![Component::Address("foo.bar@x".into())]));
        c("<foo@bar>", Some(vec![Component::Address("foo@bar".into())]));

        c("<foo@@bar>", None);
        c("<f@oo@bar>", None);

        // Quote the local part.
        c("<\"foo\"@bar.com>",
          Some(vec![Component::Address("foo@bar.com".into())]));
        c("<\"f\\\"oo\"@bar.com>",
          Some(vec![Component::Address("f\"oo@bar.com".into())]));
        // The whole thing has to be quoted.
        c("<\"foo\".bar@x>", None);

        c("<foo@[bar.com]>",
          Some(vec![Component::Address("foo@[bar.com]".into())]));
        c("<foo@[bar]>",
          Some(vec![Component::Address("foo@[bar]".into())]));
        c("<foo.bar@[x]>",
          Some(vec![Component::Address("foo.bar@[x]".into())]));

        c("<foo.bar@x.>", None);

        // White space is ignored at the beginning and ending of the
        // local part, but not in the middle.
        c("<  \r\n   foo.bar@x>",
          Some(vec![
              Component::WS,
              Component::Address("foo.bar@x".into()),
          ]));
        c("<  \r\n   foo.bar \r\n @x>",
          Some(vec![
              Component::WS,
              Component::Address("foo.bar@x".into())
          ]));
        c("<  (quuz) \r\n   foo.bar@x>",
          Some(vec![
              Component::WS,
              Component::Comment("quuz".into()),
              Component::WS,
              Component::Address("foo.bar@x".into()),
          ]));
        c("<  \r\n   foo.bar \r\n @x>",
          Some(vec![
              Component::WS,
              Component::Address("foo.bar@x".into()),
          ]));
        c("<f  \r\n   oo.bar@x>", None);

        c("<foo.bar@x \r\n >",
          Some(vec![
              Component::Address("foo.bar@x".into()),
              Component::WS,
          ]));
        c("<f  \r\n   oo.bar@x \r\n y>", None);

        c("  <foo.bar@x>  ",
          Some(vec![
              Component::WS,
              Component::Address("foo.bar@x".into()),
              Component::WS,
          ]));

        // And don't forget comments...
        c("< (Hello!) foo.bar@x \r\n >",
          Some(vec![
              Component::WS,
              Component::Comment("Hello!".into()),
              Component::WS,
              Component::Address("foo.bar@x".into()),
              Component::WS,
          ]));
        // Comments in the local part are always moved left.
        c("< (Hello!) foo.bar (bye?) \r\n @x \r\n >",
          Some(vec![
              Component::WS,
              Component::Comment("Hello!".into()),
              Component::WS,
              Component::Comment("bye?".into()),
              Component::WS,
              Component::Address("foo.bar@x".into()),
              Component::WS,
          ]));
        c("< (Hello!) foo.bar@x \r\n >",
          Some(vec![
              Component::WS,
              Component::Comment("Hello!".into()),
              Component::WS,
              Component::Address("foo.bar@x".into()),
              Component::WS,
          ]));
        // Comments in the domain part are always moved right.
        c("< x@  (Hello!) foo.bar (bye?) >",
          Some(vec![
              Component::WS,
              Component::Address("x@foo.bar".into()),
              Component::WS,
              Component::Comment("Hello!".into()),
              Component::WS,
              Component::Comment("bye?".into()),
              Component::WS,
          ]));

        // Try the same with quoted strings.
        c("< (Hello!) \"f oo.bar\"@x \r\n >",
          Some(vec![
              Component::WS,
              Component::Comment("Hello!".into()),
              Component::WS,
              Component::Address("f oo.bar@x".into()),
              Component::WS,
          ]));
    }

    #[test]
    fn name_addr_parser() {
        c!(grammar::NameAddrParser::new(), Vec<Component>);

        // A name-addr doesn't match a bare email address.
        c("foo@example.org", None);

        // Tricky, tricky: the local part is the empty string.
        c("<\"\"@example.org>",
          Some(vec![ Component::Address("@example.org".into()) ]));
        c("Willi Wonka <\"\"@無.com>",
          Some(vec![ Component::Text("Willi Wonka".into()),
                     Component::WS,
                     Component::Address("@無.com".into()) ]));
    }

    #[test]
    fn name_addr_api() {
        fn c_(name: Option<&str>, comment: Option<&str>, email: Option<&str>)
        {
            eprintln!("checking: name: {:?}, comment: {:?}, email: {:?}",
                      name, comment, email);
            let na = NameAddr::new(name, comment, email).unwrap();
            assert_eq!(na.name(), name);
            assert_eq!(na.comment(), comment);
            assert_eq!(na.address(), email);
        }

        fn c(name: &str, comment: &str, email: &str)
        {
            // A name-addr requires an address.  And, it only allows a
            // comment if there is also a name.

            c_(Some(name), Some(comment), Some(email));
            // c_(None, Some(comment), Some(email));
            c_(Some(name), None, Some(email));
            // c_(Some(name), Some(comment), None);
            c_(None, None, Some(email));
            // c_(None, Some(comment), None);
            // c_(Some(name), None, None);
        }

        c("Harold Hutchins", "(artist)", "harold.hutchins@captain-underpants.com");
        c("Mr. Meaner", "(Gym Teacher)", "kenny@jerome-horwitz.k12.us");
    }

    #[test]
    fn name_addr_or_other_api() {
        fn c_(name: Option<&str>, comment: Option<&str>,
              email: Option<&str>, valid: bool)
        {
            eprintln!("checking: name: {:?}, comment: {:?}, email: {:?}",
                      name, comment, email);
            let na = NameAddrOrOther::new(name, comment, email).unwrap();
            assert_eq!(na.name(), name);
            assert_eq!(na.comment(), comment);
            if let Some(email) = email {
                if valid {
                    assert_eq!(na.address().unwrap(), email);
                    assert!(na.other().is_none());
                } else {
                    assert!(na.address().is_err());
                    assert_eq!(na.other().unwrap(), email);
                }
            }
        }

        fn c(name: &str, comment: &str, email: &str, valid: bool)
        {
            // A name-addr requires an address.  And, it only allows a
            // comment if there is also a name.

            c_(Some(name), Some(comment), Some(email), valid);
            // c_(None, Some(comment), Some(email), valid);
            c_(Some(name), None, Some(email), valid);
            // c_(Some(name), Some(comment), None, valid);
            c_(None, None, Some(email), valid);
            // c_(None, Some(comment), None, valid);
            // c_(Some(name), None, None, valid);
        }

        c("Harold Hutchins", "(artist)", "harold.hutchins@captain-underpants.com", true);
        c("Mr. Meaner", "(Gym Teacher)", "kenny@jerome-horwitz.k12.us", true);
        c("Mr. Meaner", "(Gym Teacher)", "ssh://nas.jerome-horwitz.k12.us", false);
    }

    #[test]
    fn addr_spec_api() {
        fn c(email: &str, ok: bool)
        {
            match AddrSpec::new(email) {
                Ok(ref a) if ok => assert_eq!(a.address(), email),
                Ok(ref a) if !ok =>
                    panic!("Expected parser to fail for '{:?}': got '{:?}'",
                           email, a),
                Err(ref err) if ok =>
                    panic!("Expected parser to succeed for '{:?}': {:?}",
                           email, err),
                Err(_) if !ok => (),
                _ => unreachable!(),
            }
        }

        c("example@foo.com", true);
        c("<example@foo.com>", false);
        c("example@@foo.com", false);
    }

    #[test]
    fn addr_spec_or_other_api() {
        fn c(email: &str, ok: bool)
        {
            match AddrSpecOrOther::new(email) {
                Ok(ref a) if ok => {
                    assert_eq!(a.address().unwrap(), email);
                    assert_eq!(a.other(), None);
                }
                Ok(ref a) if !ok => {
                    assert!(a.address().is_err());
                    assert_eq!(a.other(), Some(email));
                }
                Err(ref err) if ok =>
                    panic!("Expected parser to succeed for '{:?}': {:?}",
                           email, err),
                Err(_) if !ok => (),
                _ => unreachable!(),
            }
        }

        c("example@foo.com", true);
        c("<example@foo.com>", false);
        c("example@@foo.com", false);
    }

    #[test]
    fn name_escape_test() {
        fn c(raw: &str, escaped_expected: &str) {
            eprintln!("\nInput: {:?}", raw);
            eprintln!("Expecting escaped version to be: {:?}", escaped_expected);
            let escaped_got = Name::escaped(raw).expect("Parse error");
            eprintln!("             Escaped version is: {:?}", escaped_got);

            // There are often multiple ways to validly escape a name.
            // This check relies on knowing how a name is escaped.  In
            // other words: if the implementation changes and this
            // test fails, then this failure may not be indicative of
            // a bug; we may just need to adjust what this test
            // expects.
            assert_eq!(escaped_got, escaped_expected);

            // Make sure when we parse it, we get the original back.
            let lexer = lexer::Lexer::new(&escaped_got);
            let raw_got = grammar::DisplayNameParser::new()
                .parse(&escaped_got, lexer)
                .expect(&format!("Parse error: {}", escaped_got));

            eprintln!("Parsing escaped version, got: {:?}", raw_got);

            assert_eq!(raw_got, vec![ Component::Text(raw.to_string()) ]);
        }

        c("Foo Q. Bar", r#""Foo Q. Bar""#);
        c(r#""Foo Q. Bar""#, r#""\"Foo Q. Bar\"""#);
        c(r#""Foo Q Bar""#, r#""\"Foo Q Bar\"""#);
        c("Foo, the Bar", r#""Foo, the Bar""#);

        // Make sure leading and trailing spaces are quoted.
        c(" Foo Bar", r#"" Foo Bar""#);
        c("Foo Bar ", r#""Foo Bar ""#);
    }
}
