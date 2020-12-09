//! S-Expression support.
//!
//! This implements parsing of [S-Expressions] encoded using the
//! canonical and basic transport encoding.
//!
//! [S-Expressions]: https://people.csail.mit.edu/rivest/Sexp.txt

use std::cmp;
use std::io::{Read, Write};
use std::path::Path;

use buffered_reader::{self, BufferedReader};
use lalrpop_util::{lalrpop_mod, ParseError};
use sequoia_openpgp as openpgp;
use openpgp::parse::Parse;

use openpgp::Error;
use crate::Result;
use crate::sexp::Sexp;

mod lexer;
use self::lexer::Lexer;

// Load the generated code.
lalrpop_mod!(
    #[allow(clippy::all)]
    #[allow(missing_docs, unused_parens)]
    grammar,
    "/sexp/parse/grammar.rs"
);

impl<'a> Parse<'a, Sexp> for Sexp {
    fn from_reader<R: 'a + Read + Send + Sync>(reader: R) -> Result<Sexp> {
        Self::from_bytes(
            buffered_reader::Generic::new(reader, None).data_eof()?)
    }

    fn from_file<P: AsRef<Path>>(path: P) -> Result<Sexp> {
        Self::from_bytes(
            buffered_reader::File::open(path)?.data_eof()?)
    }

    fn from_bytes<D: AsRef<[u8]> + ?Sized>(data: &'a D) -> Result<Sexp> {
        Self::from_bytes_private(data.as_ref())
    }
}

impl Sexp {
    fn from_bytes_private(data: &[u8]) -> Result<Sexp> {
        match self::grammar::SexprParser::new().parse(Lexer::new(data)) {
            Ok(r) => Ok(r),
            Err(err) => {
                let mut msg = Vec::new();
                writeln!(&mut msg, "Parsing: {:?}: {:?}", data, err)?;
                if let ParseError::UnrecognizedToken {
                            token: (start, _, end), ..
                        } = err
                        {
                            writeln!(&mut msg, "Context:")?;
                            let chars = data.iter().enumerate()
                                .filter_map(|(i, c)| {
                                    if cmp::max(8, start) - 8 <= i
                                        && i <= end + 8
                                    {
                                        Some((i, c))
                                    } else {
                                        None
                                    }
                                });
                            for (i, c) in chars {
                                writeln!(&mut msg, "{} {} {}: {:?}",
                                         if i == start { "*" } else { " " },
                                         i,
                                         *c as char,
                                         c)?;
                            }
                        }
                Err(Error::InvalidArgument(String::from_utf8_lossy(&msg)
                                           .to_string()).into())
            },
        }
    }
}


#[cfg(test)]
mod tests {
    use crate::sexp::{Sexp, String_};
    use sequoia_openpgp::parse::Parse;

    #[test]
    fn basics() {
        assert_eq!(Sexp::from_bytes(b"()").unwrap(),
                   Sexp::List(vec![]));
        assert_eq!(Sexp::from_bytes(b"2:hi").unwrap(),
                   Sexp::String(b"hi"[..].into()));
        assert_eq!(Sexp::from_bytes(b"[5:fancy]2:hi").unwrap(),
                   Sexp::String(String_::with_display_hint(
                       b"hi".to_vec(), b"fancy".to_vec())));
        assert_eq!(Sexp::from_bytes(b"(2:hi2:ho)").unwrap(),
                   Sexp::List(vec![
                       Sexp::String(b"hi"[..].into()),
                       Sexp::String(b"ho"[..].into()),
                   ]));
        assert_eq!(Sexp::from_bytes(b"(2:hi[5:fancy]2:ho)").unwrap(),
                   Sexp::List(vec![
                       Sexp::String(b"hi"[..].into()),
                       Sexp::String(String_::with_display_hint(
                           b"ho".to_vec(), b"fancy".to_vec())),
                   ]));
        assert_eq!(Sexp::from_bytes(b"(2:hi(2:ha2:ho))").unwrap(),
                   Sexp::List(vec![
                       Sexp::String(b"hi"[..].into()),
                       Sexp::List(vec![
                           Sexp::String(b"ha"[..].into()),
                           Sexp::String(b"ho"[..].into()),
                       ]),
                   ]));
        assert_eq!(Sexp::from_bytes(b"(7:sig-val(3:rsa(1:s3:abc)))").unwrap(),
                   Sexp::List(vec![
                       Sexp::String(b"sig-val"[..].into()),
                       Sexp::List(vec![
                           Sexp::String(b"rsa"[..].into()),
                           Sexp::List(vec![
                               Sexp::String(b"s"[..].into()),
                               Sexp::String(b"abc"[..].into()),
                           ]),
                       ]),
                   ]));

        assert!(Sexp::from_bytes(b"").is_err());
        assert!(Sexp::from_bytes(b"(").is_err());
        assert!(Sexp::from_bytes(b"(2:hi").is_err());
        assert!(Sexp::from_bytes(b"(2:hi)(2:hi)").is_err());
        assert!(Sexp::from_bytes(b"([2:hi])").is_err());
    }

    #[test]
    fn signatures() {
        assert!(Sexp::from_bytes(
            crate::tests::file("sexp/dsa-signature.sexp")).is_ok());
        assert!(Sexp::from_bytes(
            crate::tests::file("sexp/ecdsa-signature.sexp")).is_ok());
        assert!(Sexp::from_bytes(
            crate::tests::file("sexp/eddsa-signature.sexp")).is_ok());
        assert!(Sexp::from_bytes(
            crate::tests::file("sexp/rsa-signature.sexp")).is_ok());
    }
}
