//! S-Expression support.
//!
//! This implements parsing of [S-Expressions] encoded using the
//! canonical and basic transport encoding.
//!
//! [S-Expressions]: https://people.csail.mit.edu/rivest/Sexp.txt

use std::cmp;
use std::io::Write;
use std::rc::Rc;

use openpgp::parse::buffered_reader::{self, BufferedReader};
use lalrpop_util::{lalrpop_mod, ParseError};
use sequoia_openpgp as openpgp;
use openpgp::parse::Cookie;

use openpgp::Error;
use crate::Result;
use crate::sexp::Sexp;

mod lexer;
use lexer::Lexer;

// Load the generated code.
lalrpop_mod!(
    #[allow(clippy::all)]
    #[allow(missing_docs, unused_parens)]
    grammar,
    "/sexp/parse/grammar.rs"
);

impl<'a> Sexp {
    /// Reads from the given buffered reader.
    ///
    /// Implementations of this function should be short.  Ideally,
    /// they should hand of the reader to a private function erasing
    /// the readers type by invoking [`BufferedReader::into_boxed`].
    pub fn from_buffered_reader<R>(mut reader: R) -> Result<Self>
    where
        R: BufferedReader<Cookie> + 'a,
    {
        Self::from_bytes(reader.data_eof()?)
    }


    /// Reads from the given reader.
    ///
    /// The default implementation just uses
    /// [`Parse::from_buffered_reader`], but implementations can
    /// provide their own specialized version.
    pub fn from_reader<R: 'a + std::io::Read + Send + Sync>(reader: R) -> Result<Self> {
        Self::from_buffered_reader(
            buffered_reader::Generic::with_cookie(reader,
                                                  None,
                                                  Default::default())
                .into_boxed())
    }

    /// Reads from the given file.
    ///
    /// The default implementation just uses
    /// [`Parse::from_buffered_reader`], but implementations can
    /// provide their own specialized version.
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self>
    {
        Self::from_buffered_reader(
            buffered_reader::File::with_cookie(path.as_ref(),
                                               Default::default())?
                .into_boxed())
    }

    /// Reads from the given slice.
    ///
    /// The default implementation just uses
    /// [`Parse::from_buffered_reader`], but implementations can
    /// provide their own specialized version.
    pub fn from_bytes<D: AsRef<[u8]> + ?Sized>(data: &'a D) -> Result<Sexp> {
        Self::from_bytes_private(data.as_ref())
    }
}

impl Sexp {
    fn from_bytes_private(data: &[u8]) -> Result<Sexp> {
        let lexer = Lexer::new(data);
        let state = Rc::clone(&lexer.state);

        match self::grammar::SexprParser::new().parse(&state, lexer) {
            Ok(r) => Ok(r),
            Err(err) => {
                let mut msg = Vec::new();
                writeln!(&mut msg, "Parsing: {:?}: {:?}",
                         String::from_utf8_lossy(data), err)?;
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


        // Tokens.
        assert_eq!(Sexp::from_bytes(b"(private-key)").unwrap(),
                   Sexp::List(vec![
                       Sexp::String(b"private-key"[..].into())
                   ]));
        assert_eq!(Sexp::from_bytes(b"(foo bar)").unwrap(),
                   Sexp::List(vec![
                       Sexp::String(b"foo"[..].into()),
                       Sexp::String(b"bar"[..].into()),
                   ]));
        assert_eq!(Sexp::from_bytes(b"(:foo *bar)").unwrap(),
                   Sexp::List(vec![
                       Sexp::String(b":foo"[..].into()),
                       Sexp::String(b"*bar"[..].into()),
                   ]));
        assert_eq!(Sexp::from_bytes(b"(2:hifoo)").unwrap(),
                   Sexp::List(vec![
                       Sexp::String(b"hi"[..].into()),
                       Sexp::String(b"foo"[..].into()),
                   ]));
        assert_eq!(Sexp::from_bytes(b"(2:hifoo bar)").unwrap(),
                   Sexp::List(vec![
                       Sexp::String(b"hi"[..].into()),
                       Sexp::String(b"foo"[..].into()),
                       Sexp::String(b"bar"[..].into()),
                   ]));
        // Check that a token can be followed by a [ or a ].
        assert_eq!(Sexp::from_bytes(b"(hi[fancy]ho)").unwrap(),
                   Sexp::List(vec![
                       Sexp::String(b"hi"[..].into()),
                       Sexp::String(String_::with_display_hint(
                           b"ho".to_vec(), b"fancy".to_vec())),
                   ]));
        assert_eq!(Sexp::from_bytes(b"(hi [fancy]ho)").unwrap(),
                   Sexp::List(vec![
                       Sexp::String(b"hi"[..].into()),
                       Sexp::String(String_::with_display_hint(
                           b"ho".to_vec(), b"fancy".to_vec())),
                   ]));
        assert_eq!(Sexp::from_bytes(b"(hi [fancy ]ho)").unwrap(),
                   Sexp::List(vec![
                       Sexp::String(b"hi"[..].into()),
                       Sexp::String(String_::with_display_hint(
                           b"ho".to_vec(), b"fancy".to_vec())),
                   ]));
        // Check that a token can be followed by a ( or a ).
        assert_eq!(Sexp::from_bytes(b"(hi(fancy)ho)").unwrap(),
                   Sexp::List(vec![
                       Sexp::String(b"hi"[..].into()),
                       Sexp::List(vec![
                           Sexp::String(b"fancy"[..].into()),
                       ]),
                       Sexp::String(b"ho"[..].into()),
                   ]));
        // No space between two quoted strings => two tokens.
        assert_eq!(Sexp::from_bytes(b"(\"hi \"\" ho\")").unwrap(),
                   Sexp::List(vec![
                       Sexp::String(b"hi "[..].into()),
                       Sexp::String(b" ho"[..].into()),
                   ]));
        assert_eq!(Sexp::from_bytes(b"(\"hi \"  \" ho\")").unwrap(),
                   Sexp::List(vec![
                       Sexp::String(b"hi "[..].into()),
                       Sexp::String(b" ho"[..].into()),
                   ]));
        // Quoted strings with escape sequences.
        assert_eq!(Sexp::from_bytes(b"(\"\\?\")").unwrap(),
                   Sexp::List(vec![
                       Sexp::String(b"?"[..].into()),
                   ]));
        // Quoted strings with escape sequences including hexadecimal.
        assert_eq!(Sexp::from_bytes(b"(\"\\?\\\\\\x24\\x58\")").unwrap(),
                   Sexp::List(vec![
                       Sexp::String(b"?\\$X"[..].into()),
                   ]));
        // Quoted strings with octal escape sequences.
        assert_eq!(Sexp::from_bytes(b"(\"foo  \\066\\122  bar\")").unwrap(),
                   Sexp::List(vec![
                       Sexp::String(b"foo  6R  bar"[..].into()),
                   ]));
        // Ignore newlines.
        assert_eq!(Sexp::from_bytes(b"(\"foo  \\\n\r  bar\")").unwrap(),
                   Sexp::List(vec![
                       Sexp::String(b"foo    bar"[..].into()),
                   ]));
        // Hexadecimal and quoted strings.
        assert_eq!(Sexp::from_bytes(b"(#2458# \" ho\")").unwrap(),
                   Sexp::List(vec![
                       Sexp::String(b"$X"[..].into()),
                       Sexp::String(b" ho"[..].into()),
                   ]));
        // Hexadecimal with spaces and quoted strings.
        assert_eq!(Sexp::from_bytes(b"(#245 8# \" ho\")").unwrap(),
                   Sexp::List(vec![
                       Sexp::String(b"$X"[..].into()),
                       Sexp::String(b" ho"[..].into()),
                   ]));
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

    /// Demonstrates a crash in the lexer.
    #[test]
    fn issue_742() {
        Sexp::from_bytes(b"7").unwrap_err();
    }
}
