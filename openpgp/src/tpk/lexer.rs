use std::fmt;

use Error;
use Packet;
use packet::Tag;
use tpk::SubkeyBinding;
use tpk::UserIDBinding;
use tpk::UserAttributeBinding;
use tpk::UnknownBinding;

// The type of the parser's input.
//
// The parser iterators over tuples consisting of the token's starting
// position, the token itself, and the token's ending position.
pub(crate) type LexerItem<Tok, Loc, Error>
    = ::std::result::Result<(Loc, Tok, Loc), Error>;

/// The components of an OpenPGP Message.
#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    /// A `PublicKey` packet.
    PublicKey(Option<Packet>),
    /// A `SecretKey` packet.
    SecretKey(Option<Packet>),

    /// A `PublicSubkey` packet.
    PublicSubkey(Option<Packet>),
    /// A `SecretSubkey` packet.
    SecretSubkey(Option<Packet>),

    /// A `UserID` packet.
    UserID(Option<Packet>),
    /// A `UserAttribute` packet.
    UserAttribute(Option<Packet>),

    /// A `Signature` packet.
    Signature(Option<Packet>),

    /// An `Unknown` packet.
    Unknown(Tag, Option<Packet>),
}

/// Internal data-structure used by the parser.
///
/// Due to the way the parser code is generated, it must be marked as
/// public.  But, since this module is not public, it will not
/// actually be exported to used of the library.
pub enum Component {
    SubkeyBinding(SubkeyBinding),
    UserIDBinding(UserIDBinding),
    UserAttributeBinding(UserAttributeBinding),
    UnknownBinding(UnknownBinding),
}

impl<'a> From<&'a Token> for Tag {
    fn from(token: &'a Token) -> Self {
        match token {
            &Token::PublicKey(_) => Tag::PublicKey,
            &Token::SecretKey(_) => Tag::SecretKey,
            &Token::PublicSubkey(_) => Tag::PublicSubkey,
            &Token::SecretSubkey(_) => Tag::SecretSubkey,
            &Token::UserID(_) => Tag::UserID,
            &Token::UserAttribute(_) => Tag::UserAttribute,
            &Token::Signature(_) => Tag::Signature,
            &Token::Unknown(tag, _) => tag,
        }
    }
}

impl From<Token> for Tag {
    fn from(token: Token) -> Self {
        (&token).into()
    }
}

impl From<Token> for Option<Packet> {
    fn from(token: Token) -> Self {
        match token {
            Token::PublicKey(p @ Some(_)) => p,
            Token::SecretKey(p @ Some(_)) => p,
            Token::PublicSubkey(p @ Some(_)) => p,
            Token::SecretSubkey(p @ Some(_)) => p,
            Token::UserID(p @ Some(_)) => p,
            Token::UserAttribute(p @ Some(_)) => p,
            Token::Signature(p @ Some(_)) => p,
            Token::Unknown(_, p @ Some(_)) => p,

            Token::PublicKey(None)
            | Token::SecretKey(None)
            | Token::PublicSubkey(None)
            | Token::SecretSubkey(None)
            | Token::UserID(None)
            | Token::UserAttribute(None)
            | Token::Signature(None)
            | Token::Unknown(_, None)
                => None,
        }
    }
}

impl From<Packet> for Option<Token> {
    fn from(p: Packet) -> Self {
        match p.tag() {
            Tag::PublicKey => Some(Token::PublicKey(Some(p))),
            Tag::SecretKey => Some(Token::SecretKey(Some(p))),
            Tag::PublicSubkey => Some(Token::PublicSubkey(Some(p))),
            Tag::SecretSubkey => Some(Token::SecretSubkey(Some(p))),
            Tag::UserID => Some(Token::UserID(Some(p))),
            Tag::UserAttribute => Some(Token::UserAttribute(Some(p))),
            Tag::Signature => Some(Token::Signature(Some(p))),
            t @ Tag::Unknown(_) => Some(Token::Unknown(t, Some(p))),
            _ => None,
        }
    }
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&format!("{:?}", self)[..])
    }
}

pub(crate) struct Lexer<'input> {
    iter: Box<Iterator<Item=(usize, &'input Token)> + 'input>,
}

impl<'input> Iterator for Lexer<'input> {
    type Item = LexerItem<Token, usize, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let n = self.iter.next().map(|(pos, tok)| (pos, tok.clone()));
        if let Some((pos, tok)) = n {
            Some(Ok((pos, tok, pos)))
        } else {
            None
        }
    }
}

impl<'input> Lexer<'input> {
    /// Uses a raw sequence of tokens as input to the parser.
    pub(crate) fn from_tokens(raw: &'input [Token]) -> Self {
        Lexer {
            iter: Box::new(raw.iter().enumerate())
        }
    }
}
