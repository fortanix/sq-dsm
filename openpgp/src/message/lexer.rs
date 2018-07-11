use Error;
use Result;

use Packet;
use PacketPile;

// The type of the parser's input.
//
// The parser iterators over tuples consisting of the token's starting
// position, the token itself, and the token's ending position.
pub(crate) type LexerItem<Tok, Loc, Error>
    = ::std::result::Result<(Loc, Tok, Loc), Error>;

#[derive(Debug, Clone)]
pub enum Token {
    Literal,
    CompressedData,

    SKESK,
    PKESK,
    SEIP,

    OPS,
    SIG,

    Pop,

    // This represents the content of a container that is not parsed.
    OpaqueContent,
}

#[derive(Debug)]
pub enum LexicalError {
    // There are no lexing errors.
}

pub(crate) enum Lexer<'input> {
    Refed(Box<Iterator<Item=(usize, &'input Token)> + 'input>),
    Owned(Box<Iterator<Item=(usize, Token)> + 'input>),
}

impl<'input> Iterator for Lexer<'input> {
    type Item = LexerItem<Token, usize, LexicalError>;

    fn next(&mut self) -> Option<Self::Item> {
        let n = match self {
            Lexer::Refed(ref mut i) =>
                i.next().map(|(pos, tok)| (pos, tok.clone())),
            Lexer::Owned(ref mut i) => i.next(),
        };

        if let Some((pos, tok)) = n {
            Some(Ok((pos, tok, pos)))
        } else {
            None
        }
    }
}

impl<'input> Lexer<'input> {
    /// Uses a raw sequence of tokens as input to the parser.
    // This is only used in the test code.  It would be better to use
    // cfg(test), but then we have to do the same for the Lexer enum
    // above and then we also have to specialize Lexer::next().  This
    // is significantly less ugly.
    #[allow(unused)]
    pub(crate) fn from_tokens(raw: &'input [Token]) -> Self {
        let iter = raw.iter().enumerate();
        Lexer::Refed(Box::new(iter))
    }

    /// Uses a `PacketPile` as input to the parser.
    pub(crate) fn from_packet_pile(pp: &'input PacketPile) -> Result<Self> {
        let mut t = vec![];
        let mut last_path = vec![0];

        for (path, p) in pp.descendants().paths() {
            if last_path.len() > path.len() {
                // We popped one or more containers.
                for _ in 1..last_path.len() - path.len() + 1 {
                    t.push(Token::Pop);
                }
            }
            last_path = path;

            match p {
                Packet::Literal(_) => t.push(Token::Literal),
                Packet::CompressedData(_) => t.push(Token::CompressedData),
                Packet::SKESK(_) => t.push(Token::SKESK),
                Packet::PKESK(_) => t.push(Token::PKESK),
                Packet::SEIP(_) => t.push(Token::SEIP),
                Packet::OnePassSig(_) => t.push(Token::OPS),
                Packet::Signature(_) => t.push(Token::SIG),

                p =>
                    return Err(Error::MalformedMessage(
                        format!("Invalid OpenPGP message: \
                                 unexpected packet: {:?}",
                                p.tag()).into()).into()),
            }

            match p {
                Packet::CompressedData(_) | Packet::SEIP(_) => {
                    // If a container's content is not unpacked, then
                    // we treat the content as an opaque message.

                    if p.children.is_none() && p.body.is_some() {
                        t.push(Token::OpaqueContent);
                        t.push(Token::Pop);
                    }
                }
                _ => {}
            }
        }

        if last_path.len() > 1 {
            // We popped one or more containers.
            for _ in 1..last_path.len() {
                t.push(Token::Pop);
            }
        }

        Ok(Lexer::Owned(Box::new(t.into_iter().enumerate())))
    }
}
