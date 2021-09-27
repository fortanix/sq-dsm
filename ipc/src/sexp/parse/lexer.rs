use std::fmt;

// Controls tracing in the lexer.
const TRACE: bool = false;

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum LexicalError {
    LengthOverflow(String),
    TruncatedInput(String),
    UnexpectedCharacter(String),
}

impl fmt::Display for LexicalError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub type Spanned<Token, Loc, LexicalError>
    = Result<(Loc, Token, Loc), LexicalError>;

// The type of the parser's input.
//
// The parser iterators over tuples consisting of the token's starting
// position, the token itself, and the token's ending position.
pub(crate) type LexerItem<Token, Loc, LexicalError>
    = Spanned<Token, Loc, LexicalError>;

#[derive(Debug, Clone, PartialEq)]
pub enum Token<'a> {
    LPAREN,
    RPAREN,
    LBRACKET,
    RBRACKET,
    RAW(&'a [u8]),
}

impl<'a> fmt::Display for Token<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl<'a> From<Token<'a>> for String {
    fn from(t: Token<'a>) -> String {
        use self::Token::*;
        match t {
            LPAREN => '('.to_string(),
            RPAREN => ')'.to_string(),
            LBRACKET => '['.to_string(),
            RBRACKET => ']'.to_string(),
            RAW(b) => format!("{:?}", b),
        }
    }
}

#[derive(Debug)]
pub(crate) struct Lexer<'input> {
    offset: usize,
    input: &'input [u8],
}

impl<'input> Lexer<'input> {
    pub fn new(input: &'input [u8]) -> Self {
        Lexer { offset: 0, input }
    }
}

impl<'input> Iterator for Lexer<'input> {
    type Item = LexerItem<Token<'input>, usize, LexicalError>;

    fn next(&mut self) -> Option<Self::Item> {
        use self::Token::*;

        tracer!(TRACE, "Lexer::next", 0);
        t!("input is {:?}", String::from_utf8_lossy(self.input));

        let len_token = (|input: &'input [u8]| {
            let c = input.iter().next()?;
            match *c as char {
                '(' => Some(Ok((1, LPAREN))),
                ')' => Some(Ok((1, RPAREN))),
                '[' => Some(Ok((1, LBRACKET))),
                ']' => Some(Ok((1, RBRACKET))),
                '0'..='9' => {
                    for (i, c) in input.iter().enumerate() {
                        let offset = i + 1;       // Offset in input.

                        match *c as char {
                            '0'..='9' =>
                                (), // Keep consuming all the digits.
                            ':' => {
                                let len = std::str::from_utf8(&input[..i])
                                    .expect("only contains digits");
                                if let Ok(l) = len.parse() {
                                    if input.len() - offset < l {
                                        return Some(Err(
                                            LexicalError::TruncatedInput(
                                                format!("Expected {} octets, \
                                                         got {}", l,
                                                        input.len() - offset))));
                                    }

                                    return Some(Ok((offset + l, RAW(
                                        &input[offset..offset + l]))));
                                } else {
                                    return Some(Err(LexicalError::LengthOverflow(
                                        format!("{:?} overflows usize", len))));
                                }
                            },
                            _ => return
                                Some(Err(LexicalError::UnexpectedCharacter(
                                    format!("Unexpected character {}, \
                                             got {:?} so far",
                                            *c as char, &input[..offset])))),
                        }
                    }

                    let len = String::from_utf8_lossy(&input);
                    Some(Err(LexicalError::TruncatedInput(
                        format!("Expected colon and data after {:?}", len))))
                },
                _ => Some(Err(LexicalError::UnexpectedCharacter(
                    format!("Unexpected character {}", *c as char)))),
            }
        })(&self.input)?;

        let (l, token) = match len_token {
            Ok(x) => x,
            Err(e) => return Some(Err(e)),
        };
        self.input = &self.input[l..];

        let start = self.offset;
        let end = start + l;
        self.offset += l;

        t!("Returning token at offset {}: '{:?}'",
           start, token);

        Some(Ok((start, token, end)))
    }
}

impl<'input> From<&'input [u8]> for Lexer<'input> {
    fn from(i: &'input [u8]) -> Lexer<'input> {
        Lexer::new(i)
    }
}
