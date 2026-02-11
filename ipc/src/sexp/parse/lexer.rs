use std::cell::RefCell;
use std::fmt;
use std::rc::Rc;

// Controls tracing in the lexer.
const TRACE: bool = false;

#[derive(Debug)]
pub struct State {
    // If Some, the next N characters should be returned as a Raw
    // token.
    pub raw: Option<usize>,
}

impl State {
    pub fn new() -> Self {
        Self {
            raw: None,
        }
    }
}

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
#[allow(non_camel_case_types)]
pub enum Token<'a> {
    LPAREN,
    RPAREN,
    LBRACKET,
    RBRACKET,
    HASH,
    DASH,
    DOT,
    FORWARDSLASH,
    UNDERSCORE,
    COLON,
    STAR,
    PLUS,
    EQUAL,
    DQUOTE,

    // Whitespace.
    SPACE,
    HTAB,
    VTAB,
    CR,
    LF,
    FORMFEED,

    // Other printable.
    EXCLAMATION,
    DOLLAR,
    PERCENT,
    AMPERSAND,
    SQUOTE,
    COMMA,
    SEMICOLON,
    LT,
    GT,
    QUESTION,
    AT,
    BACKSLASH,
    CARAT,
    BACKTICK,
    LCURLY,
    PIPE,
    RCURLY,
    TILDE,

    L_A,
    L_B,
    L_C,
    L_D,
    L_E,
    L_F,
    L_G,
    L_H,
    L_I,
    L_J,
    L_K,
    L_L,
    L_M,
    L_N,
    L_O,
    L_P,
    L_Q,
    L_R,
    L_S,
    L_T,
    L_U,
    L_V,
    L_W,
    L_X,
    L_Y,
    L_Z,
    L_a,
    L_b,
    L_c,
    L_d,
    L_e,
    L_f,
    L_g,
    L_h,
    L_i,
    L_j,
    L_k,
    L_l,
    L_m,
    L_n,
    L_o,
    L_p,
    L_q,
    L_r,
    L_s,
    L_t,
    L_u,
    L_v,
    L_w,
    L_x,
    L_y,
    L_z,
    N_0,
    N_1,
    N_2,
    N_3,
    N_4,
    N_5,
    N_6,
    N_7,
    N_8,
    N_9,
    Bytes(&'a [u8]),
}

impl<'a> fmt::Display for Token<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl<'a> Token<'a> {
    pub fn as_bytes(&self) -> &'a [u8] {
        use self::Token::*;
        match self {
            LPAREN => &[ '(' as u8 ],
            RPAREN => &[ ')' as u8 ],
            LBRACKET => &[ '[' as u8 ],
            RBRACKET => &[ ']' as u8 ],
            HASH => &[ '#' as u8 ],
            DASH => &[ '-' as u8 ],
            DOT => &[ '.' as u8 ],
            FORWARDSLASH => &[ '/' as u8 ],
            UNDERSCORE => &[ '_' as u8 ],
            COLON => &[ ':' as u8 ],
            STAR => &[ '*' as u8 ],
            PLUS => &[ '+' as u8 ],
            EQUAL => &[ '=' as u8 ],
            DQUOTE => &[ '"' as u8 ],

            // Whitespace.
            SPACE => &[ ' ' as u8 ],
            HTAB => &[ '\t' as u8 ],
            VTAB => &[ 0x0b ],
            CR => &[ 0x0d ],
            LF => &[ 0x0a ],
            FORMFEED => &[ 0x0c ],

            // Other printable.
            EXCLAMATION => &[ '!' as u8 ],
            DOLLAR => &[ '$' as u8 ],
            PERCENT => &[ '%' as u8 ],
            AMPERSAND => &[ '&' as u8 ],
            SQUOTE => &[ '\'' as u8 ],
            COMMA => &[ ',' as u8 ],
            SEMICOLON => &[ ';' as u8 ],
            LT => &[ '<' as u8 ],
            GT => &[ '>' as u8 ],
            QUESTION => &[ '?' as u8 ],
            AT => &[ '@' as u8 ],
            BACKSLASH => &[ '\\' as u8 ],
            CARAT => &[ '^' as u8 ],
            BACKTICK => &[ '`' as u8 ],
            LCURLY => &[ '{' as u8 ],
            PIPE => &[ '|' as u8 ],
            RCURLY => &[ '}' as u8 ],
            TILDE => &[ '~' as u8 ],

            L_A => &[ 'A' as u8 ],
            L_B => &[ 'B' as u8 ],
            L_C => &[ 'C' as u8 ],
            L_D => &[ 'D' as u8 ],
            L_E => &[ 'E' as u8 ],
            L_F => &[ 'F' as u8 ],
            L_G => &[ 'G' as u8 ],
            L_H => &[ 'H' as u8 ],
            L_I => &[ 'I' as u8 ],
            L_J => &[ 'J' as u8 ],
            L_K => &[ 'K' as u8 ],
            L_L => &[ 'L' as u8 ],
            L_M => &[ 'M' as u8 ],
            L_N => &[ 'N' as u8 ],
            L_O => &[ 'O' as u8 ],
            L_P => &[ 'P' as u8 ],
            L_Q => &[ 'Q' as u8 ],
            L_R => &[ 'R' as u8 ],
            L_S => &[ 'S' as u8 ],
            L_T => &[ 'T' as u8 ],
            L_U => &[ 'U' as u8 ],
            L_V => &[ 'V' as u8 ],
            L_W => &[ 'W' as u8 ],
            L_X => &[ 'X' as u8 ],
            L_Y => &[ 'Y' as u8 ],
            L_Z => &[ 'Z' as u8 ],
            L_a => &[ 'a' as u8 ],
            L_b => &[ 'b' as u8 ],
            L_c => &[ 'c' as u8 ],
            L_d => &[ 'd' as u8 ],
            L_e => &[ 'e' as u8 ],
            L_f => &[ 'f' as u8 ],
            L_g => &[ 'g' as u8 ],
            L_h => &[ 'h' as u8 ],
            L_i => &[ 'i' as u8 ],
            L_j => &[ 'j' as u8 ],
            L_k => &[ 'k' as u8 ],
            L_l => &[ 'l' as u8 ],
            L_m => &[ 'm' as u8 ],
            L_n => &[ 'n' as u8 ],
            L_o => &[ 'o' as u8 ],
            L_p => &[ 'p' as u8 ],
            L_q => &[ 'q' as u8 ],
            L_r => &[ 'r' as u8 ],
            L_s => &[ 's' as u8 ],
            L_t => &[ 't' as u8 ],
            L_u => &[ 'u' as u8 ],
            L_v => &[ 'v' as u8 ],
            L_w => &[ 'w' as u8 ],
            L_x => &[ 'x' as u8 ],
            L_y => &[ 'y' as u8 ],
            L_z => &[ 'z' as u8 ],
            N_0 => &[ '0' as u8 ],
            N_1 => &[ '1' as u8 ],
            N_2 => &[ '2' as u8 ],
            N_3 => &[ '3' as u8 ],
            N_4 => &[ '4' as u8 ],
            N_5 => &[ '5' as u8 ],
            N_6 => &[ '6' as u8 ],
            N_7 => &[ '7' as u8 ],
            N_8 => &[ '8' as u8 ],
            N_9 => &[ '9' as u8 ],
            Bytes(bytes) => bytes,
        }
    }
}

#[derive(Debug)]
pub(crate) struct Lexer<'input> {
    offset: usize,
    pending: Option<Token<'input>>,
    input: &'input [u8],
    pub state: Rc<RefCell<State>>,
}

impl<'input> Lexer<'input> {
    pub fn new(input: &'input [u8]) -> Self {
        Lexer {
            offset: 0,
            pending: None,
            input,
            state: Rc::new(RefCell::new(State::new())),
        }
    }
}

impl<'input> Iterator for Lexer<'input> {
    type Item = LexerItem<Token<'input>, usize, LexicalError>;

    fn next(&mut self) -> Option<Self::Item> {
        use self::Token::*;

        tracer!(TRACE, "Lexer::next", 0);
        t!("input is {:?}", String::from_utf8_lossy(self.input));

        let len_token = if let Some(pending) = self.pending.take() {
            Ok((1, pending))
        } else if let Some(count) = self.state.borrow_mut().raw.take() {
            if self.input.len() < count {
                Err(LexicalError::TruncatedInput(
                    format!("Expected {} octets, got {}",
                            count, self.input.len())))
            } else {
                Ok((count, Bytes(&self.input[..count])))
            }
        } else {
            (|input: &'input [u8]| {
                let c = input.iter().next()?;
                match *c as char {
                    '(' => {
                        // When we see a left paren, right paren, left
                        // bracket, or right bracket, we insert a
                        // space into the stream.  This greatly
                        // simplifies the grammar: a Token has to be
                        // followed by whitespace or one of the four
                        // aforementioned tokens.  By inserting
                        // whitespace before them, we just need to
                        // check that a token is followed by
                        // whitespace.
                        self.pending = Some(LPAREN);
                        Some(Ok((0, SPACE)))
                    }
                    ')' => {
                        self.pending = Some(RPAREN);
                        Some(Ok((0, SPACE)))
                    },
                    '[' => {
                        self.pending = Some(LBRACKET);
                        Some(Ok((0, SPACE)))
                    },
                    ']' => {
                        self.pending = Some(RBRACKET);
                        Some(Ok((0, SPACE)))
                    },
                    '#' => Some(Ok((1, HASH))),
                    '-' => Some(Ok((1, DASH))),
                    '.' => Some(Ok((1, DOT))),
                    '/' => Some(Ok((1, FORWARDSLASH))),
                    '_' => Some(Ok((1, UNDERSCORE))),
                    ':' => Some(Ok((1, COLON))),
                    '*' => Some(Ok((1, STAR))),
                    '+' => Some(Ok((1, PLUS))),
                    '=' => Some(Ok((1, EQUAL))),
                    '"' => Some(Ok((1, DQUOTE))),

                    // Whitespace.
                    ' ' => Some(Ok((1, SPACE))),
                    '\t' => Some(Ok((1, HTAB))),
                    '\u{0b}' => Some(Ok((1, VTAB))),
                    '\u{0d}' => Some(Ok((1, CR))),
                    '\u{0a}' => Some(Ok((1, LF))),
                    '\u{0c}' => Some(Ok((1, FORMFEED))),

                    // Other printable.
                    '!' => Some(Ok((1, EXCLAMATION))),
                    '$' => Some(Ok((1, DOLLAR))),
                    '%' => Some(Ok((1, PERCENT))),
                    '&' => Some(Ok((1, AMPERSAND))),
                    '\'' => Some(Ok((1, SQUOTE))),
                    ',' => Some(Ok((1, COMMA))),
                    ';' => Some(Ok((1, SEMICOLON))),
                    '<' => Some(Ok((1, LT))),
                    '>' => Some(Ok((1, GT))),
                    '?' => Some(Ok((1, QUESTION))),
                    '@' => Some(Ok((1, AT))),
                    '\\' => Some(Ok((1, BACKSLASH))),
                    '^' => Some(Ok((1, CARAT))),
                    '`' => Some(Ok((1, BACKTICK))),
                    '{' => Some(Ok((1, LCURLY))),
                    '|' => Some(Ok((1, PIPE))),
                    '}' => Some(Ok((1, RCURLY))),
                    '~' => Some(Ok((1, TILDE))),

                    'A' => Some(Ok((1, L_A))),
                    'B' => Some(Ok((1, L_B))),
                    'C' => Some(Ok((1, L_C))),
                    'D' => Some(Ok((1, L_D))),
                    'E' => Some(Ok((1, L_E))),
                    'F' => Some(Ok((1, L_F))),
                    'G' => Some(Ok((1, L_G))),
                    'H' => Some(Ok((1, L_H))),
                    'I' => Some(Ok((1, L_I))),
                    'J' => Some(Ok((1, L_J))),
                    'K' => Some(Ok((1, L_K))),
                    'L' => Some(Ok((1, L_L))),
                    'M' => Some(Ok((1, L_M))),
                    'N' => Some(Ok((1, L_N))),
                    'O' => Some(Ok((1, L_O))),
                    'P' => Some(Ok((1, L_P))),
                    'Q' => Some(Ok((1, L_Q))),
                    'R' => Some(Ok((1, L_R))),
                    'S' => Some(Ok((1, L_S))),
                    'T' => Some(Ok((1, L_T))),
                    'U' => Some(Ok((1, L_U))),
                    'V' => Some(Ok((1, L_V))),
                    'W' => Some(Ok((1, L_W))),
                    'X' => Some(Ok((1, L_X))),
                    'Y' => Some(Ok((1, L_Y))),
                    'Z' => Some(Ok((1, L_Z))),
                    'a' => Some(Ok((1, L_a))),
                    'b' => Some(Ok((1, L_b))),
                    'c' => Some(Ok((1, L_c))),
                    'd' => Some(Ok((1, L_d))),
                    'e' => Some(Ok((1, L_e))),
                    'f' => Some(Ok((1, L_f))),
                    'g' => Some(Ok((1, L_g))),
                    'h' => Some(Ok((1, L_h))),
                    'i' => Some(Ok((1, L_i))),
                    'j' => Some(Ok((1, L_j))),
                    'k' => Some(Ok((1, L_k))),
                    'l' => Some(Ok((1, L_l))),
                    'm' => Some(Ok((1, L_m))),
                    'n' => Some(Ok((1, L_n))),
                    'o' => Some(Ok((1, L_o))),
                    'p' => Some(Ok((1, L_p))),
                    'q' => Some(Ok((1, L_q))),
                    'r' => Some(Ok((1, L_r))),
                    's' => Some(Ok((1, L_s))),
                    't' => Some(Ok((1, L_t))),
                    'u' => Some(Ok((1, L_u))),
                    'v' => Some(Ok((1, L_v))),
                    'w' => Some(Ok((1, L_w))),
                    'x' => Some(Ok((1, L_x))),
                    'y' => Some(Ok((1, L_y))),
                    'z' => Some(Ok((1, L_z))),
                    '0' => Some(Ok((1, N_0))),
                    '1' => Some(Ok((1, N_1))),
                    '2' => Some(Ok((1, N_2))),
                    '3' => Some(Ok((1, N_3))),
                    '4' => Some(Ok((1, N_4))),
                    '5' => Some(Ok((1, N_5))),
                    '6' => Some(Ok((1, N_6))),
                    '7' => Some(Ok((1, N_7))),
                    '8' => Some(Ok((1, N_8))),
                    '9' => Some(Ok((1, N_9))),
                    c => Some(Err(LexicalError::UnexpectedCharacter(
                        format!("Unexpected character {}", c as char)))),
                }
            })(self.input)?
        };

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
