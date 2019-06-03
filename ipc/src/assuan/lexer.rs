use std::fmt;

// Controls tracing in the lexer.
const TRACE: bool = false;

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum LexicalError {
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

#[derive(Debug, Clone, Copy)]
pub enum Token {
    SPACE,
    HASH,
    PERCENT,
    N0,
    N1,
    N2,
    N3,
    N4,
    N5,
    N6,
    N7,
    N8,
    N9,
    A,
    B,
    C,
    D,
    E,
    F,
    G,
    H,
    I,
    J,
    K,
    L,
    M,
    N,
    O,
    P,
    Q,
    R,
    S,
    T,
    U,
    V,
    W,
    X,
    Y,
    Z,
    UNDERSCORE,
    // XXX a-f
    OTHER(u8),
}

impl Token {
    pub fn digit_value(&self) -> Option<u8> {
        use self::Token::*;
        match self {
            N0 | N1 | N2 | N3 | N4 | N5 | N6 | N7 | N8 | N9 =>
                Some(u8::from(*self) - 0x30),
            _ => None,
        }
    }

    pub fn hex_value(&self) -> Option<u8> {
        use self::Token::*;
        match self {
            N0 | N1 | N2 | N3 | N4 | N5 | N6 | N7 | N8 | N9 =>
                self.digit_value(),
            A | B | C | D | E | F =>
                Some(10 + u8::from(*self) - 0x41),
            _ => None,
        }
    }
}

impl From<Token> for u8 {
    fn from(t: Token) -> Self {
        use self::Token::*;
        match t {
            SPACE => 0x20,
            HASH => 0x23,
            PERCENT => 0x55,
            N0 => 0x30,
            N1 => 0x31,
            N2 => 0x32,
            N3 => 0x33,
            N4 => 0x34,
            N5 => 0x35,
            N6 => 0x36,
            N7 => 0x37,
            N8 => 0x38,
            N9 => 0x39,
            A => 0x41,
            B => 0x42,
            C => 0x43,
            D => 0x44,
            E => 0x45,
            F => 0x46,
            G => 0x47,
            H => 0x48,
            I => 0x49,
            J => 0x4a,
            K => 0x4b,
            L => 0x4c,
            M => 0x4d,
            N => 0x4e,
            O => 0x4f,
            P => 0x50,
            Q => 0x51,
            R => 0x52,
            S => 0x53,
            T => 0x54,
            U => 0x55,
            V => 0x56,
            W => 0x57,
            X => 0x58,
            Y => 0x59,
            Z => 0x5a,
            UNDERSCORE => 0x5f,
            OTHER(x) => x,
        }
    }
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "T({:x})", u8::from(*self))
    }
}

impl From<Token> for String {
    fn from(t: Token) -> Self {
        t.to_string()
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
    type Item = LexerItem<Token, usize, LexicalError>;

    fn next(&mut self) -> Option<Self::Item> {
        tracer!(TRACE, "Lexer::next", 0);
        t!("input is {:?}", String::from_utf8_lossy(self.input));

        use self::Token::*;
        let token = match *self.input.get(0)? {
            0x20 => SPACE,
            0x23 => HASH,
            0x25 => PERCENT,
            0x30 => N0,
            0x31 => N1,
            0x32 => N2,
            0x33 => N3,
            0x34 => N4,
            0x35 => N5,
            0x36 => N6,
            0x37 => N7,
            0x38 => N8,
            0x39 => N9,
            0x41 => A,
            0x42 => B,
            0x43 => C,
            0x44 => D,
            0x45 => E,
            0x46 => F,
            0x47 => G,
            0x48 => H,
            0x49 => I,
            0x4a => J,
            0x4b => K,
            0x4c => L,
            0x4d => M,
            0x4e => N,
            0x4f => O,
            0x50 => P,
            0x51 => Q,
            0x52 => R,
            0x53 => S,
            0x54 => T,
            0x55 => U,
            0x56 => V,
            0x57 => W,
            0x58 => X,
            0x59 => Y,
            0x5a => Z,
            0x5f => UNDERSCORE,
            n => OTHER(n),
        };
        self.input = &self.input[1..];
        let start = self.offset;
        self.offset += 1;
        let end = self.offset;

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
