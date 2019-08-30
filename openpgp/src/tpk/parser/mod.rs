use std::vec;

use lalrpop_util::ParseError;

use crate::{
    Error,
    packet::Tag,
};

pub mod low_level;
use low_level::{
    Lexer,
    TPKParser as TPKLowLevelParser,
    TPKParserError,
    Token,
    parse_error_downcast,
};

/// Whether a packet sequence is a valid key ring.
#[derive(Debug)]
pub enum KeyringValidity {
    /// The packet sequence is a valid key ring.
    Keyring,
    /// The packet sequence is a valid key ring prefix.
    KeyringPrefix,
    /// The packet sequence is definitely not a key ring.
    Error(failure::Error),
}

impl KeyringValidity {
    /// Returns whether the packet sequence is a valid key ring.
    ///
    /// Note: a `KeyringValidator` will only return this after
    /// `KeyringValidator::finish` has been called.
    pub fn is_keyring(&self) -> bool {
        if let KeyringValidity::Keyring = self {
            true
        } else {
            false
        }
    }

    /// Returns whether the packet sequence is a valid Keyring prefix.
    ///
    /// Note: a `KeyringValidator` will only return this before
    /// `KeyringValidator::finish` has been called.
    pub fn is_keyring_prefix(&self) -> bool {
        if let KeyringValidity::KeyringPrefix = self {
            true
        } else {
            false
        }
    }

    /// Returns whether the packet sequence is definitely not a valid
    /// key ring.
    pub fn is_err(&self) -> bool {
        if let KeyringValidity::Error(_) = self {
            true
        } else {
            false
        }
    }
}

/// Used to help validate that a packet sequence is a valid key ring.
#[derive(Debug)]
pub struct KeyringValidator {
    tokens: Vec<Token>,
    n_keys: usize,
    n_packets: usize,
    finished: bool,

    // If we know that the packet sequence is invalid.
    error: Option<TPKParserError>,
}

impl Default for KeyringValidator {
    fn default() -> Self {
        KeyringValidator::new()
    }
}

impl KeyringValidator {
    /// Instantiates a new `KeyringValidator`.
    pub fn new() -> Self {
        KeyringValidator {
            tokens: vec![],
            n_keys: 0,
            n_packets: 0,
            finished: false,
            error: None,
        }
    }

    /// Returns whether the packet sequence is a valid keyring.
    ///
    /// Note: a `KeyringValidator` will only return this after
    /// `KeyringValidator::finish` has been called.
    pub fn is_keyring(&self) -> bool {
        self.check().is_keyring()
    }

    /// Returns whether the packet sequence forms a valid keyring
    /// prefix.
    ///
    /// Note: a `KeyringValidator` will only return this before
    /// `KeyringValidator::finish` has been called.
    pub fn is_keyring_prefix(&self) -> bool {
        self.check().is_keyring_prefix()
    }

    /// Returns whether the packet sequence is definitely not a valid
    /// keyring.
    pub fn is_err(&self) -> bool {
        self.check().is_err()
    }

    /// Add the token `token` to the token stream.
    pub fn push_token(&mut self, token: Token) {
        assert!(!self.finished);

        if self.error.is_some() {
            return;
        }

        match token {
            Token::PublicKey(_) | Token::SecretKey(_) => {
                self.tokens.clear();
                self.n_keys += 1;
            },
            _ => (),
        }

        self.n_packets += 1;
        if destructures_to!(Token::Signature(None) = &token)
            && destructures_to!(Some(Token::Signature(None)) = self.tokens.last())
        {
            // Compress multiple signatures in a row.  This is
            // essential for dealing with flooded keys.
        } else {
            self.tokens.push(token);
        }
    }

    /// Add a packet of type `tag` to the token stream.
    pub fn push(&mut self, tag: Tag) {
        let token = match tag {
            Tag::PublicKey => Token::PublicKey(None),
            Tag::SecretKey => Token::SecretKey(None),
            Tag::PublicSubkey => Token::PublicSubkey(None),
            Tag::SecretSubkey => Token::SecretSubkey(None),
            Tag::UserID => Token::UserID(None),
            Tag::UserAttribute => Token::UserAttribute(None),
            Tag::Signature => Token::Signature(None),
            Tag::Trust => Token::Trust(None),
            _ => {
                // Unknown token.
                self.error = Some(TPKParserError::OpenPGP(
                    Error::MalformedMessage(
                        format!("Invalid TPK: {:?} packet (at {}) not expected",
                                tag, self.n_packets).into())));
                self.tokens.clear();
                return;
            }
        };

        self.push_token(token)
    }

    /// Note that the entire message has been seen.
    ///
    /// This function may only be called once.
    ///
    /// Once called, this function will no longer return
    /// `KeyringValidity::KeyringPrefix`.
    pub fn finish(&mut self) {
        assert!(!self.finished);
        self.finished = true;
    }

    /// Returns whether the token stream corresponds to a valid
    /// keyring.
    ///
    /// This returns a tri-state: if the packet sequence is a valid
    /// Keyring, it returns KeyringValidity::Keyring, if the packet sequence is
    /// invalid, then it returns KeyringValidity::Error.  If the packet
    /// sequence could be valid, then it returns
    /// KeyringValidity::KeyringPrefix.
    ///
    /// Note: if KeyringValidator::finish() *hasn't* been called, then
    /// this function will only ever return either
    /// KeyringValidity::KeyringPrefix or KeyringValidity::Error.  Once
    /// KeyringValidity::finish() has been called, then only
    /// KeyringValidity::Keyring or KeyringValidity::Bad will be called.
    pub fn check(&self) -> KeyringValidity {
        if let Some(ref err) = self.error {
            return KeyringValidity::Error((*err).clone().into());
        }

        let r = TPKLowLevelParser::new().parse(
            Lexer::from_tokens(&self.tokens));

        if self.finished {
            match r {
                Ok(_) => KeyringValidity::Keyring,
                Err(err) =>
                    KeyringValidity::Error(
                        TPKParserError::Parser(parse_error_downcast(err)).into()),
            }
        } else {
            match r {
                Ok(_) => KeyringValidity::KeyringPrefix,
                Err(ParseError::UnrecognizedEOF { .. }) =>
                    KeyringValidity::KeyringPrefix,
                Err(err) =>
                    KeyringValidity::Error(
                        TPKParserError::Parser(parse_error_downcast(err)).into()),
            }
        }
    }
}

/// Whether a packet sequence is a valid TPK.
#[derive(Debug)]
pub enum TPKValidity {
    /// The packet sequence is a valid TPK.
    TPK,
    /// The packet sequence is a valid TPK prefix.
    TPKPrefix,
    /// The packet sequence is definitely not a TPK.
    Error(failure::Error),
}

impl TPKValidity {
    /// Returns whether the packet sequence is a valid TPK.
    ///
    /// Note: a `TPKValidator` will only return this after
    /// `TPKValidator::finish` has been called.
    pub fn is_tpk(&self) -> bool {
        if let TPKValidity::TPK = self {
            true
        } else {
            false
        }
    }

    /// Returns whether the packet sequence is a valid TPK prefix.
    ///
    /// Note: a `TPKValidator` will only return this before
    /// `TPKValidator::finish` has been called.
    pub fn is_tpk_prefix(&self) -> bool {
        if let TPKValidity::TPKPrefix = self {
            true
        } else {
            false
        }
    }

    /// Returns whether the packet sequence is definitely not a valid
    /// TPK.
    pub fn is_err(&self) -> bool {
        if let TPKValidity::Error(_) = self {
            true
        } else {
            false
        }
    }
}

/// Used to help validate that a packet sequence is a valid TPK.
#[derive(Debug)]
pub struct TPKValidator(KeyringValidator);

impl Default for TPKValidator {
    fn default() -> Self {
        TPKValidator::new()
    }
}

impl TPKValidator {
    /// Instantiates a new `TPKValidator`.
    pub fn new() -> Self {
        TPKValidator(Default::default())
    }

    /// Returns whether the packet sequence is a valid TPK.
    ///
    /// Note: a `TPKValidator` will only return this after
    /// `TPKValidator::finish` has been called.
    pub fn is_tpk(&self) -> bool {
        self.check().is_tpk()
    }

    /// Returns whether the packet sequence forms a valid TPK
    /// prefix.
    ///
    /// Note: a `TPKValidator` will only return this before
    /// `TPKValidator::finish` has been called.
    pub fn is_tpk_prefix(&self) -> bool {
        self.check().is_tpk_prefix()
    }

    /// Returns whether the packet sequence is definitely not a valid
    /// TPK.
    pub fn is_err(&self) -> bool {
        self.check().is_err()
    }

    /// Add the token `token` to the token stream.
    pub fn push_token(&mut self, token: Token) {
        self.0.push_token(token)
    }

    /// Add a packet of type `tag` to the token stream.
    pub fn push(&mut self, tag: Tag) {
        self.0.push(tag)
    }

    /// Note that the entire message has been seen.
    ///
    /// This function may only be called once.
    ///
    /// Once called, this function will no longer return
    /// `TPKValidity::TPKPrefix`.
    pub fn finish(&mut self) {
        self.0.finish()
    }

    /// Returns whether the token stream corresponds to a valid
    /// TPK.
    ///
    /// This returns a tri-state: if the packet sequence is a valid
    /// TPK, it returns TPKValidity::TPK, if the packet sequence is
    /// invalid, then it returns TPKValidity::Error.  If the packet
    /// sequence could be valid, then it returns
    /// TPKValidity::TPKPrefix.
    ///
    /// Note: if TPKValidator::finish() *hasn't* been called, then
    /// this function will only ever return either
    /// TPKValidity::TPKPrefix or TPKValidity::Error.  Once
    /// TPKValidity::finish() has been called, then only
    /// TPKValidity::TPK or TPKValidity::Bad will be called.
    pub fn check(&self) -> TPKValidity {
        if self.0.n_keys > 1 {
            return TPKValidity::Error(Error::MalformedMessage(
                    "More than one key found, this is a keyring".into()).into());
        }

        match self.0.check() {
            KeyringValidity::Keyring => TPKValidity::TPK,
            KeyringValidity::KeyringPrefix => TPKValidity::TPKPrefix,
            KeyringValidity::Error(e) => TPKValidity::Error(e),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn tokens() {
        use crate::tpk::parser::low_level::lexer::{Token, Lexer};
        use crate::tpk::parser::low_level::lexer::Token::*;
        use crate::tpk::parser::low_level::TPKParser;

        struct TestVector<'a> {
            s: &'a [Token],
            result: bool,
        }

        let test_vectors = [
            TestVector {
                s: &[ PublicKey(None) ],
                result: true,
            },
            TestVector {
                s: &[ SecretKey(None) ],
                result: true,
            },
            TestVector {
                s: &[ PublicKey(None), Signature(None) ],
                result: true,
            },
            TestVector {
                s: &[ PublicKey(None), Signature(None), Signature(None) ],
                result: true,
            },

            TestVector {
                s: &[ PublicKey(None), Signature(None), Signature(None),
                     UserID(None) ],
                result: true,
            },
            TestVector {
                s: &[ PublicKey(None), Signature(None), Signature(None),
                     UserID(None), Signature(None) ],
                result: true,
            },
            TestVector {
                s: &[ PublicKey(None), Signature(None), Signature(None),
                     UserAttribute(None) ],
                result: true,
            },
            TestVector {
                s: &[ PublicKey(None), Signature(None), Signature(None),
                     UserAttribute(None), Signature(None) ],
                result: true,
            },
            TestVector {
                s: &[ PublicKey(None), Signature(None), Signature(None),
                     PublicSubkey(None) ],
                result: true,
            },
            TestVector {
                s: &[ PublicKey(None), Signature(None), Signature(None),
                     PublicSubkey(None), Signature(None) ],
                result: true,
            },
            TestVector {
                s: &[ PublicKey(None), Signature(None), Signature(None),
                     SecretSubkey(None) ],
                result: true,
            },
            TestVector {
                s: &[ PublicKey(None), Signature(None), Signature(None),
                     SecretSubkey(None), Signature(None) ],
                result: true,
            },

            TestVector {
                s: &[ PublicKey(None), Signature(None), Signature(None),
                      SecretSubkey(None), Signature(None),
                      SecretSubkey(None), Signature(None),
                      SecretSubkey(None), Signature(None),
                      SecretSubkey(None), Signature(None),
                      SecretSubkey(None), Signature(None),
                      UserID(None), Signature(None),
                        Signature(None), Signature(None),
                      SecretSubkey(None), Signature(None),
                      UserAttribute(None), Signature(None),
                      Signature(None), Signature(None),
                      SecretSubkey(None), Signature(None),
                      UserID(None),
                      UserAttribute(None), Signature(None),
                        Signature(None), Signature(None),
                ],
                result: true,
            },

            TestVector {
                s: &[ PublicKey(None), Signature(None), Signature(None),
                      PublicKey(None), Signature(None), Signature(None),
                ],
                result: false,
            },
            TestVector {
                s: &[ PublicKey(None), Signature(None), Signature(None),
                      SecretKey(None), Signature(None), Signature(None),
                ],
                result: false,
            },
            TestVector {
                s: &[ SecretKey(None), Signature(None), Signature(None),
                      SecretKey(None), Signature(None), Signature(None),
                ],
                result: false,
            },
            TestVector {
                s: &[ SecretKey(None), Signature(None), Signature(None),
                      PublicKey(None), Signature(None), Signature(None),
                ],
                result: false,
            },
            TestVector {
                s: &[ SecretSubkey(None), Signature(None), Signature(None),
                      PublicSubkey(None), Signature(None), Signature(None),
                ],
                result: false,
            },
        ];

        for v in test_vectors.into_iter() {
            if v.result {
                let mut l = TPKValidator::new();
                for token in v.s.into_iter() {
                    l.push_token((*token).clone());
                    assert_match!(TPKValidity::TPKPrefix = l.check());
                }

                l.finish();
                assert_match!(TPKValidity::TPK = l.check());
            }

            match TPKParser::new().parse(Lexer::from_tokens(v.s)) {
                Ok(r) => assert!(v.result, "Parsing: {:?} => {:?}", v.s, r),
                Err(e) => assert!(! v.result, "Parsing: {:?} => {:?}", v.s, e),
            }
        }
    }
}
