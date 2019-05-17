use std::cmp;

use lalrpop_util::ParseError;
use quickcheck::{Arbitrary, Gen};
use rand::Rng;
use lexer;
use grammar;
use component::{Component, components_merge};

// We put each type of token in its own struct, which contains exactly
// one element, a String (e.g., 'Foo(String)').
macro_rules! token {
    ( $name:ident, $g:ident, $arbitrary:block ) => {
        #[derive(Debug, Clone)]
        #[allow(non_camel_case_types)]
        struct $name(String);

        impl $name {
            fn to_string(self) -> String {
                self.0.to_string()
            }
        }

        impl Arbitrary for $name {
            fn arbitrary<G: Gen>(g: &mut G) -> Self {
                let $g = g;
                // eprintln!("{} -> generating...", stringify!($name));
                let r = $arbitrary;
                // eprintln!("{} <- {:?}", stringify!($name), r);
                $name(r.to_string())
            }
        }
    };
    ( $name:ident, $g:ident, $arbitrary:block, $self:ident, $shrink:block ) => {
        #[derive(Debug, Clone)]
        #[allow(non_camel_case_types)]
        struct $name(String);

        impl $name {
            fn to_string(self) -> String {
                self.0.to_string()
            }
        }

        impl Arbitrary for $name {
            fn arbitrary<G: Gen>(g: &mut G) -> Self {
                let $g = g;
                // eprintln!("{} -> generating...", stringify!($name));
                let r = $arbitrary;
                // eprintln!("{} <- {:?}", stringify!($name), r);
                $name(r.to_string())
            }

            fn shrink(&$self) -> Box<Iterator<Item=Self>> {
                $shrink
            }
        }
    };
}

trait Production {
    fn components(&self) -> Vec<Component>;
    fn input(&self) -> String;

    fn inner(&self) -> (Vec<Component>, String) {
        (self.components(), self.input())
    }

    fn to_input(&self) -> Input {
        Input::from(self.components(), self.input())
    }
}

// Input (s) and its expected parse (c).
#[derive(Debug, Clone)]
struct Input {
    c: Vec<Component>,
    s: String,
}

impl Production for Input {
    fn components(&self) -> Vec<Component> {
        self.c.clone()
    }

    fn input(&self) -> String {
        self.s.clone()
    }
}

impl Input {
    fn new() -> Self {
        Input {
            c: vec![],
            s: String::new(),
        }
    }

    fn from<S: AsRef<str>>(c: Vec<Component>, s: S) -> Self {
        Input {
            c: c,
            s: s.as_ref().to_string(),
        }
    }

    fn push<S: AsRef<str>>(&mut self, c: Component, s: S) {
        self.c.push(c);
        self.s.push_str(s.as_ref());
    }

    fn append<S: AsRef<str>>(&mut self, mut c: Vec<Component>, s: S) {
        self.c.append(&mut c);
        self.s.push_str(s.as_ref());
    }

    fn concat<P: Production>(&mut self, other: P) {
        self.c.append(&mut other.components());
        self.s.push_str(&other.input()[..]);
    }

    fn push_input<S: AsRef<str>>(&mut self, s: S) {
        self.s.push_str(s.as_ref())
    }
}

macro_rules! production {
    ( $name:ident, $g:ident, $arbitrary:block ) => {
        #[derive(Debug, Clone)]
        struct $name(Input);

        impl Production for $name {
            fn components(&self) -> Vec<Component> {
                self.0.components()
            }

            fn input(&self) -> String {
                self.0.input()
            }
        }

        impl Arbitrary for $name {
            fn arbitrary<G: Gen>(g: &mut G) -> Self {
                let $g = g;
                eprintln!("{} -> generating...", stringify!($name));
                let r = $arbitrary;
                eprintln!("{} <- {:?}", stringify!($name), r);
                $name(r)
            }
        }
    };
}

macro_rules! parser_quickcheck {
    ( $type:ident, $parser:ident ) => {
        quickcheck! {
            fn $parser(t: $type) -> bool {
                let s = t.clone().input();
                let lexer = lexer::Lexer::new(s.as_ref());

                match grammar::$parser::new().parse(lexer) {
                    Ok(components) => {
                        let got = components;
                        let expected = t.components();

                        if got == expected {
                            true
                        } else {
                            eprintln!("     Got: {:?}\nExpected: {:?}",
                                      got, expected);
                            for (i, (got, expected))
                                in got.iter().zip(expected).enumerate()
                            {
                                if *got != expected {
                                    eprintln!("First difference at offset {}: \
                                               got: {:?}; expected: {:?}",
                                              i, got, expected);
                                    break;
                                }
                            }
                            false
                        }
                    }
                    Err(err) => {
                        eprintln!("Parsing: {:?}: {:?}", t, err);
                        if let ParseError::UnrecognizedToken {
                            token: Some((start, _, end)), ..
                        } = err
                        {
                            eprintln!("Context:");
                            let chars = s.char_indices()
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
                                eprintln!("{} {}: {:?}",
                                          if i == start { "*" } else { " " },
                                          i, c);
                            }
                        }
                        false
                    },
                }
            }
        }
    };
}

// ' ' or tab.
token!(WSP, g, {
    lazy_static! {
        static ref WSP_CHARS : Vec<char> = vec![ ' ', '\t' ];
    }

    WSP_CHARS[g.gen_range(0, WSP_CHARS.len())]
});

// NO-WS-CTL = %d1-8 /          ; US-ASCII control characters
//             %d11 /    0xB    ;  that do not include the
//             %d12 /    0xC    ;  carriage return, line feed,
//             %d14-31 / 0xE-1F ;  and white space characters
//             %d127     0x7F
token!(NO_WS_CTL, g, {
    lazy_static! {
        static ref NO_WS_CTL_CHARS : Vec<char> = {
            vec![
                (0..=8u8).map(|i| i as char).collect(),
                vec![ 11 as char, 12 as char ],
                (14..=31u8).map(|i| i as char).collect(),
                vec![ 127 as char ]
            ]
                .into_iter()
                .flatten()
                .collect()
        };
    }

    NO_WS_CTL_CHARS[g.gen_range(0, NO_WS_CTL_CHARS.len())]
});

// specials        =       "(" / ")" /     ; Special characters used in
//                         "<" / ">" /     ;  other parts of the syntax
//                         "[" / "]" /
//                         ":" / ";" /
//                         "@" / "\" /
//                         "," / "." /
//                         DQUOTE
token!(Special, g, {
    lazy_static! {
        static ref SPECIAL_CHARS : Vec<char> = vec![
            '(', ')', '<', '>', '[', ']', ':', ';', '@', '\\', ',', '.', '"'
        ];
    }

    SPECIAL_CHARS[g.gen_range(0, SPECIAL_CHARS.len())]
});

// In RFC 2822, other is a single character.  But, in our
// implementation, other is a run of characters.
token!(Other, g, {
    lazy_static! {
        // There are many UTF-8 characters.  Instead of considering all,
        // we select a subset with (hopefully) representative
        // characteristics (different number of bytes) and potential edge
        // cases (symbols that could be accidentally be interpreted as
        // 'special', but aren't).
        static ref OTHER_CHARS : Vec<char> = vec![
            'a', 'z', 'A', 'Z', '1', '9', '0',
            '|', '!', '#', '$', '%', '^', '&', '*', '-', '+', '/',
            // The following unicode characters were taken from:
            // https://doc.rust-lang.org/std/primitive.char.html
            'é', 'ß', 'ℝ', '💣', '❤', '東', '京', '𝕊', '💝', 'δ',
            'Δ', '中', '越', '٣', '7', '৬', '¾', '①', 'K',
            'و', '藏', '山', 'I', 'ï', 'İ', 'i'
        ];
    }

    // Don't generate too many.  But, we need at least 1.
    (0..g.gen_range(1, 5))
        .map(|_| OTHER_CHARS[g.gen_range(0, OTHER_CHARS.len())])
        .collect::<String>()
});

// text            =       %d1-9 /         ; Characters excluding CR and LF
//                         %d11 /
//                         %d12 /
//                         %d14-127 /
//                         obs-text
//
// This is equivalent to WSP / NO_WS_CTL / specials / OTHER
token!(Text, g, {
    match g.gen_range(0, 4) {
        0 => WSP::arbitrary(g).to_string(),
        1 => NO_WS_CTL::arbitrary(g).to_string(),
        2 => Special::arbitrary(g).to_string(),
        3 => Other::arbitrary(g).to_string(),
        _ => unreachable!(),
    }
});

quickcheck! {
    fn text_roundtrip(t: Text) -> bool {
        let s = t.clone().to_string();
        let lexer = lexer::Lexer::new(s.as_ref());

        match grammar::TextParser::new().parse(lexer) {
            Ok(token) => token.to_string() == s,
            Err(err) => {
                eprintln!("Parsing: {:?}: {:?}", t, err);
                false
            },
        }
    }
}

// quoted-pair     =       ("\" text) / obs-qp
production!(QuotedPair, g, {
    let t = Text::arbitrary(g).to_string();
    Input::from(vec![ Component::Text(t.clone()) ],
                format!("\\{}", t))
});

// FWS             =       ([*WSP CRLF] 1*WSP) /   ;
//                         obs-FWS
production!(FWS, g, {
    let mut fws = String::new();

    // [*WSP CRLF]
    if let Some(wsp) = Option::<Vec<WSP>>::arbitrary(g) {
        for wsp in wsp.into_iter() {
            fws.push_str(&wsp.to_string()[..]);
        }
        // CRLF
        fws.push_str("\r\n");
    };

    // 1*WSP
    fws.push_str(&WSP::arbitrary(g).to_string());

    Input::from(vec![ Component::WS ], fws)
});

quickcheck! {
    fn fws_roundtrip(fws: FWS) -> bool {
        let s = fws.input();
        let lexer = lexer::Lexer::new(s.as_ref());

        match grammar::FWS_Parser::new().parse(lexer) {
            Ok(component) =>
                destructures_to!(Component::WS = component),
            Err(err) => {
                eprintln!("Parsing: {:?}: {:?}", fws, err);
                false
            },
        }
    }
}

// ctext           =       NO-WS-CTL /     ; Non white space controls
//                         %d33-39 /       ; The rest of the US-ASCII
//                         %d42-91 /       ;  characters not including "(",
//                         %d93-126        ;  ")", or "\"
token!(CText, g, {
    match g.gen_range(0, 3) {
        0 => NO_WS_CTL::arbitrary(g).to_string(),
        1 =>
        // Reject unallowed characters.
            loop {
                match &Special::arbitrary(g).to_string()[..] {
                    "(" | ")" | "\\" => (),
                    c => break c.to_string(),
                }
            },
        2 => Other::arbitrary(g).to_string(),
        _ => unreachable!(),
    }
});

quickcheck! {
    fn ctext_roundtrip(t: CText) -> bool {
        let s = t.clone().to_string();
        let lexer = lexer::Lexer::new(s.as_ref());

        match grammar::CTextParser::new().parse(lexer) {
            Ok(token) => token.to_string() == s,
            Err(err) => {
                eprintln!("Parsing: {:?}: {:?}", t, err);
                false
            },
        }
    }
}

// ccontent        =       ctext / quoted-pair / comment
production!(CContent, g, {
    let (productions, input) = match g.gen_range(0, 3) {
        0 => {
            let input = CText::arbitrary(g).to_string();
            (vec![ Component::Text(input.clone()) ], input)
        },
        1 => {
            let qp = QuotedPair::arbitrary(g);
            (qp.components(), qp.input())
        },
        2 => {
            let comment = NestedComment::arbitrary(g);
            (comment.components(), comment.input())
        },
        _ => unreachable!(),
    };

    Input::from(productions, input)
});

// comment         =       "(" *([FWS] ccontent) [FWS] ")"

// An NestedComment generates components with the surrounding "("
// and ")".  A Comment does not include them.
production!(NestedComment, g, {
    let mut p = Input::new();

    p.push(Component::Text("(".to_string()), "(");

    let i = g.gen_range(0, 4);
    if i == 0 {
        p.push(Component::Text("".into()), "");
    } else {
        (0..=i)
            .into_iter()
            .for_each(|_| {
                if let Some(fws) = Option::<FWS>::arbitrary(g) {
                    p.concat(fws);
                }

                p.concat(CContent::arbitrary(g));
            });
    }

    p.push(Component::Text(")".to_string()), ")");
    p
});

production!(Comment, g, {
    let nc = NestedComment::arbitrary(g);
    let (components, input) = nc.inner();

    // The leading and trailing parentheses are not returned.
    if let Some(Component::Text(s)) = components.first() {
        assert_eq!(s, "(");
    } else {
        panic!("Expected a leading (");
    }
    if let Some(Component::Text(s)) = components.last() {
        assert_eq!(s, ")");
    } else {
        panic!("Expected a trailing (");
    }
    let components = components[1..components.len() - 1].to_vec();

    // In comments, whitespace is preserved.
    let components = components
        .into_iter()
        .map(|c| if let Component::WS = c {
            Component::Text(" ".into())
        } else {
            c
        })
        .collect();

    // We should have exactly one component now, a Text
    // component.  Turn it into a comment.
    let components = components_merge(components)
        .into_iter()
        .map(|c| match c {
            Component::Text(t) => Component::Comment(t),
            _ => c,
        })
        .collect();

    Input::from(components, input)
});


quickcheck! {
    fn comment_roundtrip(t: Comment) -> bool {
        let s = t.clone().input();
        let lexer = lexer::Lexer::new(s.as_ref());

        match grammar::CommentParser::new().parse(lexer) {
            Ok(component) => {
                let got = vec![ component ];
                let expected = t.components();

                if got == expected {
                    true
                } else {
                    eprintln!("     Got: {:?}\nExpected: {:?}", got, expected);
                    false
                }
            }
            Err(err) => {
                eprintln!("Parsing: {:?}: {:?}", t, err);
                false
            },
        }
    }
}

// CFWS            =       *([FWS] comment) (([FWS] comment) / FWS)
production!(CFWS, g, {
    let mut p = Input::new();

    let i = g.gen_range(0, 4);
    (0..=i)
        .into_iter()
        .for_each(|_| {
            if bool::arbitrary(g) {
                p.concat(FWS::arbitrary(g));
            }

            p.concat(Comment::arbitrary(g));
        });

    if i == 0 || bool::arbitrary(g) {
        p.concat(FWS::arbitrary(g));
    }

    p
});

quickcheck! {
    fn cfws_roundtrip(t: CFWS) -> bool {
        let s = t.clone().input();
        let lexer = lexer::Lexer::new(s.as_ref());

        match grammar::CfwsParser::new().parse(lexer) {
            Ok(components) => {
                let got = components;
                let expected = t.components();

                if got == expected {
                    true
                } else {
                    eprintln!("     Got: {:?}\nExpected: {:?}", got, expected);
                    false
                }
            }
            Err(err) => {
                eprintln!("Parsing: {:?}: {:?}", t, err);
                false
            },
        }
    }
}

// atext           =       ALPHA / DIGIT / ; Any character except controls,
//                         "!" / "#" /     ;  SP, and specials.
//                         "$" / "%" /     ;  Used for atoms
//                         "&" / "'" /
//                         "*" / "+" /
//                         "-" / "/" /
//                         "=" / "?" /
//                         "^" / "_" /
//                         "`" / "{" /
//                         "|" / "}" /
//                         "~"
//
// As an optimization the lexer collects atexts, i.e., Token::OTHER is
// 1*atext.
token!(ATextPlus, g, {
    Other::arbitrary(g)
});

// other_or_dot : OTHER / DOT
token!(OtherOrDot, g, {
    match g.gen_range(0, 10) {
        0 => ".".to_string(),
        _ => Other::arbitrary(g).to_string(),
    }
});

// atext_dot_plus : other_or_dot+
token!(ATextDotPlus, g, {
    // The grammar requires at least one.
    let mut v = Vec::<OtherOrDot>::arbitrary(g);
    v.push(OtherOrDot::arbitrary(g));

    ATextDotPlus(v.into_iter()
                 .map(|x| x.to_string())
                 .collect())
});

// atom            =       [CFWS] 1*atext [CFWS]
//
// "Both atom and dot-atom are interpreted as a single unit, comprised
// of the string of characters that make it up.  Semantically, the
// optional comments and FWS surrounding the rest of the characters
// are not part of the atom"
production!(Atom, g, {
    let mut p = Input::new();

    if let Some(cfws) = Option::<CFWS>::arbitrary(g) {
        p.concat(cfws);
    }

    let t = ATextPlus::arbitrary(g).to_string();
    p.push(Component::Text(t.clone()), t);

    // Consider:
    //
    //   phrase          =       1*word / obs-phrase
    //   word            =       atom / quoted-string
    //
    // That is, two atoms can be next to each other, which means that
    // we can have two CFWSes next to each other:
    //
    //           phrase
    //          /      \
    //      word       word
    //     /    \     /    \
    //   atom  cfws cfws  atom
    //
    // But, that is not actually allowed...

    // if let Some(cfws) = Option::<CFWS>::arbitrary(g) {
    //     let (mut components, input) = cfws.inner();
    //     p.append(components, input);
    // }

    p
});

quickcheck! {
    fn atom_roundtrip(t: Atom) -> bool {
        let s = t.clone().input();
        let lexer = lexer::Lexer::new(s.as_ref());

        match grammar::AtomParser::new().parse(lexer) {
            Ok(components) => {
                let got = components;
                let expected = t.components();

                if got == expected {
                    true
                } else {
                    eprintln!("     Got: {:?}\nExpected: {:?}", got, expected);
                    false
                }
            }
            Err(err) => {
                eprintln!("Parsing: {:?}: {:?}", t, err);
                false
            },
        }
    }
}

// atom_prime : atext_dot_plus
production!(AtomPrime, g, {
    let t = ATextDotPlus::arbitrary(g).to_string();
    Input::from(vec![ Component::Text(t.clone()) ], t)
});

// dot-atom        =       [CFWS] dot-atom-text [CFWS]
//
// "Both atom and dot-atom are interpreted as a single unit, comprised
// of the string of characters that make it up.  Semantically, the
// optional comments and FWS surrounding the rest of the characters
// are not part of the atom"
production!(DotAtom, g, {
    let mut p = Input::new();

    if let Some(cfws) = Option::<CFWS>::arbitrary(g) {
        p.concat(cfws);
    }

    p.concat(DotAtomText::arbitrary(g));

    if let Some(cfws) = Option::<CFWS>::arbitrary(g) {
        p.concat(cfws);
    }

    p
});

parser_quickcheck!(DotAtom, DotAtomParser);

// A variant of dot_atom that places all comments to the left.
// dot_atom_left = <c1:CFWS?> <a:dot_atom_text> <c2:CFWS?>
production!(DotAtomLeft, g, {
    let mut p = Input::new();

    if let Some(cfws) = Option::<CFWS>::arbitrary(g) {
        p.concat(cfws);
    }

    let (mut production, input) = DotAtomText::arbitrary(g).inner();
    p.s.push_str(&input);

    if let Some(cfws) = Option::<CFWS>::arbitrary(g) {
        p.concat(cfws);
    }

    p.c.append(&mut production);
    p
});

// A variant of dot_atom that places all comments to the right.
// dot_atom_left = <c1:CFWS?> <a:dot_atom_text> <c2:CFWS?>
production!(DotAtomRight, g, {
    let mut p = Input::new();

    let (mut production, input) = DotAtomText::arbitrary(g).inner();
    p.c.append(&mut production);

    if let Some(cfws) = Option::<CFWS>::arbitrary(g) {
        p.concat(cfws);
    }

    p.s.push_str(&input);

    if let Some(cfws) = Option::<CFWS>::arbitrary(g) {
        p.concat(cfws);
    }

    p
});

// dot-atom-text   =       1*atext *("." 1*atext)
production!(DotAtomText, g, {
    // The grammar requires at least one ATextPlus.
    let mut v = Vec::<ATextPlus>::arbitrary(g);
    v.push(ATextPlus::arbitrary(g));

    let t = v.into_iter()
        .enumerate()
        .fold(String::new(), |mut s, (i, e)| {
            if i > 0 {
                s.push('.');
            }
            s.push_str(&e.to_string()[..]);
            s
        });
    Input::from(vec![ Component::Text(t.clone()) ], t)
});

// qtext           =       NO-WS-CTL /     ; Non white space controls
//                         %d33 /          ; The rest of the US-ASCII
//                         %d35-91 /       ;  characters not including "\"
//                         %d93-126        ;  or the quote character
token!(QText, g, {
    match g.gen_range(0, 3) {
        0 => NO_WS_CTL::arbitrary(g).to_string(),
        1 =>
        // Reject unallowed characters.
            loop {
                match &Special::arbitrary(g).to_string()[..] {
                    "\\" | "\"" => (),
                    c => break c.to_string(),
                }
            },
        2 => Other::arbitrary(g).to_string(),
        _ => unreachable!(),
    }
});

// qcontent        =       qtext / quoted-pair
production!(QContent, g, {
    match g.gen_range(0, 2) {
        0 => {
            let t = QText::arbitrary(g).to_string();
            Input::from(vec![ Component::Text(t.clone()) ], t)
        },
        1 => QuotedPair::arbitrary(g).to_input(),
        _ => unreachable!(),
    }
});

parser_quickcheck!(QContent, QContentParser);

// quoted-string   =       [CFWS]
//                         DQUOTE *([FWS] qcontent) [FWS] DQUOTE
//                         [CFWS]
fn quoted_string_arbitrary<G: Gen>(g: &mut G, cfws_left: bool,
                                   cfws_right: bool) -> Input {
    let mut input = Input::new();

    if cfws_left {
        if let Some(cfws) = Option::<CFWS>::arbitrary(g) {
            input.concat(cfws);
        }
    }

    input.push_input("\"");

    let component_count = input.c.len();
    Vec::<(Option<FWS>, QContent)>::arbitrary(g)
        .into_iter()
        .enumerate()
        .for_each(|(i, (fws, qcontent))| {
            if let Some(fws) = fws {
                if i == 0 {
                    // Leading and trailing space inside a quoted
                    // string are part of the content.
                    input.append(vec![Component::Text(" ".into())],
                                 fws.input());
                } else {
                    input.concat(fws);
                }
            }
            input.concat(qcontent);
        });

    if let Some(fws) = Option::<FWS>::arbitrary(g) {
        input.append(vec![Component::Text(" ".into())], fws.input());
    }

    if component_count == input.c.len() {
        // Empty, i.e., "".  This corresponds to a single empty text
        // component.
        input.append(vec![ Component::Text("".into()) ], "");
    }

    input.push_input("\"");

    // Consider:
    //
    //   phrase          =       1*word / obs-phrase
    //   word            =       atom / quoted-string
    //
    // That is, two quoted-strings can be next to each other, which
    // means that we can have two CFWSes next to each other:
    //
    //                    phrase
    //                   /      \
    //               word       word
    //              /    \     /    \
    //   quoted-string  cfws cfws  quoted-string
    //
    // But, that is not actually allowed...  Thus, we only generate a
    // CFWS on the right if we don't have a CFWS on the left.

    if ! cfws_left && cfws_right {
        if let Some(cfws) = Option::<CFWS>::arbitrary(g) {
            input.concat(cfws);
        }
    }

    input
}

production!(QuotedString, g, {
    quoted_string_arbitrary(g, true, true)
});

// Variant of quoted_string that moves all comments to the left.
production!(QuotedStringLeft, g, {
    quoted_string_arbitrary(g, true, false)
});

// See the phrase production for this variant of the 'quoted_string'
// production exists, and why the 'CFWS?'es are not included.
production!(QuotedStringPrime, g, {
    quoted_string_arbitrary(g, false, false)
});

// word            =       atom / quoted-string
production!(Word, g, {
    let mut input = match g.gen_range(0, 2) {
        0 => Atom::arbitrary(g).to_input(),
        1 => QuotedString::arbitrary(g).to_input(),
        _ => unreachable!(),
    };

    input.c = components_merge(input.c);
    input
});

parser_quickcheck!(Word, WordParser);

// phrase          =       1*word / obs-phrase
production!(Phrase, g, {
    let input = Word::arbitrary(g).to_input();
    // let v = Vec::<Word>::arbitrary(g).into_iter();
    let v = (0..g.gen_range(0, 4))
        .into_iter()
        .map(|_| Word::arbitrary(g));

    let mut input : Input = v
        .fold(input,
              |mut input, word| {
                  input.concat(word);
                  input
              });
    input.c = components_merge(input.c);
    input
});

parser_quickcheck!(Phrase, PhraseParser);

// name-addr       =       [display-name] angle-addr
production!(NameAddr, g, {
    let mut input = Input::new();

    if let Some(name) = Option::<DisplayName>::arbitrary(g) {
        input.concat(name.to_input());
    }

    input.concat(AngleAddr::arbitrary(g).to_input());

    input.c = components_merge(input.c);
    input
});

parser_quickcheck!(NameAddr, NameAddrParser);

// angle-addr      =       [CFWS] "<" addr-spec ">" [CFWS] / obs-angle-addr
production!(AngleAddr, g, {
    let mut input = Input::new();

    if let Some(cfws) = Option::<CFWS>::arbitrary(g) {
        input.concat(cfws.to_input());
    }

    input.push_input("<");
    input.concat(AddrSpec::arbitrary(g).to_input());
    input.push_input(">");

    if let Some(cfws) = Option::<CFWS>::arbitrary(g) {
        input.concat(cfws.to_input());
    }

    input.c = components_merge(input.c);
    input
});

parser_quickcheck!(AngleAddr, AngleAddrParser);

// display-name    =       phrase
production!(DisplayName, g, {
    let mut input = Phrase::arbitrary(g).to_input();
    input.c = components_merge(input.c);
    input
});

parser_quickcheck!(DisplayName, DisplayNameParser);

// addr-spec       =       local-part "@" domain
production!(AddrSpec, g, {
    let mut local = LocalPart::arbitrary(g).to_input();
    let l = match local.c.pop() {
        Some(Component::Text(l)) => l,
        Some(c) => panic!("Last component in a local-part must be a text, got: {:?}", c),
        None => panic!("Empty local part!"),
    };

    let mut domain = Domain::arbitrary(g).to_input();
    let d = match domain.c.remove(0) {
        Component::Text(d) => d,
        c => panic!("First component in a domain must be a text, got: {:?}", c),
    };

    let address = format!("{}@{}", l, d);

    Input::from(
        components_concat!(
            local.c, Component::Address(address.clone()), domain.c),
        format!("{}@{}", local.s, domain.s))
});

parser_quickcheck!(AddrSpec, AddrSpecParser);

// local-part      =       dot-atom / quoted-string / obs-local-part
production!(LocalPart, g, {
    let mut input = match g.gen_range(0, 2) {
        0 => DotAtomLeft::arbitrary(g).to_input(),
        1 => QuotedStringLeft::arbitrary(g).to_input(),
        _ => unreachable!(),
    };

    input.c = components_merge(input.c);
    input
});

parser_quickcheck!(LocalPart, LocalPartParser);

// domain          =       dot-atom / domain-literal / obs-domain
production!(Domain, g, {
    let mut input = match g.gen_range(0, 2) {
        0 => DotAtomRight::arbitrary(g).to_input(),
        1 => DomainLiteralRight::arbitrary(g).to_input(),
        _ => unreachable!(),
    };

    input.c = components_merge(input.c);
    input
});

parser_quickcheck!(Domain, DomainParser);

// domain-literal  =       [CFWS] "[" *([FWS] dcontent) [FWS] "]" [CFWS]
fn domain_literal_arbitrary<G: Gen>(g: &mut G, cfws_left: bool,
                                    cfws_right: bool) -> Input {
    let mut input = Input::new();

    if cfws_left {
        if let Some(cfws) = Option::<CFWS>::arbitrary(g) {
            input.concat(cfws);
        }
    }

    input.append(vec![Component::Text("[".to_string())], "[");

    Vec::<(Option<FWS>, DContent)>::arbitrary(g)
        .into_iter()
        .for_each(|(fws, dcontent)| {
            if let Some(fws) = fws {
                input.concat(fws);
            }
            input.concat(dcontent);
        });

    if let Some(fws) = Option::<FWS>::arbitrary(g) {
        input.concat(fws);
    }

    input.append(vec![Component::Text("]".to_string())], "]");

    if cfws_right {
        if let Some(cfws) = Option::<CFWS>::arbitrary(g) {
            input.concat(cfws);
        }
    }

    input.c = components_merge(input.c);
    input
}

production!(DomainLiteral, g, {
    domain_literal_arbitrary(g, true, true)
});

parser_quickcheck!(DomainLiteral, DomainLiteralParser);

production!(DomainLiteralRight, g, {
    domain_literal_arbitrary(g, false, true)
});

// dcontent        =       dtext / quoted-pair
production!(DContent, g, {
    match g.gen_range(0, 2) {
        0 => {
            let t = DText::arbitrary(g).to_string();
            Input::from(vec![ Component::Text(t.clone()) ], t)
        },
        1 => QuotedPair::arbitrary(g).to_input(),
        _ => unreachable!(),
    }
});

parser_quickcheck!(DContent, DContentParser);

// dtext           =       NO-WS-CTL /     ; Non white space controls
//                         %d33-90 /       ; The rest of the US-ASCII
//                         %d94-126        ;  characters not including "[",
//                                         ;  "]", or "\"
token!(DText, g, {
    match g.gen_range(0, 3) {
        0 => NO_WS_CTL::arbitrary(g).to_string(),
        1 =>
        // Reject unallowed characters.
            loop {
                match &Special::arbitrary(g).to_string()[..] {
                    "[" | "]" | "\\" => (),
                    c => break c.to_string(),
                }
            },
        2 => Other::arbitrary(g).to_string(),
        _ => unreachable!(),
    }
});
