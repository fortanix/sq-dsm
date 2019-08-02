use lalrpop_util::ParseError;
use super::lexer::LexicalError;

/// A UserID value typically looks something like:
///
///    Text (Comment) <name@example.org>
///
/// That is, it contains three components: a text string, a comment,
/// and an email address.
///
/// The actual format allows for lots of interleaved comments and
/// multiple texts.  Thus, when parsing we build up a vector of
/// Components in the order that they were encountered.
#[derive(Debug, Clone)]
pub enum Component {
    // A text string.
    Text(String),
    // A comment.
    //
    // The outermost parens are removed.  That is, if the comment is:
    // "(foo(bar)bam)", then "foo(bar)bam" is stored.
    Comment(String),
    // An email address.
    Address(String),

    // The text found where an address was expected.
    InvalidAddress(ParseError<usize, String, LexicalError>, String),

    // White space.
    WS,
}

// When comparing two `Component::InvalidAddress`es, we consider them
// equal if the values match; we don't compare the saved errors.  This
// is because the parser will always generate the same error for the
// same input.  And, the PartialEq implementation is only used to
// support comparing two `Component`s in assertions.
impl PartialEq for Component {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Component::Text(a), Component::Text(b)) => a == b,
            (Component::Comment(a), Component::Comment(b)) => a == b,
            (Component::Address(a), Component::Address(b)) => a == b,
            (Component::InvalidAddress(_, a), Component::InvalidAddress(_, b)) =>
                a == b,
            (Component::WS, Component::WS) => true,
            (_, _) => false,
        }
    }
}

impl Eq for Component {
}

impl From<Component> for Vec<Component> {
    fn from(c: Component) -> Self {
        vec![c]
    }
}

impl From<Component> for Option<Vec<Component>> {
    fn from(c: Component) -> Self {
        Some(vec![c])
    }
}

// Collect the `Component`s to the vector `v`.
//
// The Components can be anything that can be turned into an
// Option<Vec<Component>>.  This currently includes `Component`, and
// `Vec<Component>`.
macro_rules! components_concat_into {
    ( $v:expr, $c:expr ) => {{
        let v: &mut Vec<Component> = $v;
        let c : Option<Vec<Component>> = $c.into();
        if let Some(mut c) = c {
            // If v ends in a WS and c starts with a WS, then collapse
            // them.
            if destructures_to!(Some(Component::WS) = v.last())
                && destructures_to!(Some(Component::WS) = c.first())
            {
                v.pop();
            }
            v.append(&mut c);
        }
    }};
    ( $v:expr, $car:expr, $($cdr:expr),* ) => {{
        let v: &mut Vec<Component> = $v;
        let car : Option<Vec<Component>> = $car.into();
        if let Some(mut car) = car {
            if destructures_to!(Some(Component::WS) = v.last())
                && destructures_to!(Some(Component::WS) = car.first())
            {
                v.pop();
            }
            v.append(&mut car)
        }
        components_concat_into!(v, $($cdr),*);
    }};
}

// Collect the `Component`s into a vector `v`.
//
// The Components can be anything that can be turned into an
// Option<Vec<Component>>.  This currently includes `Component`, and
// `Vec<Component>`.
macro_rules! components_concat {
    ( $( $args:expr ),*) => {{
        let mut v : Vec<Component> = Vec::new();
        components_concat_into!(&mut v, $($args),*);
        v
    }};
}

// Merge the components in the vector.
pub(crate) fn components_merge(components: Vec<Component>)
    -> Vec<Component>
{
    tracer!(super::TRACE, "components_merge", 0);
    t!("{:?}", components);

    let mut iter = components.into_iter();
    let mut components = vec![];

    let mut left = if let Some(left) = iter.next() {
        left
    } else {
        return components;
    };
    let mut middleo = iter.next();
    let mut righto = iter.next();

    while let Some(mut middle) = middleo {
        enum Kill {
            None,
            Middle,
            MiddleRight,
        };
        let mut kill = Kill::None;

        match (&mut left, &mut middle, righto.as_mut()) {
            (Component::Text(ref mut l),
             Component::Text(ref mut m),
             _) => {
                t!("Merging '{}' and '{}'", l, m);
                l.push_str(m);
                kill = Kill::Middle;
            },

            (Component::Text(ref mut l),
             Component::WS,
             Some(Component::Text(ref mut r))) => {
                t!("Merging '{}', WS and '{}'", l, r);
                l.push(' ');
                l.push_str(r);
                kill = Kill::MiddleRight;
            },
            (Component::WS,
             Component::WS,
             _) => {
                // This can happen when we have a local-part of the
                // following form:
                //
                //   (comment) foo (comment)
                //
                // The local-part is produced by the dot_atom_left
                // production, which puts the dot_atom_text (foo) to
                // the right:
                //
                //   COMMENT WS WS COMMENT TEXT
                //
                // It is also possible to have:
                //
                //   WS WS COMMENT TEXT
                //
                // as CFWS can expand to just a WS.
                kill = Kill::Middle;
            },
            _ => (),
        }

        match kill {
            Kill::Middle => {
                middleo = righto;
                righto = iter.next();
            }
            Kill::MiddleRight => {
                middleo = iter.next();
                righto = iter.next();
            }
            Kill::None => {
                components.push(left);
                left = middle;
                middleo = righto;
                righto = iter.next();
            }
        }
    }

    components.push(left);
    if let Some(middle) = middleo {
        components.push(middle);
    }

    components
}
