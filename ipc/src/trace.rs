use std::cmp;

macro_rules! trace {
    ( $TRACE:expr, $fmt:expr, $($pargs:expr),* ) => {
        if $TRACE {
            eprintln!($fmt, $($pargs),*);
        }
    };
    ( $TRACE:expr, $fmt:expr ) => {
        trace!($TRACE, $fmt, );
    };
}

// Converts an indentation level to whitespace.
pub(crate) fn indent(i: usize) -> &'static str {
    let s = "                                                  ";
    &s[0..cmp::min(i, s.len())]
}

// A very simply tracer.
//
// ```text
// tracer!(enable_predicate, "function_name");
// t!("(arg1: {:?}, arg2: {:?})", arg1, arg2);
// ...
// t!("=> {:?}", return_value);
// ```
macro_rules! tracer {
    ( $TRACE:expr, $func:expr ) => {
        tracer!($TRACE, $func, 0)
    };
    ( $TRACE:expr, $func:expr, $indent:expr ) => {
        // Currently, Rust doesn't support $( ... ) in a nested
        // macro's definition.  See:
        // https://users.rust-lang.org/t/nested-macros-issue/8348/2
        macro_rules! t {
            ( $fmt:expr ) =>
            { trace!($TRACE, "{}{}: {}", ::trace::indent($indent as usize), $func, $fmt) };
            ( $fmt:expr, $a:expr ) =>
            { trace!($TRACE, "{}{}: {}", ::trace::indent($indent as usize), $func, format!($fmt, $a)) };
            ( $fmt:expr, $a:expr, $b:expr ) =>
            { trace!($TRACE, "{}{}: {}", ::trace::indent($indent as usize), $func, format!($fmt, $a, $b)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr ) =>
            { trace!($TRACE, "{}{}: {}", ::trace::indent($indent as usize), $func, format!($fmt, $a, $b, $c)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr ) =>
            { trace!($TRACE, "{}{}: {}", ::trace::indent($indent as usize), $func, format!($fmt, $a, $b, $c, $d)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr ) =>
            { trace!($TRACE, "{}{}: {}", ::trace::indent($indent as usize), $func, format!($fmt, $a, $b, $c, $d, $e)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr ) =>
            { trace!($TRACE, "{}{}: {}", ::trace::indent($indent as usize), $func, format!($fmt, $a, $b, $c, $d, $e, $f)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr ) =>
            { trace!($TRACE, "{}{}: {}", ::trace::indent($indent as usize), $func, format!($fmt, $a, $b, $c, $d, $e, $f, $g)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr ) =>
            { trace!($TRACE, "{}{}: {}", ::trace::indent($indent as usize), $func, format!($fmt, $a, $b, $c, $d, $e, $f, $g, $h)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $i:expr ) =>
            { trace!($TRACE, "{}{}: {}", ::trace::indent($indent as usize), $func, format!($fmt, $a, $b, $c, $d, $e, $f, $g, $h, $i)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $i:expr, $j:expr ) =>
            { trace!($TRACE, "{}{}: {}", ::trace::indent($indent as usize), $func, format!($fmt, $a, $b, $c, $d, $e, $f, $g, $h, $i, $j)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $i:expr, $j:expr, $k:expr ) =>
            { trace!($TRACE, "{}{}: {}", ::trace::indent($indent as usize), $func, format!($fmt, $a, $b, $c, $d, $e, $f, $g, $h, $i, $j, $k)) };
        }
    };
}
