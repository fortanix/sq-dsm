use std::cmp;

// Turns an `if let` into an expression so that it is possible to do
// things like:
//
// ```rust,nocompile
// if destructures_to(Foo::Bar(_) = value)
//    || destructures_to(Foo::Bam(_) = value) { ... }
// ```
// TODO: Replace with `std::matches!` once MSRV is bumped to 1.42.
macro_rules! destructures_to {
    ( $error: pat = $expr:expr ) => {
        {
            let x = $expr;
            if let $error = x {
                true
            } else {
                false
            }
        }
    };
}

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
pub(crate) fn indent(i: isize) -> &'static str {
    use std::convert::TryFrom;
    let s = "                                                  ";
    &s[0..cmp::min(usize::try_from(i).unwrap_or(0), s.len())]
}

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
            { trace!($TRACE, "{}{}: {}", crate::macros::indent($indent), $func, $fmt) };
            ( $fmt:expr, $a:expr ) =>
            { trace!($TRACE, "{}{}: {}", crate::macros::indent($indent), $func, format!($fmt, $a)) };
            ( $fmt:expr, $a:expr, $b:expr ) =>
            { trace!($TRACE, "{}{}: {}", crate::macros::indent($indent), $func, format!($fmt, $a, $b)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr ) =>
            { trace!($TRACE, "{}{}: {}", crate::macros::indent($indent), $func, format!($fmt, $a, $b, $c)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr ) =>
            { trace!($TRACE, "{}{}: {}", crate::macros::indent($indent), $func, format!($fmt, $a, $b, $c, $d)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr ) =>
            { trace!($TRACE, "{}{}: {}", crate::macros::indent($indent), $func, format!($fmt, $a, $b, $c, $d, $e)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr ) =>
            { trace!($TRACE, "{}{}: {}", crate::macros::indent($indent), $func, format!($fmt, $a, $b, $c, $d, $e, $f)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr ) =>
            { trace!($TRACE, "{}{}: {}", crate::macros::indent($indent), $func, format!($fmt, $a, $b, $c, $d, $e, $f, $g)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr ) =>
            { trace!($TRACE, "{}{}: {}", crate::macros::indent($indent), $func, format!($fmt, $a, $b, $c, $d, $e, $f, $g, $h)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $i:expr ) =>
            { trace!($TRACE, "{}{}: {}", crate::macros::indent($indent), $func, format!($fmt, $a, $b, $c, $d, $e, $f, $g, $h, $i)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $i:expr, $j:expr ) =>
            { trace!($TRACE, "{}{}: {}", crate::macros::indent($indent), $func, format!($fmt, $a, $b, $c, $d, $e, $f, $g, $h, $i, $j)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $i:expr, $j:expr, $k:expr ) =>
            { trace!($TRACE, "{}{}: {}", crate::macros::indent($indent), $func, format!($fmt, $a, $b, $c, $d, $e, $f, $g, $h, $i, $j, $k)) };
        }
    }
}


/// A very simple profiling tool.
///
/// Note: don't ever profile code that has not been compiled in
/// release mode.  There can be orders of magnitude difference in
/// execution time between it and debug mode!
///
/// This macro measures the wall time it takes to execute the block.
/// If the time is at least $ms_threshold (in milli-seconds), then it
/// displays the output on stderr.  The output is prefixed with label,
/// if it is provided.
///
/// ```
/// let result = time_it!("Some code", 10, {
///     // Some code.
///     5
/// });
/// assert_eq!(result, 5);
/// ```
#[allow(unused_macros)]
macro_rules! time_it {
    ( $label:expr, $ms_threshold:expr, $body:expr ) => {{
        use std::time::{SystemTime, Duration};

        // We use drop so that code that uses non-local exits (e.g.,
        // using break 'label) still works.
        struct Timer {
            start: SystemTime,
        };
        impl Drop for Timer {
            fn drop(&mut self) {
                let elapsed = self.start.elapsed();
                if elapsed.clone().unwrap_or(Duration::from_millis($ms_threshold))
                    >= Duration::from_millis($ms_threshold)
                {
                    if $label.len() > 0 {
                        eprint!("{}:", $label);
                    }
                    eprintln!("{}:{}: {:?}", file!(), line!(), elapsed);
                }
            }
        }

        let _start = Timer { start: SystemTime::now() };
        $body
    }};
    ( $label:expr, $body:expr ) => {
        time_it!($label, 0, $body)
    };
    ( $body:expr ) => {
        time_it!("", $body)
    };
}
