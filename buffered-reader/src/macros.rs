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
    &s[0..usize::try_from(i).unwrap_or(0).min(s.len())]
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

/// A simple shortcut for ensuring a type is send and sync.
///
/// For most types just call it after defining the type:
///
/// ```
/// pub struct MyStruct {}
/// assert_send_and_sync!(MyStruct);
/// ```
///
/// For types with lifetimes, use the anonymous lifetime:
///
/// ```
/// pub struct WithLifetime<'a> {}
/// assert_send_and_sync!(MyStruct<'_>);
/// ```
///
/// For a type generic over another type `W`,
/// pass the type `W` as a where clause
/// including a trait bound when needed:
///
/// ```
/// pub struct MyWriter<W: io::Write> {}
/// assert_send_and_sync!(MyWriterStruct<W> where W: io::Write);
/// ```
///
/// This will assert that `MyWriterStruct<W>` is `Send` and `Sync`
/// if `W` is `Send` and `Sync`.
///
/// You can also combine the two and be generic over multiple types.
/// Just make sure to list all the types - even those without additional
/// trait bounds:
///
/// ```
/// pub struct MyWriterWithLifetime<a', C, W: io::Write> {}
/// assert_send_and_sync!(MyWriterStruct<'_, C, W> where C, W: io::Write);
/// ```
///
/// If you need multiple additional trait bounds on a single type
/// you can add them separated by `+` like in normal where clauses.
/// However you have to make sure they are `Identifiers` like `Write`.
/// In macro patterns `Paths` (like `io::Write`) may not be followed
/// by `+` characters.
macro_rules! assert_send_and_sync {
    ( $x:ty where $( $g:ident$( : $a:path )? $(,)?)*) => {
        impl<$( $g ),*> crate::macros::Sendable for $x
            where $( $g: Send + Sync $( + $a )? ),*
            {}
        impl<$( $g ),*> crate::macros::Syncable for $x
            where $( $g: Send + Sync $( + $a )? ),*
            {}
    };
    ( $x:ty where $( $g:ident$( : $a:ident $( + $b:ident )* )? $(,)?)*) => {
        impl<$( $g ),*> crate::macros::Sendable for $x
            where $( $g: Send + Sync $( + $a $( + $b )* )? ),*
            {}
        impl<$( $g ),*> crate::macros::Syncable for $x
            where $( $g: Send + Sync $( + $a $( + $b )* )? ),*
            {}
    };
    ( $x:ty ) => {
        impl crate::macros::Sendable for $x {}
        impl crate::macros::Syncable for $x {}
    };
}

pub(crate) trait Sendable : Send {}
pub(crate) trait Syncable : Sync {}
