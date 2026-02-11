//! Various macros used in this crate.

/// A simple shortcut for ensuring a type is send and sync.
///
/// For most types just call it after defining the type:
///
/// ```ignore
/// pub struct MyStruct {}
/// assert_send_and_sync!(MyStruct);
/// ```
///
/// For types with lifetimes, use the anonymous lifetime:
///
/// ```ignore
/// pub struct WithLifetime<'a> { _p: std::marker::PhantomData<&'a ()> }
/// assert_send_and_sync!(WithLifetime<'_>);
/// ```
///
/// For a type generic over another type `W`,
/// pass the type `W` as a where clause
/// including a trait bound when needed:
///
/// ```ignore
/// pub struct MyWriter<W: std::io::Write> { _p: std::marker::PhantomData<W> }
/// assert_send_and_sync!(MyWriter<W> where W: std::io::Write);
/// ```
///
/// This will assert that `MyWriterStruct<W>` is `Send` and `Sync`
/// if `W` is `Send` and `Sync`.
///
/// You can also combine the two and be generic over multiple types.
/// Just make sure to list all the types - even those without additional
/// trait bounds:
///
/// ```ignore
/// pub struct MyWriterWithLifetime<'a, C, W: std::io::Write> {
///     _p: std::marker::PhantomData<&'a (C, W)>,
/// }
/// assert_send_and_sync!(MyWriterWithLifetime<'_, C, W> where C, W: std::io::Write);
/// ```
///
/// If you need multiple additional trait bounds on a single type
/// you can add them separated by `+` like in normal where clauses.
/// However you have to make sure they are `Identifiers` like `Write`.
/// In macro patterns `Paths` (like `std::io::Write`) may not be followed
/// by `+` characters.
// Note: We cannot test the macro in doctests, because the macro is
// not public.  We test the cases in the test module below, instead.
// If you change the examples here, propagate the changes to the
// module below.
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

#[allow(dead_code)]
pub(crate) trait Sendable : Send {}
#[allow(dead_code)]
pub(crate) trait Syncable : Sync {}

/// We cannot test the macro in doctests, because the macro is not
/// public.  We test the cases here, instead.  If you change the
/// examples here, propagate the changes to the docstring above.
#[cfg(test)]
#[allow(dead_code)]
mod test {
    /// For most types just call it after defining the type:
    pub struct MyStruct {}
    assert_send_and_sync!(MyStruct);

    /// For types with lifetimes, use the anonymous lifetime:
    pub struct WithLifetime<'a> { _p: std::marker::PhantomData<&'a ()> }
    assert_send_and_sync!(WithLifetime<'_>);

    /// For a type generic over another type `W`, pass the type `W` as
    /// a where clause including a trait bound when needed:
    pub struct MyWriter<W: std::io::Write> { _p: std::marker::PhantomData<W> }
    assert_send_and_sync!(MyWriter<W> where W: std::io::Write);

    /// This will assert that `MyWriterStruct<W>` is `Send` and `Sync`
    /// if `W` is `Send` and `Sync`.
    ///
    /// You can also combine the two and be generic over multiple
    /// types.  Just make sure to list all the types - even those
    /// without additional trait bounds:
    pub struct MyWriterWithLifetime<'a, C, W: std::io::Write> {
        _p: std::marker::PhantomData<&'a (C, W)>,
    }
    assert_send_and_sync!(MyWriterWithLifetime<'_, C, W> where C, W: std::io::Write);
}
