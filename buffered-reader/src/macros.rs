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
