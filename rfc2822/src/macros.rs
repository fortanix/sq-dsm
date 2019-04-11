// Turns an `if let` into an expression so that it is possible to do
// things like:
//
// ```rust,nocompile
// if destructures_to(Foo::Bar(_) = value)
//    || destructures_to(Foo::Bam(_) = value) { ... }
// ```
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
