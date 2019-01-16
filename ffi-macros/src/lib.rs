//! Common macros for Sequoia's FFI crates.

extern crate syn;
extern crate quote;
extern crate proc_macro;
extern crate proc_macro2;

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;

use quote::{quote, ToTokens};

/// Wraps a function's body in a catch_unwind block, aborting on
/// panics.
///
/// Unwinding the stack across the FFI boundary is [undefined
/// behavior].  We therefore need to wrap every FFI function's body
/// with [catch_unwind].  This macro does that in an unobtrusive
/// manner.
///
/// [undefined behavior]: https://doc.rust-lang.org/nomicon/unwinding.html
/// [catch_unwind]: https://doc.rust-lang.org/std/panic/fn.catch_unwind.html
///
/// # Example
///
/// ```rust,ignore
/// #[ffi_catch_abort]
/// #[no_mangle]
/// pub extern "system" fn sahnetorte() {
///     assert_eq!(2 * 3, 4);  // See what happens...
/// }
/// ```
#[proc_macro_attribute]
pub fn ffi_catch_abort(_attr: TokenStream, item: TokenStream) -> TokenStream {
    // Parse tokens into a function declaration.
    let fun = syn::parse_macro_input!(item as syn::ItemFn);

    // Extract all information from the parsed function that we need
    // to compose the new function.
    let attrs = fun.attrs.iter()
        .fold(TokenStream2::new(),
              |mut acc, attr| {
                  acc.extend(attr.clone().into_token_stream());
                  acc
              });
    let vis = &fun.vis;
    let constness = &fun.constness;
    let unsafety = &fun.unsafety;
    let asyncness = &fun.asyncness;
    let abi = &fun.abi;
    let ident = &fun.ident;

    let decl = &fun.decl;
    let fn_token = &decl.fn_token;
    let fn_generics = &decl.generics;
    let fn_out = &decl.output;
    let fn_in = &decl.inputs;

    let block = &fun.block;

    // We wrap the functions body into an catch_unwind, asserting that
    // all variables captured by the closure are unwind safe.  This is
    // safe because we terminate the process on panics, therefore no
    // inconsistencies can be observed.
    let expanded = quote! {
        #attrs #vis #constness #unsafety #asyncness #abi
        #fn_token #ident #fn_generics ( #fn_in ) #fn_out
        {
            match ::std::panic::catch_unwind(
                ::std::panic::AssertUnwindSafe(|| #fn_out #block))
            {
                Ok(v) => v,
                Err(p) => {
                    unsafe {
                        ::libc::abort();
                    }
                },
            }
        }
    };

    // To debug problems with the generated code, just eprintln it:
    //
    // eprintln!("{}", expanded);

    expanded.into()
}
