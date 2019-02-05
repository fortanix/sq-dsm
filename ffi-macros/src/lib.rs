//! Common macros for Sequoia's FFI crates.

#![recursion_limit="512"]

use std::collections::HashMap;
use std::io::Write;

extern crate lazy_static;
use lazy_static::lazy_static;
extern crate nettle;
use nettle::hash::Hash;
extern crate syn;
use syn::spanned::Spanned;
extern crate quote;
extern crate proc_macro;
extern crate proc_macro2;

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;

use quote::{quote, ToTokens};

/// Transforms exported functions.
///
/// This macro is used to decorate every function exported from
/// Sequoia.  It applies the following transformations:
///
///  - [ffi_catch_abort](attr.ffi_catch_abort.html)
#[proc_macro_attribute]
pub fn extern_fn(attr: TokenStream, item: TokenStream) -> TokenStream {
    ffi_catch_abort(attr, item)
}

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

    let mut fn_params = TokenStream2::new();
    decl.paren_token.surround(&mut fn_params, |ts| decl.inputs.to_tokens(ts));

    let block = &fun.block;

    // We wrap the functions body into an catch_unwind, asserting that
    // all variables captured by the closure are unwind safe.  This is
    // safe because we terminate the process on panics, therefore no
    // inconsistencies can be observed.
    let expanded = quote! {
        #attrs #vis #constness #unsafety #asyncness #abi
        #fn_token #ident #fn_generics #fn_params #fn_out
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

/// Derives FFI functions for a wrapper type.
///
/// # Example
///
/// ```rust,ignore
/// /// Holds a fingerprint.
/// #[::ffi_wrapper_type(prefix = "pgp_",
///                      derive = "Clone, Debug, Display, PartialEq, Hash")]
/// pub struct Fingerprint(openpgp::Fingerprint);
/// ```
#[proc_macro_attribute]
pub fn ffi_wrapper_type(args: TokenStream, input: TokenStream) -> TokenStream {
    // Parse tokens into a function declaration.
    let args = syn::parse_macro_input!(args as syn::AttributeArgs);
    let st = syn::parse_macro_input!(input as syn::ItemStruct);

    let mut name = None;
    let mut prefix = None;
    let mut derive = Vec::new();

    for arg in args.iter() {
        match arg {
            syn::NestedMeta::Meta(syn::Meta::NameValue(ref mnv)) => {
                let value = match mnv.lit {
                    syn::Lit::Str(ref s) => s.value(),
                    _ => unreachable!(),
                };
                match mnv.ident.to_string().as_ref() {
                    "name" => name = Some(value),
                    "prefix" => prefix = Some(value),
                    "derive" => {
                        for ident in value.split(",").map(|d| d.trim()
                                                          .to_string()) {
                            if let Some(f) = derive_functions().get::<str>(&ident) {
                                derive.push(f);
                            } else {
                                return syn::Error::new(
                                    mnv.ident.span(),
                                    format!("unknown derive: {}", ident))
                                    .to_compile_error().into();
                            }
                        }
                    },
                    name => return
                        syn::Error::new(mnv.ident.span(),
                                        format!("unexpected parameter: {}",
                                                name))
                        .to_compile_error().into(),
                }
            },
            _ => return syn::Error::new(arg.span(),
                                        "expected key = \"value\" pair")
                .to_compile_error().into(),
        }
    }

    let wrapper = st.ident.clone();
    let name = name.unwrap_or(ident2c(&st.ident));
    let prefix = prefix.unwrap_or("".into());

    // Parse the type of the wrapped object.
    let argument_span = st.fields.span();
    let wrapped_type = match &st.fields {
        syn::Fields::Unnamed(fields) => {
            if fields.unnamed.len() != 1 {
                return
                    syn::Error::new(argument_span,
                                    "expected a single field")
                    .to_compile_error().into();
            }
            fields.unnamed.first().unwrap().value().ty.clone()
        },
        _ => return
            syn::Error::new(argument_span,
                            format!("expected tuple struct, try: {}(...)",
                                    wrapper))
            .to_compile_error().into(),
    };

    // We now assemble the derived functions.
    let mut impls = TokenStream2::new();

    // First, we derive the conversion functions.  As a side-effect,
    // this function injects fields into the struct definition.
    impls.extend(derive_conversion_functions(st, &prefix, &name, &wrapped_type));

    // Now, we derive both the default and the requested functions.
    let default_derives: &[DeriveFn] = &[
        derive_free,
    ];
    for dfn in derive.into_iter().chain(default_derives.iter()) {
        impls.extend(dfn(proc_macro2::Span::call_site(), &prefix, &name,
                         &wrapper, &wrapped_type));
    }

    impls.into()
}

/// Derives the C type from the Rust type.
fn ident2c(ident: &syn::Ident) -> String {
    let mut s = String::new();
    for (i, c) in ident.to_string().chars().enumerate() {
        if c.is_uppercase() {
            if i > 0 {
                s += "_";
            }
            s += &c.to_lowercase().to_string();
        } else {
            s += &c.to_string();
        }
    }
    s
}

#[test]
fn ident2c_tests() {
    let span = proc_macro2::Span::call_site();
    assert_eq!(&ident2c(&syn::Ident::new("Fingerprint", span)), "fingerprint");
    assert_eq!(&ident2c(&syn::Ident::new("PacketPile", span)), "packet_pile");
}

/// Describes our custom derive functions.
type DeriveFn = fn(proc_macro2::Span, &str, &str, &syn::Ident, &syn::Type)
                   -> TokenStream2;

/// Maps trait names to our generator functions.
fn derive_functions() -> &'static HashMap<&'static str, DeriveFn>
{
    lazy_static! {
        static ref MAP: HashMap<&'static str, DeriveFn> = {
            let mut h = HashMap::new();
            h.insert("Clone", derive_clone as DeriveFn);
            h.insert("PartialEq", derive_equal as DeriveFn);
            h.insert("Hash", derive_hash as DeriveFn);
            h.insert("Display", derive_to_string as DeriveFn);
            h.insert("Debug", derive_debug as DeriveFn);
            h.insert("Parse", derive_parse as DeriveFn);
            h.insert("Serialize", derive_serialize as DeriveFn);
            h
        };
    }
    &MAP
}

/// Produces a deterministic hash of the given identifier.
fn hash_ident(i: &syn::Ident) -> u64 {
    let mut hash = ::nettle::hash::Sha256::default();
    write!(hash, "{}", i).unwrap();

    let mut buf = [0; 8];
    hash.digest(&mut buf);

    buf.iter().fold(0, |acc, b| (acc << 8) + (*b as u64))
}

/// Derives type and conversion functions.
fn derive_conversion_functions(mut st: syn::ItemStruct,
                               prefix: &str, name: &str,
                               wrapped: &syn::Type)
                               -> TokenStream2
{
    let wrapper = st.ident.clone();
    let c_type_name = format!("{}{}_t", prefix, name);

    // We now inject a field into the struct definition.  This tag
    // uniquely identifies this wrapper at runtime.

    // We use a word sized unsigned type to avoid alignment issues.
    let tag_type = syn::parse_quote!(u64);

    // The value is a compile-time constant.
    let magic_value = hash_ident(&wrapper);

    // To help during debugging, we store the name of the type.
    const C_TYPE_NAME_LEN: usize = 32;
    let c_type_name_type = syn::parse_quote!([u8; #C_TYPE_NAME_LEN]);
    let mut c_type_name_padded = [0u8; C_TYPE_NAME_LEN];
    &mut c_type_name_padded[..::std::cmp::min(C_TYPE_NAME_LEN,
                                              c_type_name.as_bytes().len())]
        .copy_from_slice(c_type_name.as_bytes());
    let c_type_name_padded_literal =
        syn::parse_str::<proc_macro2::TokenStream>(
            &format!("{:?}", c_type_name_padded))
        .expect("parsing array failed");

    let ownership =
        proc_macro2::Ident::new(&format!("{}Ownership", wrapper),
                                proc_macro2::Span::call_site());

    // Inject the tag.
    let argument_span = st.fields.span();
    match &mut st.fields {
        syn::Fields::Unnamed(fields) => {
            if fields.unnamed.len() != 1 {
                return
                    syn::Error::new(argument_span,
                                    "expected a single field")
                    .to_compile_error().into();
            }
            fields.unnamed.pop();
            fields.unnamed.push(
                syn::Field {
                    attrs: vec![],
                    vis: syn::Visibility::Inherited,
                    ident: None,
                    colon_token: None,
                    ty: syn::parse_quote!(#ownership),
                }
            );
            fields.unnamed.push(
                syn::Field {
                    attrs: vec![],
                    vis: syn::Visibility::Inherited,
                    ident: None,
                    colon_token: None,
                    ty: tag_type,
                }
            );
            fields.unnamed.push(
                syn::Field {
                    attrs: vec![],
                    vis: syn::Visibility::Inherited,
                    ident: None,
                    colon_token: None,
                    ty: c_type_name_type,
                }
            );
        },
        _ => return
            syn::Error::new(argument_span,
                            format!("expected tuple struct, try: {}(...)",
                            wrapper))
            .to_compile_error().into(),
    };

    quote! {
        enum #ownership {
            Owned(#wrapped),
            Ref(*const #wrapped),
            RefMut(*mut #wrapped),
        }

        #st

        impl #wrapper {
            fn assert_tag(&self) {
                if self.1 != #magic_value {
                    if self.1 == 0x5050505050505050 {
                        panic!(
                            "FFI contract violation: \
                             Use after move or use after free detected");
                    } else {
                        panic!(
                            "FFI contract violation: Wrong parameter type: \
                             expected {}, got {}",
                            #c_type_name,
                            String::from_utf8_lossy(&self.2),
                        );
                    }
                }
            }
        }

        use MoveFromRaw;
        impl MoveFromRaw<#wrapped> for *mut #wrapper {
            fn move_from_raw(self) -> #wrapped {
                if self.is_null() {
                    panic!("FFI contract violation: Parameter is NULL");
                }
                let mut wrapper = unsafe {
                    Box::from_raw(self)
                };
                wrapper.assert_tag();
                let obj = match wrapper.0 {
                    #ownership::Owned(o) => o,
                    #ownership::Ref(r) => {
                        panic!("FFI contract violation: \
                                expected object, got reference: {:?}", r);
                    },
                    #ownership::RefMut(r) => {
                        panic!("FFI contract violation: \
                                expected object, got mutable reference: {:?}",
                               r);
                    },
                };

                // Poison the wrapper.
                unsafe {
                    // Overwrite with P.
                    memsec::memset(self as *mut u8,
                                   0x50,
                                   ::std::mem::size_of::<#wrapper>())
                };

                obj
            }
        }

        use RefRaw;
        impl RefRaw<#wrapped> for *const #wrapper {
            fn ref_raw(self) -> &'static #wrapped {
                if self.is_null() {
                    panic!("FFI contract violation: Parameter is NULL");
                }
                let wrapper = unsafe {
                    &(*self)
                };
                wrapper.assert_tag();
                match wrapper.0 {
                    #ownership::Owned(ref o) => o,
                    #ownership::Ref(r) => unsafe {
                        &*r
                    },
                    #ownership::RefMut(r) => unsafe {
                        &*r
                    },
                }
            }
        }

        use RefMutRaw;
        impl RefMutRaw<&'static mut #wrapped> for *mut #wrapper {
            fn ref_mut_raw(self) -> &'static mut #wrapped {
                if self.is_null() {
                    panic!("FFI contract violation: Parameter is NULL");
                }
                let wrapper = unsafe {
                    &mut (*self)
                };
                wrapper.assert_tag();
                match wrapper.0 {
                    #ownership::Owned(ref mut o) => o,
                    #ownership::Ref(r) => {
                        panic!("FFI contract violation: expected mutable \
                                reference, got immutable reference: {:?}", r);
                    },
                    #ownership::RefMut(r) => unsafe {
                        &mut *r
                    },
                }
            }
        }

        impl RefMutRaw<Option<&'static mut #wrapped>> for ::Maybe<#wrapper> {
            fn ref_mut_raw(self) -> Option<&'static mut #wrapped> {
                if self.is_none() {
                    return None;
                }
                let wrapper = unsafe {
                    &mut (*self.unwrap().as_ptr())
                };
                wrapper.assert_tag();
                match wrapper.0 {
                    #ownership::Owned(ref mut o) => Some(o),
                    #ownership::Ref(r) => {
                        panic!("FFI contract violation: expected mutable \
                                reference, got immutable reference: {:?}", r);
                    },
                    #ownership::RefMut(r) => unsafe {
                        Some(&mut *r)
                    },
                }
            }
        }

        impl #wrapper {
            fn wrap(obj: #ownership) -> *mut #wrapper {
                Box::into_raw(Box::new(#wrapper(obj, #magic_value,
                                                #c_type_name_padded_literal)))
            }
        }

        use MoveIntoRaw;
        impl MoveIntoRaw<*mut #wrapper> for #wrapped {
            fn move_into_raw(self) -> *mut #wrapper {
                #wrapper::wrap(#ownership::Owned(self))
            }
        }

        impl MoveIntoRaw<*mut #wrapper> for &#wrapped {
            fn move_into_raw(self) -> *mut #wrapper {
                #wrapper::wrap(#ownership::Ref(self))
            }
        }

        impl MoveIntoRaw<*mut #wrapper> for &mut #wrapped {
            fn move_into_raw(self) -> *mut #wrapper {
                #wrapper::wrap(#ownership::RefMut(self))
            }
        }

        impl MoveIntoRaw<Option<::std::ptr::NonNull<#wrapper>>>
            for Option<#wrapped>
        {
            fn move_into_raw(self) -> Option<::std::ptr::NonNull<#wrapper>> {
                self.map(|mut v| {
                    let ptr = #wrapper::wrap(#ownership::Owned(v));
                    ::std::ptr::NonNull::new(ptr).unwrap()
                })
            }
        }

        impl MoveIntoRaw<Option<::std::ptr::NonNull<#wrapper>>>
            for Option<&#wrapped>
        {
            fn move_into_raw(self) -> Option<::std::ptr::NonNull<#wrapper>> {
                self.map(|mut v| {
                    let ptr = #wrapper::wrap(#ownership::Ref(v));
                    ::std::ptr::NonNull::new(ptr).unwrap()
                })
            }
        }

        impl MoveIntoRaw<Option<::std::ptr::NonNull<#wrapper>>>
            for Option<&mut #wrapped>
        {
            fn move_into_raw(self) -> Option<::std::ptr::NonNull<#wrapper>> {
                self.map(|mut v| {
                    let ptr = #wrapper::wrap(#ownership::RefMut(v));
                    ::std::ptr::NonNull::new(ptr).unwrap()
                })
            }
        }

        use MoveResultIntoRaw;
        impl MoveResultIntoRaw<Option<::std::ptr::NonNull<#wrapper>>>
            for ::failure::Fallible<#wrapped>
        {
            fn move_into_raw(self, errp: Option<&mut *mut ::error::Error>)
                             -> Option<::std::ptr::NonNull<#wrapper>> {
                match self {
                    Ok(v) => {
                        let ptr = #wrapper::wrap(#ownership::Owned(v));
                        Some(::std::ptr::NonNull::new(ptr).unwrap())
                    },
                    Err(e) => {
                        if let Some(errp) = errp {
                            *errp = e.move_into_raw();
                        }
                        None
                    },
                }
            }
        }

        impl MoveResultIntoRaw<Option<::std::ptr::NonNull<#wrapper>>>
            for ::failure::Fallible<&#wrapped>
        {
            fn move_into_raw(self, errp: Option<&mut *mut ::error::Error>)
                             -> Option<::std::ptr::NonNull<#wrapper>> {
                match self {
                    Ok(v) => {
                        let ptr = #wrapper::wrap(#ownership::Ref(v));
                        Some(::std::ptr::NonNull::new(ptr).unwrap())
                    },
                    Err(e) => {
                        if let Some(errp) = errp {
                            *errp = e.move_into_raw();
                        }
                        None
                    },
                }
            }
        }

        impl MoveResultIntoRaw<Option<::std::ptr::NonNull<#wrapper>>>
            for ::failure::Fallible<&mut #wrapped>
        {
            fn move_into_raw(self, errp: Option<&mut *mut ::error::Error>)
                             -> Option<::std::ptr::NonNull<#wrapper>> {
                match self {
                    Ok(v) => {
                        let ptr = #wrapper::wrap(#ownership::RefMut(v));
                        Some(::std::ptr::NonNull::new(ptr).unwrap())
                    },
                    Err(e) => {
                        if let Some(errp) = errp {
                            *errp = e.move_into_raw();
                        }
                        None
                    },
                }
            }
        }
    }
}

/// Derives prefix_name_free.
fn derive_free(span: proc_macro2::Span, prefix: &str, name: &str,
               wrapper: &syn::Ident, _wrapped: &syn::Type)
               -> TokenStream2
{
    let ident = syn::Ident::new(&format!("{}{}_free", prefix, name),
                                span);
    quote! {
        /// Frees this object.
        #[::sequoia_ffi_macros::extern_fn] #[no_mangle]
        pub extern "system" fn #ident (this: Option<&mut #wrapper>) {
            if let Some(ref_) = this {
                drop((ref_ as *mut #wrapper).move_from_raw())
            }
        }
    }
}

/// Derives prefix_name_clone.
fn derive_clone(span: proc_macro2::Span, prefix: &str, name: &str,
                wrapper: &syn::Ident, _wrapped: &syn::Type)
                -> TokenStream2
{
    let ident = syn::Ident::new(&format!("{}{}_clone", prefix, name),
                                span);
    quote! {
        /// Clones this object.
        #[::sequoia_ffi_macros::extern_fn] #[no_mangle]
        pub extern "system" fn #ident (this: *const #wrapper)
                                       -> *mut #wrapper {
            this.ref_raw().clone().move_into_raw()
        }
    }
}

/// Derives prefix_name_equal.
fn derive_equal(span: proc_macro2::Span, prefix: &str, name: &str,
                wrapper: &syn::Ident, _wrapped: &syn::Type)
                -> TokenStream2
{
    let ident = syn::Ident::new(&format!("{}{}_equal", prefix, name),
                                span);
    quote! {
        /// Compares objects.
        #[::sequoia_ffi_macros::extern_fn] #[no_mangle]
        pub extern "system" fn #ident (a: *const #wrapper,
                                       b: *const #wrapper)
                                       -> bool {
            a.ref_raw() == b.ref_raw()
        }
    }
}


/// Derives prefix_name_to_string.
fn derive_to_string(span: proc_macro2::Span, prefix: &str, name: &str,
                    wrapper: &syn::Ident, _wrapped: &syn::Type)
                    -> TokenStream2
{
    let ident = syn::Ident::new(&format!("{}{}_to_string", prefix, name),
                                span);
    quote! {
        /// Returns a human readable description of this object
        /// intended for communication with end users.
        #[::sequoia_ffi_macros::extern_fn] #[no_mangle]
        pub extern "system" fn #ident (this: *const #wrapper)
                                       -> *mut ::libc::c_char {
            ffi_return_string!(format!("{}", this.ref_raw()))
        }
    }
}

/// Derives prefix_name_debug.
fn derive_debug(span: proc_macro2::Span, prefix: &str, name: &str,
                wrapper: &syn::Ident, _wrapped: &syn::Type)
                -> TokenStream2
{
    let ident = syn::Ident::new(&format!("{}{}_debug", prefix, name),
                                span);
    quote! {
        /// Returns a human readable description of this object
        /// suitable for debugging.
        #[::sequoia_ffi_macros::extern_fn] #[no_mangle]
        pub extern "system" fn #ident (this: *const #wrapper)
                                       -> *mut ::libc::c_char {
            ffi_return_string!(format!("{:?}", this.ref_raw()))
        }
    }
}

/// Derives prefix_name_hash.
fn derive_hash(span: proc_macro2::Span, prefix: &str, name: &str,
               wrapper: &syn::Ident, _wrapped: &syn::Type)
               -> TokenStream2
{
    let ident = syn::Ident::new(&format!("{}{}_hash", prefix, name),
                                span);
    quote! {
        /// Hashes this object.
        #[::sequoia_ffi_macros::extern_fn] #[no_mangle]
        pub extern "system" fn #ident (this: *const #wrapper)
                                       -> ::libc::uint64_t {
            use ::std::hash::{Hash, Hasher};

            let mut hasher = ::build_hasher();
            this.ref_raw().hash(&mut hasher);
            hasher.finish()
        }
    }
}

/// Derives prefix_name_parse_*.
fn derive_parse(span: proc_macro2::Span, prefix: &str, name: &str,
                wrapper: &syn::Ident, wrapped: &syn::Type)
                -> TokenStream2
{
    let from_reader = syn::Ident::new(&format!("{}{}_from_reader",
                                               prefix, name),
                                      span);
    let from_file = syn::Ident::new(&format!("{}{}_from_file",
                                             prefix, name),
                                    span);
    let from_bytes = syn::Ident::new(&format!("{}{}_from_bytes",
                                              prefix, name),
                                     span);
    quote! {
        /// Parses an object from the given reader.
        #[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "system"
        fn #from_reader(errp: Option<&mut *mut ::error::Error>,
                        reader: *mut Box<::std::io::Read>)
                        -> ::Maybe<#wrapper> {
            let reader = ffi_param_ref_mut!(reader);
            #wrapped::from_reader(reader).move_into_raw(errp)
        }

        /// Parses an object from the given file.
        #[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "system"
        fn #from_file(errp: Option<&mut *mut ::error::Error>,
                      filename: *const ::libc::c_char)
                      -> ::Maybe<#wrapper> {
            let filename =
                ffi_param_cstr!(filename).to_string_lossy().into_owned();
            #wrapped::from_file(&filename).move_into_raw(errp)
        }

        /// Parses an object from the given buffer.
        #[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "system"
        fn #from_bytes(errp: Option<&mut *mut ::error::Error>,
                       b: *const ::libc::uint8_t, len: ::libc::size_t)
                       -> ::Maybe<#wrapper> {
            assert!(!b.is_null());
            let buf = unsafe {
                ::std::slice::from_raw_parts(b, len as usize)
            };

            #wrapped::from_bytes(buf).move_into_raw(errp)
        }
    }
}

/// Derives prefix_name_serialize.
fn derive_serialize(span: proc_macro2::Span, prefix: &str, name: &str,
                    wrapper: &syn::Ident, _wrapped: &syn::Type)
                    -> TokenStream2
{
    let ident = syn::Ident::new(&format!("{}{}_serialize", prefix, name),
                                span);
    quote! {
        /// Serializes this object.
        #[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "system"
        fn #ident (errp: Option<&mut *mut ::error::Error>,
                   tsk: *const #wrapper,
                   writer: *mut Box<::std::io::Write>)
                   -> ::error::Status {
            let writer = ffi_param_ref_mut!(writer);
            tsk.ref_raw().serialize(writer).move_into_raw(errp)
        }
    }
}
