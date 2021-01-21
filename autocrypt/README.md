This crate deals with Autocrypt encoded data (see the [Autocrypt
Spec]).

  [Autocrypt Spec]: https://autocrypt.org/level1.html#openpgp-based-key-data

# Scope

This implements low-level functionality like encoding and decoding of
Autocrypt headers and setup messages.  Note: Autocrypt is more than
just headers; it requires tight integration with the MUA.
