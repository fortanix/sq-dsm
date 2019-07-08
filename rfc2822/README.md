An [RFC 2822] parser.

  [RFC 2822]: https://tools.ietf.org/html/rfc2822

Currently, this crate only recognizes the [RFC 2822] [name-addr] and
[addr-spec] productions, i.e., things of the form:

  [name-addr]: https://tools.ietf.org/html/rfc2822#section-3.4
  [addr-spec]: https://tools.ietf.org/html/rfc2822#section-3.4.1

```
Name (Comment) <email@example.org>
```

and

```
email@example.org
```

Although the above appear simple to parse, [RFC 2822]'s whitespace and
comment rules are rather complex.  This crate implements the whole
grammar.

As an extension, in addition to ASCII, we also recognize all UTF-8
code points.  NUL, controls, and specials retain their meaning as
defined in RFC 2822.  Other UTF-8 code points are considered to be
text like `a`.

Further, we also allow dots (`.`) and at symbols (`@`) in the `atom`
production.  That is, the `atom` production is extended from:

```
atom            =       [CFWS] 1*atext [CFWS]
```

to:

```
atom               =       [CFWS] 1*atext_or_dot_or_at [CFWS]
atext_or_dot_or_at =       atext | DOT | AT
```

And, as such:

```
Professor Pippy P. Poopypants <pippy@jerome-horwitz.k12.oh.us>
```

is recognized as a `name-addr` even though [RFC 2822] strictly
requires that the `display-name` be quoted like:

```
"Professor Pippy P. Poopypants" <pippy@jerome-horwitz.k12.oh.us>
```

Likewise,

```
foo@bar.com <foo@bar.com>
```

is recognized as a `name-addr` even though the `@` should be quoted.

This crate does not (yet) implement the new [RFC 5322].

  [RFC 5322]: https://tools.ietf.org/html/rfc5322
