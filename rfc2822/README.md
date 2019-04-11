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
text.

Further, we also allow dots in the name-addr Name.  That is:

```
Professor Pippy P. Poopypants <pippy@jerome-horwitz.k12.oh.us>
```

is recognized.  But [RFC 2822] strictly requires that the name be
quoted:

```
"Professor Pippy P. Poopypants" <pippy@jerome-horwitz.k12.oh.us>
```


This crate does not (yet) implement the new [RFC 5322].

  [RFC 5322]: https://tools.ietf.org/html/rfc5322
