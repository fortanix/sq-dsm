//! An OpenPGP packet parser.
//!
//! An OpenPGP message is a sequence of packets.  Some of the packets
//! contain other packets.  These containers include encrypted packets
//! (the SED and SEIP packets), and compressed packets.  This
//! structure results in a tree, which is laid out in depth-first
//! order.
//!
//! There are two major concerns that inform the design of the parsing
//! API.
//!
//! First, when processing a container, it is possible to either
//! recurse into the container, and process its children, or treat the
//! contents of the container as an opaque byte stream, and process
//! the packet following the container.  The low-level
//! [`PacketParser`] and mid-level [`MessageParser`] abstractions
//! allow the caller to choose the behavior by either calling the
//! `recurse()` method or the `next()` method, as appropriate.
//! OpenPGP doesn't impose any restrictions on the amount of nesting.
//! So, to prevent a denial of service attack, the parsers doesn't
//! recurse more than `MAX_RECURSION_DEPTH` times, by default.
//!
//! Second, packets can contain an effectively unbounded amount of
//! data.  To avoid errors due to memory exhaustion, the
//! [`PacketParser`] and [`MessageParser`] abstractions support
//! parsing packets in a streaming manner, i.e., never buffering more
//! than O(1) bytes of data.  To do this, the parsers initially only
//! parse a packet's header (which is rarely more than a few kilobytes
//! of data), and return control to the caller.  After inspecting that
//! data, the caller can decide how to handle the packet's contents.
//! If the content is deemed interesting, it can be streamed or
//! buffered.  Otherwise, it can be dropped.  Streaming is possible
//! not only for literal data packets, but also containers (other
//! packets also support the interface, but just return EOF).  For
//! instance, encryption can be stripped by saving the decrypted
//! content of an encryption packet, which is just an OpenPGP message.
//!
//! We explicitly chose to not use a callback-based API, but something
//! that is closer to Rust's iterator API.  Unfortunately, because a
//! [`PacketParser`] needs mutable access to the input stream (so that
//! the content can be streamed), only a single [`PacketParser`] item
//! can be live at a time (without a fair amount of unsafe nastiness).
//! This is incompatible with Rust's iterator concept, which allows
//! any number of items to be live at any time.  For instance:
//!
//! ```rust
//! let mut v = vec![1, 2, 3, 4];
//! let mut iter = v.iter_mut();
//!
//! let x = iter.next().unwrap();
//! let y = iter.next().unwrap();
//!
//! *x += 10; // This does not cause an error!
//! *y += 10;
//! ```
//!
//! This crate provide three abstractions for parsing OpenPGP
//! messages:
//!
//!   - The [`PacketParser`] abstraction produces one packet at a
//!     time.  What is done with those packets is completely up to the
//!     caller.
//!
//!   - The [`MessageParser`] abstraction builds on the
//!     [`PacketParser`] abstraction and provides a similar interface.
//!     However, after each iteration, the `MessageParser` adds the
//!     packet to a [`Message`], which is returned once the message is
//!     completely processed.
//!
//!     This interface should only be used if the caller actually
//!     wants a `Message`; if the OpenPGP message is parsed in place,
//!     then using a `PacketParser` is better.
//!
//!   - The [`Message::from_file`] (and related metods) is the most
//!     convenient, but least flexible way to parse an OpenPGP
//!     message.  Whereas a `MessageParser` allows the caller to
//!     determine how to handle individual packets, the
//!     [`Message::from_file`] parses the whole message at once and
//!     returns a [`Message`].
//!
//!     This interface should only be used if the caller is certain
//!     that the parsed message will fit in memory.
//!
//! In all cases, the default behavior can be configured using a
//! [`PacketParserBuilder`].
//!
//!   [`PacketParser`]: struct.PacketParser.html
//!   [`MessageParser`]: struct.MessageParser.html
//!   [`Message`]: ../struct.Message.html
//!   [`Message::from_file`]: ../struct.Message.html#method.from_file
//!   [`PacketParserBuilder`]: struct.PacketParserBuilder.html

// Hack so that the file doesn't have to be named mod.rs.
include!("parse.rs");
