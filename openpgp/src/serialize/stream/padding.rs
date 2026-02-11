//! Padding for OpenPGP messages.
//!
//! To reduce the amount of information leaked via the message length,
//! encrypted OpenPGP messages (see [Section 10.3 of RFC 9580]) should
//! be padded.
//!
//!   [Section 10.3 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-10.3
//!
//! To pad a message using the streaming serialization interface, the
//! [`Padder`] needs to be inserted into the writing stack between the
//! [`Encryptor`] and [`Signer`].  This is illustrated in this
//! [example].
//!
//!   [`Encryptor`]: super::Encryptor
//!   [`Signer`]: super::Signer
//!   [example]: Padder#examples
//!
//! # Padding in OpenPGP
//!
//! RFC9580 introduced a [padding packet] that will be emitted when
//! composing an RFC9580 message.  Unfortunately, RFC4880 does not
//! have a robust way to pad messages.  Therefore, when composing an
//! RFC4880 message, the message will not be padded.
//!
//!   [padding packet]: https://www.rfc-editor.org/rfc/rfc9580.html#name-padding-packet-type-id-21
//!
//! To be effective, the padding layer must be placed inside the
//! encryption container.  To increase compatibility, the padding
//! layer must not be signed.  That is to say, the message structure
//! should be `(encryption (ops literal signature padding))`.
use std::fmt;
use std::io;

use crate::{
    Profile,
    Result,
    packet::prelude::*,
};
use crate::serialize::{
    Marshal,
    stream::{
        writer,
        Cookie,
        Message,
        Private,
    },
};

/// Pads a packet stream.
///
/// Writes a compressed data packet containing all packets written to
/// this writer, and pads it according to the given policy.
///
/// The policy is a `Fn(u64) -> u64`, that given the number of bytes
/// written to this writer `N`, computes the size the compression
/// container should be padded up to.  It is an error to return a
/// number that is smaller than `N`.
///
/// # Compatibility
///
/// RFC9580 introduced a [padding packet] that will be emitted when
/// composing an RFC9580 message.  Unfortunately, RFC4880 does not
/// have a robust way to pad messages.  Therefore, when composing an
/// RFC4880 message, the message will not be padded.
///
///   [padding packet]: https://www.rfc-editor.org/rfc/rfc9580.html#name-padding-packet-type-id-21
/// # Examples
///
/// This example illustrates the use of `Padder` with the [Padmé]
/// policy.  Note that for brevity, the encryption and signature
/// filters are omitted.
///
/// [Padmé]: padme()
///
/// ```
/// use std::io::Write;
/// use sequoia_openpgp as openpgp;
/// use openpgp::serialize::stream::{Message, LiteralWriter};
/// use openpgp::serialize::stream::padding::Padder;
/// use openpgp::types::CompressionAlgorithm;
/// # fn main() -> sequoia_openpgp::Result<()> {
///
/// let mut unpadded = vec![];
/// {
///     let message = Message::new(&mut unpadded);
///     // XXX: Insert Encryptor here.
///     // XXX: Insert Signer here.
///     let mut message = LiteralWriter::new(message).build()?;
///     message.write_all(b"Hello world.")?;
///     message.finalize()?;
/// }
///
/// let mut padded = vec![];
/// {
///     let message = Message::new(&mut padded);
///     // XXX: Insert Encryptor here.
///     let message = Padder::new(message).build()?;
///     // XXX: Insert Signer here.
///     let mut message = LiteralWriter::new(message).build()?;
///     message.write_all(b"Hello world.")?;
///     message.finalize()?;
/// }
/// # Ok(())
/// # }
pub struct Padder<'a, 'p: 'a> {
    inner: writer::BoxStack<'a, Cookie>,
    policy: Box<dyn Fn(u64) -> u64 + Send + Sync + 'p>,
    cookie: Cookie,
}
assert_send_and_sync!(Padder<'_, '_>);

impl<'a, 'p> Padder<'a, 'p> {
    /// Creates a new padder with the given policy.
    ///
    /// # Examples
    ///
    /// This example illustrates the use of `Padder` with the [Padmé]
    /// policy.
    ///
    /// [Padmé]: padme()
    ///
    /// The most useful filter to push to the writer stack next is the
    /// [`Signer`] or the [`LiteralWriter`].  Finally, literal data
    /// *must* be wrapped using the [`LiteralWriter`].
    ///
    ///   [`Signer`]: super::Signer
    ///   [`LiteralWriter`]: super::LiteralWriter
    ///
    /// ```
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::serialize::stream::padding::Padder;
    ///
    /// # let message = openpgp::serialize::stream::Message::new(vec![]);
    /// // XXX: Insert Encryptor here.
    /// let message = Padder::new(message).build()?;
    /// // XXX: Optionally add a `Signer` here.
    /// // XXX: Add a `LiteralWriter` here.
    /// # let _ = message;
    /// # Ok(()) }
    /// ```
    pub fn new(inner: Message<'a>) -> Self {
        let level = inner.as_ref().cookie_ref().level;
        let cookie = Cookie::new(level + 1);

        Self {
            inner: writer::BoxStack::from(inner),
            policy: Box::new(padme),
            cookie,
        }
    }

    /// Sets padding policy, returning the padder.
    ///
    /// # Examples
    ///
    /// This example illustrates the use of `Padder` with an explicit policy.
    ///
    /// ```
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::serialize::stream::padding::{Padder, padme};
    ///
    /// # let message = openpgp::serialize::stream::Message::new(vec![]);
    /// // XXX: Insert Encryptor here.
    /// let message = Padder::new(message).with_policy(padme).build()?;
    /// // XXX: Optionally add a `Signer` here.
    /// // XXX: Add a `LiteralWriter` here.
    /// # let _ = message;
    /// # Ok(()) }
    /// ```
    pub fn with_policy<P>(mut self, p: P) -> Self
    where
        P: Fn(u64) -> u64 + Send + Sync + 'p,
    {
        self.policy = Box::new(p);
        self
    }

    /// Builds the padder, returning the writer stack.
    ///
    /// # Examples
    ///
    /// This example illustrates the use of `Padder` with the [Padmé]
    /// policy.
    ///
    /// [Padmé]: padme()
    ///
    /// The most useful filter to push to the writer stack next is the
    /// [`Signer`] or the [`LiteralWriter`].  Finally, literal data
    /// *must* be wrapped using the [`LiteralWriter`].
    ///
    ///   [`Signer`]: super::Signer
    ///   [`LiteralWriter`]: super::LiteralWriter
    ///
    /// ```
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::serialize::stream::padding::Padder;
    ///
    /// # let message = openpgp::serialize::stream::Message::new(vec![]);
    /// // XXX: Insert Encryptor here.
    /// let message = Padder::new(message).build()?;
    /// // XXX: Optionally add a `Signer` here.
    /// // XXX: Add a `LiteralWriter` here.
    /// # let _ = message;
    /// # Ok(()) }
    /// ```
    pub fn build(self) -> Result<Message<'a>> {
        Ok(Message::from(Box::new(self)))
    }
}

impl<'a, 'p> fmt::Debug for Padder<'a, 'p> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Padder")
            .field("inner", &self.inner)
            .field("cookie", &self.cookie)
            .finish()
    }
}

impl<'a, 'p> io::Write for Padder<'a, 'p> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<'a, 'p> writer::Stackable<'a, Cookie> for Padder<'a, 'p>
{
    fn into_inner(mut self: Box<Self>)
                  -> Result<Option<writer::BoxStack<'a, Cookie>>>
    {
        let enabled = writer::map(
            self.as_ref(),
            |w| match w.cookie_ref().private {
                Private::Encryptor { profile, .. } =>
                    Some(profile == Profile::RFC9580),
                _ => None,
            })
            .unwrap_or(false);

        if enabled {
            // Make a note of the amount of data written to this
            // filter.
            let size = self.position();

            // Compute the amount of padding required according to the
            // given policy.
            let padded_size = (self.policy)(size);
            if padded_size < size {
                return Err(crate::Error::InvalidOperation(
                    format!("Padding policy({}) returned {}: \
                             smaller than argument",
                            size, padded_size)).into());
            }
            let amount = padded_size - size;

            // Write 'amount' of padding.
            Packet::from(Padding::new(amount.try_into()
                                      .unwrap_or(usize::MAX))?)
                .serialize(&mut self)?;
        }

        Ok(Some(self.inner))
    }
    fn pop(&mut self) -> Result<Option<writer::BoxStack<'a, Cookie>>> {
        unreachable!("Only implemented by Signer")
    }
    /// Sets the inner stackable.
    fn mount(&mut self, _new: writer::BoxStack<'a, Cookie>) {
        unreachable!("Only implemented by Signer")
    }
    fn inner_ref(&self) -> Option<&(dyn writer::Stackable<'a, Cookie> + Send + Sync)> {
        Some(self.inner.as_ref())
    }
    fn inner_mut(&mut self) -> Option<&mut (dyn writer::Stackable<'a, Cookie> + Send + Sync)> {
        Some(self.inner.as_mut())
    }
    fn cookie_set(&mut self, cookie: Cookie) -> Cookie {
        std::mem::replace(&mut self.cookie, cookie)
    }
    fn cookie_ref(&self) -> &Cookie {
        &self.cookie
    }
    fn cookie_mut(&mut self) -> &mut Cookie {
        &mut self.cookie
    }
    fn position(&self) -> u64 {
        self.inner.position()
    }
}

/// Padmé padding scheme.
///
/// Padmé leaks at most O(log log M) bits of information (with M being
/// the maximum length of all messages) with an overhead of at most
/// 12%, decreasing with message size.
///
/// This scheme leaks the same order of information as padding to the
/// next power of two, while avoiding an overhead of up to 100%.
///
/// See Section 4 of [Reducing Metadata Leakage from Encrypted Files
/// and Communication with
/// PURBs](https://bford.info/pub/sec/purb.pdf).
///
/// This function is meant to be used with [`Padder`], see this
/// [example].
///
///   [example]: Padder#examples
pub fn padme(l: u64) -> u64 {
    if l < 2 {
        return 1; // Avoid cornercase.
    }

    let e = log2(l);               // l's floating-point exponent
    let s = log2(e as u64) + 1;    // # of bits to represent e
    let z = e - s;                 // # of low bits to set to 0
    let m = (1 << z) - 1;          // mask of z 1's in LSB
    (l + (m as u64)) & !(m as u64) // round up using mask m to clear last z bits
}

/// Compute the log2 of an integer.  (This is simply the most
/// significant bit.)  Note: log2(0) = -Inf, but this function returns
/// log2(0) as 0 (which is the closest number that we can represent).
fn log2(x: u64) -> usize {
    if x == 0 {
        0
    } else {
        63 - x.leading_zeros() as usize
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn log2_test() {
        for i in 0..64 {
            assert_eq!(log2(1u64 << i), i);
            if i > 0 {
                assert_eq!(log2((1u64 << i) - 1), i - 1);
                assert_eq!(log2((1u64 << i) + 1), i);
            }
        }
    }

    fn padme_multiplicative_overhead(p: u64) -> f32 {
        let c = padme(p);
        let (p, c) = (p as f32, c as f32);
        (c - p) / p
    }

    /// Experimentally, we observe the maximum overhead to be ~11.63%
    /// when padding 129 bytes to 144.
    const MAX_OVERHEAD: f32 = 0.1163;

    #[test]
    fn padme_max_overhead() {
        // The paper says the maximum multiplicative overhead is
        // 11.(11)% when padding 9 bytes to 10.
        assert!(0.111 < padme_multiplicative_overhead(9));
        assert!(padme_multiplicative_overhead(9) < 0.112);

        // Contrary to that, we observe the maximum overhead to be
        // ~11.63% when padding 129 bytes to 144.
        assert!(padme_multiplicative_overhead(129) < MAX_OVERHEAD);
    }

    quickcheck! {
        fn padme_overhead(l: u32) -> bool {
            if l < 2 {
                return true; // Avoid cornercase.
            }

            let o = padme_multiplicative_overhead(l as u64);
            let l_ = l as f32;
            let e = l_.log2().floor();     // l's floating-point exponent
            let s = e.log2().floor() + 1.; // # of bits to represent e
            let max_overhead = (2.0_f32.powf(e-s) - 1.) / l_;

            assert!(o < MAX_OVERHEAD,
                    "padme({}) => {}: overhead {} exceeds maximum overhead {}",
                    l, padme(l.into()), o, MAX_OVERHEAD);
            assert!(o <= max_overhead,
                    "padme({}) => {}: overhead {} exceeds maximum overhead {}",
                    l, padme(l.into()), o, max_overhead);
            true
        }
    }

    /// Asserts that we can consume the padded messages.
    #[test]
    fn roundtrip() {
        use std::io::Write;
        use crate::crypto::random;
        use crate::parse::Parse;
        use crate::serialize::stream::*;

        let mut two_bytes = [0; 2];
        random(&mut two_bytes).expect("Have RNG");
        let size: usize = ((two_bytes[0] as usize) << 8) + (two_bytes[1] as usize);

        let mut msg = vec![0; size % 1024];
        crate::crypto::random(&mut msg).unwrap();

        let mut padded = vec![];
        {
            let message = Message::new(&mut padded);
            let padder = Padder::new(message).with_policy(padme).build().unwrap();
            let mut w = LiteralWriter::new(padder).build().unwrap();
            w.write_all(&msg).unwrap();
            w.finalize().unwrap();
        }

        let m = crate::Message::from_bytes(&padded).unwrap();
        assert_eq!(m.body().unwrap().body(), &msg[..]);
    }

    /// Asserts that no actual compression is done.
    ///
    /// We want to avoid having the size of the data stream depend on
    /// the data's compressibility, therefore it is best to disable
    /// the compression.
    #[test]
    fn no_compression() {
        use std::io::Write;
        use crate::serialize::stream::*;
        const MSG: &[u8] = b"@@@@@@@@@@@@@@";
        let mut padded = vec![];
        {
            let message = Message::new(&mut padded);
            let padder = Padder::new(message).build().unwrap();
            let mut w = LiteralWriter::new(padder).build().unwrap();
            w.write_all(MSG).unwrap();
            w.finalize().unwrap();
        }

        assert!(padded.windows(MSG.len()).any(|ch| ch == MSG),
                "Could not find uncompressed message");
    }
}
