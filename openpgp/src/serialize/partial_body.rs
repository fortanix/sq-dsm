//! Encodes a byte stream using OpenPGP's partial body encoding.

use std;
use std::fmt;
use std::io;
use std::cmp;

use Error;
use Result;
use ::BodyLength;
use super::{writer, write_byte, Serialize};

// Compute the log2 of an integer.  (This is simply the most
// significant bit.)  Note: log2(0) = -Inf, but this function returns
// log2(0) as 0 (which is the closest number that we can represent).
fn log2(mut x: u32) -> usize {
    for i in 0..32 {
        x /= 2;
        if x == 0 {
            return i;
        }
    }

    return 31;
}

#[test]
fn log2_test() {
    for i in 0..32 {
        // eprintln!("log2(1 << {} = {}) = {}", i, 1u32 << i, log2(1u32 << i));
        assert_eq!(log2(1u32 << i), i);
        if i > 0 {
            assert_eq!(log2((1u32 << i) - 1), i - 1);
            assert_eq!(log2((1u32 << i) + 1), i);
        }
    }
}

pub struct PartialBodyFilter<'a, C: 'a> {
    // The underlying writer.
    //
    // Because this writer implements `Drop`, we cannot move the inner
    // writer out of this writer.  We therefore wrap it with `Option`
    // so that we can `take()` it.
    inner: Option<writer::Stack<'a, C>>,

    // The cookie.
    cookie: C,

    // The buffer.
    buffer: Vec<u8>,

    // The amount to buffer before flushing.
    buffer_threshold: usize,

    // The maximum size of a partial body chunk.  The standard allows
    // for chunks up to 1 GB in size.
    max_chunk_size: u32,
}

const PARTIAL_BODY_FILTER_MAX_CHUNK_SIZE : u32 = 1 << 30;

// The amount to buffer before flushing.  If this is small, we get
// lots of small partial body packets, which is annoying.
const PARTIAL_BODY_FILTER_BUFFER_THRESHOLD : usize = 4 * 1024 * 1024;

impl<'a, C: 'a> PartialBodyFilter<'a, C> {
    /// Returns a new partial body encoder.
    pub fn new(inner: writer::Stack<'a, C>, cookie: C) -> writer::Stack<'a, C> {
        let buffer_threshold = PARTIAL_BODY_FILTER_BUFFER_THRESHOLD;
        let max_chunk_size = PARTIAL_BODY_FILTER_MAX_CHUNK_SIZE;
        Box::new(PartialBodyFilter {
            inner: Some(inner),
            cookie: cookie,
            buffer: Vec::with_capacity(buffer_threshold as usize),
            buffer_threshold: buffer_threshold,
            max_chunk_size: max_chunk_size,
        })
    }

    // Writes out any full chunks between `self.buffer` and `other`.
    // Any extra data is buffered.
    //
    // If `done` is set, then flushes any data, and writes the end of
    // the partial body encoding.
    fn write_out(&mut self, other: &[u8], done: bool)
                 -> io::Result<()> {
        if self.inner.is_none() {
            return Ok(());
        }
        let mut inner = self.inner.as_mut().unwrap();

        if done {
            // We're done.  The last header MUST be a non-partial body
            // header.  We have to write it even if it is 0 bytes
            // long.

            // Write the header.
            let l = self.buffer.len() + other.len();
            if l > std::u32::MAX as usize {
                unimplemented!();
            }
            BodyLength::Full(l as u32).serialize(inner).map_err(
                |e| {
                    match e.downcast::<io::Error>() {
                        Ok(err) => err,
                        Err(e) => {
                            match e.downcast::<Error>()
                                .expect("Unexpected error encoding full length")
                            {
                                Error::InvalidArgument(s) =>
                                    panic!("Error encoding full length: {}", s),
                                _ =>
                                    panic!("Unexpected error encoding \
                                            full length"),
                            }
                        }
                    }
                })?;

            // Write the body.
            inner.write_all(&self.buffer[..])?;
            self.buffer.clear();
            inner.write_all(other)?;
        } else {
            // Write a partial body length header.

            let chunk_size_log2 =
                log2(cmp::min(self.max_chunk_size,
                              self.buffer_threshold as u32));
            let chunk_size = (1 as usize) << chunk_size_log2;

            let size_byte = 224 + chunk_size_log2;
            assert!(size_byte < 255);
            let size_byte = size_byte as u8;

            // The first pass we process self.buffer, the second pass
            // we process other.
            for i in 0..2 {
                let mut rest = Vec::new();

                for chunk in self.buffer.chunks(chunk_size) {
                    if chunk.len() < chunk_size {
                        // We don't have enough for a whole chunk.
                        rest = chunk.to_vec();
                        break;
                    }

                    // Write out the chunk.
                    write_byte(&mut inner, size_byte)?;
                    inner.write_all(chunk)?;
                }

                // In between, we have to see if we have a whole
                // chunk.
                if i == 0 && rest.len() + other.len() >= chunk_size {
                    write_byte(&mut inner, size_byte)?;
                    inner.write_all(&rest[..])?;
                    let amount = chunk_size - rest.len();

                    inner.write_all(&other[..amount])?;
                    rest = other[amount..].to_vec();
                }

                self.buffer = rest;
            }
        }

        Ok(())
    }
}

impl<'a, C: 'a> io::Write for PartialBodyFilter<'a, C> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // If we can write out a chunk, avoid an extra copy.
        if buf.len() >= self.buffer.capacity() - self.buffer.len() {
            self.write_out(buf, false)?;
        } else {
            self.buffer.append(buf.to_vec().as_mut());
        }
        Ok(buf.len())
    }

    // XXX: The API says that `flush` is supposed to flush any
    // internal buffers to disk.  We don't do that.
    fn flush(&mut self) -> io::Result<()> {
        self.write_out(&b""[..], false)
    }
}

impl<'a, C: 'a> Drop for PartialBodyFilter<'a, C> {
    // Make sure the internal buffer is flushed.
    fn drop(&mut self) {
        let _ = self.write_out(&b""[..], true);
    }
}

impl<'a, C: 'a> fmt::Debug for PartialBodyFilter<'a, C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("PartialBodyFilter")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<'a, C: 'a> writer::Stackable<'a, C> for PartialBodyFilter<'a, C> {
    fn into_inner(mut self: Box<Self>) -> Result<Option<writer::Stack<'a, C>>> {
        self.write_out(&b""[..], true)?;
        Ok(self.inner.take())
    }
    fn pop(&mut self) -> Result<Option<writer::Stack<'a, C>>> {
        self.write_out(&b""[..], true)?;
        Ok(self.inner.take())
    }
    fn mount(&mut self, new: writer::Stack<'a, C>) {
        self.inner = Some(new);
    }
    fn inner_mut(&mut self) -> Option<&mut writer::Stackable<'a, C>> {
        if let Some(ref mut i) = self.inner {
            Some(i)
        } else {
            None
        }
    }
    fn inner_ref(&self) -> Option<&writer::Stackable<'a, C>> {
        if let Some(ref i) = self.inner {
            Some(i)
        } else {
            None
        }
    }
    fn cookie_set(&mut self, cookie: C) -> C {
        ::std::mem::replace(&mut self.cookie, cookie)
    }
    fn cookie_ref(&self) -> &C {
        &self.cookie
    }
    fn cookie_mut(&mut self) -> &mut C {
        &mut self.cookie
    }
}
