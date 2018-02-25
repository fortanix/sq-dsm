use std::io;
use std::io::Read;
use std::fmt;

use BufferedReader;

/// A `BufferedReaderEOF` always returns EOF.
pub struct BufferedReaderEOF<C> {
    cookie: C,
}

impl<C> fmt::Debug for BufferedReaderEOF<C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("BufferedReaderEOF")
            .finish()
    }
}

impl BufferedReaderEOF<()> {
    pub fn new() -> Self {
        BufferedReaderEOF {
            cookie: (),
        }
    }
}

impl<C> BufferedReaderEOF<C> {
    pub fn with_cookie(cookie: C) -> Self {
        BufferedReaderEOF {
            cookie: cookie,
        }
    }
}

impl<C> Read for BufferedReaderEOF<C> {
    fn read(&mut self, _buf: &mut [u8]) -> Result<usize, io::Error> {
        return Ok(0);
    }
}

impl<C> BufferedReader<C> for BufferedReaderEOF<C> {
    fn buffer(&self) -> &[u8] {
        return &b""[..];
    }

    fn data(&mut self, _amount: usize) -> Result<&[u8], io::Error> {
        return Ok(&b""[..]);
    }

    fn consume(&mut self, amount: usize) -> &[u8] {
        assert_eq!(amount, 0);
        return &b""[..];
    }

    fn data_consume(&mut self, amount: usize) -> Result<&[u8], io::Error> {
        assert_eq!(amount, 0);
        return Ok(&b""[..]);
    }

    fn data_consume_hard(&mut self, amount: usize) -> Result<&[u8], io::Error> {
        assert_eq!(amount, 0);
        return Ok(&b""[..]);
    }

    fn into_inner<'a>(self: Box<Self>) -> Option<Box<BufferedReader<C> + 'a>>
        where Self: 'a
    {
        return None;
    }

    fn get_mut(&mut self) -> Option<&mut BufferedReader<C>>
    {
        return None;
    }

    fn get_ref(&self) -> Option<&BufferedReader<C>>
    {
        return None;
    }


    fn cookie_set(&mut self, cookie: C) -> C {
        use std::mem;

        mem::replace(&mut self.cookie, cookie)
    }

    fn cookie_ref(&self) -> &C {
        &self.cookie
    }

    fn cookie_mut(&mut self) -> &mut C {
        &mut self.cookie
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn basics() {
        let mut reader = BufferedReaderEOF::new();

        assert_eq!(reader.buffer(), &b""[..]);
        assert_eq!(reader.data(100).unwrap(), &b""[..]);
        assert_eq!(reader.buffer(), &b""[..]);
        assert_eq!(reader.consume(0), &b""[..]);
        assert_eq!(reader.data_hard(0).unwrap(), &b""[..]);
        assert!(reader.data_hard(1).is_err());
    }
}
