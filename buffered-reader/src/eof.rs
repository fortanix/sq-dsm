use std::io;
use std::io::{Error, ErrorKind, Read};
use std::fmt;

use crate::BufferedReader;

/// Always returns EOF.
pub struct EOF<C> {
    cookie: C,
}

impl<C> fmt::Display for EOF<C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "EOF")
    }
}

impl<C> fmt::Debug for EOF<C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("EOF")
            .finish()
    }
}

impl EOF<()> {
    /// Instantiates a new `EOF`.
    pub fn new() -> Self {
        EOF {
            cookie: (),
        }
    }
}

impl<C> EOF<C> {
    /// Instantiates a new `EOF` with a cookie.
    pub fn with_cookie(cookie: C) -> Self {
        EOF {
            cookie: cookie,
        }
    }
}

impl<C> Read for EOF<C> {
    fn read(&mut self, _buf: &mut [u8]) -> Result<usize, io::Error> {
        return Ok(0);
    }
}

impl<C> BufferedReader<C> for EOF<C> {
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

    fn data_consume(&mut self, _amount: usize) -> Result<&[u8], io::Error> {
        return Ok(&b""[..]);
    }

    fn data_consume_hard(&mut self, amount: usize) -> Result<&[u8], io::Error> {
        if amount == 0 {
            Ok(&b""[..])
        } else {
            Err(Error::new(ErrorKind::UnexpectedEof, "unexpected EOF"))
        }
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
        let mut reader = EOF::new();

        assert_eq!(reader.buffer(), &b""[..]);
        assert_eq!(reader.data(100).unwrap(), &b""[..]);
        assert_eq!(reader.buffer(), &b""[..]);
        assert_eq!(reader.consume(0), &b""[..]);
        assert_eq!(reader.data_hard(0).unwrap(), &b""[..]);
        assert!(reader.data_hard(1).is_err());
    }
}
