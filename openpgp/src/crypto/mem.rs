//! Memory protection.

use std::cmp::{min, Ordering};
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;

use memsec;

/// Holds a session key.
///
/// The session key is cleared when dropped.
#[derive(Clone, Eq, Hash)]
pub struct Protected(Pin<Box<[u8]>>);

impl PartialEq for Protected {
    fn eq(&self, other: &Self) -> bool {
        secure_cmp(&self.0, &other.0) == Ordering::Equal
    }
}

impl Protected {
    /// Converts to a buffer for modification.
    pub unsafe fn into_vec(self) -> Vec<u8> {
        self.iter().cloned().collect()
    }
}

impl Deref for Protected {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for Protected {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl DerefMut for Protected {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl From<Vec<u8>> for Protected {
    fn from(v: Vec<u8>) -> Self {
        Protected(Pin::new(v.into_boxed_slice()))
    }
}

impl From<Box<[u8]>> for Protected {
    fn from(v: Box<[u8]>) -> Self {
        Protected(Pin::new(v))
    }
}

impl From<&[u8]> for Protected {
    fn from(v: &[u8]) -> Self {
        Vec::from(v).into()
    }
}

impl Drop for Protected {
    fn drop(&mut self) {
        unsafe {
            memsec::memzero(self.0.as_mut_ptr(), self.0.len());
        }
    }
}

impl fmt::Debug for Protected {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if cfg!(debug_assertions) {
            write!(f, "{:?}", self.0)
        } else {
            f.write_str("[<Redacted>]")
        }
    }
}

/// Time-constant comparison.
pub fn secure_cmp(a: &[u8], b: &[u8]) -> Ordering {
    let ord1 = a.len().cmp(&b.len());
    let ord2 = unsafe {
        memsec::memcmp(a.as_ptr(), b.as_ptr(), min(a.len(), b.len()))
    };
    let ord2 = match ord2 {
        0 => Ordering::Equal,
        a if a < 0 => Ordering::Less,
        a if a > 0 => Ordering::Greater,
        _ => unreachable!(),
    };

    if ord1 == Ordering::Equal { ord2 } else { ord1 }
}
