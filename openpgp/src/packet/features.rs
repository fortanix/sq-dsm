use std::fmt;

/// Describes features supported by an OpenPGP implementation.
#[derive(Clone)]
pub struct Features(Vec<u8>);

impl Default for Features {
    fn default() -> Self {
        Features::none()
    }
}

impl PartialEq for Features {
    fn eq(&self, other: &Features) -> bool {
        // To deal with unknown flags, we do a bitwise comparison.
        // First, we need to bring both flag fields to the same
        // length.
        let len = ::std::cmp::max(self.0.len(), other.0.len());
        let mut mine = vec![0; len];
        let mut hers = vec![0; len];
        &mut mine[..self.0.len()].copy_from_slice(&self.0);
        &mut hers[..other.0.len()].copy_from_slice(&other.0);

        mine == hers
    }
}

impl fmt::Debug for Features {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut dirty = false;
        if self.supports_mdc() {
            f.write_str("MDC")?;
            dirty = true;
        }

        if self.supports_aead() {
            if dirty {
                f.write_str(", ")?;
            }
            f.write_str("AEAD")?;
            dirty = true;
        }

        let _ = dirty;
        Ok(())
    }
}

impl Features {
    /// Creates a new instance from `v`.
    pub fn new(v: Vec<u8>) -> Self {
        Features(v)
    }

    /// Returns an empty feature set.
    pub fn none() -> Self {
        Features(vec![0])
    }

    /// Returns an feature set describing Sequoia.
    pub fn sequoia() -> Self {
        Features::none()
            .set_mdc(true)
            .set_aead(true)
    }

    /// Grows the vector to the given length.
    fn grow(&mut self, target: usize) {
        while self.0.len() < target {
            self.0.push(0);
        }
    }

    /// Returns a slice referencing the raw values.
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Whether or not MDC is supported.
    pub fn supports_mdc(&self) -> bool {
        self.0.get(0)
            .map(|v0| v0 & FEATURE_FLAG_MDC > 0).unwrap_or(false)
    }

    /// Sets whether or not MDC is supported.
    pub fn set_mdc(mut self, v: bool) -> Self {
        self.grow(1);
        if v {
            self.0[0] |= FEATURE_FLAG_MDC;
        } else {
            self.0[0] &= !FEATURE_FLAG_MDC;
        }
        self
    }

    /// Whether or not AEAD is supported.
    pub fn supports_aead(&self) -> bool {
        self.0.get(0)
            .map(|v0| v0 & FEATURE_FLAG_AEAD > 0).unwrap_or(false)
    }

    /// Sets whether or not AEAD is supported.
    pub fn set_aead(mut self, v: bool) -> Self {
        self.grow(1);
        if v {
            self.0[0] |= FEATURE_FLAG_AEAD;
        } else {
            self.0[0] &= !FEATURE_FLAG_AEAD;
        }
        self
    }
}

/// Modification Detection (packets 18 and 19).
const FEATURE_FLAG_MDC: u8 = 0x01;

/// AEAD Encrypted Data Packet (packet 20) and version 5 Symmetric-Key
/// Encrypted Session Key Packets (packet 3).
const FEATURE_FLAG_AEAD: u8 = 0x02;
