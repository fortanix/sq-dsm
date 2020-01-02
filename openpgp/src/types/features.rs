use std::hash::{Hash, Hasher};

/// Describes features supported by an OpenPGP implementation.
#[derive(Clone, Debug)]
pub struct Features{
    mdc: bool,
    aead: bool,
    unknown: Box<[u8]>,
    /// Original length, including trailing zeros.
    pad_to: usize,
}

impl Default for Features {
    fn default() -> Self {
        Features{
            mdc: false,
            aead: false,
            unknown: Default::default(),
            pad_to: 0,
        }
    }
}

impl PartialEq for Features {
    fn eq(&self, other: &Self) -> bool {
        self.mdc == other.mdc
            && self.aead == other.aead
            && self.unknown == other.unknown
    }
}

impl Eq for Features {}

impl Hash for Features {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.mdc.hash(state);
        self.aead.hash(state);
        self.unknown.hash(state);
    }
}

impl Features {
    /// Creates a new instance from `bits`.
    pub fn new<B: AsRef<[u8]>>(bits: B) -> Self {
        let bits = bits.as_ref();
        let mut pad_to = 0;

        let mdc = bits.get(0)
            .map(|x| x & FEATURE_FLAG_MDC != 0).unwrap_or(false);
        let aead = bits.get(0)
            .map(|x| x & FEATURE_FLAG_AEAD != 0).unwrap_or(false);
        let unk = if bits.is_empty() {
            Box::default()
        } else {
            let mut cpy = Vec::from(bits);

            cpy[0] &= (FEATURE_FLAG_MDC | FEATURE_FLAG_AEAD) ^ 0xff;

            pad_to = crate::types::bitfield_remove_padding(&mut cpy);
            cpy.into_boxed_slice()
        };

        Features{
            mdc: mdc, aead: aead, unknown: unk, pad_to,
        }
    }

    /// Returns an feature set describing Sequoia.
    pub fn sequoia() -> Self {
        Features{
            mdc: true,
            aead: false,
            unknown: Default::default(),
            pad_to: 0,
        }
    }

    /// Returns a slice referencing the raw values.
    pub(crate) fn to_vec(&self) -> Vec<u8> {
        let mut ret = if self.unknown.is_empty() {
            vec![0]
        } else {
            self.unknown.clone().into()
        };

        if self.mdc { ret[0] |= FEATURE_FLAG_MDC; }
        if self.aead { ret[0] |= FEATURE_FLAG_AEAD; }

        // Corner case: empty flag field.  We initialized ret to
        // vec![0] for easy setting of flags.  See if any of the above
        // was set.
        if ret.len() == 1 && ret[0] == 0 {
            // Nope.  Trim this byte.
            ret.pop();
        }

        for _ in ret.len()..self.pad_to {
            ret.push(0);
        }

        ret
    }

    /// Whether or not MDC is supported.
    pub fn supports_mdc(&self) -> bool {
        self.mdc
    }

    /// Sets whether or not MDC is supported.
    pub fn set_mdc(mut self, v: bool) -> Self {
        self.mdc = v;
        self
    }

    /// Whether or not AEAD is supported.
    pub fn supports_aead(&self) -> bool {
        self.aead
    }

    /// Sets whether or not AEAD is supported.
    pub fn set_aead(mut self, v: bool) -> Self {
        self.aead = v;
        self
    }
}

/// Modification Detection (packets 18 and 19).
const FEATURE_FLAG_MDC: u8 = 0x01;

/// AEAD Encrypted Data Packet (packet 20) and version 5 Symmetric-Key
/// Encrypted Session Key Packets (packet 3).
const FEATURE_FLAG_AEAD: u8 = 0x02;

#[cfg(test)]
mod tests {
    use super::*;

    quickcheck! {
        fn roundtrip(raw: Vec<u8>) -> bool {
            let val = Features::new(&raw);
            assert_eq!(raw, val.to_vec());

            // Check that equality ignores padding.
            let mut val_without_padding = val.clone();
            val_without_padding.pad_to = val.unknown.len();
            assert_eq!(val, val_without_padding);

            true
        }
    }
}
