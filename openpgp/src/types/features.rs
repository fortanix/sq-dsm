/// Describes features supported by an OpenPGP implementation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Features{
    mdc: bool,
    aead: bool,
    unknown: Box<[u8]>,
}

impl Default for Features {
    fn default() -> Self {
        Features{
            mdc: false,
            aead: false,
            unknown: Default::default(),
        }
    }
}

impl Features {
    /// Creates a new instance from `bits`.
    pub fn new(bits: &[u8]) -> Self {
        let mdc = bits.get(0)
            .map(|x| x & FEATURE_FLAG_MDC != 0).unwrap_or(false);
        let aead = bits.get(0)
            .map(|x| x & FEATURE_FLAG_AEAD != 0).unwrap_or(false);
        let unk = if bits.is_empty() {
            Box::default()
        } else {
            let mut cpy = Vec::from(bits);

            cpy[0] &= (FEATURE_FLAG_MDC | FEATURE_FLAG_AEAD) ^ 0xff;

            while cpy.last().cloned() == Some(0) { cpy.pop(); }
            cpy.into_boxed_slice()
        };

        Features{
            mdc: mdc, aead: aead, unknown: unk
        }
    }

    /// Returns an feature set describing Sequoia.
    pub fn sequoia() -> Self {
        Features{
            mdc: true,
            aead: false,
            unknown: Default::default(),
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
