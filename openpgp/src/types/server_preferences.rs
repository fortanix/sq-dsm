use std::fmt;

/// Describes preferences regarding key servers.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct KeyServerPreferences{
    no_modify: bool,
    unknown: Box<[u8]>,
}

impl Default for KeyServerPreferences {
    fn default() -> Self {
        KeyServerPreferences::new(&[0])
    }
}

impl fmt::Debug for KeyServerPreferences {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.no_modify() {
            f.write_str("no modify")?;
        }

        Ok(())
    }
}

impl KeyServerPreferences {
    /// Creates a new instance from `bits`.
    pub fn new(bits: &[u8]) -> Self {
        let no_mod = bits.get(0)
            .map(|x| x & KEYSERVER_PREFERENCE_NO_MODIFY != 0).unwrap_or(false);
        let unk = if bits.is_empty() {
            Box::default()
        } else {
            let mut cpy = Vec::from(bits);

            cpy[0] &= KEYSERVER_PREFERENCE_NO_MODIFY ^ 0xff;

            while cpy.last().cloned() == Some(0) { cpy.pop(); }
            cpy.into_boxed_slice()
        };

        KeyServerPreferences{
            no_modify: no_mod, unknown: unk
        }
    }

    /// Returns a slice referencing the raw values.
    pub(crate) fn as_vec(&self) -> Vec<u8> {
        let mut ret = if self.unknown.is_empty() {
            vec![0]
        } else {
            self.unknown.clone().into()
        };

        if self.no_modify { ret[0] |= KEYSERVER_PREFERENCE_NO_MODIFY; }

        ret
    }

    /// Whether or not keyservers are allowed to modify this key.
    pub fn no_modify(&self) -> bool {
        !self.no_modify
    }

    /// Sets whether or not keyservers are allowed to modify this key.
    pub fn set_no_modify(mut self, v: bool) -> Self {
        self.no_modify = v;
        self
    }
}

/// The private component of this key may be in the possession of more
/// than one person.
const KEYSERVER_PREFERENCE_NO_MODIFY: u8 = 0x80;
