use std::hash::{Hash, Hasher};
use std::fmt;

/// Describes preferences regarding key servers.
///
/// # A note on equality
///
/// `PartialEq` is implements semantic equality, i.e. it ignores
/// padding.
#[derive(Clone)]
pub struct KeyServerPreferences{
    no_modify: bool,
    unknown: Box<[u8]>,
    /// Original length, including trailing zeros.
    pad_to: usize,
}

impl Default for KeyServerPreferences {
    fn default() -> Self {
        KeyServerPreferences::new(&[0])
    }
}

impl fmt::Debug for KeyServerPreferences {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut dirty = false;
        if self.no_modify() {
            f.write_str("no modify")?;
            dirty = true;
        }
        if ! self.unknown.is_empty() {
            if dirty { f.write_str(", ")?; }
            f.write_str("+0x")?;
            f.write_str(
                &crate::fmt::hex::encode_pretty(&self.unknown))?;
            dirty = true;
        }
        if self.pad_to >
            KEYSERVER_PREFERENCES_N_KNOWN_BYTES + self.unknown.len()
        {
            if dirty { f.write_str(", ")?; }
            write!(f, "+padding({} bytes)", self.pad_to - self.unknown.len())?;
        }

        Ok(())
    }
}

impl PartialEq for KeyServerPreferences {
    fn eq(&self, other: &Self) -> bool {
        self.no_modify == other.no_modify
    }
}

impl Eq for KeyServerPreferences {}

impl Hash for KeyServerPreferences {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.no_modify.hash(state);
    }
}

impl KeyServerPreferences {
    /// Creates a new instance from `bits`.
    pub fn new<B: AsRef<[u8]>>(bits: B) -> Self {
        let bits = bits.as_ref();
        let mut pad_to = 0;

        let no_mod = bits.get(0)
            .map(|x| x & KEYSERVER_PREFERENCE_NO_MODIFY != 0).unwrap_or(false);
        let unk = if bits.is_empty() {
            Box::default()
        } else {
            let mut cpy = Vec::from(bits);

            cpy[0] &= KEYSERVER_PREFERENCE_NO_MODIFY ^ 0xff;

            pad_to = crate::types::bitfield_remove_padding(&mut cpy);
            cpy.into_boxed_slice()
        };

        KeyServerPreferences{
            no_modify: no_mod, unknown: unk, pad_to,
        }
    }

    /// Returns a slice referencing the raw values.
    pub(crate) fn to_vec(&self) -> Vec<u8> {
        let mut ret = if self.unknown.is_empty() {
            vec![0]
        } else {
            self.unknown.clone().into()
        };

        if self.no_modify { ret[0] |= KEYSERVER_PREFERENCE_NO_MODIFY; }

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

    /// Whether or not keyservers are allowed to modify this key.
    pub fn no_modify(&self) -> bool {
        self.no_modify
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

/// Number of bytes with known flags.
const KEYSERVER_PREFERENCES_N_KNOWN_BYTES: usize = 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basics() -> crate::Result<()> {
        let p = KeyServerPreferences::default();
        assert_eq!(p.no_modify(), false);
        let p = KeyServerPreferences::new(&[]);
        assert_eq!(p.no_modify(), false);
        let p = KeyServerPreferences::new(&[0xff]);
        assert_eq!(p.no_modify(), true);
        Ok(())
    }

    quickcheck! {
        fn roundtrip(raw: Vec<u8>) -> bool {
            let val = KeyServerPreferences::new(&raw);
            assert_eq!(raw, val.to_vec());

            // Check that equality ignores padding.
            let mut val_without_padding = val.clone();
            val_without_padding.pad_to = val.unknown.len();
            assert_eq!(val, val_without_padding);

            true
        }
    }
}
