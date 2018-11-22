use std::fmt;

/// Describes preferences regarding key servers.
#[derive(Clone)]
pub struct KeyServerPreferences(pub Vec<u8>);

impl Default for KeyServerPreferences {
    fn default() -> Self {
        KeyServerPreferences(vec![0])
    }
}

impl PartialEq for KeyServerPreferences {
    fn eq(&self, other: &KeyServerPreferences) -> bool {
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

impl fmt::Debug for KeyServerPreferences {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.no_modify() {
            f.write_str("no modify")?;
        }

        Ok(())
    }
}

impl KeyServerPreferences {
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

    /// Whether or not the key on the key severs should only be
    /// modified by the owner or server administrator.
    pub fn no_modify(&self) -> bool {
        self.0.get(0)
            .map(|v0| v0 & KEYSERVER_PREFERENCE_NO_MODIFY > 0).unwrap_or(false)
    }


    /// Sets whether or not the key on the key severs should only be
    /// modified by the owner or server administrator.
    pub fn set_no_modify(mut self, v: bool) -> Self {
        self.grow(1);
        if v {
            self.0[0] |= KEYSERVER_PREFERENCE_NO_MODIFY;
        } else {
            self.0[0] &= !KEYSERVER_PREFERENCE_NO_MODIFY;
        }
        self
    }
}

/// The private component of this key may be in the possession of more
/// than one person.
const KEYSERVER_PREFERENCE_NO_MODIFY: u8 = 0x80;
