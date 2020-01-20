//! Module to serialize and enarmor a Cert and add informative headers.
use std::io;
use std::str;

use crate::armor;
use crate::Result;
use crate::RevocationStatus;
use crate::serialize::{
    Serialize, SerializeInto, generic_serialize_into, generic_export_into,
};
use crate::Cert;


/// Whether or not a character is printable.
pub(crate) fn is_printable(c: &char) -> bool {
    // c.is_ascii_alphanumeric || c.is_whitespace || c.is_ascii_punctuation
    // would exclude any utf8 character, so it seems that to obtain all
    // printable chars, it works just excluding the control chars.
    !c.is_control() && !c.is_ascii_control()
}

impl Cert {
    /// Creates descriptive armor headers.
    ///
    /// Returns armor headers that describe this Cert.  The Cert's
    /// primary fingerprint and userids are included as comments, so
    /// that it is easier to identify the Cert when looking at the
    /// armored data.
    pub fn armor_headers(&self) -> Vec<String> {
        let length_value = armor::LINE_LENGTH - "Comment: ".len();
        // Create a header per userid.
        let mut headers: Vec<String> = self.userids().components()
            // Ignore revoked userids.
            .filter_map(|uidb| {
                if let RevocationStatus::Revoked(_) = uidb.revoked(None) {
                    None
                } else {
                    Some(uidb)
                }
            // Ignore userids not "alive".
            }).filter_map(|uidb| {
                if uidb.binding_signature(None)?
                    .signature_alive(None, None).is_ok()
                {
                    Some(uidb)
                } else {
                    None
                }
            // Ignore userids with non-printable characters.
            }).filter_map(|uidb| {
                let value = str::from_utf8(uidb.userid().value()).ok()?;
                for c in value.chars().take(length_value) {
                    if !is_printable(&c){
                        return None;
                    }
                }
                // Make sure the line length does not exceed armor::LINE_LENGTH
                Some(value.chars().take(length_value).collect())
            }).collect();

        // Add the fingerprint to the front.
        headers.insert(0, self.fingerprint().to_string());

        headers
    }

    /// Wraps this Cert in an armor structure when serialized.
    ///
    /// Derives an object from this Cert that adds an armor structure
    /// to the serialized Cert when it is serialized.  Additionally,
    /// the Cert's userids are added as comments, so that it is easier
    /// to identify the Cert when looking at the armored data.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::cert;
    /// use openpgp::serialize::SerializeInto;
    ///
    /// # f().unwrap();
    /// # fn f() -> openpgp::Result<()> {
    /// let (cert, _) =
    ///     cert::CertBuilder::general_purpose(None, Some("Mr. Pink ☮☮☮"))
    ///     .generate()?;
    /// let armored = String::from_utf8(cert.armored().to_vec()?)?;
    ///
    /// assert!(armored.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
    /// assert!(armored.contains("Mr. Pink ☮☮☮"));
    /// # Ok(()) }
    /// ```
    pub fn armored<'a>(&'a self) -> impl Serialize + SerializeInto + 'a {
        Encoder::new(self)
    }
}

/// A `Cert` to be armored and serialized.
struct Encoder<'a> {
    cert: &'a Cert,
}


impl<'a> Encoder<'a> {
    /// Returns a new Encoder to enarmor and serialize a `Cert`.
    fn new(cert: &'a Cert) -> Self {
        Self {
            cert: cert,
        }
    }

    fn serialize_common(&self, o: &mut dyn io::Write, export: bool)
                        -> Result<()> {
        let headers = self.cert.armor_headers();

        // Convert the Vec<String> into Vec<(&str, &str)>
        // `iter_into` can not be used here because will take ownership and
        // what is needed is the reference.
        let headers: Vec<_> = headers.iter()
            .map(|value| ("Comment", value.as_str()))
            .collect();

        let mut w = armor::Writer::new(o, armor::Kind::PublicKey, &headers)?;
        if export {
            self.cert.export(&mut w)
        } else {
            self.cert.serialize(&mut w)
        }
    }
}

impl<'a> Serialize for Encoder<'a> {
    fn serialize(&self, o: &mut dyn io::Write) -> Result<()> {
        self.serialize_common(o, false)
    }

    fn export(&self, o: &mut dyn io::Write) -> Result<()> {
        self.serialize_common(o, true)
    }
}

impl<'a> SerializeInto for Encoder<'a> {
    fn serialized_len(&self) -> usize {
        let h = self.cert.armor_headers();
        let headers_len =
            "Comment: ".len() * h.len()
            + h.iter().map(|c| c.len()).sum::<usize>();
        let body_len = (self.cert.serialized_len() + 2) / 3 * 4; // base64

        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n".len()
            + headers_len
            + body_len
            + (body_len + armor::LINE_LENGTH - 1) / armor::LINE_LENGTH // NLs
            + "=FUaG\n-----END PGP PUBLIC KEY BLOCK-----\n".len()
    }

    fn serialize_into(&self, buf: &mut [u8]) -> Result<usize> {
        generic_serialize_into(self, buf)
    }

    fn export_into(&self, buf: &mut [u8]) -> Result<usize> {
        generic_export_into(self, buf)
    }
}


#[cfg(test)]
mod tests {
    use crate::armor::{Kind, Reader, ReaderMode};
    use crate::cert::CertBuilder;
    use crate::parse::Parse;

    use super::*;

    #[test]
    fn is_printable_succeed() {
        let chars: Vec<char> = vec![
            'a', 'z', 'A', 'Z', '1', '9', '0',
            '|', '!', '#', '$', '%', '^', '&', '*', '-', '+', '/',
            // The following unicode characters were taken from:
            // https://doc.rust-lang.org/std/primitive.char.html
            'é', 'ß', 'ℝ', '💣', '❤', '東', '京', '𝕊', '💝', 'δ',
            'Δ', '中', '越', '٣', '7', '৬', '¾', '①', 'K',
            'و', '藏', '山', 'I', 'ï', 'İ', 'i'
        ];
        for c in &chars {
            assert!(is_printable(c));
        }
    }

    #[test]
    fn is_printable_fail() {
        let chars: Vec<char> = vec![
            '\n', 0x1b_u8.into(),
            // U+009C, STRING TERMINATOR
            ''
        ];
        for c in &chars {
            assert!(!is_printable(c));
        }
    }

    #[test]
    fn serialize_succeed() {
        let cert = Cert::from_bytes(crate::tests::key("neal.pgp")).unwrap();

        // Enarmor the Cert.
        let mut buffer = Vec::new();
        cert.armored()
            .serialize(&mut buffer)
            .unwrap();

        // Parse the armor.
        let mut cursor = io::Cursor::new(&buffer);
        let mut reader = Reader::new(
            &mut cursor, ReaderMode::Tolerant(Some(Kind::PublicKey)));

        // Extract the headers.
        let mut headers: Vec<&str> = reader.headers()
            .unwrap()
            .into_iter()
            .map(|header| {
                assert_eq!(&header.0[..], "Comment");
                &header.1[..]})
            .collect();
        headers.sort();

        // Ensure the headers are correct
        let mut expected_headers = [
            "Neal H. Walfield <neal@walfield.org>",
            "Neal H. Walfield <neal@gnupg.org>",
            "Neal H. Walfield <neal@pep-project.org>",
            "Neal H. Walfield <neal@pep.foundation>",
            "Neal H. Walfield <neal@sequoia-pgp.org>",
            "8F17 7771 18A3 3DDA 9BA4  8E62 AACB 3243 6300 52D9"];
        expected_headers.sort();

        assert_eq!(&expected_headers[..], &headers[..]);
    }

    #[test]
    fn serialize_length_succeed() {
        let length_value = armor::LINE_LENGTH - "Comment: ".len();

        // Create userids one character longer than the size allowed in the
        // header and expect headers with the correct length.
        // 1 byte character
        // Can not use `to_string` here because not such method for
        //`std::vec::Vec<char>`
        let userid1: String = vec!['a'; length_value + 1].into_iter()
            .collect();
        let userid1_expected: String = vec!['a'; length_value].into_iter()
            .collect();
        // 2 bytes character.
        let userid2: String = vec!['ß'; length_value + 1].into_iter()
            .collect();
        let userid2_expected: String = vec!['ß'; length_value].into_iter()
            .collect();
        // 3 bytes character.
        let userid3: String = vec!['€'; length_value + 1].into_iter()
            .collect();
        let userid3_expected: String = vec!['€'; length_value].into_iter()
            .collect();
        // 4 bytes character.
        let userid4: String = vec!['𐍈'; length_value + 1].into_iter()
            .collect();
        let userid4_expected: String = vec!['𐍈'; length_value].into_iter()
            .collect();
        let mut userid5 = vec!['a'; length_value];
        userid5[length_value-1] = 'ß';
        let userid5: String = userid5.into_iter().collect();

        // Create a Cert with the userids.
        let (cert, _) = CertBuilder::autocrypt(None, Some(&userid1[..]))
            .add_userid(&userid2[..])
            .add_userid(&userid3[..])
            .add_userid(&userid4[..])
            .add_userid(&userid5[..])
            .generate()
            .unwrap();

        // Enarmor the Cert.
        let mut buffer = Vec::new();
        cert.armored()
            .serialize(&mut buffer)
            .unwrap();

        // Parse the armor.
        let mut cursor = io::Cursor::new(&buffer);
        let mut reader = Reader::new(
            &mut cursor, ReaderMode::Tolerant(Some(Kind::PublicKey)));

        // Extract the headers.
        let mut headers: Vec<&str> = reader.headers()
            .unwrap()
            .into_iter()
            .map(|header| {
                assert_eq!(&header.0[..], "Comment");
                &header.1[..]})
            .skip(1) // Ignore the first header since it is the fingerprint
            .collect();
        // Cert canonicalization does not preserve the order of
        // userids.
        headers.sort();

        let mut headers_iter = headers.into_iter();
        assert_eq!(headers_iter.next().unwrap(), &userid1_expected);
        assert_eq!(headers_iter.next().unwrap(), &userid5);
        assert_eq!(headers_iter.next().unwrap(), &userid2_expected);
        assert_eq!(headers_iter.next().unwrap(), &userid3_expected);
        assert_eq!(headers_iter.next().unwrap(), &userid4_expected);
    }
}
