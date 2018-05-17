use nettle::Hash;
use nettle::hash::insecure_do_not_use::Sha1;

use {
    Key,
    KeyID,
    Fingerprint,
};

#[cfg(test)]
use std::path::PathBuf;

#[cfg(test)]
fn path_to(artifact: &str) -> PathBuf {
    [env!("CARGO_MANIFEST_DIR"), "tests", "data", "messages", artifact]
        .iter().collect()
}

impl Key {
    /// Computes and returns the key's fingerprint as per Section 12.2
    /// of RFC 4880.
    pub fn fingerprint(&self) -> Fingerprint {
        let mut h = Sha1::default();

        self.hash(&mut h);

        let mut digest = vec![0u8; h.digest_size()];
        h.digest(&mut digest);
        Fingerprint::from_bytes(digest.as_slice())
    }

    /// Computes and returns the key's key ID as per Section 12.2 of
    /// RFC 4880.
    pub fn keyid(&self) -> KeyID {
        self.fingerprint().to_keyid()
    }
}

#[cfg(test)]
mod fingerprint_test {
    use super::*;

    use Packet;
    use Message;

    #[test]
    fn fingerprint_test () {
        let path = path_to("public-key.gpg");
        let message = Message::from_file(&path).unwrap();

        // The blob contains a public key and a three subkeys.
        let mut pki = 0;
        let mut ski = 0;

        let pks = [ "8F17 7771 18A3 3DDA 9BA4  8E62 AACB 3243 6300 52D9" ];
        let sks = [ "C03F A641 1B03 AE12 5764  6118 7223 B566 78E0 2528",
                    "50E6 D924 308D BF22 3CFB  510A C2B8 1905 6C65 2598",
                    "2DC5 0AB5 5BE2 F3B0 4C2D  2CF8 A350 6AFB 820A BD08"];

        for p in message.descendants() {
            if let &Packet::PublicKey(ref p) = p {
                let fp = p.fingerprint().to_string();
                // eprintln!("PK: {:?}", fp);

                assert!(pki < pks.len());
                assert_eq!(fp, pks[pki]);
                pki += 1;
            }

            if let &Packet::PublicSubkey(ref p) = p {
                let fp = p.fingerprint().to_string();
                // eprintln!("SK: {:?}", fp);

                assert!(ski < sks.len());
                assert_eq!(fp, sks[ski]);
                ski += 1;
            }
        }
        assert!(pki == pks.len() && ski == sks.len());
    }
}
