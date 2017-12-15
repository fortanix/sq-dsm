use super::*;
use sha1;

#[cfg(test)]
use std::path::PathBuf;

#[cfg(test)]
fn path_to(artifact: &str) -> PathBuf {
    [env!("CARGO_MANIFEST_DIR"), "tests", "data", "messages", artifact]
        .iter().collect()
}

impl Key {
    // Computes and returns the key's fingerprint as per Section 12.2
    // of RFC 4880.
    pub fn fingerprint(&self) -> Fingerprint {
        let mut m = sha1::Sha1::new();

        // We hash 8 bytes plus the MPIs.  But, the len doesn't
        // include the tag (1 byte) or the length (2 bytes).
        let len = (9 - 3) + self.mpis.len();

        let mut header : Vec<u8> = Vec::with_capacity(9);

        // Tag.
        header.push(0x99);

        // Length (big endian).
        header.push(((len >> 8) & 0xFF) as u8);
        header.push((len & 0xFF) as u8);

        // Version.
        header.push(4);

        // Creation time.
        header.push(((self.creation_time >> 24) & 0xFF) as u8);
        header.push(((self.creation_time >> 16) & 0xFF) as u8);
        header.push(((self.creation_time >> 8) & 0xFF) as u8);
        header.push((self.creation_time & 0xFF) as u8);

        // Algorithm.
        header.push(self.pk_algo);

        m.update(&header[..]);

        // MPIs.
        m.update(&self.mpis[..]);

        Fingerprint::from_bytes(&m.digest().bytes()[..])
    }
}

#[cfg(test)]
mod fingerprint_test {
    use super::*;

    #[test]
    fn fingerprint_test () {
        use std::fs::File;
        use ::buffered_reader::*;

        let path = path_to("public-key.gpg");
        let mut f = File::open(&path).expect(&path.to_string_lossy());
        let bio = BufferedReaderGeneric::new(&mut f, None);
        let message = Message::deserialize(bio).unwrap();

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
