//! Select functionality from [assuan-socket.c].
//!
//! [assuan-socket.c]: https://github.com/gpg/libassuan/blob/master/src/assuan-socket.c

use std::io;
use std::path::Path;

use crate::Result;

#[derive(Debug)]
pub(crate) struct Rendezvous {
    port: u16,
    socket_kind: SocketKind,
    nonce: [u8; 16],
}

#[derive(Debug)]
pub(crate) enum SocketKind {
    Cygwin,
    Emulated
}

pub(crate) fn read_port_and_nonce(fname: &Path) -> Result<Rendezvous> {
    let contents = std::fs::read_to_string(fname)?;

    read_port_and_nonce_from_string(&contents)
}

fn read_port_and_nonce_from_string(contents: &str) -> Result<Rendezvous> {
    match contents.strip_prefix("!<socket >") {
        // libassuan's Cygwin compatible socket emulation.
        // Format: "!<socket >%u %c %08x-%08x-%08x-%08x\x00" (scanf-like)
        Some(buf) => {
            let opt_skip_nul = buf.strip_suffix("\x00").unwrap_or(buf);
            // Split into parts: port, kind of socket and nonce
            let mut iter = opt_skip_nul.split_terminator(' ');
            match (iter.next(), iter.next(), iter.next()) {
                (Some(port), Some("s"), Some(nonce)) => {
                    let port = port.parse()?;
                    let socket_kind = SocketKind::Cygwin;

                    // This is wasteful but an allocation-free alternative is even
                    // more verbose and it's not enough to pull a hex parser dep.
                    let nonce_chunks = nonce.split_terminator('-')
                        .map(|dword| u32::from_str_radix(dword, 16).map_err(Into::into))
                        .collect::<Result<Vec<_>>>();

                    let nonce = match nonce_chunks.ok().as_deref() {
                        Some(&[d0, d1, d2, d3, ..]) => {
                            let mut nonce = [0u8; 16];
                            nonce[0..4].copy_from_slice(&d0.to_ne_bytes());
                            nonce[4..8].copy_from_slice(&d1.to_ne_bytes());
                            nonce[8..12].copy_from_slice(&d2.to_ne_bytes());
                            nonce[12..16].copy_from_slice(&d3.to_ne_bytes());
                            nonce
                        },
                        _ => return Err(anyhow::anyhow!("Couldn't parse Cygwin socket nonce: {}", contents)),
                    };
                    Ok(Rendezvous { port, nonce, socket_kind })
                },
                _ => return Err(anyhow::anyhow!("Couldn't parse Cygwin socket: {}", contents)),
            }
        },
        // libassuan's own socket emulation
        // Format: [<whitespace>?, port, .., '\n', <16 byte nonce>]
        None => {
            let pos = match contents.as_bytes().iter().position(|&x| x == b'\n') {
                // Also ensure that there are exactly 16 bytes following
                Some(pos) if pos + 1 + 16 == contents.len() => pos,
                _ => return Err(anyhow::anyhow!("Malformed socket description: {}", contents)),
            };
            let port = contents[..pos].trim().parse()?;
            let mut nonce = [0u8; 16];
            nonce[..].copy_from_slice(&contents.as_bytes()[pos + 1..]);
            let socket_kind = SocketKind::Emulated;

            Ok(Rendezvous { port, nonce, socket_kind: SocketKind::Emulated })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_port_and_nonce_from_files() -> Result<()> {
        let test_fn = read_port_and_nonce_from_string;
        assert!(test_fn("\t 12 \n1234567890123456").is_ok());
        assert!(test_fn("\t 12 \n123456789012345").is_err());
        assert!(test_fn("\t 12 \n12345678901234567").is_err());

        assert!(matches!(
            test_fn("  12345\n\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"),
            Ok(Rendezvous {
                port: 12345,
                socket_kind: SocketKind::Emulated,
                nonce: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            })
        ));
        assert!(matches!(
            test_fn("  -152\n\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"),
            Err(..)
        ));

        assert!(matches!(
            test_fn("!<socket >12345 s AABBCCDD-DDCCBBAA-01234567-890ABCDE\x00"),
            Ok(Rendezvous {
                port: 12345,
                socket_kind: SocketKind::Cygwin,
                nonce: [
                    0xDD, 0xCC, 0xBB, 0xAA,
                    0xAA, 0xBB, 0xCC, 0xDD,
                    0x67, 0x45, 0x23, 0x01,
                    0xDE, 0xBC, 0x0A, 0x89,
                ]
            })
        ));
        assert!(matches!(
            test_fn("!<socket >12345 s AABBCCDD-DDCCBBAA-01234567-890ABCDE"),
            Ok(Rendezvous {
                port: 12345,
                socket_kind: SocketKind::Cygwin,
                nonce: [
                    0xDD, 0xCC, 0xBB, 0xAA,
                    0xAA, 0xBB, 0xCC, 0xDD,
                    0x67, 0x45, 0x23, 0x01,
                    0xDE, 0xBC, 0x0A, 0x89,
                ]
            })
        ));

        Ok(())
    }
}
