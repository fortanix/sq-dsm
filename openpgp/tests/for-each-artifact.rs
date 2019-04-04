use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

extern crate sequoia_openpgp as openpgp;
use openpgp::parse::*;
use openpgp::serialize::Serialize;

mod for_each_artifact {
    use super::*;

    #[test]
    fn packet_roundtrip() {
        for_all_files(&test_data_dir(), |src| {
            for_all_packets(src, |p| {
                let mut v = Vec::new();
                p.serialize(&mut v)?;
                let q = openpgp::Packet::from_bytes(&v)?;
                assert_eq!(p, &q);
                Ok(())
            })
        }).unwrap();
    }
}

/// Computes the path to the test directory.
fn test_data_dir() -> PathBuf {
    let manifest_dir = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR")
        .as_ref()
        .expect("CARGO_MANIFEST_DIR not set"));

    manifest_dir.join("tests").join("data")
}

/// Maps the given function `fun` over all Rust files in `src`.
fn for_all_files<F>(src: &Path, mut fun: F) -> openpgp::Result<()>
    where F: FnMut(&Path) -> openpgp::Result<()>
{
    let mut dirs = vec![src.to_path_buf()];

    while let Some(dir) = dirs.pop() {
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                fun(&path)?;
            }
            if path.is_dir() {
                dirs.push(path.clone());
            }
        }
    }
    Ok(())
}

/// Maps the given function `fun` over all packets in `src`.
fn for_all_packets<F>(src: &Path, mut fun: F) -> openpgp::Result<()>
    where F: FnMut(&openpgp::Packet) -> openpgp::Result<()>
{
    let ppb = PacketParserBuilder::from_file(src)?.buffer_unread_content();
    let mut ppr = if let Ok(ppr) = ppb.finalize() {
        ppr
    } else {
        // Ignore junk.
        return Ok(());
    };

    while let PacketParserResult::Some(pp) = ppr {
        match pp.recurse() {
            Ok((packet, ppr_)) => {
                ppr = ppr_;

                if let openpgp::Packet::Unknown(_) = packet {
                    continue;  // Ignore packets that we cannot parse.
                }

                match fun(&packet) {
                    Ok(_) => (),
                    Err(e) => {
                        eprintln!("Failed on packet {:?}:\n", packet);
                        let mut sink = io::stderr();
                        let mut w = openpgp::armor::Writer::new(
                            &mut sink,
                            openpgp::armor::Kind::File,
                            &[])?;
                        packet.serialize(&mut w)?;
                        return Err(e);
                    },
                }
            },
            Err(_) => break,
        }
    }
    Ok(())
}
