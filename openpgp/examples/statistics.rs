/// Collects statistics about the SKS packet dump using the openpgp
/// crate, Sequoia's low-level API.
///
/// Note that to achieve reasonable performance, you need to compile
/// Sequoia and this program with optimizations:
///
///     % cargo run -p sequoia-openpgp --example statistics --release \
///           -- <packet-dump>

use std::env;
extern crate sequoia_openpgp as openpgp;
use crate::openpgp::Packet;
use crate::openpgp::constants::SignatureType;
use crate::openpgp::packet::{user_attribute, header::BodyLength, Tag};
use crate::openpgp::packet::signature::subpacket::SubpacketTag;
use crate::openpgp::parse::{Parse, PacketParserResult, PacketParser};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        panic!("Collects statistics about OpenPGP packet dumps.\n\n\
                Usage: {} <packet-dump> [<packet-dump>...]\n", args[0]);
    }

    // Global stats.
    let mut packet_count = 0;
    let mut packet_size = 0 as usize;

    // Per-tag statistics.
    let mut tags_count = vec![0; 64];
    let mut tags_unknown = vec![0; 64];
    let mut tags_size_bytes = vec![0 as usize; 64];
    let mut tags_size_count = vec![0; 64];
    let mut tags_size_min = vec![::std::u32::MAX; 64];
    let mut tags_size_max = vec![0; 64];
    let mut sigs_count = vec![0; 256];

    // Signature Subpacket statistics.
    let mut sigs_subpacket_tags_count = vec![0; 256];
    let mut sigs_subpacket_tags_unknown = vec![0; 256];
    let mut sigs_subpacket_tags_size_bytes = vec![0 as usize; 256];
    let mut sigs_subpacket_tags_size_count = vec![0; 256];
    let mut sigs_subpacket_tags_size_min = vec![::std::u32::MAX; 256];
    let mut sigs_subpacket_tags_size_max = vec![0; 256];

    // Per-Signature statistics.
    let mut signature_min = PerSignature::max();
    let mut signature_max = PerSignature::min();

    // Per-TPK statistics.
    let mut tpk_count = 0;
    let mut tpk = PerTPK::min();
    let mut tpk_min = PerTPK::max();
    let mut tpk_max = PerTPK::min();

    // UserAttribute statistics.
    let mut ua_image_count = vec![0; 256];
    let mut ua_unknown_count = vec![0; 256];
    let mut ua_invalid_count = 0;

    // For each input file, create a parser.
    for input in &args[1..] {
        eprintln!("Parsing {}...", input);
        let mut ppr = PacketParser::from_file(input)
            .expect("Failed to create reader");

        // Iterate over all packets.
        while let PacketParserResult::Some(pp) = ppr {
            // While the packet is in the parser, get some data for later.
            let size = match pp.header().length() {
                &BodyLength::Full(n) => Some(n),
                _ => None,
            };

            // Get the packet and advance the parser.
            let (packet, tmp) = pp.next().expect("Failed to get next packet");
            ppr = tmp;

            packet_count += 1;
            if let Some(n) = size {
                packet_size += n as usize;
            }
            let i = u8::from(packet.tag()) as usize;
            tags_count[i] += 1;

            match packet {
                // If a new TPK starts, update TPK statistics.
                Packet::PublicKey(_) | Packet::SecretKey(_) => {
                    if tpk_count > 0 {
                        tpk.update_min_max(&mut tpk_min, &mut tpk_max);
                    }
                    tpk_count += 1;
                    tpk = PerTPK::min();
                },

                Packet::Signature(ref sig) => {
                    sigs_count[u8::from(sig.typ()) as usize] += 1;
                    tpk.sigs[u8::from(sig.typ()) as usize] += 1;
                    let mut signature = PerSignature::min();

                    for (_offset, len, sub) in sig.hashed_area().iter()
                        .chain(sig.unhashed_area().iter())
                    {
                        use crate::openpgp::packet::signature::subpacket::*;
                        let i = u8::from(sub.tag) as usize;
                        sigs_subpacket_tags_count[i] += 1;
                        tpk.sigs_subpacket_tags_count[i] += 1;
                        signature.subpacket_tags_count[i] += 1;
                        if let SubpacketValue::Unknown(_) = sub.value {
                            sigs_subpacket_tags_unknown
                                [u8::from(sub.tag) as usize] += 1;
                        } else {
                            sigs_subpacket_tags_size_bytes[i] += len;
                            sigs_subpacket_tags_size_count[i] += 1;
                            let len = len as u32;
                            if len < sigs_subpacket_tags_size_min[i] {
                                sigs_subpacket_tags_size_min[i] = len;
                            }
                            if len > sigs_subpacket_tags_size_max[i] {
                                sigs_subpacket_tags_size_max[i] = len;
                            }
                        }
                    }

                    signature.update_min_max(&mut signature_min,
                                             &mut signature_max);
                },

                Packet::UserAttribute(ref ua) => {
                    use crate::user_attribute::Subpacket;
                    use crate::user_attribute::Image;
                    for subpacket in ua.subpackets() {
                        match subpacket {
                            Ok(Subpacket::Image(i)) => match i {
                                Image::JPEG(_) =>
                                    ua_image_count[1] += 1,
                                Image::Private(n, _) =>
                                    ua_image_count[n as usize] += 1,
                                Image::Unknown(n, _) =>
                                    ua_image_count[n as usize] += 1,
                            },
                            Ok(Subpacket::Unknown(n, _)) =>
                                ua_unknown_count[n as usize] += 1,
                            Err(_) => ua_invalid_count += 1,
                        }
                    }
                },

                _ => (),
            }

            if let Packet::Unknown(_) = packet {
                tags_unknown[i] += 1;
            } else {
                // Only record size statistics of packets we successfully
                // parsed.
                if let Some(n) = size {
                    tags_size_bytes[i] += n as usize;
                    tags_size_count[i] += 1;
                    if n < tags_size_min[i] {
                        tags_size_min[i] = n;
                    }
                    if n > tags_size_max[i] {
                        tags_size_max[i] = n;
                    }

                    tpk.bytes += n as usize;
                }

                tpk.packets += 1;
                tpk.tags[i] += 1;
            }
        }
        tpk.update_min_max(&mut tpk_min, &mut tpk_max);
    }

    // Print statistics.
    println!("# Packet statistics");
    println!();
    println!("{:>14} {:>9} {:>9} {:>9} {:>9} {:>9} {:>12}",
             "", "count", "unknown",
             "min size", "mean size", "max size", "sum size");
    println!("-------------------------------------------------------\
              -----------------------");

    for t in 0..64 {
        let count = tags_count[t];
        if count > 0 {
            println!("{:>14} {:>9} {:>9} {:>9} {:>9} {:>9} {:>12}",
                     format!("{:?}", Tag::from(t as u8)),
                     count,
                     tags_unknown[t],
                     tags_size_min[t],
                     tags_size_bytes[t] / tags_size_count[t],
                     tags_size_max[t],
                     tags_size_bytes[t]);
        }
    }

    let signature_count = tags_count[u8::from(Tag::Signature) as usize];
    if signature_count > 0 {
        println!();
        println!("# Signature statistics");
        println!();
        println!("{:>22} {:>9}",
                 "", "count",);
        println!("--------------------------------");
        for t in 0..256 {
            let max = tpk_max.sigs[t];
            if max > 0 {
                println!("{:>22} {:>9}",
                         format!("{:?}", SignatureType::from(t as u8)),
                         sigs_count[t]);
            }
        }

        println!();
        println!("# Per-Signature Subpacket statistics");
        println!();
        println!("{:>30} {:>9} {:>9} {:>9}", "", "min", "mean", "max");
        println!("----------------------------------------------------\
                  --------");

        for t in 0..256 {
            let max = signature_max.subpacket_tags_count[t];
            if max > 0 {
                println!("{:>30} {:>9} {:>9} {:>9}",
                         subpacket_short_name(t),
                         signature_min.subpacket_tags_count[t],
                         sigs_subpacket_tags_count[t] / signature_count,
                         max);
            }
        }


        println!();
        println!("# Signature Subpacket statistics");
        println!();
        println!("{:>30} {:>8} {:>6} {:>4} {:>4} {:>5} {:>14}",
                 "", "", "",
                 "min", "mean", "max", "sum");
        println!("{:>30} {:>8} {:>6} {:>4} {:>4} {:>5} {:>14}",
                 "", "#", "?",
                 "size", "size", "size", "size");
        println!("-------------------------------------------------------\
                  ----------------------");

        for t in 0..256 {
            let count = sigs_subpacket_tags_count[t];
            let size_count = sigs_subpacket_tags_size_count[t];
            if size_count > 0 {
                println!("{:>30} {:>8} {:>6} {:>4} {:>4} {:>5} {:>14}",
                         subpacket_short_name(t),
                         count,
                         sigs_subpacket_tags_unknown[t],
                         sigs_subpacket_tags_size_min[t],
                         sigs_subpacket_tags_size_bytes[t] / size_count,
                         sigs_subpacket_tags_size_max[t],
                         sigs_subpacket_tags_size_bytes[t]);
            } else if count > 0 {
                println!("{:>30} {:>8} {:>6} {:>4} {:>4} {:>5} {:>14}",
                         subpacket_short_name(t),
                         count,
                         sigs_subpacket_tags_unknown[t],
                         "-", "-", "-", "-");
            }
        }
    }

    if ua_invalid_count > 0
        || ua_image_count.iter().any(|c| *c > 0)
        || ua_unknown_count.iter().any(|c| *c > 0)
    {
        println!();
        println!("# User Attribute Subpacket statistics");
        println!();
        println!("{:>18} {:>9}",
                 "", "count",);
        println!("----------------------------");
        for t in 0..256 {
            let n = ua_image_count[t];
            if n > 0 {
                println!("{:>18} {:>9}",
                         match t {
                             1 =>         "Image::JPEG".into(),
                             100..=110 => format!("Image::Private({})", t),
                             _ =>         format!("Image::Unknown({})", t),
                         }, n);
            }
        }
        for t in 0..256 {
            let n = ua_unknown_count[t];
            if n > 0 {
                println!("{:>18} {:>9}", format!("Unknown({})", t), n);
            }
        }
        if ua_invalid_count > 0 {
            println!("{:>18} {:>9}", "Invalid", ua_invalid_count);
        }
    }

    if tpk_count == 0 {
        return;
    }

    println!();
    println!("# TPK statistics\n\n\
              {:>30} {:>9} {:>9} {:>9}",
             "", "min", "mean", "max");
    println!("------------------------------------------------------------");
    println!("{:>30} {:>9} {:>9} {:>9}",
             "Size (packets)",
             tpk_min.packets, packet_count / tpk_count, tpk_max.packets);
    println!("{:>30} {:>9} {:>9} {:>9}",
             "Size (bytes)",
             tpk_min.bytes, packet_size / tpk_count, tpk_max.bytes);

    println!("\n{:>30}", "- Packets -");
    for t in 0..64 {
        let max = tpk_max.tags[t];
        if t as u8 != Tag::PublicKey.into() && max > 0 {
            println!("{:>30} {:>9} {:>9} {:>9}",
                     format!("{:?}", Tag::from(t as u8)),
                     tpk_min.tags[t],
                     tags_count[t] / tpk_count,
                     max);
        }
    }

    println!("\n{:>30}", "- Signatures -");
    for t in 0..256 {
        let max = tpk_max.sigs[t];
        if max > 0 {
            println!("{:>30} {:>9} {:>9} {:>9}",
                     format!("{:?}",
                             SignatureType::from(t as u8)),
                     tpk_min.sigs[t],
                     sigs_count[t] / tpk_count,
                     max);
        }
    }

    println!("\n{:>30}", "- Signature Subpackets -");
    for t in 0..256 {
        let max = tpk_max.sigs_subpacket_tags_count[t];
        if max > 0 {
            println!("{:>30} {:>9} {:>9} {:>9}",
                     subpacket_short_name(t),
                     tpk_min.sigs_subpacket_tags_count[t],
                     sigs_subpacket_tags_count[t] / tpk_count,
                     max);
        }
    }
}

fn subpacket_short_name(t: usize) -> String {
    let tag_name = format!("{:?}", SubpacketTag::from(t as u8));
    String::from_utf8_lossy(
        tag_name.as_bytes().chunks(30).next().unwrap()).into()
}

struct PerTPK {
    packets: usize,
    bytes: usize,
    tags: Vec<u32>,
    sigs: Vec<u32>,
    sigs_subpacket_tags_count: Vec<u32>,
}

impl PerTPK {
    fn min() -> Self {
        PerTPK {
            packets: 0,
            bytes: 0,
            tags: vec![0; 64],
            sigs: vec![0; 256],
            sigs_subpacket_tags_count: vec![0; 256],
        }
    }

    fn max() -> Self {
        PerTPK {
            packets: ::std::usize::MAX,
            bytes: ::std::usize::MAX,
            tags: vec![::std::u32::MAX; 64],
            sigs: vec![::std::u32::MAX; 256],
            sigs_subpacket_tags_count: vec![::std::u32::MAX; 256],
        }
    }

    fn update_min_max(&self, min: &mut PerTPK, max: &mut PerTPK) {
        if self.packets < min.packets {
            min.packets = self.packets;
        }
        if self.packets > max.packets {
            max.packets = self.packets;
        }
        if self.bytes < min.bytes {
            min.bytes = self.bytes;
        }
        if self.bytes > max.bytes {
            max.bytes = self.bytes;
        }
        for i in 0..64 {
            if self.tags[i] < min.tags[i] {
                min.tags[i] = self.tags[i];
            }
            if self.tags[i] > max.tags[i] {
                max.tags[i] = self.tags[i];
            }
        }
        for i in 0..256 {
            if self.sigs[i] < min.sigs[i] {
                min.sigs[i] = self.sigs[i];
            }
            if self.sigs[i] > max.sigs[i] {
                max.sigs[i] = self.sigs[i];
            }
        }
        for i in 0..256 {
            if self.sigs_subpacket_tags_count[i] < min.sigs_subpacket_tags_count[i] {
                min.sigs_subpacket_tags_count[i] = self.sigs_subpacket_tags_count[i];
            }
            if self.sigs_subpacket_tags_count[i] > max.sigs_subpacket_tags_count[i] {
                max.sigs_subpacket_tags_count[i] = self.sigs_subpacket_tags_count[i];
            }
        }
    }
}

struct PerSignature {
    subpacket_tags_count: Vec<u32>,
}

impl PerSignature {
    fn min() -> Self {
        PerSignature {
            subpacket_tags_count: vec![0; 256],
        }
    }

    fn max() -> Self {
        PerSignature {
            subpacket_tags_count: vec![::std::u32::MAX; 256],
        }
    }

    fn update_min_max(&self, min: &mut PerSignature, max: &mut PerSignature) {
        for i in 0..256 {
            if self.subpacket_tags_count[i] < min.subpacket_tags_count[i] {
                min.subpacket_tags_count[i] = self.subpacket_tags_count[i];
            }
            if self.subpacket_tags_count[i] > max.subpacket_tags_count[i] {
                max.subpacket_tags_count[i] = self.subpacket_tags_count[i];
            }
        }
    }
}
