use anyhow::Context as _;
use std::io;

extern crate sequoia_openpgp as openpgp;
use crate::openpgp::packet::Literal;
use crate::openpgp::packet::Tag;
use crate::openpgp::parse::{PacketParser, PacketParserResult, Parse};
use crate::openpgp::serialize::stream::{LiteralWriter, Message};
use crate::openpgp::serialize::Serialize;
use crate::openpgp::{Packet, Result};

pub fn merge_signatures(
    input1: &mut (dyn io::Read + Send + Sync),
    input2: &mut (dyn io::Read + Send + Sync),
    mut sink: Message,
) -> Result<()> {
    let parser1 =
        PacketParser::from_reader(input1).context("Failed to build parser")?;
    let parser2 =
        PacketParser::from_reader(input2).context("Failed to build parser")?;

    let (ops1, post_ops_parser1) = read_while_by_tag(parser1, Tag::OnePassSig)?;
    let (ops2, post_ops_parser2) = read_while_by_tag(parser2, Tag::OnePassSig)?;

    let ops1 = ops1
        .into_iter()
        .map(ops_with_last_false)
        .collect::<Result<Vec<_>>>()?;

    write_packets(ops1, &mut sink)?;
    write_packets(ops2, &mut sink)?;

    let (sink_new, post_literal_parser1, post_literal_parser2) =
        compare_and_write_literal(sink, post_ops_parser1, post_ops_parser2)?;
    sink = sink_new;

    let (sigs2, _) = read_while_by_tag(post_literal_parser2, Tag::Signature)?;
    let (sigs1, _) = read_while_by_tag(post_literal_parser1, Tag::Signature)?;
    write_packets(sigs2, &mut sink)?;
    write_packets(sigs1, &mut sink)?;

    sink.finalize().context("Failed to write data")?;
    Ok(())
}

fn ops_with_last_false(p: Packet) -> Result<Packet> {
    if let Packet::OnePassSig(mut ops) = p {
        ops.set_last(false);
        Ok(Packet::OnePassSig(ops))
    } else {
        Err(anyhow::anyhow!("Not a OnePassSig packet"))
    }
}

fn write_packets(packets: Vec<Packet>, mut sink: &mut Message) -> Result<()> {
    for packet in packets {
        packet.serialize(&mut sink)?;
    }
    Ok(())
}

fn compare_and_write_literal<'a, 'b, 'c>(
    sink: Message<'a>,
    ppr1: PacketParserResult<'b>,
    ppr2: PacketParserResult<'c>,
) -> Result<(Message<'a>, PacketParserResult<'b>, PacketParserResult<'c>)> {
    // We want to compare the bodies of the literal packets, by comparing their digests.
    // Digests are only known after reading the packets, so:
    // First, move both parsers past the literal packet, copy out the body of one of them.
    // Second, compare the packets which now include the correct hashes,
    // normalize to ignore metadata.
    let (mut lp1, ppr1) = read_while_by_tag(ppr1, Tag::Literal)?;
    let lp1 = lp1.remove(0);

    let (sink, lp2, ppr2) = write_literal_(sink, ppr2)?;

    let lp1 = normalize_literal(lp1)?;
    let lp2 = normalize_literal(lp2)?;
    eprintln!("lp1: {:?}", lp1);
    eprintln!("lp2: {:?}", lp2);

    if lp1 == lp2 {
        Ok((sink, ppr1, ppr2))
    } else {
        Err(anyhow::anyhow!("Literal Packets differ, aborting!"))
    }
}

// Clear date and filename.
fn normalize_literal(p: Packet) -> Result<Literal> {
    if let Packet::Literal(mut l) = p {
        l.set_date(None)?;
        l.set_filename(&[])?;
        Ok(l)
    } else {
        Err(anyhow::anyhow!("Not a literal packet"))
    }
}

fn write_literal_<'a, 'b>(
    mut sink: Message<'a>,
    ppr: PacketParserResult<'b>,
) -> Result<(Message<'a>, Packet, PacketParserResult<'b>)> {
    if let PacketParserResult::Some(mut pp) = ppr {
        // Assemble a new Literal packet.
        // Cannot use packet.serialize because that does not include the body.
        if let Packet::Literal(l) = pp.packet.clone() {
            // Create a literal writer to wrap the data in a literal
            // message packet.
            let mut literal = LiteralWriter::new(sink)
                .format(l.format())
                .build()
                .context("Failed to create literal writer")?;
            // Do not add any metadata as it is unprotected anyway.

            // Just copy all the data.
            io::copy(&mut pp, &mut literal).context("Failed to copy data")?;

            // Pop the literal writer.
            sink = literal
                .finalize_one()
                .context("Failed to write literal packet")?
                .unwrap();
        }

        let (packet, ppr) = pp.recurse()?;
        Ok((sink, packet, ppr))
    } else {
        Err(anyhow::anyhow!("Unexpected end of file"))
    }
}

fn read_while_by_tag(
    mut ppr: PacketParserResult,
    tag: Tag,
) -> Result<(Vec<Packet>, PacketParserResult)> {
    let mut result = vec![];

    while let PacketParserResult::Some(pp) = ppr {
        let next_tag_matches = pp.header().ctb().tag() == tag;
        if !next_tag_matches {
            return Ok((result, PacketParserResult::Some(pp)));
        }

        // Start parsing the next packet, recursing.
        let (packet, next_ppr) = pp.recurse()?;
        ppr = next_ppr;
        result.push(packet);
    }

    Ok((result, ppr))
}
