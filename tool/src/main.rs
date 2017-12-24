/// A command-line frontend for Sequoia.

extern crate clap;

use clap::{Arg, App, SubCommand, AppSettings};
use std::fs::File;
use std::io;

extern crate openpgp;
extern crate sequoia_core;
extern crate sequoia_net;

use openpgp::armor;

fn open_or_stdin(f: Option<&str>) -> Box<io::Read> {
    match f {
        Some(f) => Box::new(File::open(f).unwrap()),
        None => Box::new(io::stdin()),
    }
}

fn create_or_stdout(f: Option<&str>) -> Box<io::Write> {
    match f {
        Some(f) => Box::new(File::create(f).unwrap()),
        None => Box::new(io::stdout()),
    }
}

fn real_main() -> Result<(), io::Error> {
    let matches = App::new("sq")
        .version("0.1.0")
        .about("Sequoia is an implementation of OpenPGP.  This is a command-line frontend.")
        .setting(AppSettings::ArgRequiredElseHelp)
        .subcommand(SubCommand::with_name("enarmor")
                    .about("Applies ASCII Armor to a file")
                    .arg(Arg::with_name("input").value_name("FILE")
                         .long("input")
                         .short("i")
                         .help("Sets the input file to use"))
                    .arg(Arg::with_name("output").value_name("FILE")
                         .long("output")
                         .short("o")
                         .help("Sets the output file to use")))
        .subcommand(SubCommand::with_name("dearmor")
                    .about("Removes ASCII Armor from a file")
                    .arg(Arg::with_name("input").value_name("FILE")
                         .long("input")
                         .short("i")
                         .help("Sets the input file to use"))
                    .arg(Arg::with_name("output").value_name("FILE")
                         .long("output")
                         .short("o")
                         .help("Sets the output file to use")))
        .subcommand(SubCommand::with_name("dump")
                    .about("Lists OpenPGP packets")
                    .arg(Arg::with_name("input").value_name("FILE")
                         .long("input")
                         .short("i")
                         .help("Sets the input file to use"))
                    .arg(Arg::with_name("output").value_name("FILE")
                         .long("output")
                         .short("o")
                         .help("Sets the output file to use"))
                    .arg(Arg::with_name("dearmor")
                         .long("dearmor")
                         .short("A")
                         .help("Remove ASCII Armor from input")))
        .get_matches();

    match matches.subcommand() {
        ("enarmor",  Some(m)) => {
            let mut input = open_or_stdin(m.value_of("input"));
            let mut output = create_or_stdout(m.value_of("output"));
            let mut filter = armor::Writer::new(&mut output, armor::Kind::File);
            io::copy(&mut input, &mut filter).unwrap();
        },
        ("dearmor",  Some(m)) => {
            let mut input = open_or_stdin(m.value_of("input"));
            let mut output = create_or_stdout(m.value_of("output"));
            let mut filter = armor::Reader::new(&mut input, armor::Kind::Any);
            io::copy(&mut filter, &mut output).unwrap();
        },
        ("dump",  Some(m)) => {
            let mut input = open_or_stdin(m.value_of("input"));
            let mut output = create_or_stdout(m.value_of("output"));
            let input = if m.is_present("dearmor") {
                Box::new(armor::Reader::new(&mut input, armor::Kind::Any))
            } else {
                input
            };

            // Indent packets according to their recursion level.
            let indent = "                                                  ";

            let mut ppo
                = openpgp::parse::PacketParserBuilder::from_reader(input)?
                    .finalize()?;
            while ppo.is_some() {
                let mut pp = ppo.unwrap();

                if let openpgp::Packet::Literal(_) = pp.packet {
                    // XXX: We should actually stream this.  In fact,
                    // we probably only want to print out the first
                    // line or so and then print the total number of
                    // bytes.
                    pp.buffer_unread_content()?;
                }
                writeln!(output, "{}{:?}",
                         &indent[0..pp.recursion_depth as usize], pp.packet)?;

                let (_, _, ppo_tmp, _) = pp.recurse()?;
                ppo = ppo_tmp;
            }
        },
        _ => {
            unreachable!();
        },
    }

    return Ok(())
}

fn main() { real_main().expect("An error occured"); }
