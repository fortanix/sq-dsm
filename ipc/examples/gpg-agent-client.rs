/// Connects to and sends commands to gpg-agent.

extern crate futures;
use futures::future::Future;
use futures::stream::Stream;
extern crate clap;
extern crate sequoia_ipc as ipc;
use crate::ipc::gnupg::{Context, Agent};

fn main() {
    let matches = clap::App::new("gpg-agent-client")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Connects to and sends commands to gpg-agent.")
        .arg(clap::Arg::with_name("homedir").value_name("PATH")
             .long("homedir")
             .help("Use this GnuPG home directory, default: $GNUPGHOME"))
        .arg(clap::Arg::with_name("commands").value_name("COMMAND")
             .required(true)
             .multiple(true)
             .help("Commands to send to the server"))
        .get_matches();

    let ctx = if let Some(homedir) = matches.value_of("homedir") {
        Context::with_homedir(homedir).unwrap()
    } else {
        Context::new().unwrap()
    };
    let mut agent = Agent::connect(&ctx).wait().unwrap();

    for command in matches.values_of("commands").unwrap() {
        eprintln!("> {}", command);
        agent.send(command).unwrap();
        agent.by_ref().for_each(|response| {
            eprintln!("< {:?}", response);
            Ok(())
        }).wait().unwrap();
    }
}
