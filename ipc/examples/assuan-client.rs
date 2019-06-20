extern crate futures;
use futures::future::Future;
use futures::stream::Stream;
extern crate clap;
extern crate sequoia_ipc as ipc;
use ipc::assuan::Client;

fn main() {
    let matches = clap::App::new("assuan-client")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Connects to and sends commands to assuan servers.")
        .arg(clap::Arg::with_name("server").value_name("PATH")
             .required(true)
             .help("Server to connect to"))
        .arg(clap::Arg::with_name("commands").value_name("COMMAND")
             .required(true)
             .multiple(true)
             .help("Commands to send to the server"))
        .get_matches();

    let mut c = Client::connect(matches.value_of("server").unwrap())
        .wait().unwrap();
    for command in matches.values_of("commands").unwrap() {
        eprintln!("> {}", command);
        c.send(command).unwrap();
        c.by_ref().for_each(|response| {
            eprintln!("< {:?}", response);
            Ok(())
        }).wait().unwrap();
    }
}
