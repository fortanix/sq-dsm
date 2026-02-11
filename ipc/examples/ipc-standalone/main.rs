use anyhow::Result;
use capnp_rpc::pry;
use capnp_rpc::rpc_twoparty_capnp::Side;
use capnp_rpc::{twoparty, RpcSystem};
use clap::{Parser, ValueEnum};
use std::path::PathBuf;

use sequoia_ipc as ipc;

mod hello_protocol_capnp;
use hello_protocol_capnp::hello;

mod client;
mod server;

struct Hello {
    c: hello::Client,
}

impl Hello {
    pub fn new(
        _descriptor: ipc::Descriptor,
        _local: &tokio::task::LocalSet,
    ) -> Result<Box<dyn ipc::Handler>> {
        Ok(Box::new(Self {
            c: capnp_rpc::new_client(HelloServer {}),
        }) as Box<dyn ipc::Handler>)
    }
}

impl ipc::Handler for Hello {
    fn handle(
        &self,
        network: twoparty::VatNetwork<tokio_util::compat::Compat<tokio::net::tcp::OwnedReadHalf>>,
    ) -> RpcSystem<Side> {
        RpcSystem::new(Box::new(network), Some(self.c.clone().client))
    }
}

struct HelloServer {}

impl hello::Server for HelloServer {
    fn hello(
        &mut self,
        params: hello::HelloParams,
        mut results: hello::HelloResults,
    ) -> ::capnp::capability::Promise<(), ::capnp::Error> {
        let p = pry!(params.get());
        let name: String = pry!(p.get_name()).to_string().expect("");
        let response = format!("Hello {}!", name);

        results.get().set_response(&response);

        ::capnp::capability::Promise::ok(())
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum Ephemeral {
    /// Enable ephemeral mode.
    True,
    /// Disable ephemeral mode.
    False,
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[clap(long, help = "Set the server's home directory", default_value = ".")]
    pub home: PathBuf,

    #[clap(long, value_enum, help = "Whether to create an ephemeral context")]
    pub ephemeral: Option<Ephemeral>,

    #[clap(
        long,
        help = "Set the directory containing the server executable",
        default_value = "."
    )]
    pub lib: PathBuf,

    #[clap(long, help = "The socket is passed on the given file descriptor")]
    pub socket: Option<usize>,

    #[clap(long, help = "Whether to run as client")]
    pub client: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut config = ipc::Context::configure();
    config.set_home(&args.home);
    config.set_lib(&args.lib);

    if let Some(Ephemeral::True) = args.ephemeral {
        config.set_ephemeral();
    }

    let c = config.build()?;

    let desc = ipc::Descriptor::new(
        &c,
        c.home().join("ipc-standalone.cookie"),
        std::env::current_exe()?,
        Hello::new,
    );

    if args.client {
        client::run(desc)
    } else {
        server::run(desc, args.socket)
    }
}
