use crate::hello_protocol_capnp::hello;
use anyhow::Result;
use capnp_rpc::rpc_twoparty_capnp::Side;
use sequoia_ipc as ipc;

pub fn run(desc: ipc::Descriptor) -> Result<()> {
    let client = async move {
        let mut rpc_system = desc.connect()?;
        let hello: hello::Client = rpc_system.bootstrap(Side::Server);

        tokio::task::spawn_local(rpc_system);

        let mut request = hello.hello_request();
        request.get().set_name("ipc-client");

        let response = request.send().promise.await?;

        println!("received: {}", response.get()?.get_response()?.to_str()?);

        Ok(())
    };

    let local = tokio::task::LocalSet::new();
    let runtime = tokio::runtime::Runtime::new()?;
    local.block_on(&runtime, client)
}
