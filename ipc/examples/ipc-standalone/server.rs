use anyhow::Result;
use sequoia_ipc as ipc;

pub fn run(mut desc: ipc::Descriptor, socket: Option<usize>) -> Result<()> {
    if let Some(fd) = socket {
        // The server socket is passed on the specified file
        // descriptor.
        if fd != 0 {
            eprintln!("Currently the socket can only be passed on fd 0");
            std::process::exit(1);
        }

        let mut server = ipc::Server::new(desc)?;

        // This blocks the current thread.
        server.serve()?;
    } else {
        // Bootstrap.
        let join_handle = desc.bootstrap()?;

        if let Some(join_handle) = join_handle {
            match join_handle.join() {
                // Server thread panicked.
                Err(err) => panic!("The server thread panicked: {:?}", err),
                // Server thread returned an error.
                Ok(Err(err)) => return Err(err),
                // Server thread exited normally.
                Ok(Ok(())) => (),
            }
        }
    }

    Ok(())
}
