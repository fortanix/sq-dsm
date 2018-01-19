//! Low-level IPC mechanism for Sequoia.
//!
//! # Rationale
//!
//! Sequoia makes use of background services e.g. for managing and
//! updating public keys.
//!
//! # Design
//!
//! We use the filesystem as namespace to discover services.  Every
//! service has a file called rendezvous point.  Access to this file
//! is serialized using file locking.  This file contains a socket
//! address and a cookie that we use to connect to the server and
//! authenticate us.  If the file does not exist, is malformed, or
//! does not point to a usable server, we start a new one on demand.
//!
//! This design mimics Unix sockets, but works on Windows too.
//!
//! # External vs internal servers
//!
//! These servers can be either in external processes, or co-located
//! within the current process.  We will first start an external
//! process, and fall back to starting a thread instead.
//!
//! Using an external process is the preferred option.  It allows us
//! to continuously update the keys in the keystore, for example.  It
//! also means that we do not spawn a thread in your process, which is
//! frowned upon for various reasons.
//!
//! Please see [IPCPolicy] for more information.
//!
//! [IPCPolicy]: ../../sequoia_core/enum.IPCPolicy.html
//!
//! # Note
//!
//! Windows support is currently not implemented, but should be
//! straight forward.

extern crate fs2;
use self::fs2::FileExt;

use std::fs;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, AddrParseError, TcpStream, TcpListener};
use std::path::PathBuf;

use futures::{Future, Stream};

use tokio_core::{self, net};
use tokio_io;
use tokio_io::io::{ReadHalf, ReadExact};
use tokio_io::AsyncRead;

use capnp_rpc::{RpcSystem, twoparty};
use capnp_rpc::rpc_twoparty_capnp::Side;

/* Unix-specific options.  */
use std::os::unix::io::FromRawFd;
use std::os::unix::fs::OpenOptionsExt;

/* XXX: Implement Windows support.  */

use std::process::{Command, Stdio};
use std::os::unix::io::AsRawFd;

use std::thread;

use sequoia_core as core;

/// Servers need to implement this trait.
pub trait Handler {
    /// Called on every connection.
    fn handle(&self,
              network: twoparty::VatNetwork<ReadHalf<net::TcpStream>>)
              -> RpcSystem<Side>;
}

/// A factory for handlers.
pub type HandlerFactory = fn(descriptor: Descriptor,
                             handle: tokio_core::reactor::Handle) -> Option<Box<Handler>>;

/// A descriptor is used to connect to a service.
#[derive(Clone)]
pub struct Descriptor {
    ipc_policy: core::IPCPolicy,
    pub home: PathBuf,
    pub rendezvous: PathBuf,
    executable: PathBuf,
    factory: HandlerFactory,
}

const LOCALHOST: &str = "127.0.0.1";

impl Descriptor {
    /// Create a descriptor given its rendezvous point, the path to
    /// the servers executable file, and a handler factory.
    pub fn new(ctx: &core::Context, rendezvous: PathBuf,
               executable: PathBuf, factory: HandlerFactory)
               -> Self {
        Descriptor {
            home: ctx.home().into(),
            ipc_policy: *ctx.ipc_policy(),
            rendezvous: rendezvous,
            executable: executable,
            factory: factory,
        }
    }

    /// Connect to a descriptor, starting the server if necessary.
    pub fn connect(&self, handle: &tokio_core::reactor::Handle) -> io::Result<RpcSystem<Side>> {
        let do_connect =
            move |cookie: Cookie, mut s: TcpStream| -> io::Result<RpcSystem<Side>> {
            cookie.send(&mut s)?;

            /* Tokioize.  */
            let stream = net::TcpStream::from_stream(s, &handle)?;
            stream.set_nodelay(true)?;
            let (reader, writer) = stream.split();

            let network =
                Box::new(twoparty::VatNetwork::new(reader, writer,
                                                   Side::Client,
                                                   Default::default()));
            let rpc_system = RpcSystem::new(network, None);

            Ok(rpc_system)
        };

        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .open(&self.rendezvous)?;
        file.lock_exclusive()?;

        let mut c = vec![];
        file.read_to_end(&mut c)?;

        if let Some((cookie, a)) = Cookie::extract(c) {
            let addr: Result<SocketAddr, AddrParseError> = String::from_utf8_lossy(&a).parse();
            if addr.is_err() {
                /* Malformed.  Invalidate the cookie and try again.  */
                file.set_len(0)?;
                drop(file);
                return self.connect(handle);
            }

            let stream = TcpStream::connect(addr.unwrap());
            if let Ok(s) = stream {
                do_connect(cookie, s)
            } else {
                /* Failed to connect.  Invalidate the cookie and try again.  */
                file.set_len(0)?;
                drop(file);
                self.connect(handle)
            }
        } else {
            let cookie = Cookie::new()?;
            for external in [true, false].iter() {
                // Implement the IPC pocicy.
                if self.ipc_policy == core::IPCPolicy::Internal && *external {
                    // Do not try to fork.
                    continue;
                }

                let addr = match self.start(*external) {
                    Ok(a) => a,
                    Err(e) => if *external {
                        if self.ipc_policy == core::IPCPolicy::External {
                            // Fail!
                            return Err(e);
                        }

                        // Try to spawn a thread next.
                        continue;
                    } else {
                        // Failed to spawn a thread.
                        return Err(e);
                    }
                };

                let mut stream = TcpStream::connect(addr)?;
                cookie.send(&mut stream)?;

                /* XXX: It'd be nice not to waste this connection.  */
                drop(stream);

                if *external {
                    /* Write connection information to file.  */
                    file.set_len(0)?;
                    cookie.send(&mut file)?;
                    write!(file, "{}:{}", LOCALHOST, addr.port())?;
                }
                drop(file);

                return do_connect(cookie, TcpStream::connect(addr)?);
            }
            unreachable!();
        }
    }

    /// Try to create a TCP socket, bind it to a random port on
    /// localhost.
    fn listen(&self) -> io::Result<TcpListener> {
        let port = OsRng::new()?.next_u32() as u16;
        TcpListener::bind((LOCALHOST, port))
    }

    /// Start the service, either as an external process or as a
    /// thread.
    fn start(&self, external: bool) -> io::Result<SocketAddr> {
        /* Listen on a random port on localhost.  */
        let mut listener = self.listen();
        while listener.is_err() {
            listener = self.listen();
        }
        let listener = listener.unwrap();
        let addr = listener.local_addr()?;

        /* Start the server, connect to it, and send the cookie.  */
        if external {
            self.fork(listener)?;
        } else {
            self.spawn(listener)?;
        }

        Ok(addr)
    }

    fn fork(&self, l: TcpListener) -> io::Result<()> {
        // Convert to raw fd, then forget l so that it will not be
        // closed when it is dropped.
        let fd = l.as_raw_fd();
        ::std::mem::forget(l);

        Command::new(&self.executable.clone().into_os_string())
            .arg("--home")
            .arg(self.home.to_string_lossy().into_owned())
            // l will be closed here if the exec fails.
            .stdin(unsafe { Stdio::from_raw_fd(fd) })
            .spawn()?;
        Ok(())
    }

    fn spawn(&self, l: TcpListener) -> io::Result<()> {
        let descriptor = self.clone();
        thread::spawn(move || -> io::Result<()> {
            Ok(Server::new(descriptor)
               .expect("Failed to spawn server") // XXX
               .serve_listener(l)
               .expect("Failed to spawn server")) // XXX
        });
        Ok(())
    }
}

/// A server.
pub struct Server {
    core: tokio_core::reactor::Core,
    descriptor: Descriptor,
}

impl Server {
    /// Creates a new server for the descriptor.
    pub fn new(descriptor: Descriptor) -> io::Result<Self> {
        Ok(Server {
            core: tokio_core::reactor::Core::new()?,
            descriptor: descriptor,
        })
    }

    /// Turn the current process into an descriptor.  External servers
    /// must call this early on.  Expects 'stdin' to be a listening
    /// TCP socket.
    pub fn serve(&mut self) -> io::Result<()> {
        self.serve_listener(unsafe { TcpListener::from_raw_fd(0) })
    }

    fn serve_listener(&mut self, l: TcpListener) -> io::Result<()> {
        /* The first client tells us our cookie.  */
        let mut i = l.accept()?;
        let cookie = Cookie::receive(&mut i.0)?;
        /* XXX: It'd be nice to recycle this connection.  */
        drop(i);

        let handler = (self.descriptor.factory)(self.descriptor.clone(), self.core.handle())
            .ok_or(
                io::Error::new(io::ErrorKind::BrokenPipe, "Failed to start server"))?;

        /* Tokioize.  */
        let handle = self.core.handle();
        let a = l.local_addr()?;
        let socket = tokio_core::net::TcpListener::from_listener(l, &a, &handle).unwrap();

        let done = socket.incoming().and_then(|(socket, _addr)| {
            let _ = socket.set_nodelay(true);
            Cookie::receive_async(socket)
        }).and_then(|(socket, buf)| {
            if cookie.expect(Cookie::from(&buf)) {
                Ok(socket)
            } else {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "Bad cookie."))
            }
        }).for_each(|socket| {
            let (reader, writer) = socket.split();

            let network =
                twoparty::VatNetwork::new(reader, writer,
                                          Side::Server, Default::default());

            let rpc_system = handler.handle(network);
            handle.spawn(rpc_system.map_err(|e| println!("error: {:?}", e)));
            Ok(())
        });

        self.core.run(done)
    }
}

/// Cookies are used to authenticate clients.
#[derive(PartialEq)]
struct Cookie(Vec<u8>);

extern crate rand;
use self::rand::Rng;
use self::rand::os::OsRng;

const COOKIE_SIZE: usize = 32;

impl Cookie {
    /// Make a new cookie.
    fn new() -> io::Result<Self> {
        let mut c = vec![0; COOKIE_SIZE];
        OsRng::new()?.fill_bytes(&mut c);
        Ok(Cookie(c))
    }

    /// Make a new cookie from a slice.
    fn from(buf: &Vec<u8>) -> Option<Self> {
        if buf.len() == COOKIE_SIZE {
            let mut c = Vec::<u8>::with_capacity(COOKIE_SIZE);
            c.extend_from_slice(buf);
            Some(Cookie(c))
        } else {
            None
        }
    }

    /// Given a vector starting with a cookie, extract it and return
    /// the rest.
    fn extract(mut buf: Vec<u8>) -> Option<(Self, Vec<u8>)> {
        if buf.len() >= COOKIE_SIZE {
            let r = buf.split_off(COOKIE_SIZE);
            Some((Cookie(buf), r))
        } else {
            None
        }
    }

    /// Read a cookie from 'from'.
    fn receive<R: Read>(from: &mut R) -> io::Result<Self> {
        let mut buf = vec![0; COOKIE_SIZE];
        from.read_exact(&mut buf)?;
        Ok(Cookie(buf))
    }

    /// Asynchronously read a cookie from 'socket'.
    fn receive_async(socket: net::TcpStream) -> ReadExact<net::TcpStream,
                                                          Vec<u8>> {
        let buf = vec![0; COOKIE_SIZE];
        tokio_io::io::read_exact(socket, buf)
    }


    /// Check that an asynchronously received cookie matches this
    /// cookie.
    fn expect(&self, other: Option<Cookie>) -> bool {
        if let Some(c) = other {
            c.0 == self.0
        } else {
            false
        }
    }

    /// Write a cookie to 'to'.
    fn send<W: Write>(&self, to: &mut W) -> io::Result<()> {
        to.write_all(&self.0)?;
        Ok(())
    }
}
