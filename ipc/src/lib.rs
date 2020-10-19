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

use std::fs;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream, TcpListener};
use std::path::PathBuf;

use anyhow::{anyhow, Result};
use fs2::FileExt;

use tokio_util::compat::Compat;

use capnp_rpc::{RpcSystem, twoparty};
use capnp_rpc::rpc_twoparty_capnp::Side;

#[cfg(unix)]
use std::os::unix::{io::{IntoRawFd, FromRawFd}, fs::OpenOptionsExt};
#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, IntoRawSocket, FromRawSocket};
#[cfg(windows)]
use winapi::um::winsock2;

use std::process::{Command, Stdio};
use std::thread;

use sequoia_openpgp as openpgp;
use sequoia_core as core;

// Turns an `if let` into an expression so that it is possible to do
// things like:
//
// ```rust,nocompile
// if destructures_to(Foo::Bar(_) = value)
//    || destructures_to(Foo::Bam(_) = value) { ... }
// ```
// TODO: Replace with `std::matches!` once MSRV is bumped to 1.42.
#[cfg(test)]
macro_rules! destructures_to {
    ( $error: pat = $expr:expr ) => {
        {
            let x = $expr;
            if let $error = x {
                true
            } else {
                false
            }
        }
    };
}

#[macro_use] mod trace;
pub mod assuan;
pub mod gnupg;
mod keygrip;
pub use self::keygrip::Keygrip;
pub mod sexp;

#[cfg(test)]
mod tests;

macro_rules! platform {
    { unix => { $($unix:tt)* }, windows => { $($windows:tt)* } } => {
        if cfg!(unix) {
            #[cfg(unix)] { $($unix)* }
            #[cfg(not(unix))] { unreachable!() }
        } else if cfg!(windows) {
            #[cfg(windows)] { $($windows)* }
            #[cfg(not(windows))] { unreachable!() }
        } else {
            #[cfg(not(any(unix, windows)))] compile_error!("Unsupported platform");
            unreachable!()
        }
    }
}

/// Servers need to implement this trait.
pub trait Handler {
    /// Called on every connection.
    fn handle(&self,
              network: twoparty::VatNetwork<Compat<tokio::net::tcp::OwnedReadHalf>>)
              -> RpcSystem<Side>;
}

/// A factory for handlers.
pub type HandlerFactory = fn(
    descriptor: Descriptor,
    local: &tokio::task::LocalSet
) -> Result<Box<dyn Handler>>;

/// A descriptor is used to connect to a service.
#[derive(Clone)]
pub struct Descriptor {
    ctx: core::Context,
    rendezvous: PathBuf,
    executable: PathBuf,
    factory: HandlerFactory,
}

impl Descriptor {
    /// Create a descriptor given its rendezvous point, the path to
    /// the servers executable file, and a handler factory.
    pub fn new(ctx: &core::Context, rendezvous: PathBuf,
               executable: PathBuf, factory: HandlerFactory)
               -> Self {
        Descriptor {
            ctx: ctx.clone(),
            rendezvous,
            executable,
            factory,
        }
    }

    /// Returns the context.
    pub fn context(&self) -> &core::Context {
        &self.ctx
    }

    /// Connects to a descriptor, starting the server if necessary.
    ///
    /// # Panic
    /// This will panic if called outside of the Tokio runtime context. See
    /// See [`Handle::enter`] for more details.
    ///
    /// [`Handle::enter`]: https://docs.rs/tokio/0.2.22/tokio/runtime/struct.Handle.html#method.enter
    pub fn connect(&self) -> Result<RpcSystem<Side>> {
        self.connect_with_policy(*self.ctx.ipc_policy())
    }

    /// Connects to a descriptor, starting the server if necessary.
    ///
    /// This function does not use the context's IPC policy, but uses
    /// the given one.
    ///
    /// # Panic
    /// This will panic if called outside of the Tokio runtime context. See
    /// See [`Handle::enter`] for more details.
    ///
    /// [`Handle::enter`]: https://docs.rs/tokio/0.2.22/tokio/runtime/struct.Handle.html#method.enter
    pub fn connect_with_policy(&self, policy: core::IPCPolicy)
                   -> Result<RpcSystem<Side>> {
        let do_connect = |cookie: Cookie, mut s: TcpStream| {
            cookie.send(&mut s)?;

            /* Tokioize.  */
            let stream = tokio::net::TcpStream::from_std(s)?;
            stream.set_nodelay(true)?;

            let (reader, writer) = stream.into_split();
            use tokio_util::compat::Tokio02AsyncReadCompatExt;
            use tokio_util::compat::Tokio02AsyncWriteCompatExt;
            let (reader, writer) = (reader.compat(), writer.compat_write());

            let network =
                Box::new(twoparty::VatNetwork::new(reader, writer,
                                                   Side::Client,
                                                   Default::default()));

            Ok(RpcSystem::new(network, None))
        };

        fs::create_dir_all(self.ctx.home())?;
        let mut file = fs::OpenOptions::new();
        file
            .read(true)
            .write(true)
            .create(true);
        #[cfg(unix)]
        file.mode(0o600);
        let mut file = file.open(&self.rendezvous)?;
        file.lock_exclusive()?;

        let mut c = vec![];
        file.read_to_end(&mut c)?;

        if let Some((cookie, rest)) = Cookie::extract(c) {
            let stream = String::from_utf8(rest).map_err(drop)
                .and_then(|rest| rest.parse::<SocketAddr>().map_err(drop))
                .and_then(|addr| TcpStream::connect(addr).map_err(drop));

            if let Ok(s) = stream {
                do_connect(cookie, s)
            } else {
                /* Failed to connect.  Invalidate the cookie and try again.  */
                file.set_len(0)?;
                drop(file);
                self.connect()
            }
        } else {
            let cookie = Cookie::new();

            let (addr, external) = match policy {
                core::IPCPolicy::Internal => self.start(false)?,
                core::IPCPolicy::External => self.start(true)?,
                core::IPCPolicy::Robust => self.start(true)
                    .or_else(|_| self.start(false))?
            };

            /* XXX: It'd be nice not to waste this connection.  */
            cookie.send(&mut TcpStream::connect(addr)?)?;

            if external {
                /* Write connection information to file.  */
                file.set_len(0)?;
                file.write_all(&cookie.0)?;
                write!(file, "{}", addr)?;
            }
            drop(file);

            do_connect(cookie, TcpStream::connect(addr)?)
        }
    }

    /// Start the service, either as an external process or as a
    /// thread.
    fn start(&self, external: bool) -> Result<(SocketAddr, bool)> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr()?;

        /* Start the server, connect to it, and send the cookie.  */
        if external {
            self.fork(listener)?;
        } else {
            self.spawn(listener)?;
        }

        Ok((addr, external))
    }

    fn fork(&self, listener: TcpListener) -> Result<()> {
        let mut cmd = Command::new(&self.executable);
        cmd
            .arg("--home")
            .arg(self.ctx.home())
            .arg("--lib")
            .arg(self.ctx.lib())
            .arg("--ephemeral")
            .arg(self.ctx.ephemeral().to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        platform! {
            unix => {
                // Pass the listening TCP socket as child stdin.
                cmd.stdin(unsafe { Stdio::from_raw_fd(listener.into_raw_fd()) });
            },
            windows => {
                // Sockets for `TcpListener` are not inheritable by default, so
                // let's make them so, since we'll pass them to a child process.
                unsafe {
                    match winapi::um::handleapi::SetHandleInformation(
                        listener.as_raw_socket() as _,
                        winapi::um::winbase::HANDLE_FLAG_INHERIT,
                        winapi::um::winbase::HANDLE_FLAG_INHERIT,
                    ) {
                        0 => Err(std::io::Error::last_os_error()),
                        _ => Ok(())
                    }?
                };
                // We can't pass the socket to stdin directly on Windows, since
                // non-overlapped (blocking) I/O handles can be redirected there.
                // We use Tokio (async I/O), so we just pass it via env var rather
                // than establishing a separate channel to pass the socket through.
                cmd.env("SOCKET", format!("{}", listener.into_raw_socket()));
            }
        }

        cmd.spawn()?;
        Ok(())
    }

    fn spawn(&self, l: TcpListener) -> Result<()> {
        let descriptor = self.clone();
        thread::spawn(move || -> Result<()> {
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
    runtime: tokio::runtime::Runtime,
    descriptor: Descriptor,
}

impl Server {
    /// Creates a new server for the descriptor.
    pub fn new(descriptor: Descriptor) -> Result<Self> {
        Ok(Server {
            runtime: tokio::runtime::Runtime::new()?,
            descriptor,
        })
    }

    /// Creates a Context from `env::args()`.
    pub fn context() -> Result<core::Context> {
        use std::env::args;
        let args: Vec<String> = args().collect();

        if args.len() != 7 || args[1] != "--home"
            || args[3] != "--lib" || args[5] != "--ephemeral" {
                return Err(anyhow!(
                    "Usage: {} --home <HOMEDIR> --lib <LIBDIR> \
                     --ephemeral true|false", args[0]));
            }

        let mut cfg = core::Context::configure()
            .home(&args[2]).lib(&args[4]);

        if let Ok(ephemeral) = args[6].parse() {
            if ephemeral {
                cfg.set_ephemeral();
            }
        } else {
            return Err(anyhow!(
                "Expected 'true' or 'false' for --ephemeral, got: {}",
                args[6]));
        }

        cfg.build()
    }

    /// Turns this process into a server.
    ///
    /// External servers must call this early on.
    ///
    /// On Linux expects 'stdin' to be a listening TCP socket.
    /// On Windows this expects `SOCKET` env var to be set to a listening socket
    /// of the Windows Sockets API `SOCKET` value.
    ///
    /// # Examples
    ///
    /// ```compile_fail
    /// // We cannot run this because sequoia-store is not built yet.
    /// use sequoia_core;
    /// use sequoia_net;
    /// use sequoia_store;
    ///
    /// use sequoia_ipc::Server;
    ///
    /// fn main() {
    ///     let ctx = Server::context()
    ///         .expect("Failed to create context");
    ///     Server::new(sequoia_store::descriptor(&ctx))
    ///         .expect("Failed to create server")
    ///         .serve()
    ///         .expect("Failed to start server");
    /// }
    /// ```
    pub fn serve(&mut self) -> Result<()> {
        let listener = platform! {
            unix => { unsafe { TcpListener::from_raw_fd(0) } },
            windows => {
                let socket = std::env::var("SOCKET")?.parse()?;
                unsafe { TcpListener::from_raw_socket(socket) }
            }
        };
        self.serve_listener(listener)
    }

    fn serve_listener(&mut self, l: TcpListener) -> Result<()> {
        /* The first client tells us our cookie.  */
        let cookie = {
            /* XXX: It'd be nice to recycle this connection.  */
            let mut i = l.accept()?;
            Cookie::receive(&mut i.0)?
        };

        /* Tokioize.  */
        let local = tokio::task::LocalSet::new();
        let handler = (self.descriptor.factory)(self.descriptor.clone(), &local)?;

        let server = async move {
            let mut socket = tokio::net::TcpListener::from_std(l).unwrap();

            loop {
                let (mut socket, _) = socket.accept().await?;

                let _ = socket.set_nodelay(true);
                let received_cookie = Cookie::receive_async(&mut socket).await?;
                if received_cookie != cookie {
                    return Err(anyhow::anyhow!("Bad cookie"));
                }

                let (reader, writer) = socket.into_split();

                use tokio_util::compat::Tokio02AsyncReadCompatExt;
                use tokio_util::compat::Tokio02AsyncWriteCompatExt;
                let (reader, writer) = (reader.compat(), writer.compat_write());

                let network =
                    twoparty::VatNetwork::new(reader, writer,
                                            Side::Server, Default::default());

                let rpc_system = handler.handle(network);
                let _ = tokio::task::spawn_local(rpc_system).await;
            }
        };

        local.block_on(&mut self.runtime, server)
    }
}

/// Cookies are used to authenticate clients.
struct Cookie(Vec<u8>);

use rand::RngCore;
use rand::rngs::OsRng;

impl Cookie {
    const SIZE: usize = 32;

    /// Make a new cookie.
    fn new() -> Self {
        let mut c = vec![0; Cookie::SIZE];
        OsRng.fill_bytes(&mut c);
        Cookie(c)
    }

    /// Make a new cookie from a slice.
    fn from(buf: &[u8]) -> Option<Self> {
        if buf.len() == Cookie::SIZE {
            let mut c = Vec::with_capacity(Cookie::SIZE);
            c.extend_from_slice(buf);
            Some(Cookie(c))
        } else {
            None
        }
    }

    /// Given a vector starting with a cookie, extract it and return
    /// the rest.
    fn extract(mut buf: Vec<u8>) -> Option<(Self, Vec<u8>)> {
        if buf.len() >= Cookie::SIZE {
            let r = buf.split_off(Cookie::SIZE);
            Some((Cookie(buf), r))
        } else {
            None
        }
    }

    /// Read a cookie from 'from'.
    fn receive<R: Read>(from: &mut R) -> Result<Self> {
        let mut buf = vec![0; Cookie::SIZE];
        from.read_exact(&mut buf)?;
        Ok(Cookie(buf))
    }

    /// Asynchronously read a cookie from 'socket'.
    async fn receive_async(socket: &mut tokio::net::TcpStream) -> io::Result<Cookie> {
        use tokio::io::AsyncReadExt;

        let mut buf = vec![0; Cookie::SIZE];
        socket.read_exact(&mut buf).await?;
        Ok(Cookie::from(&buf).expect("enough bytes read"))
    }


    /// Write a cookie to 'to'.
    fn send<W: Write>(&self, to: &mut W) -> io::Result<()> {
        to.write_all(&self.0)
    }
}

impl PartialEq for Cookie {
    fn eq(&self, other: &Cookie) -> bool {
        // First, compare the length.
        self.0.len() == other.0.len()
            // The length is not a secret, hence we can use && here.
            && unsafe {
                ::memsec::memeq(self.0.as_ptr(),
                                other.0.as_ptr(),
                                self.0.len())
            }
    }
}

#[derive(thiserror::Error, Debug)]
/// Errors returned from the network routines.
pub enum Error {
    /// Handshake failed.
    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),
    /// Connection closed unexpectedly.
    #[error("Connection closed unexpectedly.")]
    ConnectionClosed(Vec<u8>),
}

// Global initialization and cleanup of the Windows Sockets API (WSA) module.
// NOTE: This has to be top-level in order for `ctor::{ctor, dtor}` to work.
#[cfg(windows)]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(windows)]
static WSA_INITED: AtomicBool = AtomicBool::new(false);

#[cfg(windows)]
#[ctor::ctor]
fn wsa_startup() {
    unsafe {
        let ret = winsock2::WSAStartup(
            0x202, // version 2.2
            &mut std::mem::zeroed(),
        );
        WSA_INITED.store(ret != 0, Ordering::SeqCst);
    }
}

#[cfg(windows)]
#[ctor::dtor]
fn wsa_cleanup() {
    if WSA_INITED.load(Ordering::SeqCst) {
        let _ = unsafe { winsock2::WSACleanup() };
    }
}
