//! IPC mechanisms for Sequoia.
//!
//! This crate implements IPC mechanisms to communicate with Sequoia
//! services.
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
//! Please see [`IPCPolicy`] for more information.

#![doc(html_favicon_url = "https://docs.sequoia-pgp.org/favicon.png")]
#![doc(html_logo_url = "https://docs.sequoia-pgp.org/logo.svg")]
#![warn(missing_docs)]

use std::fs;
use std::io::{self, Read, Seek, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream, TcpListener};
use std::path::Path;
use std::path::PathBuf;
use std::thread::JoinHandle;

use anyhow::anyhow;
use anyhow::Context as _;

use fs2::FileExt;

use capnp_rpc::{RpcSystem, twoparty};
use capnp_rpc::rpc_twoparty_capnp::Side;
pub use capnp_rpc as capnp_rpc;

#[cfg(unix)]
use std::os::unix::{io::{IntoRawFd, FromRawFd}, fs::OpenOptionsExt};
#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, IntoRawSocket, FromRawSocket};
#[cfg(windows)]
use winapi::um::winsock2;

use std::process::{Command, Stdio};
use std::thread;

#[macro_use] mod macros;
pub mod keybox;
mod keygrip;
pub use self::keygrip::Keygrip;
pub mod sexp;
mod core;
pub use crate::core::{Config, Context, IPCPolicy};

#[cfg(test)]
mod tests;

/// Servers need to implement this trait.
pub trait Handler {
    /// Called on every connection.
    fn handle(&self,
              network: capnp_rpc::twoparty::VatNetwork<tokio_util::compat::Compat<tokio::net::tcp::OwnedReadHalf>>)
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

impl std::fmt::Debug for Descriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Descriptor")
            .field("rendezvous", &self.rendezvous)
            .field("executable", &self.executable)
            .finish()
    }
}

impl Descriptor {
    /// Create a descriptor given its rendez-vous point, the path to
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

    /// Returns the rendez-vous point.
    pub fn rendez_vous(&self) -> &Path {
        &self.rendezvous
    }

    /// Connects to a descriptor, starting the server if necessary.
    ///
    /// # Panic
    /// This will panic if called outside of the Tokio runtime context. See
    /// See [`Handle::enter`] for more details.
    ///
    /// [`Handle::enter`]: tokio::runtime::Handle::enter()
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
    /// [`Handle::enter`]: tokio::runtime::Handle::enter()
    pub fn connect_with_policy(&self, policy: core::IPCPolicy)
                   -> Result<RpcSystem<Side>> {
        let do_connect = |cookie: Cookie, mut s: TcpStream| {
            cookie.send(&mut s)?;

            /* Tokioize.  */
            s.set_nonblocking(true)?;
            let stream = tokio::net::TcpStream::from_std(s)?;
            stream.set_nodelay(true)?;

            let (reader, writer) = stream.into_split();
            use tokio_util::compat::TokioAsyncReadCompatExt;
            use tokio_util::compat::TokioAsyncWriteCompatExt;
            let (reader, writer) = (reader.compat(), writer.compat_write());

            let network =
                Box::new(twoparty::VatNetwork::new(reader, writer,
                                                   Side::Client,
                                                   Default::default()));

            Ok(RpcSystem::new(network, None))
        };

        fs::create_dir_all(self.ctx.home())?;

        let mut file = CookieFile::open(&self.rendezvous)?;

        if let Some((cookie, rest)) = file.read()? {
            let stream = String::from_utf8(rest).map_err(drop)
                .and_then(|rest| rest.parse::<SocketAddr>().map_err(drop))
                .and_then(|addr| TcpStream::connect(addr).map_err(drop));

            if let Ok(s) = stream {
                do_connect(cookie, s)
            } else {
                /* Failed to connect.  Invalidate the cookie and try again.  */
                file.clear()?;
                drop(file);
                self.connect()
            }
        } else {
            let cookie = Cookie::new();

            let (addr, external, _join_handle) = match policy {
                core::IPCPolicy::Internal => self.start(false)?,
                core::IPCPolicy::External => self.start(true)?,
                core::IPCPolicy::Robust => self.start(true)
                    .or_else(|_| self.start(false))?
            };

            /* XXX: It'd be nice not to waste this connection.  */
            cookie.send(&mut TcpStream::connect(addr)?)?;

            if external {
                /* Write connection information to file.  */
                file.write(&cookie, format!("{}", addr).as_bytes())?;
            }
            drop(file);

            do_connect(cookie, TcpStream::connect(addr)?)
        }
    }

    /// Start the service, either as an external process or as a
    /// thread.
    fn start(&self, external: bool)
        -> Result<(SocketAddr, bool, Option<JoinHandle<Result<()>>>)>
    {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr()?;

        /* Start the server, connect to it, and send the cookie.  */
        let join_handle: Option<JoinHandle<Result<()>>> = if external {
            self.fork(listener)?;
            None
        } else {
            Some(self.spawn(listener)?)
        };

        Ok((addr, external, join_handle))
    }

    fn fork(&self, listener: TcpListener) -> Result<()> {
        let mut cmd = new_background_command(&self.executable);
        cmd
            .arg("--home")
            .arg(self.ctx.home())
            .arg("--lib")
            .arg(self.ctx.lib())
            .arg("--ephemeral")
            .arg(self.ctx.ephemeral().to_string())
            .arg("--socket").arg("0")
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

    fn spawn(&self, l: TcpListener) -> Result<JoinHandle<Result<()>>> {
        let descriptor = self.clone();
        let join_handle = thread::spawn(move || -> Result<()> {
            Server::new(descriptor)
                .with_context(|| "Failed to spawn server".to_string())?
                .serve_listener(l)
                .with_context(|| "Failed to spawn server".to_string())?;
            Ok(())
        });

        Ok(join_handle)
    }

    /// Turn this process into a server.
    ///
    /// This checks if a server is running.  If not, it turns the
    /// current process into a server.
    ///
    /// This function is for servers trying to start themselves.
    /// Normally, servers are started by clients on demand.  A client
    /// should never call this function.
    pub fn bootstrap(&mut self) -> Result<Option<JoinHandle<Result<()>>>> {
        let mut file = CookieFile::open(&self.rendezvous)?;

        // Try to connect to the server.  If it is already running,
        // we're done.
        if let Some((cookie, rest)) = file.read()? {
            if let Ok(addr) = String::from_utf8(rest).map_err(drop)
                .and_then(|rest| rest.parse::<SocketAddr>().map_err(drop))
            {
                let stream = TcpStream::connect(&addr).map_err(drop);

                if let Ok(mut s) = stream {
                    if let Ok(()) = cookie.send(&mut s) {
                        // There's already a server running.
                        return Ok(None);
                    }
                }
            }
        }

        // Create a new cookie.
        let cookie = Cookie::new();

        // Start an *internal* server.
        let (addr, _external, join_handle) = self.start(false)?;
        let join_handle = join_handle
            .expect("start returns the join handle for in-process servers");

        file.write(&cookie, format!("{}", addr).as_bytes())?;
        // Release the lock.
        drop(file);

        // Send the cookie to the server.
        let mut s = TcpStream::connect(addr)?;
        cookie.send(&mut s)?;

        Ok(Some(join_handle))
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
    pub fn serve(&mut self) -> Result<()> {
        let listener = platform! {
            unix => unsafe { TcpListener::from_raw_fd(0) },
            windows => {
                let socket = std::env::var("SOCKET")?.parse()?;
                unsafe { TcpListener::from_raw_socket(socket) }
            }
        };
        self.serve_listener(listener)
    }

    fn serve_listener(&mut self, l: TcpListener) -> Result<()> {
        // The protocol is:
        //
        // - The first client exclusively locks the cookie file.
        //
        // - The client allocates a TCP socket, and generates a
        //   cookie.
        //
        // - The client starts the server, and passes the listener to
        //   it.
        //
        // - The client connects to the server via the socket, and
        //   sends it the cookie.
        //
        // - The client drops the connection and unlocks the cookie
        //   file thereby allowing other clients to connect.
        //
        // - The server waits for the cookie on the first connection.
        //
        // - The server starts serving clients.
        //
        // Note: this initial connection cannot (currently) be used
        // for executing RPCs; the server closes it immediately after
        // receiving the cookie.

        // The first client sends us the cookie.
        let cookie = {
            let mut i = l.accept()?;
            Cookie::receive(&mut i.0)?
        };

        /* Tokioize.  */
        let local = tokio::task::LocalSet::new();
        let handler = (self.descriptor.factory)(self.descriptor.clone(), &local)?;

        let server = async move {
            l.set_nonblocking(true)?;
            let socket = tokio::net::TcpListener::from_std(l).unwrap();

            loop {
                let (mut socket, _) = socket.accept().await?;

                let _ = socket.set_nodelay(true);
                let received_cookie = match Cookie::receive_async(&mut socket).await {
                    Err(_) => continue, // XXX: Log the error?
                    Ok(received_cookie) => received_cookie,
                };
                if received_cookie != cookie {
                    continue;   // XXX: Log the error?
                }

                let (reader, writer) = socket.into_split();

                use tokio_util::compat::TokioAsyncReadCompatExt;
                use tokio_util::compat::TokioAsyncWriteCompatExt;
                let (reader, writer) = (reader.compat(), writer.compat_write());

                let network =
                    twoparty::VatNetwork::new(reader, writer,
                                            Side::Server, Default::default());

                let rpc_system = handler.handle(network);
                let _ = tokio::task::spawn_local(rpc_system).await;
            }
        };

        local.block_on(&self.runtime, server)
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

/// Wraps a cookie file.
struct CookieFile {
    path: PathBuf,
    file: fs::File,
}

impl CookieFile {
    /// Opens the specified cookie.
    ///
    /// The file is opened, and immediately locked.  (The lock is
    /// dropped when the file is closed.)
    fn open(path: &Path) -> Result<CookieFile> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Creating {}", parent.display()))?;
        }

        let mut file = fs::OpenOptions::new();
        file
            .read(true)
            .write(true)
            .create(true);
        #[cfg(unix)]
        file.mode(0o600);
        let file = file.open(path)
            .with_context(|| format!("Opening {}", path.display()))?;
        file.lock_exclusive()
            .with_context(|| format!("Locking {}", path.display()))?;

        Ok(Self {
            path: path.to_path_buf(),
            file,
        })
    }

    /// Reads the cookie file.
    ///
    /// If the file contains a cookie, returns it and any other data.
    ///
    /// Returns `None` if the file does not contain a cookie.
    fn read(&mut self) -> Result<Option<(Cookie, Vec<u8>)>> {
        let mut content = vec![];
        self.file.read_to_end(&mut content)
            .with_context(|| format!("Opening {}", self.path.display()))?;
        Ok(Cookie::extract(content))
    }

    /// Writes the specified cookie to the cookie file followed by the
    /// specified data.
    ///
    /// The contents of the cookie file are replaced.
    fn write(&mut self, cookie: &Cookie, data: &[u8]) -> Result<()> {
        self.file.rewind()
            .with_context(|| format!("Rewinding {}", self.path.display()))?;
        self.file.set_len(0)
            .with_context(|| format!("Truncating {}", self.path.display()))?;
        self.file.write_all(&cookie.0)
            .with_context(|| format!("Updating {}", self.path.display()))?;
        self.file.write_all(data)
            .with_context(|| format!("Updating {}", self.path.display()))?;

        Ok(())
    }

    /// Clears the cookie file.
    ///
    /// The cookie file is truncated.
    fn clear(&mut self) -> Result<()> {
        self.file.set_len(0)
            .with_context(|| format!("Truncating {}", self.path.display()))?;
        Ok(())
    }
}

#[derive(thiserror::Error, Debug)]
/// Errors returned from the network routines.
pub enum Error {
    /// Connection closed unexpectedly.
    #[error("Connection closed unexpectedly.")]
    ConnectionClosed(Vec<u8>),
}

/// Result type specialization.
pub type Result<T> = ::std::result::Result<T, anyhow::Error>;

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

pub(crate) fn new_background_command<S>(program: S) -> Command
where
    S: AsRef<std::ffi::OsStr>,
{
    let command = Command::new(program);

    #[cfg(windows)]
    let command = {
        use std::os::windows::process::CommandExt;

        // see https://docs.microsoft.com/en-us/windows/win32/procthread/process-creation-flags
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        let mut command = command;
        command.creation_flags(CREATE_NO_WINDOW);
        command
    };

    command
}
