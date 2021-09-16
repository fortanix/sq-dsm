//! GnuPG RPC support.

#![warn(missing_docs)]

use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::ffi::OsStr;
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};

use futures::{Future, Stream};

use std::task::{Poll, self};
use std::pin::Pin;

use sequoia_openpgp as openpgp;
use openpgp::types::HashAlgorithm;
use openpgp::fmt::hex;
use openpgp::crypto;
use openpgp::packet::prelude::*;
use openpgp::parse::Parse;

use crate::Result;
use crate::assuan;
use crate::Keygrip;
use crate::sexp::Sexp;

/// A GnuPG context.
#[derive(Debug)]
pub struct Context {
    homedir: Option<PathBuf>,
    sockets: BTreeMap<String, PathBuf>,
    #[allow(dead_code)] // We keep it around for the cleanup.
    ephemeral: Option<tempfile::TempDir>,
    // XXX: Remove me once hack for Cygwin won't be necessary.
    #[cfg(windows)]
    cygwin: bool,
}

impl Context {
    /// Creates a new context for the default GnuPG home directory.
    pub fn new() -> Result<Self> {
        Self::make(None, None)
    }

    /// Creates a new context for the given GnuPG home directory.
    pub fn with_homedir<P>(homedir: P) -> Result<Self>
        where P: AsRef<Path>
    {
        Self::make(Some(homedir.as_ref()), None)
    }

    /// Creates a new ephemeral context.
    ///
    /// The created home directory will be deleted once this object is
    /// dropped.
    pub fn ephemeral() -> Result<Self> {
        Self::make(None, Some(tempfile::tempdir()?))
    }

    fn make(homedir: Option<&Path>, ephemeral: Option<tempfile::TempDir>)
            -> Result<Self> {
        let mut sockets: BTreeMap<String, PathBuf> = Default::default();

        let ephemeral_dir = ephemeral.as_ref().map(|tmp| tmp.path());
        let homedir = ephemeral_dir.or(homedir);
        // Guess if we're dealing with Unix/Cygwin or native Windows variant
        // We need to do that in order to pass paths in correct style to gpgconf
        let a_gpg_path = Self::gpgconf(&None, &["--list-dirs", "homedir"], 1)?;
        let first_byte = a_gpg_path.get(0).and_then(|c| c.get(0)).and_then(|c| c.get(0));
        let gpg_style = match first_byte {
            Some(b'/') => Mode::Unix,
            _ => Mode::native(),
        };
        let homedir = homedir.map(|dir|
            convert_path(dir, gpg_style)
                .unwrap_or_else(|_| PathBuf::from(dir))
        );

        for fields in Self::gpgconf(&homedir, &["--list-dirs"], 2)? {
            let key = std::str::from_utf8(&fields[0])?;

            // For now, we're only interested in sockets.
            let socket = match key.strip_suffix("-socket") {
                Some(socket) => socket,
                _ => continue,
            };

            // NOTE: Directories and socket paths are percent-encoded if no
            // argument to "--list-dirs" is given
            let mut value = std::str::from_utf8(&fields[1])?.to_owned();
            // FIXME: Percent-decode everything, but for now at least decode
            // colons to support Windows drive letters
            value = value.replace("%3a", ":");
            // Store paths in native format, following the least surprise rule.
            let path = convert_path(&value, Mode::native())?;

            sockets.insert(socket.into(), path);
        }

        /// Whether we're dealing with gpg that expects Windows or Unix-style paths.
        #[derive(Copy, Clone)]
        enum Mode {
            Windows,
            Unix
        }

        impl Mode {
            fn native() -> Self {
                match () {
                    _ if cfg!(windows) => Mode::Windows,
                    _ if cfg!(unix) => Mode::Unix,
                    _ => unimplemented!(),
                }
            }
        }

        #[cfg(not(windows))]
        fn convert_path(path: impl AsRef<OsStr>, mode: Mode) -> Result<PathBuf> {
            match mode {
                Mode::Unix => Ok(PathBuf::from(path.as_ref())),
                Mode::Windows => Err(anyhow::anyhow!(
                    "Converting to Windows-style paths is only supported on Windows"
                )),
            }
        }

        #[cfg(windows)]
        fn convert_path(path: impl AsRef<OsStr>, mode: Mode) -> Result<PathBuf> {
            let conversion_type = match mode {
                Mode::Windows => "--windows",
                Mode::Unix => "--unix",
            };
            crate::new_background_command("cygpath")
		.arg(conversion_type)
		.arg(path.as_ref())
                .output()
                .map_err(Into::into)
                .and_then(|out|
                    if out.status.success() {
                        let output = std::str::from_utf8(&out.stdout)?.trim();
                        Ok(PathBuf::from(output))
                    } else {
                        Err(anyhow::anyhow!(
                            "Executing cygpath encountered error for path {}",
                            path.as_ref().to_string_lossy()
                        ))
                    }
                )
        }

        Ok(Context {
            homedir,
            sockets,
            ephemeral,
            #[cfg(windows)]
            cygwin: cfg!(windows) && matches!(gpg_style, Mode::Unix),
        })
    }

    fn gpgconf(homedir: &Option<PathBuf>, arguments: &[&str], nfields: usize)
               -> Result<Vec<Vec<Vec<u8>>>> {
        let nl = |&c: &u8| c as char == '\n';
        let colon = |&c: &u8| c as char == ':';

        let mut gpgconf = crate::new_background_command("gpgconf");
        if let Some(homedir) = homedir {
            gpgconf.arg("--homedir").arg(homedir);

            // https://dev.gnupg.org/T4496
            gpgconf.env("GNUPGHOME", homedir);
        }

        gpgconf.args(arguments);

        let output = gpgconf.output().map_err(|e| {
            Error::GPGConf(e.to_string())
        })?;

        if output.status.success() {
            let mut result = Vec::new();
            for mut line in output.stdout.split(nl) {
                if line.is_empty() {
                    // EOF.
                    break;
                }

                // Make sure to also skip \r on Windows
                if line[line.len() - 1] == b'\r' {
                    line = &line[..line.len() - 1];
                }

                let fields =
                    line.splitn(nfields, colon).map(|f| f.to_vec())
                    .collect::<Vec<_>>();

                if fields.len() != nfields {
                    return Err(Error::GPGConf(
                        format!("Malformed response, expected {} fields, \
                                 on line: {:?}", nfields, line)).into());
                }

                result.push(fields);
            }
            Ok(result)
        } else {
            Err(Error::GPGConf(String::from_utf8_lossy(
                &output.stderr).into_owned()).into())
        }
    }

    /// Returns the path to `homedir` directory.
    ///
    /// The path returned will be in a local format, i. e. one accepted by
    /// available `gpgconf` or `gpg` tools.
    ///
    ///
    pub fn homedir(&self) -> Option<&Path> {
        self.homedir.as_deref()
    }

    /// Returns the path to a GnuPG socket.
    pub fn socket<C>(&self, socket: C) -> Result<&Path>
        where C: AsRef<str>
    {
        self.sockets.get(socket.as_ref())
            .map(|p| p.as_path())
            .ok_or_else(|| {
            Error::GPGConf(format!("No such socket {:?}",
                                   socket.as_ref())).into()
        })
    }

    /// Creates directories for RPC communication.
    pub fn create_socket_dir(&self) -> Result<()> {
        // FIXME: GnuPG as packaged by MinGW fails to create socketdir because
        // it follows upstream Unix logic, which expects Unix-like `/var/run`
        // sockets to work. Additionally, GnuPG expects to work with and set
        // correct POSIX permissions that MinGW does not even support/emulate,
        // so this fails loudly.
        // Instead, don't do anything and rely on on homedir being treated
        // (correctly) as a fallback here.
        #[cfg(windows)]
        if self.cygwin {
            return Ok(());
        }

        Self::gpgconf(&self.homedir, &["--create-socketdir"], 1)?;
        Ok(())
    }

    /// Removes directories for RPC communication.
    ///
    /// Note: This will stop all servers once they note that their
    /// socket is gone.
    pub fn remove_socket_dir(&self) -> Result<()> {
        Self::gpgconf(&self.homedir, &["--remove-socketdir"], 1)?;
        Ok(())
    }

    /// Starts a GnuPG component.
    pub fn start(&self, component: &str) -> Result<()> {
        self.create_socket_dir()?;
        Self::gpgconf(&self.homedir, &["--launch", component], 1)?;
        Ok(())
    }

    /// Stops a GnuPG component.
    pub fn stop(&self, component: &str) -> Result<()> {
        Self::gpgconf(&self.homedir, &["--kill", component], 1)?;
        Ok(())
    }

    /// Stops all GnuPG components.
    pub fn stop_all(&self) -> Result<()> {
        self.stop("all")
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        if self.ephemeral.is_some() {
            let _ = self.stop_all();
            let _ = self.remove_socket_dir();
        }
    }
}

/// A connection to a GnuPG agent.
pub struct Agent {
    c: assuan::Client,
}

impl Deref for Agent {
    type Target = assuan::Client;

    fn deref(&self) -> &Self::Target {
        &self.c
    }
}

impl DerefMut for Agent {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.c
    }
}

impl Stream for Agent {
    type Item = Result<assuan::Response>;

    /// Attempt to pull out the next value of this stream, returning
    /// None if the stream is finished.
    ///
    /// Note: It _is_ safe to call this again after the stream
    /// finished, i.e. returned `Ready(None)`.
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.c).poll_next(cx)
    }
}

impl Agent {
    /// Connects to the agent.
    ///
    /// Note: This function does not try to start the server.  If no
    /// server is running for the given context, this operation will
    /// fail.
    pub async fn connect<'c>(ctx: &'c Context) -> Result<Self> {
        let path = ctx.socket("agent")?;
        Self::connect_to(path).await
    }

    /// Connects to the agent at the given path.
    ///
    /// Note: This function does not try to start the server.  If no
    /// server is running for the given context, this operation will
    /// fail.
    pub async fn connect_to<P>(path: P) -> Result<Self>
        where P: AsRef<Path>
    {
        Ok(Agent { c: assuan::Client::connect(path).await? })
    }

    /// Creates a signature over the `digest` produced by `algo` using
    /// `key` with the secret bits managed by the agent.
    pub async fn sign<'a, R>(&'a mut self,
                       key: &'a Key<key::PublicParts, R>,
                       algo: HashAlgorithm, digest: &'a [u8])
        -> Result<crypto::mpi::Signature>
        where R: key::KeyRole
    {
        SigningRequest::new(&mut self.c, key, algo, digest).await
    }

    /// Decrypts `ciphertext` using `key` with the secret bits managed
    /// by the agent.
    pub async fn decrypt<'a, R>(&'a mut self,
                          key: &'a Key<key::PublicParts, R>,
                          ciphertext: &'a crypto::mpi::Ciphertext)
        -> Result<crypto::SessionKey>
        where R: key::KeyRole
    {
        DecryptionRequest::new(&mut self.c, key, ciphertext).await
    }

    /// Computes options that we want to communicate.
    fn options() -> Vec<String> {
        use std::env::var;

        let mut r = Vec::new();

        if let Ok(tty) = var("GPG_TTY") {
            r.push(format!("OPTION ttyname={}", tty));
        } else {
            #[cfg(unix)]
            unsafe {
                use std::ffi::CStr;
                let tty = libc::ttyname(0);
                if ! tty.is_null() {
                    if let Ok(tty) = CStr::from_ptr(tty).to_str() {
                        r.push(format!("OPTION ttyname={}", tty));
                    }
                }
            }
        }

        if let Ok(term) = var("TERM") {
            r.push(format!("OPTION ttytype={}", term));
        }

        if let Ok(display) = var("DISPLAY") {
            r.push(format!("OPTION display={}", display));
        }

        if let Ok(xauthority) = var("XAUTHORITY") {
            r.push(format!("OPTION xauthority={}", xauthority));
        }

        if let Ok(dbus) = var("DBUS_SESSION_BUS_ADDRESS") {
            r.push(format!("OPTION putenv=DBUS_SESSION_BUS_ADDRESS={}", dbus));
        }

        // We're going to pop() options off the end, therefore reverse
        // the vec here to preserve the above ordering, which is the
        // one GnuPG uses.
        r.reverse();
        r
    }
}

struct SigningRequest<'a, 'b, 'c, R>
    where R: key::KeyRole
{
    c: &'a mut assuan::Client,
    key: &'b Key<key::PublicParts, R>,
    algo: HashAlgorithm,
    digest: &'c [u8],
    options: Vec<String>,
    state: SigningRequestState,
}

impl<'a, 'b, 'c, R> SigningRequest<'a, 'b, 'c, R>
    where R: key::KeyRole
{
    fn new(c: &'a mut assuan::Client,
           key: &'b Key<key::PublicParts, R>,
           algo: HashAlgorithm,
           digest: &'c [u8])
           -> Self {
        Self {
            c, key, algo, digest,
            options: Agent::options(),
            state: SigningRequestState::Start,
        }
    }
}

#[derive(Debug)]
enum SigningRequestState {
    Start,
    Options,
    SigKey,
    SetHash,
    PkSign(Vec<u8>),
}

/// Returns a convenient Err value for use in the state machines
/// below.
fn operation_failed<T>(message: &Option<String>) -> Result<T> {
    Err(Error::OperationFailed(
        message.as_ref().map(|e| e.to_string())
            .unwrap_or_else(|| "Unknown reason".into()))
        .into())
}

/// Returns a convenient Err value for use in the state machines
/// below.
fn protocol_error<T>(response: &assuan::Response) -> Result<T> {
    Err(Error::ProtocolError(
        format!("Got unexpected response {:?}", response))
        .into())
}

impl<'a, 'b, 'c, R> Future for SigningRequest<'a, 'b, 'c, R>
    where R: key::KeyRole
{
    type Output = Result<crypto::mpi::Signature>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        use self::SigningRequestState::*;

        // The compiler is not smart enough to figure out disjoint borrows
        // through Pin via DerefMut (which wholly borrows `self`), so unwrap it
        let Self { c, state, key, options, algo, digest } = Pin::into_inner(self);
        let mut client = Pin::new(c);

        loop {
            match state {
                Start => {
                    if options.is_empty() {
                        let grip = Keygrip::of(key.mpis())?;
                        client.send(format!("SIGKEY {}", grip))?;
                        *state = SigKey;
                    } else {
                        let opts = options.pop().unwrap();
                        client.send(opts)?;
                        *state = Options;
                    }
                },

                Options => match client.as_mut().poll_next(cx)? {
                    Poll::Ready(Some(r)) => match r {
                        assuan::Response::Ok { .. }
                        | assuan::Response::Comment { .. }
                        | assuan::Response::Status { .. } =>
                            (), // Ignore.
                        assuan::Response::Error { ref message, .. } =>
                            return Poll::Ready(operation_failed(message)),
                        _ =>
                            return Poll::Ready(protocol_error(&r)),
                    },
                    Poll::Ready(None) => {
                        if let Some(option) = options.pop() {
                            client.send(option)?;
                        } else {
                            let grip = Keygrip::of(key.mpis())?;
                            client.send(format!("SIGKEY {}", grip))?;
                            *state = SigKey;
                        }
                    },
                    Poll::Pending => return Poll::Pending,
                },

                SigKey => match client.as_mut().poll_next(cx)? {
                    Poll::Ready(Some(r)) => match r {
                        assuan::Response::Ok { .. }
                        | assuan::Response::Comment { .. }
                        | assuan::Response::Status { .. } =>
                            (), // Ignore.
                        assuan::Response::Error { ref message, .. } =>
                            return Poll::Ready(operation_failed(message)),
                        _ =>
                            return Poll::Ready(protocol_error(&r)),
                    },
                    Poll::Ready(None) => {
                        let algo = u8::from(*algo);
                        let digest = hex::encode(&digest);
                        client.send(format!("SETHASH {} {}", algo, digest))?;
                        *state = SetHash;
                    },
                    Poll::Pending => return Poll::Pending,
                },

                SetHash => match client.as_mut().poll_next(cx)? {
                    Poll::Ready(Some(r)) => match r {
                        assuan::Response::Ok { .. }
                        | assuan::Response::Comment { .. }
                        | assuan::Response::Status { .. } =>
                            (), // Ignore.
                        assuan::Response::Error { ref message, .. } =>
                            return Poll::Ready(operation_failed(message)),
                        _ =>
                            return Poll::Ready(protocol_error(&r)),
                    },
                    Poll::Ready(None) => {
                        client.send("PKSIGN")?;
                        *state = PkSign(Vec::new());
                    },
                    Poll::Pending => return Poll::Pending,
                },


                PkSign(ref mut data) => match client.as_mut().poll_next(cx)? {
                    Poll::Ready(Some(r)) => match r {
                        assuan::Response::Ok { .. }
                        | assuan::Response::Comment { .. }
                        | assuan::Response::Status { .. } =>
                            (), // Ignore.
                        assuan::Response::Error { ref message, .. } =>
                            return Poll::Ready(operation_failed(message)),
                        assuan::Response::Data { ref partial } =>
                            data.extend_from_slice(partial),
                        _ =>
                            return Poll::Ready(protocol_error(&r)),
                    },
                    Poll::Ready(None) => {
                        return Poll::Ready(
                            Sexp::from_bytes(&data)?.to_signature());
                    },
                    Poll::Pending => return Poll::Pending,
                },
            }
        }
    }
}

struct DecryptionRequest<'a, 'b, 'c, R>
    where R: key::KeyRole
{
    c: &'a mut assuan::Client,
    key: &'b Key<key::PublicParts, R>,
    ciphertext: &'c crypto::mpi::Ciphertext,
    options: Vec<String>,
    state: DecryptionRequestState,
}

impl<'a, 'b, 'c, R> DecryptionRequest<'a, 'b, 'c, R>
    where R: key::KeyRole
{
    fn new(c: &'a mut assuan::Client,
           key: &'b Key<key::PublicParts, R>,
           ciphertext: &'c crypto::mpi::Ciphertext)
           -> Self {
        Self {
            c,
            key,
            ciphertext,
            options: Agent::options(),
            state: DecryptionRequestState::Start,
        }
    }
}

#[derive(Debug)]
enum DecryptionRequestState {
    Start,
    Options,
    SetKey,
    PkDecrypt,
    Inquire(Vec<u8>, bool), // Buffer and padding.
}

impl<'a, 'b, 'c, R> Future for DecryptionRequest<'a, 'b, 'c, R>
    where R: key::KeyRole
{
    type Output = Result<crypto::SessionKey>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        use self::DecryptionRequestState::*;

        // The compiler is not smart enough to figure out disjoint borrows
        // through Pin via DerefMut (which wholly borrows `self`), so unwrap it
        let Self { c, state, key, ciphertext, options } = self.deref_mut();
        let mut client = Pin::new(c);

        loop {
            match state {
                Start => {
                    if options.is_empty() {
                        let grip = Keygrip::of(key.mpis())?;
                        client.send(format!("SETKEY {}", grip))?;
                        *state = SetKey;
                    } else {
                        let opts = options.pop().unwrap();
                        client.send(opts)?;
                        *state = Options;
                    }
                },

                Options => match client.as_mut().poll_next(cx)? {
                    Poll::Ready(Some(r)) => match r {
                        assuan::Response::Ok { .. }
                        | assuan::Response::Comment { .. }
                        | assuan::Response::Status { .. } =>
                            (), // Ignore.
                        assuan::Response::Error { ref message, .. } =>
                            return Poll::Ready(operation_failed(message)),
                        _ =>
                            return Poll::Ready(protocol_error(&r)),
                    },
                    Poll::Ready(None) => {
                        if let Some(option) = options.pop() {
                            client.send(option)?;
                        } else {
                            let grip = Keygrip::of(key.mpis())?;
                            client.send(format!("SETKEY {}", grip))?;
                            *state = SetKey;
                        }
                    },
                    Poll::Pending => return Poll::Pending,
                },

                SetKey => match client.as_mut().poll_next(cx)? {
                    Poll::Ready(Some(r)) => match r {
                        assuan::Response::Ok { .. }
                        | assuan::Response::Comment { .. }
                        | assuan::Response::Status { .. } =>
                            (), // Ignore.
                        assuan::Response::Error { ref message, .. } =>
                            return Poll::Ready(operation_failed(message)),
                        _ =>
                            return Poll::Ready(protocol_error(&r)),
                    },
                    Poll::Ready(None) => {
                        client.send("PKDECRYPT")?;
                        *state = PkDecrypt;
                    },
                    Poll::Pending => return Poll::Pending,
                },

                PkDecrypt => match client.as_mut().poll_next(cx)? {
                    Poll::Ready(Some(r)) => match r {
                        assuan::Response::Inquire { ref keyword, .. }
                          if keyword == "CIPHERTEXT" =>
                            (), // What we expect.
                        assuan::Response::Comment { .. }
                        | assuan::Response::Status { .. } =>
                            (), // Ignore.
                        assuan::Response::Error { ref message, .. } =>
                            return Poll::Ready(operation_failed(message)),
                        _ =>
                            return Poll::Ready(protocol_error(&r)),
                    },
                    Poll::Ready(None) => {
                        let mut buf = Vec::new();
                        Sexp::try_from(*ciphertext)?
                            .serialize(&mut buf)?;
                        client.data(&buf)?;
                        *state = Inquire(Vec::new(), true);
                    },
                    Poll::Pending => return Poll::Pending,
                },


                Inquire(ref mut data, ref mut padding) => match client.as_mut().poll_next(cx)? {
                    Poll::Ready(Some(r)) => match r {
                        assuan::Response::Ok { .. }
                        | assuan::Response::Comment { .. } =>
                            (), // Ignore.
                        assuan::Response::Status { ref keyword, ref message } =>
                            if keyword == "PADDING" {
                                *padding = &message != &"0";
                            },
                        assuan::Response::Error { ref message, .. } =>
                            return Poll::Ready(operation_failed(message)),
                        assuan::Response::Data { ref partial } =>
                            data.extend_from_slice(partial),
                        _ =>
                            return Poll::Ready(protocol_error(&r)),
                    },
                    Poll::Ready(None) => {
                        // Get rid of the safety-0.
                        //
                        // gpg-agent seems to add a trailing 0,
                        // supposedly for good measure.
                        if data.iter().last() == Some(&0) {
                            let l = data.len();
                            data.truncate(l - 1);
                        }

                        return Poll::Ready(
                            Sexp::from_bytes(&data)?.finish_decryption(
                            key, ciphertext, *padding)
                        );
                    },
                    Poll::Pending => return Poll::Pending,
                },
            }
        }
    }
}

/// A cryptographic key pair.
///
/// A `KeyPair` is a combination of public and secret key.  This
/// particular implementation does not have the secret key, but
/// diverges the cryptographic operations to `gpg-agent`.
pub struct KeyPair<'a> {
    public: &'a Key<key::PublicParts, key::UnspecifiedRole>,
    agent_socket: PathBuf,
}

impl<'a> KeyPair<'a> {
    /// Returns a `KeyPair` for `key` with the secret bits managed by
    /// the agent.
    ///
    /// This provides a convenient, synchronous interface for use with
    /// the low-level Sequoia crate.
    pub fn new<R>(ctx: &Context, key: &'a Key<key::PublicParts, R>)
                  -> Result<KeyPair<'a>>
        where R: key::KeyRole
    {
        Ok(KeyPair {
            public: key.role_as_unspecified(),
            agent_socket: ctx.socket("agent")?.into(),
        })
    }
}

impl<'a> crypto::Signer for KeyPair<'a> {
    fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole> {
        self.public
    }

    fn sign(&mut self, hash_algo: HashAlgorithm, digest: &[u8])
            -> openpgp::Result<openpgp::crypto::mpi::Signature>
    {
        use crate::openpgp::types::PublicKeyAlgorithm::*;
        use crate::openpgp::crypto::mpi::PublicKey;

        #[allow(deprecated)]
        match (self.public.pk_algo(), self.public.mpis())
        {
            (RSASign, PublicKey::RSA { .. })
                | (RSAEncryptSign, PublicKey::RSA { .. })
                | (DSA, PublicKey::DSA { .. })
                | (EdDSA, PublicKey::EdDSA { .. })
                | (ECDSA, PublicKey::ECDSA { .. }) => {
                    let mut rt = tokio::runtime::Runtime::new()?;

                    rt.block_on(async move {
                        let mut a = Agent::connect_to(&self.agent_socket).await?;
                        let sig = a.sign(self.public, hash_algo, digest).await?;
                        Ok(sig)
                    })
                },

            (pk_algo, _) => Err(openpgp::Error::InvalidOperation(format!(
                "unsupported combination of algorithm {:?} and key {:?}",
                pk_algo, self.public)).into()),
        }
    }
}

impl<'a> crypto::Decryptor for KeyPair<'a> {
    fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole> {
        self.public
    }

    fn decrypt(&mut self, ciphertext: &crypto::mpi::Ciphertext,
               _plaintext_len: Option<usize>)
               -> openpgp::Result<crypto::SessionKey>
    {
        use crate::openpgp::crypto::mpi::{PublicKey, Ciphertext};

        match (self.public.mpis(), ciphertext) {
            (PublicKey::RSA { .. }, Ciphertext::RSA { .. })
                | (PublicKey::ElGamal { .. }, Ciphertext::ElGamal { .. })
                | (PublicKey::ECDH { .. }, Ciphertext::ECDH { .. }) => {
                    let mut rt = tokio::runtime::Runtime::new()?;

                    rt.block_on(async move {
                        let mut a = Agent::connect_to(&self.agent_socket).await?;
                        let sk = a.decrypt(self.public, ciphertext).await?;
                        Ok(sk)
                    })
                },

            (public, ciphertext) =>
                Err(openpgp::Error::InvalidOperation(format!(
                    "unsupported combination of key pair {:?} \
                     and ciphertext {:?}",
                    public, ciphertext)).into()),
        }
    }
}


#[derive(thiserror::Error, Debug)]
/// Errors used in this module.
pub enum Error {
    /// Errors related to `gpgconf`.
    #[error("gpgconf: {0}")]
    GPGConf(String),
    /// The remote operation failed.
    #[error("Operation failed: {0}")]
    OperationFailed(String),
    /// The remote party violated the protocol.
    #[error("Protocol violation: {0}")]
    ProtocolError(String),

}
