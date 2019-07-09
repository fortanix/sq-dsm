//! GnuPG RPC support.

#![warn(missing_docs)]

use std::collections::BTreeMap;
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::process::Command;

use futures::{Async, Future, Stream};

extern crate libc;
extern crate tempfile;

use crate::openpgp::constants::HashAlgorithm;
use crate::openpgp::conversions::hex;
use crate::openpgp::crypto;
use crate::openpgp::crypto::sexp::Sexp;
use crate::openpgp::parse::Parse;
use crate::openpgp::serialize::Serialize;

use crate::Result;
use crate::assuan;

/// A GnuPG context.
#[derive(Debug)]
pub struct Context {
    homedir: Option<PathBuf>,
    components: BTreeMap<String, PathBuf>,
    directories: BTreeMap<String, PathBuf>,
    sockets: BTreeMap<String, PathBuf>,
    #[allow(dead_code)] // We keep it around for the cleanup.
    ephemeral: Option<tempfile::TempDir>,
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
        let mut components: BTreeMap<String, PathBuf> = Default::default();
        let mut directories: BTreeMap<String, PathBuf> = Default::default();
        let mut sockets: BTreeMap<String, PathBuf> = Default::default();

        let homedir: Option<PathBuf> =
            ephemeral.as_ref().map(|tmp| tmp.path()).or(homedir)
            .map(|p| p.into());

        for fields in Self::gpgconf(
            &homedir, &["--list-components"], 3)?.into_iter()
        {
            components.insert(String::from_utf8(fields[0].clone())?,
                              String::from_utf8(fields[2].clone())?.into());
        }

        for fields in Self::gpgconf(&homedir, &["--list-dirs"], 2)?.into_iter()
        {
            let (mut key, value) = (fields[0].clone(), fields[1].clone());
            if key.ends_with(b"-socket") {
                let l = key.len();
                key.truncate(l - b"-socket".len());
                sockets.insert(String::from_utf8(key)?,
                               String::from_utf8(value)?.into());
            } else {
                directories.insert(String::from_utf8(key)?,
                                   String::from_utf8(value)?.into());
            }
        }

        Ok(Context {
            homedir,
            components,
            directories,
            sockets,
            ephemeral,
        })
    }

    fn gpgconf(homedir: &Option<PathBuf>, arguments: &[&str], nfields: usize)
               -> Result<Vec<Vec<Vec<u8>>>> {
        let nl = |&c: &u8| c as char == '\n';
        let colon = |&c: &u8| c as char == ':';

        let mut gpgconf = Command::new("gpgconf");
        if let Some(homedir) = homedir {
            gpgconf.arg("--homedir").arg(homedir);

            // https://dev.gnupg.org/T4496
            gpgconf.env("GNUPGHOME", homedir);
        }

        for argument in arguments {
            gpgconf.arg(argument);
        }
        let output = gpgconf.output().map_err(|e| -> failure::Error {
            Error::GPGConf(e.to_string()).into()
        })?;

        if output.status.success() {
            let mut result = Vec::new();
            for line in output.stdout.split(nl) {
                if line.len() == 0 {
                    // EOF.
                    break;
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

    /// Returns the path to a GnuPG component.
    pub fn component<C>(&self, component: C) -> Result<&Path>
        where C: AsRef<str>
    {
        self.components.get(component.as_ref())
            .map(|p| p.as_path())
            .ok_or_else(|| {
            Error::GPGConf(format!("No such component {:?}",
                                   component.as_ref())).into()
        })
    }

    /// Returns the path to a GnuPG directory.
    pub fn directory<C>(&self, directory: C) -> Result<&Path>
        where C: AsRef<str>
    {
        self.directories.get(directory.as_ref())
            .map(|p| p.as_path())
            .ok_or_else(|| {
            Error::GPGConf(format!("No such directory {:?}",
                                   directory.as_ref())).into()
        })
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
    type Item = assuan::Response;
    type Error = failure::Error;

    /// Attempt to pull out the next value of this stream, returning
    /// None if the stream is finished.
    ///
    /// Note: It _is_ safe to call this again after the stream
    /// finished, i.e. returned `Ready(None)`.
    fn poll(&mut self)
            -> std::result::Result<Async<Option<Self::Item>>, Self::Error>
    {
        self.c.poll()
    }
}

impl Agent {
    /// Connects to the agent.
    ///
    /// Note: This function does not try to start the server.  If no
    /// server is running for the given context, this operation will
    /// fail.
    pub fn connect<'c>(ctx: &'c Context)
                   -> impl Future<Item = Self, Error = failure::Error> + 'c
    {
        futures::lazy(move || ctx.socket("agent"))
            .and_then(Self::connect_to)
    }

    /// Connects to the agent at the given path.
    ///
    /// Note: This function does not try to start the server.  If no
    /// server is running for the given context, this operation will
    /// fail.
    pub fn connect_to<P>(path: P)
                         -> impl Future<Item = Self, Error = failure::Error>
        where P: AsRef<Path>
    {
        assuan::Client::connect(path)
            .and_then(|c| Ok(Agent { c }))
    }

    /// Creates a signature over the `digest` produced by `algo` using
    /// `key` with the secret bits managed by the agent.
    pub fn sign<'a>(&'a mut self, key: &'a openpgp::packet::Key,
                    algo: HashAlgorithm, digest: &'a [u8])
                    -> impl Future<Item = crypto::mpis::Signature,
                                   Error = failure::Error> + 'a
    {
        SigningRequest::new(&mut self.c, key, algo, digest)
    }

    /// Decrypts `ciphertext` using `key` with the secret bits managed
    /// by the agent.
    pub fn decrypt<'a>(&'a mut self, key: &'a openpgp::packet::Key,
                       ciphertext: &'a crypto::mpis::Ciphertext)
                       -> impl Future<Item = crypto::SessionKey,
                                      Error = failure::Error> + 'a
    {
        DecryptionRequest::new(&mut self.c, key, ciphertext)
    }

    /// Computes options that we want to communicate.
    fn options() -> Vec<String> {
        use std::env::var;
        use std::ffi::CStr;

        let mut r = Vec::new();

        if let Ok(tty) = var("GPG_TTY") {
            r.push(format!("OPTION ttyname={}", tty));
        } else {
            unsafe {
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

struct SigningRequest<'a, 'b, 'c> {
    c: &'a mut assuan::Client,
    key: &'b openpgp::packet::Key,
    algo: HashAlgorithm,
    digest: &'c [u8],
    options: Vec<String>,
    state: SigningRequestState,
}

impl<'a, 'b, 'c> SigningRequest<'a, 'b, 'c> {
    fn new(c: &'a mut assuan::Client,
           key: &'b openpgp::packet::Key,
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

impl<'a, 'b, 'c> Future for SigningRequest<'a, 'b, 'c> {
    type Item = crypto::mpis::Signature;
    type Error = failure::Error;

    fn poll(&mut self) -> std::result::Result<Async<Self::Item>, Self::Error> {
        use self::SigningRequestState::*;

        loop {
            match self.state {
                Start => {
                    if self.options.is_empty() {
                        self.c.send(format!("SIGKEY {}",
                                            self.key.mpis().keygrip()?))?;
                        self.state = SigKey;
                    } else {
                        self.c.send(self.options.pop().unwrap())?;
                        self.state = Options;
                    }
                },

                Options => match self.c.poll()? {
                    Async::Ready(Some(r)) => match r {
                        assuan::Response::Ok { .. }
                        | assuan::Response::Comment { .. }
                        | assuan::Response::Status { .. } =>
                            (), // Ignore.
                        assuan::Response::Error { ref message, .. } =>
                            return operation_failed(message),
                        _ =>
                            return protocol_error(&r),
                    },
                    Async::Ready(None) => {
                        if let Some(option) = self.options.pop() {
                            self.c.send(option)?;
                        } else {
                            self.c.send(format!("SIGKEY {}",
                                                self.key.mpis().keygrip()?))?;
                            self.state = SigKey;
                        }
                    },
                    Async::NotReady =>
                        return Ok(Async::NotReady),
                },

                SigKey => match self.c.poll()? {
                    Async::Ready(Some(r)) => match r {
                        assuan::Response::Ok { .. }
                        | assuan::Response::Comment { .. }
                        | assuan::Response::Status { .. } =>
                            (), // Ignore.
                        assuan::Response::Error { ref message, .. } =>
                            return operation_failed(message),
                        _ =>
                            return protocol_error(&r),
                    },
                    Async::Ready(None) => {
                        self.c.send(format!("SETHASH {} {}",
                                            u8::from(self.algo),
                                            hex::encode(&self.digest)))?;
                        self.state = SetHash;
                    },
                    Async::NotReady =>
                        return Ok(Async::NotReady),
                },

                SetHash => match self.c.poll()? {
                    Async::Ready(Some(r)) => match r {
                        assuan::Response::Ok { .. }
                        | assuan::Response::Comment { .. }
                        | assuan::Response::Status { .. } =>
                            (), // Ignore.
                        assuan::Response::Error { ref message, .. } =>
                            return operation_failed(message),
                        _ =>
                            return protocol_error(&r),
                    },
                    Async::Ready(None) => {
                        self.c.send("PKSIGN")?;
                        self.state = PkSign(Vec::new());
                    },
                    Async::NotReady =>
                        return Ok(Async::NotReady),
                },


                PkSign(ref mut data) => match self.c.poll()? {
                    Async::Ready(Some(r)) => match r {
                        assuan::Response::Ok { .. }
                        | assuan::Response::Comment { .. }
                        | assuan::Response::Status { .. } =>
                            (), // Ignore.
                        assuan::Response::Error { ref message, .. } =>
                            return operation_failed(message),
                        assuan::Response::Data { ref partial } =>
                            data.extend_from_slice(partial),
                        _ =>
                            return protocol_error(&r),
                    },
                    Async::Ready(None) => {
                        return Ok(Async::Ready(
                            Sexp::from_bytes(&data)?.to_signature()?));
                    },
                    Async::NotReady =>
                        return Ok(Async::NotReady),
                },
            }
        }
    }
}

struct DecryptionRequest<'a, 'b, 'c> {
    c: &'a mut assuan::Client,
    key: &'b openpgp::packet::Key,
    ciphertext: &'c crypto::mpis::Ciphertext,
    options: Vec<String>,
    state: DecryptionRequestState,
}

impl<'a, 'b, 'c> DecryptionRequest<'a, 'b, 'c> {
    fn new(c: &'a mut assuan::Client,
           key: &'b openpgp::packet::Key,
           ciphertext: &'c crypto::mpis::Ciphertext)
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

impl<'a, 'b, 'c> Future for DecryptionRequest<'a, 'b, 'c> {
    type Item = crypto::SessionKey;
    type Error = failure::Error;

    fn poll(&mut self) -> std::result::Result<Async<Self::Item>, Self::Error> {
        use self::DecryptionRequestState::*;

        loop {
            match self.state {
                Start => {
                    if self.options.is_empty() {
                        self.c.send(format!("SETKEY {}",
                                            self.key.mpis().keygrip()?))?;
                        self.state = SetKey;
                    } else {
                        self.c.send(self.options.pop().unwrap())?;
                        self.state = Options;
                    }
                },

                Options => match self.c.poll()? {
                    Async::Ready(Some(r)) => match r {
                        assuan::Response::Ok { .. }
                        | assuan::Response::Comment { .. }
                        | assuan::Response::Status { .. } =>
                            (), // Ignore.
                        assuan::Response::Error { ref message, .. } =>
                            return operation_failed(message),
                        _ =>
                            return protocol_error(&r),
                    },
                    Async::Ready(None) => {
                        if let Some(option) = self.options.pop() {
                            self.c.send(option)?;
                        } else {
                            self.c.send(format!("SETKEY {}",
                                                self.key.mpis().keygrip()?))?;
                            self.state = SetKey;
                        }
                    },
                    Async::NotReady =>
                        return Ok(Async::NotReady),
                },

                SetKey => match self.c.poll()? {
                    Async::Ready(Some(r)) => match r {
                        assuan::Response::Ok { .. }
                        | assuan::Response::Comment { .. }
                        | assuan::Response::Status { .. } =>
                            (), // Ignore.
                        assuan::Response::Error { ref message, .. } =>
                            return operation_failed(message),
                        _ =>
                            return protocol_error(&r),
                    },
                    Async::Ready(None) => {
                        self.c.send("PKDECRYPT")?;
                        self.state = PkDecrypt;
                    },
                    Async::NotReady =>
                        return Ok(Async::NotReady),
                },

                PkDecrypt => match self.c.poll()? {
                    Async::Ready(Some(r)) => match r {
                        assuan::Response::Inquire { ref keyword, .. }
                          if keyword == "CIPHERTEXT" =>
                            (), // What we expect.
                        assuan::Response::Comment { .. }
                        | assuan::Response::Status { .. } =>
                            (), // Ignore.
                        assuan::Response::Error { ref message, .. } =>
                            return operation_failed(message),
                        _ =>
                            return protocol_error(&r),
                    },
                    Async::Ready(None) => {
                        let mut buf = Vec::new();
                        Sexp::from_ciphertext(&self.ciphertext)?
                            .serialize(&mut buf)?;
                        self.c.data(&buf)?;
                        self.state = Inquire(Vec::new(), true);
                    },
                    Async::NotReady =>
                        return Ok(Async::NotReady),
                },


                Inquire(ref mut data, ref mut padding) => match self.c.poll()? {
                    Async::Ready(Some(r)) => match r {
                        assuan::Response::Ok { .. }
                        | assuan::Response::Comment { .. } =>
                            (), // Ignore.
                        assuan::Response::Status { ref keyword, ref message } =>
                            if keyword == "PADDING" {
                                *padding = &message != &"0";
                            },
                        assuan::Response::Error { ref message, .. } =>
                            return operation_failed(message),
                        assuan::Response::Data { ref partial } =>
                            data.extend_from_slice(partial),
                        _ =>
                            return protocol_error(&r),
                    },
                    Async::Ready(None) => {
                        // Get rid of the safety-0.
                        //
                        // gpg-agent seems to add a trailing 0,
                        // supposedly for good measure.
                        if data.iter().last() == Some(&0) {
                            let l = data.len();
                            data.truncate(l - 1);
                        }

                        return Ok(Async::Ready(
                            Sexp::from_bytes(&data)?.finish_decryption(
                                self.key, self.ciphertext, *padding)?
                        ));
                    },
                    Async::NotReady =>
                        return Ok(Async::NotReady),
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
    public: &'a openpgp::packet::Key,
    agent_socket: PathBuf,
}

impl<'a> KeyPair<'a> {
    /// Returns a `KeyPair` for `key` with the secret bits managed by
    /// the agent.
    ///
    /// This provides a convenient, synchronous interface for use with
    /// the low-level Sequoia crate.
    pub fn new(ctx: &Context, key: &'a openpgp::packet::Key)
               -> Result<KeyPair<'a>> {
        Ok(KeyPair {
            public: key,
            agent_socket: ctx.socket("agent")?.into(),
        })
    }
}

impl<'a> crypto::Signer for KeyPair<'a> {
    fn public(&self) -> &openpgp::packet::Key {
        self.public
    }

    fn sign(&mut self, hash_algo: HashAlgorithm, digest: &[u8])
            -> Result<openpgp::crypto::mpis::Signature>
    {
        use crate::openpgp::constants::PublicKeyAlgorithm::*;
        use crate::openpgp::crypto::mpis::PublicKey;

        #[allow(deprecated)]
        match (self.public.pk_algo(), self.public.mpis())
        {
            (RSASign, PublicKey::RSA { .. })
                | (RSAEncryptSign, PublicKey::RSA { .. })
                | (DSA, PublicKey::DSA { .. })
                | (EdDSA, PublicKey::EdDSA { .. })
                | (ECDSA, PublicKey::ECDSA { .. }) => {
                    let mut a = Agent::connect_to(&self.agent_socket).wait()?;
                    let sig = a.sign(self.public, hash_algo, digest).wait()?;
                    Ok(sig)
                },

            (pk_algo, _) => Err(openpgp::Error::InvalidOperation(format!(
                "unsupported combination of algorithm {:?} and key {:?}",
                pk_algo, self.public)).into()),
        }
    }
}

impl<'a> crypto::Decryptor for KeyPair<'a> {
    fn public(&self) -> &openpgp::packet::Key {
        self.public
    }

    fn decrypt(&mut self, ciphertext: &crypto::mpis::Ciphertext)
               -> Result<crypto::SessionKey>
    {
        use crate::openpgp::crypto::mpis::{PublicKey, Ciphertext};

        match (self.public.mpis(), ciphertext) {
            (PublicKey::RSA { .. }, Ciphertext::RSA { .. })
                | (PublicKey::Elgamal { .. }, Ciphertext::Elgamal { .. })
                | (PublicKey::ECDH { .. }, Ciphertext::ECDH { .. }) => {
                    let mut a = Agent::connect_to(&self.agent_socket).wait()?;
                    let sk = a.decrypt(self.public, ciphertext).wait()?;
                    Ok(sk)
                },

            (public, ciphertext) =>
                Err(openpgp::Error::InvalidOperation(format!(
                    "unsupported combination of key pair {:?} \
                     and ciphertext {:?}",
                    public, ciphertext)).into()),
        }
    }
}


#[derive(Fail, Debug)]
/// Errors used in this module.
pub enum Error {
    /// Errors related to `gpgconf`.
    #[fail(display = "gpgconf: {}", _0)]
    GPGConf(String),
    /// The remote operation failed.
    #[fail(display = "Operation failed: {}", _0)]
    OperationFailed(String),
    /// The remote party violated the protocol.
    #[fail(display = "Protocol violation: {}", _0)]
    ProtocolError(String),

}
