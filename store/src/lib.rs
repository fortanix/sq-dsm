//! For storing OpenPGP Certificates.
//!
//! The key store stores OpenPGP Certificates ("Certs") using an
//! arbitrary label.  Stored keys are automatically updated from
//! remote sources.  This ensures that updates like new subkeys and
//! revocations are discovered in a timely manner.
//!
//! # Security considerations
//!
//! Storing public keys potentially leaks communication partners.
//! Protecting against adversaries inspecting the local storage is out
//! of scope for Sequoia.  Please take the necessary precautions.
//!
//! Sequoia updates keys in compliance with the [network policy] used
//! to create the mapping.
//!
//! [network policy]: sequoia_net::Policy
//!
//! # Examples
//!
//! ```
//! # use sequoia_openpgp as openpgp;
//! # use openpgp::Fingerprint;
//! # use sequoia_ipc::{Context, IPCPolicy};
//! # use sequoia_net as net;
//! # use sequoia_store::*;
//! # fn main() { f().unwrap(); }
//! # fn f() -> Result<()> {
//! # let ctx = Context::configure()
//! #     .ipc_policy(IPCPolicy::Internal)
//! #     .ephemeral().build()?;
//! let mapping = Mapping::open(&ctx, net::Policy::Offline,
//!                             REALM_CONTACTS, "default")?;
//!
//! let fp = Fingerprint::from_bytes(b"bbbbbbbbbbbbbbbbbbbb");
//! let binding = mapping.add("Mister B.", &fp)?;
//!
//! println!("Binding {:?}", binding.stats()?);
//! // prints:
//! // Binding Stats {
//! //     created: Some(Timespec { tv_sec: 1513704042, tv_nsec: 0 }),
//! //     updated: None,
//! //     encryption: Stamps { count: 0, first: None, last: None },
//! //     verification: Stamps { count: 0, first: None, last: None }
//! // }
//! # Ok(())
//! # }
//! ```

#![doc(html_favicon_url = "https://docs.sequoia-pgp.org/favicon.png")]
#![doc(html_logo_url = "https://docs.sequoia-pgp.org/logo.svg")]
#![warn(missing_docs)]

#[macro_use]
extern crate capnp_rpc;

use std::cell::RefCell;
use std::fmt;
use std::future::Future;
use std::rc::Rc;
use std::time;

use capnp::capability::Promise;
use capnp_rpc::rpc_twoparty_capnp::Side;

use sequoia_openpgp as openpgp;

use crate::openpgp::Fingerprint;
use crate::openpgp::KeyID;
use crate::openpgp::Cert;
use crate::openpgp::parse::Parse;
use crate::openpgp::serialize::Serialize;
use sequoia_ipc::Context;
use sequoia_ipc as ipc;
use sequoia_net as net;

#[allow(dead_code)] mod store_protocol_capnp;
use crate::store_protocol_capnp::node;

/// Macros managing requests and responses.
#[macro_use] mod macros;

pub(crate) mod backend;

/// Single-threaded Tokio runtime that drives the Cap'n Proto `RpcSystem`.
struct RpcRuntime {
    runtime: tokio::runtime::Runtime,
    rpc_task: tokio::task::LocalSet,
}

impl RpcRuntime {
    /// Blocks until a `fut` is finished, concurrently driving the RPC system.
    fn block_on<F: Future>(&mut self, fut: F) -> F::Output {
        self.rpc_task.block_on(&mut self.runtime, fut)
    }
}

/// Returns the service descriptor.
#[doc(hidden)]
pub fn descriptor(c: &Context) -> ipc::Descriptor {
    ipc::Descriptor::new(
        c,
        c.home().join("public-key-store.cookie"),
        c.lib().join("sequoia-public-key-store"),
        backend::factory,
    )
}

/// Keys used for communications.
pub const REALM_CONTACTS: &str =
    "org.sequoia-pgp.contacts";

/// Keys used for signing software updates.
pub const REALM_SOFTWARE_UPDATES: &str =
    "org.sequoia-pgp.software-updates";

/// The common key pool.
pub struct Store {
}

impl Store {
    /// Establishes a connection to the backend.
    fn connect(c: &Context) -> Result<(RpcRuntime, node::Client)> {
        let descriptor = descriptor(c);

        let rt = tokio::runtime::Builder::new()
            .basic_scheduler()
            .enable_io()
            .enable_time()
            .build()?;
        // Need to enter Tokio context due to Tokio TcpStream creation binding
        // eagerly to an I/O reactor
        let mut rpc_system = rt.enter(|| descriptor.connect())?;

        let client: node::Client = rpc_system.bootstrap(Side::Server);

        // Since RpcSystem is explicitly `!Send`, we need to spawn it on
        // a `LocalSet` that needs to be exclusively driven by `RpcRuntime`
        let rpc_task = tokio::task::LocalSet::new();
        rpc_task.spawn_local(rpc_system);

        Ok((RpcRuntime { runtime: rt, rpc_task }, client))
    }

    /// Imports a key into the common key pool.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::Cert;
    /// # use openpgp::parse::Parse;
    /// # use sequoia_ipc::{Context, IPCPolicy};
    /// # use sequoia_store::{Store, Result};
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// # let ctx = Context::configure()
    /// #     .ipc_policy(IPCPolicy::Internal)
    /// #     .ephemeral().build()?;
    /// # let cert = Cert::from_bytes(
    /// #     &include_bytes!("../../openpgp/tests/data/keys/testy.pgp")[..]).unwrap();
    /// let key = Store::import(&ctx, &cert)?;
    /// assert_eq!(key.cert()?.fingerprint(), cert.fingerprint());
    /// # Ok(())
    /// # }
    /// ```
    pub fn import(c: &Context, cert: &Cert) -> Result<Key> {
        let mut blob = vec![];
        cert.serialize(&mut blob)?;

        let (mut core, client) = Store::connect(c)?;
        let mut request = client.import_request();
        request.get().set_key(&blob);
        let key = make_request!(&mut core, request)?;
        Ok(Key::new(Rc::new(RefCell::new(core)), key))
    }

    /// Looks up a key in the common key pool.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::Cert;
    /// # use openpgp::parse::Parse;
    /// # use sequoia_ipc::{Context, IPCPolicy};
    /// # use sequoia_store::{Store, Result};
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// # let ctx = Context::configure()
    /// #     .ipc_policy(IPCPolicy::Internal)
    /// #     .ephemeral().build()?;
    /// # let cert = Cert::from_bytes(
    /// #     &include_bytes!("../../openpgp/tests/data/keys/testy.pgp")[..]).unwrap();
    /// Store::import(&ctx, &cert)?;
    /// let key = Store::lookup(&ctx, &cert.fingerprint())?;
    /// assert_eq!(key.cert()?.fingerprint(), cert.fingerprint());
    /// # Ok(())
    /// # }
    /// ```
    pub fn lookup(c: &Context, fp: &Fingerprint) -> Result<Key> {
        let (mut core, client) = Store::connect(c)?;
        let mut request = client.lookup_by_fingerprint_request();
        let fp = format!("{:X}", fp);
        request.get().set_fingerprint(&fp);
        let key = make_request!(&mut core, request)?;
        Ok(Key::new(Rc::new(RefCell::new(core)), key))
    }

    /// Looks up a key in the common key pool by KeyID.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::Cert;
    /// # use openpgp::parse::Parse;
    /// # use sequoia_ipc::{Context, IPCPolicy};
    /// # use sequoia_store::{Store, Result};
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// # let ctx = Context::configure()
    /// #     .ipc_policy(IPCPolicy::Internal)
    /// #     .ephemeral().build()?;
    /// # let cert = Cert::from_bytes(
    /// #     &include_bytes!("../../openpgp/tests/data/keys/testy.pgp")[..]).unwrap();
    /// Store::import(&ctx, &cert)?;
    /// let key = Store::lookup_by_keyid(&ctx, &cert.fingerprint().into())?;
    /// assert_eq!(key.cert()?.fingerprint(), cert.fingerprint());
    /// # Ok(())
    /// # }
    /// ```
    pub fn lookup_by_keyid(c: &Context, keyid: &KeyID) -> Result<Key> {
        let (mut core, client) = Store::connect(c)?;
        let mut request = client.lookup_by_keyid_request();
        request.get().set_keyid(keyid.as_u64()?);
        let key = make_request!(&mut core, request)?;
        Ok(Key::new(Rc::new(RefCell::new(core)), key))
    }

    /// Looks up a key in the common key pool by (Sub)KeyID.
    ///
    /// The KeyID may also reference a subkey.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::{Cert, KeyID};
    /// # use openpgp::parse::Parse;
    /// # use sequoia_ipc::{Context, IPCPolicy};
    /// # use sequoia_store::{Store, Result};
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// # let ctx = Context::configure()
    /// #     .ipc_policy(IPCPolicy::Internal)
    /// #     .ephemeral().build()?;
    /// # let cert = Cert::from_bytes(
    /// #     &include_bytes!("../../openpgp/tests/data/keys/neal.pgp")[..])
    /// #     .unwrap();
    /// Store::import(&ctx, &cert)?;
    ///
    /// // Lookup by the primary key's KeyID.
    /// let key = Store::lookup_by_subkeyid(&ctx, &"AACB3243630052D9".parse()?)?;
    /// assert_eq!(key.cert()?.fingerprint(), cert.fingerprint());
    ///
    /// // Lookup by the signing subkey's KeyID.
    /// let key = Store::lookup_by_subkeyid(&ctx, &"7223B56678E02528".parse()?)?;
    /// assert_eq!(key.cert()?.fingerprint(), cert.fingerprint());
    ///
    /// // Lookup by the encryption subkey's KeyID.
    /// let key = Store::lookup_by_subkeyid(&ctx, &"C2B819056C652598".parse()?)?;
    /// assert_eq!(key.cert()?.fingerprint(), cert.fingerprint());
    ///
    /// // Lookup by the authentication subkey's KeyID.
    /// let key = Store::lookup_by_subkeyid(&ctx, &"A3506AFB820ABD08".parse()?)?;
    /// assert_eq!(key.cert()?.fingerprint(), cert.fingerprint());
    /// # Ok(())
    /// # }
    /// ```
    pub fn lookup_by_subkeyid(c: &Context, keyid: &KeyID) -> Result<Key> {
        let (mut core, client) = Store::connect(c)?;
        let mut request = client.lookup_by_subkeyid_request();
        request.get().set_keyid(keyid.as_u64()?);
        let key = make_request!(&mut core, request)?;
        Ok(Key::new(Rc::new(RefCell::new(core)), key))
    }

    /// Lists all keys in the common key pool.
    pub fn list_keys(c: &Context) -> Result<KeyIter> {
        let (mut core, client) = Store::connect(c)?;
        let request = client.iter_keys_request();
        let iter = make_request!(&mut core, request)?;
        Ok(KeyIter{core: Rc::new(RefCell::new(core)), iter: iter})
    }

    /// Lists all log entries.
    pub fn server_log(c: &Context) -> Result<LogIter> {
        let (mut core, client) = Store::connect(c)?;
        let request = client.log_request();
        let iter = make_request!(&mut core, request)?;
        Ok(LogIter{core: Rc::new(RefCell::new(core)), iter: iter})
    }
}

/// A public key store.
pub struct Mapping {
    name: String,
    core: Rc<RefCell<RpcRuntime>>,
    mapping: node::mapping::Client,
}

impl fmt::Debug for Mapping {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Mapping {{ name: {} }}", self.name)
    }
}

impl Mapping {
    /// Opens a mapping.
    ///
    /// Opens a mapping with the given name.  If the mapping does not
    /// exist, it is created.  Mappings are handles for objects
    /// maintained by a background service.  The background service
    /// associates state with this name.
    ///
    /// The store updates Certs in compliance with the network policy
    /// of the context that created the mapping in the first place.
    /// Opening the mapping with a different network policy is
    /// forbidden.
    pub fn open(c: &Context, p: net::Policy, realm: &str, name: &str)
                -> Result<Self> {
        let (mut core, client) = Store::connect(c)?;

        let mut request = client.open_request();
        request.get().set_realm(realm);
        request.get().set_network_policy(p.into());
        request.get().set_ephemeral(c.ephemeral());
        request.get().set_name(name);

        let mapping = make_request!(&mut core, request)?;
        Ok(Self::new(Rc::new(RefCell::new(core)), name, mapping))
    }

    fn new(core: Rc<RefCell<RpcRuntime>>, name: &str, mapping: node::mapping::Client) -> Self {
        Mapping{core: core, name: name.into(), mapping: mapping}
    }

    /// Lists all mappings with the given prefix.
    pub fn list(c: &Context, realm_prefix: &str) -> Result<MappingIter> {
        let (mut core, client) = Store::connect(c)?;
        let mut request = client.iter_request();
        request.get().set_realm_prefix(realm_prefix);
        let iter = make_request!(&mut core, request)?;
        Ok(MappingIter{core: Rc::new(RefCell::new(core)), iter: iter})
    }

    /// Adds a key identified by fingerprint to the mapping.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::Fingerprint;
    /// # use sequoia_ipc::{Context, IPCPolicy};
    /// # use sequoia_net as net;
    /// # use sequoia_store::*;
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// # let ctx = Context::configure()
    /// #     .ipc_policy(IPCPolicy::Internal)
    /// #     .ephemeral().build()?;
    /// let mapping = Mapping::open(&ctx, net::Policy::Offline,
    ///                             REALM_CONTACTS, "default")?;
    /// let fp = Fingerprint::from_bytes(b"bbbbbbbbbbbbbbbbbbbb");
    /// mapping.add("Mister B.", &fp)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn add(&self, label: &str, fingerprint: &Fingerprint) -> Result<Binding> {
        let mut request = self.mapping.add_request();
        request.get().set_label(label);
        request.get().set_fingerprint(format!("{:X}", fingerprint).as_ref());
        let binding = make_request!(self.core.borrow_mut(), request)?;
        Ok(Binding::new(self.core.clone(), Some(label), binding))
    }

    /// Imports a key into the mapping.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::Cert;
    /// # use openpgp::parse::Parse;
    /// # use sequoia_ipc::{Context, IPCPolicy};
    /// # use sequoia_net as net;
    /// # use sequoia_store::*;
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// # let ctx = Context::configure()
    /// #     .ipc_policy(IPCPolicy::Internal)
    /// #     .ephemeral().build()?;
    /// # let cert = Cert::from_bytes(
    /// #     &include_bytes!("../../openpgp/tests/data/keys/testy.pgp")[..]).unwrap();
    /// let mapping = Mapping::open(&ctx, net::Policy::Offline,
    ///                             REALM_CONTACTS, "default")?;
    /// mapping.import("Testy McTestface", &cert)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn import(&self, label: &str, cert: &Cert) -> Result<Cert> {
        let fingerprint = cert.fingerprint();
        let mut request = self.mapping.add_request();
        request.get().set_label(label);
        request.get().set_fingerprint(format!("{:X}", fingerprint).as_ref());
        let binding = make_request!(self.core.borrow_mut(), request)?;
        let binding = Binding::new(self.core.clone(), Some(label), binding);
        binding.import(cert)
    }

    /// Returns the binding for the given label.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::Fingerprint;
    /// # use sequoia_ipc::{Context, IPCPolicy};
    /// # use sequoia_net as net;
    /// # use sequoia_store::*;
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// # let ctx = Context::configure()
    /// #     .ipc_policy(IPCPolicy::Internal)
    /// #     .ephemeral().build()?;
    /// let mapping = Mapping::open(&ctx, net::Policy::Offline,
    ///                             REALM_CONTACTS, "default")?;
    /// let fp = Fingerprint::from_bytes(b"bbbbbbbbbbbbbbbbbbbb");
    /// mapping.add("Mister B.", &fp)?;
    /// drop(mapping);
    /// // ...
    /// let mapping = Mapping::open(&ctx, net::Policy::Offline,
    ///                             REALM_CONTACTS, "default")?;
    /// let binding = mapping.lookup("Mister B.")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn lookup(&self, label: &str) -> Result<Binding> {
        let mut request = self.mapping.lookup_request();
        request.get().set_label(label);
        let binding = make_request!(self.core.borrow_mut(), request)?;
        Ok(Binding::new(self.core.clone(), Some(label), binding))
    }

    /// Looks up a key by (Sub)KeyID.
    ///
    /// The KeyID may also reference a subkey.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::{Cert, KeyID};
    /// # use openpgp::parse::Parse;
    /// # use sequoia_ipc::{Context, IPCPolicy};
    /// # use sequoia_net as net;
    /// # use sequoia_store::*;
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// # let ctx = Context::configure()
    /// #     .ipc_policy(IPCPolicy::Internal)
    /// #     .ephemeral().build()?;
    /// # let cert = Cert::from_bytes(
    /// #     &include_bytes!("../../openpgp/tests/data/keys/emmelie-dorothea-dina-samantha-awina-ed25519.pgp")[..])
    /// #     .unwrap();
    /// let mapping = Mapping::open(&ctx, net::Policy::Offline,
    ///                             REALM_CONTACTS, "default")?;
    /// mapping.import("Emmelie", &cert)?;
    ///
    /// // Lookup by the primary key's KeyID.
    /// let cert_ = mapping.lookup_by_subkeyid(&"069C0C348DD82C19".parse()?)?
    ///     .cert()?;
    /// assert_eq!(cert, cert_);
    ///
    /// // Lookup by the subkey's KeyID.
    /// let cert_ = mapping.lookup_by_subkeyid(&"22E3FAFE96B56C32".parse()?)?
    ///     .cert()?;
    /// assert_eq!(cert, cert_);
    /// # Ok(())
    /// # }
    /// ```
    pub fn lookup_by_subkeyid(&self, keyid: &KeyID) -> Result<Binding> {
        let mut request = self.mapping.lookup_by_subkeyid_request();
        request.get().set_keyid(keyid.as_u64()?);
        let binding = make_request!(self.core.borrow_mut(), request)?;
        let mut binding = Binding::new(self.core.clone(), None, binding);
        binding.label = binding.label().ok();
        Ok(binding)
    }

    /// Deletes this mapping.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::Fingerprint;
    /// # use sequoia_ipc::{Context, IPCPolicy};
    /// # use sequoia_net as net;
    /// # use sequoia_store::*;
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// # let ctx = Context::configure()
    /// #     .ipc_policy(IPCPolicy::Internal)
    /// #     .ephemeral().build()?;
    /// let mapping = Mapping::open(&ctx, net::Policy::Offline,
    ///                             REALM_CONTACTS, "default")?;
    /// let fp = Fingerprint::from_bytes(b"bbbbbbbbbbbbbbbbbbbb");
    /// mapping.add("Mister B.", &fp)?;
    /// mapping.delete()?;
    /// // ...
    /// let mapping = Mapping::open(&ctx, net::Policy::Offline,
    ///                             REALM_CONTACTS, "default")?;
    /// let binding = mapping.lookup("Mister B.");
    /// assert!(binding.is_err()); // not found
    /// # Ok(())
    /// # }
    /// ```
    pub fn delete(self) -> Result<()> {
        let request = self.mapping.delete_request();
        make_request_map!(self.core.borrow_mut(), request, |_| Ok(()))
    }

    /// Lists all bindings.
    pub fn iter(&self) -> Result<BundleIter> {
        let request = self.mapping.iter_request();
        let iter = make_request!(self.core.borrow_mut(), request)?;
        Ok(BundleIter{core: self.core.clone(), iter: iter})
    }

    /// Lists all log entries related to this mapping.
    pub fn log(&self) -> Result<LogIter> {
        let request = self.mapping.log_request();
        let iter = make_request!(self.core.borrow_mut(), request)?;
        Ok(LogIter{core: self.core.clone(), iter: iter})
    }
}

/// Makes a stats request and parses the result.
macro_rules! make_stats_request {
    ( $core: expr, $request: expr ) => {{
        make_request_map!(
            $core, $request,
            |s: node::stats::Reader| Ok(Stats{
                created: from_unix(s.get_created()),
                updated: from_unix(s.get_updated()),
                encryption: Stamps::new(
                    s.get_encryption_count(),
                    from_unix(s.get_encryption_first()),
                    from_unix(s.get_encryption_last())),
                verification: Stamps::new(
                    s.get_verification_count(),
                    from_unix(s.get_verification_first()),
                    from_unix(s.get_verification_last())),
            }))
    }}
}

/// Represents an entry in a Mapping.
///
/// Mappings map labels to Certs.  A `Binding` represents a pair in this
/// relation.  We make this explicit because we associate metadata
/// with these pairs.
pub struct Binding {
    label: Option<String>,
    core: Rc<RefCell<RpcRuntime>>,
    binding: node::binding::Client,
}

impl fmt::Debug for Binding {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Binding {{ label: {:?} }}", self.label)
    }
}

impl Binding {
    fn new(core: Rc<RefCell<RpcRuntime>>,
           label: Option<&str>,
           binding: node::binding::Client) -> Self {
        Binding{label: label.map(|l| l.into()), core: core, binding: binding}
    }

    /// Returns stats for this binding.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::Fingerprint;
    /// # use sequoia_ipc::{Context, IPCPolicy};
    /// # use sequoia_net as net;
    /// # use sequoia_store::*;
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// # let ctx = Context::configure()
    /// #     .ipc_policy(IPCPolicy::Internal)
    /// #     .ephemeral().build()?;
    /// let mapping = Mapping::open(&ctx, net::Policy::Offline,
    ///                             REALM_CONTACTS, "default")?;
    ///
    /// let fp = Fingerprint::from_bytes(b"bbbbbbbbbbbbbbbbbbbb");
    /// let binding = mapping.add("Mister B.", &fp)?;
    ///
    /// println!("Binding {:?}", binding.stats()?);
    /// // prints:
    /// // Binding Stats {
    /// //     created: Some(Timespec { tv_sec: 1513704042, tv_nsec: 0 }),
    /// //     updated: None,
    /// //     encryption: Stamps { count: 0, first: None, last: None },
    /// //     verification: Stamps { count: 0, first: None, last: None }
    /// // }
    /// # Ok(())
    /// # }
    /// ```
    pub fn stats(&self) -> Result<Stats> {
        make_stats_request!(self.core.borrow_mut(),
                            self.binding.stats_request())
    }

    /// Returns the `Key` of this binding.
    pub fn key(&self) -> Result<Key> {
        make_request_map!(self.core.borrow_mut(),
                          self.binding.key_request(),
                          |cert| Ok(Key::new(self.core.clone(), cert)))
    }

    /// Returns the `Cert` of this binding.
    ///
    /// A shortcut for `self.key()?.cert()`.
    pub fn cert(&self) -> Result<Cert> {
        self.key()?.cert()
    }

    /// Updates this binding with the given Cert.
    ///
    /// If the new key `cert` matches the current key, i.e. they have
    /// the same fingerprint, both keys are merged and normalized.
    /// The returned key contains all packets known to Sequoia, and
    /// should be used instead of `cert`.
    ///
    /// If the new key does not match the current key, and it does not
    /// carry a valid signature from the current key, an
    /// `Error::Conflict` is returned, and you have to resolve the
    /// conflict, either by ignoring the new key, or by using
    /// `Binding::rotate` to force a rotation.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::Cert;
    /// # use openpgp::parse::Parse;
    /// # use sequoia_ipc::{Context, IPCPolicy};
    /// # use sequoia_net as net;
    /// # use sequoia_store::*;
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// # let ctx = Context::configure()
    /// #     .ipc_policy(IPCPolicy::Internal)
    /// #     .ephemeral().build()?;
    /// # let old = Cert::from_bytes(
    /// #     &include_bytes!("../../openpgp/tests/data/keys/testy.pgp")[..]).unwrap();
    /// # let new = Cert::from_bytes(
    /// #     &include_bytes!("../../openpgp/tests/data/keys/testy-new.pgp")[..]).unwrap();
    /// let mapping = Mapping::open(&ctx, net::Policy::Offline,
    ///                             REALM_CONTACTS, "default")?;
    /// mapping.import("Testy McTestface", &old)?;
    /// // later...
    /// let binding = mapping.lookup("Testy McTestface")?;
    /// let r = binding.import(&new);
    /// assert!(r.is_err()); // Conflict!
    /// # Ok(())
    /// # }
    /// ```
    pub fn import(&self, cert: &Cert) -> Result<Cert> {
        let mut blob = vec![];
        cert.serialize(&mut blob)?;
        let mut request = self.binding.import_request();
        request.get().set_force(false);
        request.get().set_key(&blob);
        make_request_map!(
            self.core.borrow_mut(),
            request,
            |data| Cert::from_bytes(data))
    }

    /// Forces a keyrotation to the given Cert.
    ///
    /// The current key is replaced with the new key `cert`, even if
    /// they do not have the same fingerprint.  If a key with the same
    /// fingerprint as `cert` is already in the store, is merged with
    /// `cert` and normalized.  The returned key contains all packets
    /// known to Sequoia, and should be used instead of `cert`.
    ///
    /// Use this function to resolve conflicts returned from
    /// `Binding::import`.  Make sure that you have authenticated
    /// `cert` properly.  How to do that depends on your thread model.
    /// You could simply ask Alice to call her communication partner
    /// Bob and confirm that he rotated his keys.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::Cert;
    /// # use openpgp::parse::Parse;
    /// # use sequoia_ipc::{Context, IPCPolicy};
    /// # use sequoia_net as net;
    /// # use sequoia_store::*;
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// # let ctx = Context::configure()
    /// #     .ipc_policy(IPCPolicy::Internal)
    /// #     .ephemeral().build()?;
    /// # let old = Cert::from_bytes(
    /// #     &include_bytes!("../../openpgp/tests/data/keys/testy.pgp")[..]).unwrap();
    /// # let new = Cert::from_bytes(
    /// #     &include_bytes!("../../openpgp/tests/data/keys/testy-new.pgp")[..]).unwrap();
    /// let mapping = Mapping::open(&ctx, net::Policy::Offline,
    ///                             REALM_CONTACTS, "default")?;
    /// mapping.import("Testy McTestface", &old)?;
    /// // later...
    /// let binding = mapping.lookup("Testy McTestface")?;
    /// let r = binding.import(&new);
    /// assert!(r.is_err()); // Conflict!
    /// let r = binding.rotate(&new)?;
    /// assert_eq!(new.fingerprint(), r.fingerprint());
    /// # Ok(())
    /// # }
    /// ```
    pub fn rotate(&self, cert: &Cert) -> Result<Cert> {
        let mut blob = vec![];
        cert.serialize(&mut blob)?;
        let mut request = self.binding.import_request();
        request.get().set_force(true);
        request.get().set_key(&blob);
        make_request_map!(
            self.core.borrow_mut(),
            request,
            |data| Cert::from_bytes(data))
    }

    /// Deletes this binding.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::Fingerprint;
    /// # use sequoia_ipc::{Context, IPCPolicy};
    /// # use sequoia_net as net;
    /// # use sequoia_store::*;
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// # let ctx = Context::configure()
    /// #     .ipc_policy(IPCPolicy::Internal)
    /// #     .ephemeral().build()?;
    /// let mapping = Mapping::open(&ctx, net::Policy::Offline,
    ///                             REALM_CONTACTS, "default")?;
    /// let fp = Fingerprint::from_bytes(b"bbbbbbbbbbbbbbbbbbbb");
    /// let binding = mapping.add("Mister B.", &fp)?;
    /// binding.delete()?;
    /// let binding = mapping.lookup("Mister B.");
    /// assert!(binding.is_err()); // not found
    /// # Ok(())
    /// # }
    /// ```
    pub fn delete(self) -> Result<()> {
        let request = self.binding.delete_request();
        make_request_map!(self.core.borrow_mut(), request, |_| Ok(()))
    }

    fn register_encryption(&self) -> Result<Stats> {
        #![allow(dead_code)]     // XXX use
        make_stats_request!(
            self.core.borrow_mut(),
            self.binding.register_encryption_request())
    }

    fn register_verification(&self) -> Result<Stats> {
        #![allow(dead_code)]     // XXX use
        make_stats_request!(
            self.core.borrow_mut(),
            self.binding.register_verification_request())
    }

    /// Lists all log entries related to this binding.
    pub fn log(&self) -> Result<LogIter> {
        let request = self.binding.log_request();
        let iter = make_request!(self.core.borrow_mut(), request)?;
        Ok(LogIter{core: self.core.clone(), iter: iter})
    }

    /// Gets this binding's label.
    pub fn label(&self) -> Result<String> {
        if let Some(ref label) = self.label {
            return Ok(label.clone());
        }

        let request = self.binding.label_request();
        make_request_map!(self.core.borrow_mut(),
                          request,
                          |l: &str| Ok(l.into()))
    }
}

/// Represents a key in the store.
///
/// A `Key` is a handle to a stored Cert.  We make this explicit
/// because we associate metadata with Certs.
pub struct Key {
    core: Rc<RefCell<RpcRuntime>>,
    key: node::key::Client,
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Key {{ }}")
    }
}

impl Key {
    fn new(core: Rc<RefCell<RpcRuntime>>, key: node::key::Client) -> Self {
        Key{core: core, key: key}
    }

    /// Returns the Cert.
    pub fn cert(&self) -> Result<Cert> {
        make_request_map!(self.core.borrow_mut(),
                          self.key.cert_request(),
                          |cert| Cert::from_bytes(cert))
    }

    /// Returns stats for this key.
    pub fn stats(&self) -> Result<Stats> {
        make_stats_request!(self.core.borrow_mut(),
                            self.key.stats_request())
    }

    /// Updates this stored key with the given Cert.
    ///
    /// If the new key `cert` matches the current key, i.e. they have
    /// the same fingerprint, both keys are merged and normalized.
    /// The returned key contains all packets known to Sequoia, and
    /// should be used instead of `cert`.
    ///
    /// If the new key does not match the current key,
    /// `Error::Conflict` is returned.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::Fingerprint;
    /// # use openpgp::Cert;
    /// # use openpgp::parse::Parse;
    /// # use sequoia_ipc::{Context, IPCPolicy};
    /// # use sequoia_net as net;
    /// # use sequoia_store::*;
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// # let ctx = Context::configure()
    /// #     .ipc_policy(IPCPolicy::Internal)
    /// #     .ephemeral().build()?;
    /// # let old = Cert::from_bytes(
    /// #     &include_bytes!("../../openpgp/tests/data/keys/testy.pgp")[..]).unwrap();
    /// # let new = Cert::from_bytes(
    /// #     &include_bytes!("../../openpgp/tests/data/keys/testy-new.pgp")[..]).unwrap();
    /// let mapping = Mapping::open(&ctx, net::Policy::Offline,
    ///                             REALM_CONTACTS, "default")?;
    /// let fp = "3E8877C877274692975189F5D03F6F865226FE8B".parse().unwrap();
    /// let binding = mapping.add("Testy McTestface", &fp)?;
    /// let key = binding.key()?;
    /// let r = key.import(&old)?;
    /// assert_eq!(r.fingerprint(), old.fingerprint());
    /// let r = key.import(&new);
    /// assert!(r.is_err()); // conflict
    /// # Ok(())
    /// # }
    /// ```
    pub fn import(&self, cert: &Cert) -> Result<Cert> {
        let mut blob = vec![];
        cert.serialize(&mut blob)?;
        let mut request = self.key.import_request();
        request.get().set_key(&blob);
        make_request_map!(
            self.core.borrow_mut(),
            request,
            |data| Cert::from_bytes(data))
    }

    /// Lists all log entries related to this key.
    pub fn log(&self) -> Result<LogIter> {
        let request = self.key.log_request();
        let iter = make_request!(self.core.borrow_mut(), request)?;
        Ok(LogIter{core: self.core.clone(), iter: iter})
    }
}


/// Returns `t` as time::SystemTime.
fn from_unix(t: i64) -> Option<time::SystemTime> {
    if t == 0 {
        None
    } else {
        // XXX: Backend and frontend should really communicate
        // unsigned timestamps.
        Some(time::UNIX_EPOCH + time::Duration::new(t as u64, 0))
    }
}

/// Statistics about bindings and stored keys.
///
/// We collect some data about binginds and stored keys.  This
/// information can be used to make informed decisions about key
/// transitions.
#[derive(Debug)]
pub struct Stats {
    /// Records the time this item was created.
    pub created: Option<time::SystemTime>,

    /// Records the time this item was last updated.
    pub updated: Option<time::SystemTime>,

    /// Records counters and timestamps of encryptions.
    pub encryption: Stamps,

    /// Records counters and timestamps of verifications.
    pub verification: Stamps,
}

/// Represents a log entry.
#[derive(Debug)]
pub struct Log {
    /// Records the time of the entry.
    pub timestamp: time::SystemTime,

    /// Relates the entry to a mapping.
    pub mapping: Option<Mapping>,

    /// Relates the entry to a binding.
    pub binding: Option<Binding>,

    /// Relates the entry to a key.
    pub key: Option<Key>,

    /// Relates the entry to some object.
    ///
    /// This is a human-readable description of what this log entry is
    /// mainly concerned with.
    pub slug: String,

    /// Holds the result of the operation.
    ///
    /// This is either `Ok(Message)`, or `Err((Message, Error))`.
    pub status: ::std::result::Result<String, (String, String)>,
}

impl Log {
    fn new(timestamp: i64,
           mapping: Option<Mapping>, binding: Option<Binding>, key: Option<Key>,
           slug: &str, message: &str, error: Option<&str>)
           -> Option<Self> {
        let timestamp = from_unix(timestamp)?;

        Some(Log{
            timestamp: timestamp,
            mapping: mapping,
            binding: binding,
            key: key,
            slug: slug.into(),
            status: if let Some(error) = error {
                Err((message.into(), error.into()))
            } else {
                Ok(message.into())
            },
        })
    }

    /// Returns the message without context.
    pub fn short(&self) -> String {
        match self.status {
            Ok(ref m) => m.clone(),
            Err((ref m, ref e)) => format!("{}: {}", m, e),
        }
    }

    /// Returns the message with some context.
    pub fn string(&self) -> String {
        match self.status {
            Ok(ref m) => format!("{}: {}", self.slug, m),
            Err((ref m, ref e)) => format!("{}: {}: {}", self.slug, m, e),
        }
    }
}

/// Counter and timestamps.
#[derive(Debug)]
pub struct Stamps {
    /// Counts how many times this has been used.
    pub count: usize,

    /// Records the time when this has been used first.
    pub first:  Option<time::SystemTime>,

    /// Records the time when this has been used last.
    pub last: Option<time::SystemTime>,
}

impl Stamps {
    fn new(count: i64,
           first: Option<time::SystemTime>,
           last: Option<time::SystemTime>) -> Self {
        Stamps {
            count: count as usize,
            first: first,
            last: last,
        }
    }
}

/* Iterators.  */

/// Iterates over mappings.
pub struct MappingIter {
    core: Rc<RefCell<RpcRuntime>>,
    iter: node::mapping_iter::Client,
}

impl Iterator for MappingIter {
    type Item = (String, String, net::Policy, Mapping);

    fn next(&mut self) -> Option<Self::Item> {
        let request = self.iter.next_request();
        let doit = || {
            make_request_map!(
                self.core.borrow_mut(), request,
                |r: node::mapping_iter::item::Reader|
                Ok((
                    r.get_realm()?.into(),
                    r.get_name()?.into(),
                    r.get_network_policy()?.into(),
                    Mapping::new(self.core.clone(), r.get_name()?, r.get_mapping()?))))
        };
        doit().ok()
    }
}

/// Iterates over bindings in a mapping.
pub struct BundleIter {
    core: Rc<RefCell<RpcRuntime>>,
    iter: node::binding_iter::Client,
}

impl Iterator for BundleIter {
    type Item = (String, openpgp::Fingerprint, Binding);

    fn next(&mut self) -> Option<Self::Item> {
        let request = self.iter.next_request();
        let doit = || {
            make_request_map!(
                self.core.borrow_mut(), request,
                |r: node::binding_iter::item::Reader|
                Ok((String::from(r.get_label()?),
                    r.get_fingerprint().unwrap().parse()?,
                    Binding::new(self.core.clone(), Some(r.get_label()?),
                                 r.get_binding()?))))
        };
        doit().ok()
    }
}

/// Iterates over keys in the common key pool.
pub struct KeyIter {
    core: Rc<RefCell<RpcRuntime>>,
    iter: node::key_iter::Client,
}

impl Iterator for KeyIter {
    type Item = (openpgp::Fingerprint, Key);

    fn next(&mut self) -> Option<Self::Item> {
        let request = self.iter.next_request();
        let doit = || {
            make_request_map!(
                self.core.borrow_mut(), request,
                |r: node::key_iter::item::Reader|
                Ok((r.get_fingerprint().unwrap().parse()?,
                    Key::new(self.core.clone(), r.get_key()?))))
        };
        doit().ok()
    }
}

/// Iterates over logs.
pub struct LogIter {
    core: Rc<RefCell<RpcRuntime>>,
    iter: node::log_iter::Client,
}

impl Iterator for LogIter {
    type Item = Log;

    fn next(&mut self) -> Option<Self::Item> {
        let request = self.iter.next_request();
        let doit = || {
            make_request_map!(
                self.core.borrow_mut(), request,
                |r: node::log_iter::entry::Reader|
                Log::new(r.get_timestamp(),
                         r.get_mapping().ok().map(
                             |cap| Mapping::new(self.core.clone(), &"", cap)),
                         r.get_binding().ok().map(
                             |cap| Binding::new(self.core.clone(), None, cap)),
                         r.get_key().ok().map(
                             |cap| Key::new(self.core.clone(), cap)),
                         r.get_slug()?,
                         r.get_message()?,
                         if r.has_error() {
                             r.get_error().ok()
                         } else {
                             None
                         }).ok_or_else(|| Error::StoreError.into()))
        };
        doit().ok()
    }
}

/* Error handling.  */

/// Results for sequoia-store.
pub type Result<T> = ::std::result::Result<T, anyhow::Error>;


// Converts from backend errors.
impl From<node::Error> for anyhow::Error {
    fn from(error: node::Error) -> Self {
        match error {
            node::Error::Unspecified => Error::StoreError.into(),
            node::Error::NotFound => Error::NotFound.into(),
            node::Error::Conflict => Error::Conflict.into(),
            node::Error::SystemError => Error::StoreError.into(),
            node::Error::MalformedCert => Error::MalformedCert.into(),
            node::Error::MalformedFingerprint =>
                Error::MalformedFingerprint.into(),
            node::Error::NetworkPolicyViolationOffline =>
                net::Error::PolicyViolation(net::Policy::Offline).into(),
            node::Error::NetworkPolicyViolationAnonymized =>
                net::Error::PolicyViolation(net::Policy::Anonymized).into(),
            node::Error::NetworkPolicyViolationEncrypted =>
                net::Error::PolicyViolation(net::Policy::Encrypted).into(),
            node::Error::NetworkPolicyViolationInsecure =>
                net::Error::PolicyViolation(net::Policy::Insecure).into(),
        }
    }
}

#[derive(thiserror::Error, Debug)]
/// Errors returned from the store.
pub enum Error {
    /// A requested key was not found.
    #[error("Key not found")]
    NotFound,
    /// The new key is in conflict with the current key.
    #[error("New key conflicts with the current key")]
    Conflict,
    /// This is a catch-all for unspecified backend errors, and should
    /// go away soon.
    #[error("Unspecified store error")]
    StoreError,
    /// A protocol error occurred.
    #[error("Unspecified protocol error")]
    ProtocolError,
    /// A Cert is malformed.
    #[error("Malformed Cert")]
    MalformedCert,
    /// A fingerprint is malformed.
    #[error("Malformed fingerprint")]
    MalformedFingerprint,
    /// A `capnp::Error` occurred.
    #[error("Internal RPC error")]
    RpcError(#[from] capnp::Error),
}

impl From<capnp::NotInSchema> for Error {
    fn from(_: capnp::NotInSchema) -> Self {
        Error::ProtocolError
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::openpgp::parse::Parse;

    // Like assert!, but checks a pattern.
    //
    //   assert_match!(Some(_) = x);
    //
    // Note: For modules to see this macro, we need to define it before we
    // declare the modules.
    #[allow(unused_macros)]
    macro_rules! assert_match {
        ( $error: pat = $expr:expr, $fmt:expr, $($pargs:expr),* ) => {{
            let x = $expr;
            if let $error = x {
                /* Pass.  */
            } else {
                let extra = format!($fmt, $($pargs),*);
                panic!("Expected {}, got {:?}{}{}",
                       stringify!($error), x,
                       if $fmt.len() > 0 { ": " } else { "." }, extra);
            }
        }};
        ( $error: pat = $expr: expr, $fmt:expr ) => {
            assert_match!($error = $expr, $fmt, );
        };
        ( $error: pat = $expr: expr ) => {
            assert_match!($error = $expr, "");
        };
    }

    macro_rules! bytes {
        ( $x:expr ) => { include_bytes!(concat!("../../openpgp/tests/data/keys/", $x)) };
    }

    const P: net::Policy = net::Policy::Offline;

    #[test]
    fn mapping_network_policy_mismatch() {
        let ctx = ipc::Context::configure()
            .ephemeral()
            .ipc_policy(ipc::IPCPolicy::Internal)
            .build().unwrap();
        // Create mapping.
        Mapping::open(&ctx, P, REALM_CONTACTS, "default").unwrap();

        let ctx2 = ipc::Context::configure()
            .home(ctx.home())
            .ipc_policy(ipc::IPCPolicy::Internal)
            .build().unwrap();
        let mapping = Mapping::open(&ctx2, net::Policy::Encrypted,
                                    REALM_CONTACTS, "default");
        assert_match!(net::Error::PolicyViolation(_)
                      = mapping.err().unwrap().downcast::<net::Error>().unwrap());
    }

    #[test]
    fn import_key() {
        let ctx = ipc::Context::configure()
            .ephemeral()
            .ipc_policy(ipc::IPCPolicy::Internal)
            .build().unwrap();
        let mapping = Mapping::open(&ctx, P, REALM_CONTACTS, "default").unwrap();
        let cert = Cert::from_bytes(&bytes!("testy.pgp")[..]).unwrap();
        mapping.import("Mr. McTestface", &cert).unwrap();
        let binding = mapping.lookup("Mr. McTestface").unwrap();
        let cert_retrieved = binding.cert().unwrap();
        assert_eq!(cert.fingerprint(), cert_retrieved.fingerprint());
    }

    #[test]
    fn key_not_found() {
        let ctx = ipc::Context::configure()
            .ephemeral()
            .ipc_policy(ipc::IPCPolicy::Internal)
            .build().unwrap();
        let mapping = Mapping::open(&ctx, P, REALM_CONTACTS, "default").unwrap();
        let r = mapping.lookup("I do not exist");
        assert_match!(Error::NotFound
                      = r.err().unwrap().downcast::<Error>().unwrap());
    }

    #[test]
    fn add_then_import_wrong_key() {
        let ctx = ipc::Context::configure()
            .ephemeral()
            .ipc_policy(ipc::IPCPolicy::Internal)
            .build().unwrap();
        let mapping = Mapping::open(&ctx, P, REALM_CONTACTS, "default").unwrap();
        let cert = Cert::from_bytes(&bytes!("testy.pgp")[..]).unwrap();
        let fp = Fingerprint::from_bytes(b"bbbbbbbbbbbbbbbbbbbb");
        let binding = mapping.add("Mister B.", &fp).unwrap();
        let r = binding.import(&cert);
        assert_match!(Error::Conflict
                      = r.err().unwrap().downcast::<Error>().unwrap());
    }

    #[test]
    fn add_then_add_different_key() {
        let ctx = ipc::Context::configure()
            .ephemeral()
            .ipc_policy(ipc::IPCPolicy::Internal)
            .build().unwrap();
        let mapping = Mapping::open(&ctx, P, REALM_CONTACTS, "default").unwrap();
        let b = Fingerprint::from_bytes(b"bbbbbbbbbbbbbbbbbbbb");
        mapping.add("Mister B.", &b).unwrap();
        let c = Fingerprint::from_bytes(b"cccccccccccccccccccc");
        assert_match!(Error::Conflict
                      = mapping.add("Mister B.", &c)
                      .err().unwrap().downcast::<Error>().unwrap());
    }

    #[test]
    fn delete_mapping_twice() {
        let ctx = ipc::Context::configure()
            .ephemeral()
            .ipc_policy(ipc::IPCPolicy::Internal)
            .build().unwrap();
        let s0 = Mapping::open(&ctx, P, REALM_CONTACTS, "default").unwrap();
        let s1 = Mapping::open(&ctx, P, REALM_CONTACTS, "default").unwrap();
        s0.delete().unwrap();
        s1.delete().unwrap();
    }

    #[test]
    fn delete_mapping_then_use() {
        let ctx = ipc::Context::configure()
            .ephemeral()
            .ipc_policy(ipc::IPCPolicy::Internal)
            .build().unwrap();
        let s0 = Mapping::open(&ctx, P, REALM_CONTACTS, "default").unwrap();
        let s1 = Mapping::open(&ctx, P, REALM_CONTACTS, "default").unwrap();
        s0.delete().unwrap();
        let binding = s1.lookup("Foobarbaz");
        assert_match!(Error::NotFound
                      = binding.err().unwrap().downcast::<Error>().unwrap());
        let fp = Fingerprint::from_bytes(b"bbbbbbbbbbbbbbbbbbbb");
        let binding = s1.add("Mister B.", &fp);
        assert_match!(Error::NotFound
                      = binding.err().unwrap().downcast::<Error>().unwrap());
    }

    #[test]
    fn delete_binding_twice() {
        let ctx = ipc::Context::configure()
            .ephemeral()
            .ipc_policy(ipc::IPCPolicy::Internal)
            .build().unwrap();
        let mapping = Mapping::open(&ctx, P, REALM_CONTACTS, "default").unwrap();
        let fp = Fingerprint::from_bytes(b"bbbbbbbbbbbbbbbbbbbb");
        let b0 = mapping.add("Mister B.", &fp).unwrap();
        let b1 = mapping.lookup("Mister B.").unwrap();
        b0.delete().unwrap();
        b1.delete().unwrap();
    }

    #[test]
    fn delete_binding_then_use() {
        let ctx = ipc::Context::configure()
            .ephemeral()
            .ipc_policy(ipc::IPCPolicy::Internal)
            .build().unwrap();
        let mapping = Mapping::open(&ctx, P, REALM_CONTACTS, "default").unwrap();
        let fp = Fingerprint::from_bytes(b"bbbbbbbbbbbbbbbbbbbb");
        let b0 = mapping.add("Mister B.", &fp).unwrap();
        let b1 = mapping.lookup("Mister B.").unwrap();
        b0.delete().unwrap();
        assert_match!(Error::NotFound
                      = b1.stats().err().unwrap().downcast::<Error>().unwrap());
        assert_match!(Error::NotFound
                      = b1.key().err().unwrap().downcast::<Error>().unwrap());
    }

    fn make_some_mappings() -> ipc::Context {
        let ctx0 = ipc::Context::configure()
            .ephemeral()
            .ipc_policy(ipc::IPCPolicy::Internal)
            .build().unwrap();
        let mapping = Mapping::open(&ctx0, P, REALM_CONTACTS, "default").unwrap();
        let fp = Fingerprint::from_bytes(b"bbbbbbbbbbbbbbbbbbbb");
        mapping.add("Mister B.", &fp).unwrap();
        mapping.add("B4", &fp).unwrap();

        Mapping::open(&ctx0, P, REALM_CONTACTS, "another mapping").unwrap();

        let ctx1 = ipc::Context::configure()
            .home(ctx0.home())
            .ipc_policy(ipc::IPCPolicy::Internal)
            .build().unwrap();
        let mapping =
            Mapping::open(&ctx1, P, REALM_SOFTWARE_UPDATES, "default").unwrap();
        let fp = Fingerprint::from_bytes(b"cccccccccccccccccccc");
        mapping.add("Mister C.", &fp).unwrap();

        ctx0
    }

    #[test]
    fn stats() {
        let ctx = make_some_mappings();
        let mapping = Mapping::open(&ctx, P, REALM_CONTACTS, "default").unwrap();
        let fp = Fingerprint::from_bytes(b"bbbbbbbbbbbbbbbbbbbb");
        let binding = mapping.add("Mister B.", &fp).unwrap();

        let stats0 = binding.stats().unwrap();
        assert_match!(Some(_) = stats0.created);
        assert_match!(None = stats0.updated);
        assert_eq!(stats0.encryption.count, 0);
        assert_match!(None = stats0.encryption.first);
        assert_match!(None = stats0.encryption.last);
        assert_eq!(stats0.verification.count, 0);
        assert_match!(None = stats0.verification.first);
        assert_match!(None = stats0.verification.last);

        binding.register_encryption().unwrap();
        binding.register_encryption().unwrap();
        binding.register_verification().unwrap();

        let stats1 = binding.stats().unwrap();
        assert_match!(Some(_) = stats1.created);
        assert_eq!(stats0.created, stats1.created);
        assert_match!(None = stats1.updated);
        assert_eq!(stats1.encryption.count, 2);
        assert_match!(Some(_) = stats1.encryption.first);
        assert_match!(Some(_) = stats1.encryption.last);
        assert!(stats1.encryption.first <= stats1.encryption.last);
        assert_eq!(stats1.verification.count, 1);
        assert_match!(Some(_) = stats1.verification.first);
        assert_match!(Some(_) = stats1.verification.last);
        assert_eq!(stats1.verification.first, stats1.verification.last);
    }


    #[test]
    fn mapping_iterator() {
        let ctx = make_some_mappings();
        let mut iter = Mapping::list(&ctx, REALM_CONTACTS).unwrap();
        let (realm, name, network_policy, mapping) = iter.next().unwrap();
        assert_eq!(realm, REALM_CONTACTS);
        assert_eq!(name, "default");
        assert_eq!(network_policy, net::Policy::Offline);
        let fp = Fingerprint::from_bytes(b"bbbbbbbbbbbbbbbbbbbb");
        mapping.add("Mister B.", &fp).unwrap();
        let (realm, name, network_policy, mapping) = iter.next().unwrap();
        assert_eq!(realm, REALM_CONTACTS);
        assert_eq!(name, "another mapping");
        assert_eq!(network_policy, net::Policy::Offline);
        mapping.add("Mister B.", &fp).unwrap();
        assert!(iter.next().is_none());
    }

    #[test]
    fn binding_iterator() {
        let ctx = make_some_mappings();
        let mapping = Mapping::open(&ctx, P, REALM_CONTACTS, "default").unwrap();
        let mut iter = mapping.iter().unwrap();
        let (label, fingerprint, binding) = iter.next().unwrap();
        let fp = Fingerprint::from_bytes(b"bbbbbbbbbbbbbbbbbbbb");
        assert_eq!(label, "Mister B.");
        assert_eq!(fingerprint, fp);
        binding.stats().unwrap();
        let (label, fingerprint, binding) = iter.next().unwrap();
        assert_eq!(label, "B4");
        assert_eq!(fingerprint, fp);
        binding.stats().unwrap();
        assert!(iter.next().is_none());
    }

    #[test]
    fn key_iterator() {
        let ctx = make_some_mappings();
        let mut iter = Store::list_keys(&ctx).unwrap();
        let (fingerprint, key) = iter.next().unwrap();
        assert_eq!(fingerprint, Fingerprint::from_bytes(b"bbbbbbbbbbbbbbbbbbbb"));
        key.stats().unwrap();
        let (fingerprint, key) = iter.next().unwrap();
        assert_eq!(fingerprint, Fingerprint::from_bytes(b"cccccccccccccccccccc"));
        key.stats().unwrap();
        assert!(iter.next().is_none());
    }
}

