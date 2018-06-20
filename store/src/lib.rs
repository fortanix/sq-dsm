//! For storing transferable public keys.
//!
//! The key store stores transferable public keys (TPKs) using an
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
//! to create the store.
//!
//! [network policy]: ../sequoia_core/enum.NetworkPolicy.html
//!
//! # Example
//!
//! ```
//! # extern crate openpgp;
//! # extern crate sequoia_core;
//! # extern crate sequoia_store;
//! # use openpgp::Fingerprint;
//! # use sequoia_core::{Context, NetworkPolicy, IPCPolicy};
//! # use sequoia_store::{Store, Result};
//! # fn main() { f().unwrap(); }
//! # fn f() -> Result<()> {
//! # let ctx = Context::configure("org.sequoia-pgp.demo.store")
//! #     .network_policy(NetworkPolicy::Offline)
//! #     .ipc_policy(IPCPolicy::Internal)
//! #     .ephemeral().build()?;
//! let store = Store::open(&ctx, "default")?;
//!
//! let fp = Fingerprint::from_bytes(b"bbbbbbbbbbbbbbbbbbbb");
//! let binding = store.add("Mister B.", &fp)?;
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

extern crate capnp;
#[macro_use]
extern crate capnp_rpc;
#[macro_use]
extern crate failure;
extern crate futures;
extern crate rand;
extern crate rusqlite;
extern crate time;
extern crate tokio_core;
extern crate tokio_io;

use std::cell::RefCell;
use std::fmt;
use std::rc::Rc;

use capnp::capability::Promise;
use capnp_rpc::rpc_twoparty_capnp::Side;
use futures::{Future};
use time::Timespec;
use tokio_core::reactor::Core;

extern crate openpgp;
#[allow(unused_imports)]
#[macro_use]
extern crate sequoia_core;
extern crate sequoia_net;

use openpgp::Fingerprint;
use openpgp::TPK;
use sequoia_core as core;
use sequoia_core::Context;
use sequoia_net::ipc;

#[allow(dead_code)] mod store_protocol_capnp;
use store_protocol_capnp::node;

/// Macros managing requests and responses.
#[macro_use] mod macros;

pub mod backend;

/// Returns the service descriptor.
#[doc(hidden)]
pub fn descriptor(c: &Context) -> ipc::Descriptor {
    ipc::Descriptor::new(
        c,
        c.home().join("S.keystore"),
        c.lib().join("keystore"),
        backend::factory,
    )
}

/// A public key store.
pub struct Store {
    name: String,
    core: Rc<RefCell<Core>>,
    store: node::store::Client,
}

impl fmt::Debug for Store {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Store {{ name: {} }}", self.name)
    }
}

impl Store {
    /// Establishes a connection to the backend.
    fn connect(c: &Context) -> Result<(Core, node::Client)> {
        let descriptor = descriptor(c);
        let core = Core::new()?;
        let handle = core.handle();

        let mut rpc_system
            = match descriptor.connect(&handle) {
                Ok(r) => r,
                Err(e) => return Err(e.into()),
            };

        let client: node::Client = rpc_system.bootstrap(Side::Server);
        handle.spawn(rpc_system.map_err(|_e| ()));

        Ok((core, client))
    }

    /// Opens a store.
    ///
    /// Opens a store with the given name.  If the store does not
    /// exist, it is created.  Stores are handles for objects
    /// maintained by a background service.  The background service
    /// associates state with this name.
    ///
    /// The store updates TPKs in compliance with the network policy
    /// of the context that created the store in the first place.
    /// Opening the store with a different network policy is
    /// forbidden.
    pub fn open(c: &Context, name: &str) -> Result<Self> {
        let (mut core, client) = Self::connect(c)?;

        let mut request = client.open_request();
        request.get().set_domain(c.domain());
        request.get().set_network_policy(c.network_policy().into());
        request.get().set_ephemeral(c.ephemeral());
        request.get().set_name(name);

        let store = make_request!(&mut core, request)?;
        Ok(Self::new(Rc::new(RefCell::new(core)), name, store))
    }

    fn new(core: Rc<RefCell<Core>>, name: &str, store: node::store::Client) -> Self {
        Store{core: core, name: name.into(), store: store}
    }

    /// Lists all stores with the given prefix.
    pub fn list(c: &Context, domain_prefix: &str) -> Result<StoreIter> {
        let (mut core, client) = Self::connect(c)?;
        let mut request = client.iter_request();
        request.get().set_domain_prefix(domain_prefix);
        let iter = make_request!(&mut core, request)?;
        Ok(StoreIter{core: Rc::new(RefCell::new(core)), iter: iter})
    }

    /// Lists all keys in the common key pool.
    pub fn list_keys(c: &Context) -> Result<KeyIter> {
        let (mut core, client) = Self::connect(c)?;
        let request = client.iter_keys_request();
        let iter = make_request!(&mut core, request)?;
        Ok(KeyIter{core: Rc::new(RefCell::new(core)), iter: iter})
    }

    /// Lists all log entries.
    pub fn server_log(c: &Context) -> Result<LogIter> {
        let (mut core, client) = Self::connect(c)?;
        let request = client.log_request();
        let iter = make_request!(&mut core, request)?;
        Ok(LogIter{core: Rc::new(RefCell::new(core)), iter: iter})
    }

    /// Adds a key identified by fingerprint to the store.
    ///
    /// # Example
    ///
    /// ```
    /// # extern crate openpgp;
    /// # extern crate sequoia_core;
    /// # extern crate sequoia_store;
    /// # use openpgp::Fingerprint;
    /// # use sequoia_core::{Context, NetworkPolicy, IPCPolicy};
    /// # use sequoia_store::{Store, Result};
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// # let ctx = Context::configure("org.sequoia-pgp.demo.store")
    /// #     .network_policy(NetworkPolicy::Offline)
    /// #     .ipc_policy(IPCPolicy::Internal)
    /// #     .ephemeral().build()?;
    /// let store = Store::open(&ctx, "default")?;
    /// let fp = Fingerprint::from_bytes(b"bbbbbbbbbbbbbbbbbbbb");
    /// store.add("Mister B.", &fp)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn add(&self, label: &str, fingerprint: &Fingerprint) -> Result<Binding> {
        let mut request = self.store.add_request();
        request.get().set_label(label);
        request.get().set_fingerprint(fingerprint.to_hex().as_ref());
        let binding = make_request!(self.core.borrow_mut(), request)?;
        Ok(Binding::new(self.core.clone(), label, binding))
    }

    /// Imports a key into the store.
    ///
    /// # Example
    ///
    /// ```
    /// # extern crate openpgp;
    /// # extern crate sequoia_core;
    /// # extern crate sequoia_store;
    /// # use openpgp::TPK;
    /// # use sequoia_core::{Context, NetworkPolicy, IPCPolicy};
    /// # use sequoia_store::{Store, Result};
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// # let ctx = Context::configure("org.sequoia-pgp.demo.store")
    /// #     .network_policy(NetworkPolicy::Offline)
    /// #     .ipc_policy(IPCPolicy::Internal)
    /// #     .ephemeral().build()?;
    /// # let tpk = TPK::from_bytes(
    /// #     include_bytes!("../../openpgp/tests/data/keys/testy.pgp")).unwrap();
    /// let store = Store::open(&ctx, "default")?;
    /// store.import("Testy McTestface", &tpk)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn import(&self, label: &str, tpk: &TPK) -> Result<TPK> {
        let fingerprint = tpk.fingerprint();
        let mut request = self.store.add_request();
        request.get().set_label(label);
        request.get().set_fingerprint(fingerprint.to_hex().as_ref());
        let binding = make_request!(self.core.borrow_mut(), request)?;
        let binding = Binding::new(self.core.clone(), label, binding);
        binding.import(tpk)
    }

    /// Returns the binding for the given label.
    ///
    /// # Example
    ///
    /// ```
    /// # extern crate openpgp;
    /// # extern crate sequoia_core;
    /// # extern crate sequoia_store;
    /// # use openpgp::Fingerprint;
    /// # use sequoia_core::{Context, NetworkPolicy, IPCPolicy};
    /// # use sequoia_store::{Store, Result};
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// # let ctx = Context::configure("org.sequoia-pgp.demo.store")
    /// #     .network_policy(NetworkPolicy::Offline)
    /// #     .ipc_policy(IPCPolicy::Internal)
    /// #     .ephemeral().build()?;
    /// let store = Store::open(&ctx, "default")?;
    /// let fp = Fingerprint::from_bytes(b"bbbbbbbbbbbbbbbbbbbb");
    /// store.add("Mister B.", &fp)?;
    /// drop(store);
    /// // ...
    /// let store = Store::open(&ctx, "default")?;
    /// let binding = store.lookup("Mister B.")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn lookup(&self, label: &str) -> Result<Binding> {
        let mut request = self.store.lookup_request();
        request.get().set_label(label);
        let binding = make_request!(self.core.borrow_mut(), request)?;
        Ok(Binding::new(self.core.clone(), label, binding))
    }

    /// Deletes this store.
    ///
    /// # Example
    ///
    /// ```
    /// # extern crate openpgp;
    /// # #[macro_use] extern crate sequoia_core;
    /// # extern crate sequoia_store;
    /// # use openpgp::Fingerprint;
    /// # use sequoia_core::{Context, NetworkPolicy, IPCPolicy};
    /// # use sequoia_store::{Store, Result, Error};
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// # let ctx = Context::configure("org.sequoia-pgp.demo.store")
    /// #     .network_policy(NetworkPolicy::Offline)
    /// #     .ipc_policy(IPCPolicy::Internal)
    /// #     .ephemeral().build()?;
    /// let store = Store::open(&ctx, "default")?;
    /// let fp = Fingerprint::from_bytes(b"bbbbbbbbbbbbbbbbbbbb");
    /// store.add("Mister B.", &fp)?;
    /// store.delete()?;
    /// // ...
    /// let store = Store::open(&ctx, "default")?;
    /// let binding = store.lookup("Mister B.");
    /// assert!(binding.is_err()); // not found
    /// # Ok(())
    /// # }
    /// ```
    pub fn delete(self) -> Result<()> {
        let request = self.store.delete_request();
        make_request_map!(self.core.borrow_mut(), request, |_| Ok(()))
    }

    /// Lists all bindings.
    pub fn iter(&self) -> Result<BindingIter> {
        let request = self.store.iter_request();
        let iter = make_request!(self.core.borrow_mut(), request)?;
        Ok(BindingIter{core: self.core.clone(), iter: iter})
    }

    /// Lists all log entries related to this store.
    pub fn log(&self) -> Result<LogIter> {
        let request = self.store.log_request();
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

/// Represents an entry in a Store.
///
/// Stores map labels to TPKs.  A `Binding` represents a pair in this
/// relation.  We make this explicit because we associate metadata
/// with these pairs.
pub struct Binding {
    label: String,
    core: Rc<RefCell<Core>>,
    binding: node::binding::Client,
}

impl fmt::Debug for Binding {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Binding {{ label: {} }}", self.label)
    }
}

impl Binding {
    fn new(core: Rc<RefCell<Core>>, label: &str, binding: node::binding::Client) -> Self {
        Binding{label: label.into(), core: core, binding: binding}
    }

    /// Returns stats for this binding.
    ///
    /// # Example
    ///
    /// ```
    /// # extern crate openpgp;
    /// # extern crate sequoia_core;
    /// # extern crate sequoia_store;
    /// # use openpgp::Fingerprint;
    /// # use sequoia_core::{Context, NetworkPolicy, IPCPolicy};
    /// # use sequoia_store::{Store, Result};
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// # let ctx = Context::configure("org.sequoia-pgp.demo.store")
    /// #     .network_policy(NetworkPolicy::Offline)
    /// #     .ipc_policy(IPCPolicy::Internal)
    /// #     .ephemeral().build()?;
    /// let store = Store::open(&ctx, "default")?;
    ///
    /// let fp = Fingerprint::from_bytes(b"bbbbbbbbbbbbbbbbbbbb");
    /// let binding = store.add("Mister B.", &fp)?;
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
                          |tpk| Ok(Key::new(self.core.clone(), tpk)))
    }

    /// Returns the `Tpk` of this binding.
    ///
    /// A shortcut for `self.key()?.tpk()`.
    pub fn tpk(&self) -> Result<TPK> {
        self.key()?.tpk()
    }

    /// Updates this binding with the given TPK.
    ///
    /// If the new key `tpk` matches the current key, i.e. they have
    /// the same fingerprint, both keys are merged and normalized.
    /// The returned key contains all packets known to Sequoia, and
    /// should be used instead of `tpk`.
    ///
    /// If the new key does not match the current key, and it does not
    /// carry a valid signature from the current key, an
    /// `Error::Conflict` is returned, and you have to resolve the
    /// conflict, either by ignoring the new key, or by using
    /// `Binding::rotate` to force a rotation.
    ///
    /// # Example
    ///
    /// ```
    /// # extern crate openpgp;
    /// # #[macro_use] extern crate sequoia_core;
    /// # extern crate sequoia_store;
    /// # use openpgp::TPK;
    /// # use sequoia_core::{Context, NetworkPolicy, IPCPolicy};
    /// # use sequoia_store::{Store, Result, Error};
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// # let ctx = Context::configure("org.sequoia-pgp.demo.store")
    /// #     .network_policy(NetworkPolicy::Offline)
    /// #     .ipc_policy(IPCPolicy::Internal)
    /// #     .ephemeral().build()?;
    /// # let old = TPK::from_bytes(
    /// #     include_bytes!("../../openpgp/tests/data/keys/testy.pgp")).unwrap();
    /// # let new = TPK::from_bytes(
    /// #     include_bytes!("../../openpgp/tests/data/keys/testy-new.pgp")).unwrap();
    /// let store = Store::open(&ctx, "default")?;
    /// store.import("Testy McTestface", &old)?;
    /// // later...
    /// let binding = store.lookup("Testy McTestface")?;
    /// let r = binding.import(&new);
    /// assert!(r.is_err()); // Conflict!
    /// # Ok(())
    /// # }
    /// ```
    pub fn import(&self, tpk: &TPK) -> Result<TPK> {
        let mut blob = vec![];
        tpk.serialize(&mut blob)?;
        let mut request = self.binding.import_request();
        request.get().set_force(false);
        request.get().set_key(&blob);
        make_request_map!(
            self.core.borrow_mut(),
            request,
            |data| TPK::from_bytes(data).map_err(|e| e.into()))
    }

    /// Forces a keyrotation to the given TPK.
    ///
    /// The current key is replaced with the new key `tpk`, even if
    /// they do not have the same fingerprint.  If a key with the same
    /// fingerprint as `tpk` is already in the store, is merged with
    /// `tpk` and normalized.  The returned key contains all packets
    /// known to Sequoia, and should be used instead of `tpk`.
    ///
    /// Use this function to resolve conflicts returned from
    /// `Binding::import`.  Make sure that you have authenticated
    /// `tpk` properly.  How to do that depends on your thread model.
    /// You could simply ask Alice to call her communication partner
    /// Bob and confirm that he rotated his keys.
    ///
    /// # Example
    ///
    /// ```
    /// # extern crate openpgp;
    /// # #[macro_use] extern crate sequoia_core;
    /// # extern crate sequoia_store;
    /// # use openpgp::TPK;
    /// # use sequoia_core::{Context, NetworkPolicy, IPCPolicy};
    /// # use sequoia_store::{Store, Result, Error};
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// # let ctx = Context::configure("org.sequoia-pgp.demo.store")
    /// #     .network_policy(NetworkPolicy::Offline)
    /// #     .ipc_policy(IPCPolicy::Internal)
    /// #     .ephemeral().build()?;
    /// # let old = TPK::from_bytes(
    /// #     include_bytes!("../../openpgp/tests/data/keys/testy.pgp")).unwrap();
    /// # let new = TPK::from_bytes(
    /// #     include_bytes!("../../openpgp/tests/data/keys/testy-new.pgp")).unwrap();
    /// let store = Store::open(&ctx, "default")?;
    /// store.import("Testy McTestface", &old)?;
    /// // later...
    /// let binding = store.lookup("Testy McTestface")?;
    /// let r = binding.import(&new);
    /// assert!(r.is_err()); // Conflict!
    /// let r = binding.rotate(&new)?;
    /// assert_eq!(new.fingerprint(), r.fingerprint());
    /// # Ok(())
    /// # }
    /// ```
    pub fn rotate(&self, tpk: &TPK) -> Result<TPK> {
        let mut blob = vec![];
        tpk.serialize(&mut blob)?;
        let mut request = self.binding.import_request();
        request.get().set_force(true);
        request.get().set_key(&blob);
        make_request_map!(
            self.core.borrow_mut(),
            request,
            |data| TPK::from_bytes(data).map_err(|e| e.into()))
    }

    /// Deletes this binding.
    ///
    /// # Example
    ///
    /// ```
    /// # extern crate openpgp;
    /// # #[macro_use] extern crate sequoia_core;
    /// # extern crate sequoia_store;
    /// # use openpgp::Fingerprint;
    /// # use sequoia_core::{Context, NetworkPolicy, IPCPolicy};
    /// # use sequoia_store::{Store, Result, Error};
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// # let ctx = Context::configure("org.sequoia-pgp.demo.store")
    /// #     .network_policy(NetworkPolicy::Offline)
    /// #     .ipc_policy(IPCPolicy::Internal)
    /// #     .ephemeral().build()?;
    /// let store = Store::open(&ctx, "default")?;
    /// let fp = Fingerprint::from_bytes(b"bbbbbbbbbbbbbbbbbbbb");
    /// let binding = store.add("Mister B.", &fp)?;
    /// binding.delete()?;
    /// let binding = store.lookup("Mister B.");
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
}

/// Represents a key in a store.
///
/// A `Key` is a handle to a stored TPK.  We make this explicit
/// because we associate metadata with TPKs.
pub struct Key {
    core: Rc<RefCell<Core>>,
    key: node::key::Client,
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Key {{ }}")
    }
}

impl Key {
    fn new(core: Rc<RefCell<Core>>, key: node::key::Client) -> Self {
        Key{core: core, key: key}
    }

    /// Returns the TPK.
    pub fn tpk(&self) -> Result<TPK> {
        make_request_map!(self.core.borrow_mut(),
                          self.key.tpk_request(),
                          |tpk| TPK::from_bytes(tpk).map_err(|e| e.into()))
    }

    /// Returns stats for this key.
    pub fn stats(&self) -> Result<Stats> {
        make_stats_request!(self.core.borrow_mut(),
                            self.key.stats_request())
    }

    /// Updates this stored key with the given TPK.
    ///
    /// If the new key `tpk` matches the current key, i.e. they have
    /// the same fingerprint, both keys are merged and normalized.
    /// The returned key contains all packets known to Sequoia, and
    /// should be used instead of `tpk`.
    ///
    /// If the new key does not match the current key,
    /// `Error::Conflict` is returned.
    ///
    /// # Example
    ///
    /// ```
    /// # extern crate openpgp;
    /// # #[macro_use] extern crate sequoia_core;
    /// # extern crate sequoia_store;
    /// # use openpgp::Fingerprint;
    /// # use openpgp::TPK;
    /// # use sequoia_core::{Context, NetworkPolicy, IPCPolicy};
    /// # use sequoia_store::{Store, Result, Error};
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// # let ctx = Context::configure("org.sequoia-pgp.demo.store")
    /// #     .network_policy(NetworkPolicy::Offline)
    /// #     .ipc_policy(IPCPolicy::Internal)
    /// #     .ephemeral().build()?;
    /// # let old = TPK::from_bytes(
    /// #     include_bytes!("../../openpgp/tests/data/keys/testy.pgp")).unwrap();
    /// # let new = TPK::from_bytes(
    /// #     include_bytes!("../../openpgp/tests/data/keys/testy-new.pgp")).unwrap();
    /// let store = Store::open(&ctx, "default")?;
    /// let fp = Fingerprint::from_hex("3E8877C877274692975189F5D03F6F865226FE8B").unwrap();
    /// let binding = store.add("Testy McTestface", &fp)?;
    /// let key = binding.key()?;
    /// let r = key.import(&old)?;
    /// assert_eq!(r.fingerprint(), old.fingerprint());
    /// let r = key.import(&new);
    /// assert!(r.is_err()); // conflict
    /// # Ok(())
    /// # }
    /// ```
    pub fn import(&self, tpk: &TPK) -> Result<TPK> {
        let mut blob = vec![];
        tpk.serialize(&mut blob)?;
        let mut request = self.key.import_request();
        request.get().set_key(&blob);
        make_request_map!(
            self.core.borrow_mut(),
            request,
            |data| TPK::from_bytes(data).map_err(|e| e.into()))
    }

    /// Lists all log entries related to this key.
    pub fn log(&self) -> Result<LogIter> {
        let request = self.key.log_request();
        let iter = make_request!(self.core.borrow_mut(), request)?;
        Ok(LogIter{core: self.core.clone(), iter: iter})
    }
}


/// Returns `t` as Timespec.
fn from_unix(t: i64) -> Option<Timespec> {
    if t == 0 {
        None
    } else {
        Some(Timespec::new(t, 0))
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
    pub created: Option<Timespec>,

    /// Records the time this item was last updated.
    pub updated: Option<Timespec>,

    /// Records counters and timestamps of encryptions.
    pub encryption: Stamps,

    /// Records counters and timestamps of verifications.
    pub verification: Stamps,
}

/// Represents a log entry.
#[derive(Debug)]
pub struct Log {
    /// Records the time of the entry.
    pub timestamp: Timespec,

    /// Relates the entry to a store.
    pub store: Option<Store>,

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
           store: Option<Store>, binding: Option<Binding>, key: Option<Key>,
           slug: &str, message: &str, error: Option<&str>)
           -> Option<Self> {
        let timestamp = from_unix(timestamp)?;

        Some(Log{
            timestamp: timestamp,
            store: store,
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

    /// Returns the message with timestamp and context.
    pub fn full(&self) -> String {
        let timestamp =
            time::strftime("%F %H:%M", &time::at(self.timestamp))
            .unwrap(); // Only parse errors can happen.

        match self.status {
            Ok(ref m) => format!(
                "{}: {}: {}", timestamp, self.slug, m),
            Err((ref m, ref e)) => format!(
                "{}: {}: {}: {}", timestamp, self.slug, m, e),
        }
    }
}

/// Counter and timestamps.
#[derive(Debug)]
pub struct Stamps {
    /// Counts how many times this has been used.
    pub count: usize,

    /// Records the time when this has been used first.
    pub first:  Option<Timespec>,

    /// Records the time when this has been used last.
    pub last: Option<Timespec>,
}

impl Stamps {
    fn new(count: i64, first: Option<Timespec>, last: Option<Timespec>) -> Self {
        Stamps {
            count: count as usize,
            first: first,
            last: last,
        }
    }
}

/* Iterators.  */

/// Iterates over stores.
pub struct StoreIter {
    core: Rc<RefCell<Core>>,
    iter: node::store_iter::Client,
}

impl Iterator for StoreIter {
    type Item = (String, String, core::NetworkPolicy, Store);

    fn next(&mut self) -> Option<Self::Item> {
        let request = self.iter.next_request();
        let doit = || {
            make_request_map!(
                self.core.borrow_mut(), request,
                |r: node::store_iter::item::Reader|
                Ok((
                    r.get_domain()?.into(),
                    r.get_name()?.into(),
                    r.get_network_policy()?.into(),
                    Store::new(self.core.clone(), r.get_name()?, r.get_store()?))))
        };
        doit().ok()
    }
}

/// Iterates over bindings in a store.
pub struct BindingIter {
    core: Rc<RefCell<Core>>,
    iter: node::binding_iter::Client,
}

impl Iterator for BindingIter {
    type Item = (String, openpgp::Fingerprint, Binding);

    fn next(&mut self) -> Option<Self::Item> {
        let request = self.iter.next_request();
        let doit = || {
            make_request_map!(
                self.core.borrow_mut(), request,
                |r: node::binding_iter::item::Reader|
                Ok((String::from(r.get_label()?),
                    openpgp::Fingerprint::from_hex(r.get_fingerprint()?).unwrap(),
                    Binding::new(self.core.clone(), r.get_label()?, r.get_binding()?))))
        };
        doit().ok()
    }
}

/// Iterates over keys in the common key pool.
pub struct KeyIter {
    core: Rc<RefCell<Core>>,
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
                Ok((openpgp::Fingerprint::from_hex(r.get_fingerprint()?).unwrap(),
                    Key::new(self.core.clone(), r.get_key()?))))
        };
        doit().ok()
    }
}

/// Iterates over logs.
pub struct LogIter {
    core: Rc<RefCell<Core>>,
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
                         r.get_store().ok().map(
                             |cap| Store::new(self.core.clone(), &"", cap)),
                         r.get_binding().ok().map(
                             |cap| Binding::new(self.core.clone(), &"", cap)),
                         r.get_key().ok().map(
                             |cap| Key::new(self.core.clone(), cap)),
                         r.get_slug()?,
                         r.get_message()?,
                         if r.has_error() {
                             r.get_error().ok()
                         } else {
                             None
                         }).ok_or(Error::StoreError.into()))
        };
        doit().ok()
    }
}

/* Error handling.  */

/// Results for sequoia-store.
pub type Result<T> = ::std::result::Result<T, failure::Error>;


// Converts from backend errors.
impl From<node::Error> for failure::Error {
    fn from(error: node::Error) -> Self {
        match error {
            node::Error::Unspecified => Error::StoreError.into(),
            node::Error::NotFound => Error::NotFound.into(),
            node::Error::Conflict => Error::Conflict.into(),
            node::Error::SystemError => Error::StoreError.into(),
            node::Error::MalformedTPK => Error::MalformedTPK.into(),
            node::Error::MalformedFingerprint =>
                Error::MalformedFingerprint.into(),
            node::Error::NetworkPolicyViolationOffline =>
                core::Error::NetworkPolicyViolation(core::NetworkPolicy::Offline).into(),
            node::Error::NetworkPolicyViolationAnonymized =>
                core::Error::NetworkPolicyViolation(core::NetworkPolicy::Anonymized).into(),
            node::Error::NetworkPolicyViolationEncrypted =>
                core::Error::NetworkPolicyViolation(core::NetworkPolicy::Encrypted).into(),
            node::Error::NetworkPolicyViolationInsecure =>
                core::Error::NetworkPolicyViolation(core::NetworkPolicy::Insecure).into(),
        }
    }
}

#[derive(Fail, Debug)]
/// Errors returned from the store.
pub enum Error {
    /// A requested key was not found.
    #[fail(display = "Key not found")]
    NotFound,
    /// The new key is in conflict with the current key.
    #[fail(display = "New key conflicts with the current key")]
    Conflict,
    /// This is a catch-all for unspecified backend errors, and should
    /// go away soon.
    #[fail(display = "Unspecified store error")]
    StoreError,
    /// A protocol error occurred.
    #[fail(display = "Unspecified protocol error")]
    ProtocolError,
    /// A TPK is malformed.
    #[fail(display = "Malformed TPK")]
    MalformedTPK,
    /// A fingerprint is malformed.
    #[fail(display = "Malformed fingerprint")]
    MalformedFingerprint,
    /// A `capnp::Error` occurred.
    #[fail(display = "Internal RPC error")]
    RpcError(capnp::Error),
}

impl From<capnp::Error> for Error {
    fn from(error: capnp::Error) -> Self {
        Error::RpcError(error)
    }
}

impl From<capnp::NotInSchema> for Error {
    fn from(_: capnp::NotInSchema) -> Self {
        Error::ProtocolError
    }
}

#[cfg(test)]
mod store_test {
    use super::{core, Store, Error, TPK, Fingerprint};

    macro_rules! bytes {
        ( $x:expr ) => { include_bytes!(concat!("../../openpgp/tests/data/keys/", $x)) };
    }

    #[test]
    fn store_network_policy_mismatch() {
        let ctx = core::Context::configure("org.sequoia-pgp.tests")
            .ephemeral()
            .network_policy(core::NetworkPolicy::Offline)
            .ipc_policy(core::IPCPolicy::Internal)
            .build().unwrap();
        // Create store.
        Store::open(&ctx, "default").unwrap();

        let ctx2 = core::Context::configure("org.sequoia-pgp.tests")
            .home(ctx.home())
            .network_policy(core::NetworkPolicy::Encrypted)
            .ipc_policy(core::IPCPolicy::Internal)
            .build().unwrap();
        let store = Store::open(&ctx2, "default");
        assert_match!(core::Error::NetworkPolicyViolation(_)
                      = store.err().unwrap().downcast::<core::Error>().unwrap());
    }

    #[test]
    fn import_key() {
        let ctx = core::Context::configure("org.sequoia-pgp.tests")
            .ephemeral()
            .network_policy(core::NetworkPolicy::Offline)
            .ipc_policy(core::IPCPolicy::Internal)
            .build().unwrap();
        let store = Store::open(&ctx, "default").unwrap();
        let tpk = TPK::from_bytes(bytes!("testy.pgp")).unwrap();
        store.import("Mr. McTestface", &tpk).unwrap();
        let binding = store.lookup("Mr. McTestface").unwrap();
        let tpk_retrieved = binding.tpk().unwrap();
        assert_eq!(tpk.fingerprint(), tpk_retrieved.fingerprint());
    }

    #[test]
    fn key_not_found() {
        let ctx = core::Context::configure("org.sequoia-pgp.tests")
            .ephemeral()
            .network_policy(core::NetworkPolicy::Offline)
            .ipc_policy(core::IPCPolicy::Internal)
            .build().unwrap();
        let store = Store::open(&ctx, "default").unwrap();
        let r = store.lookup("I do not exist");
        assert_match!(Error::NotFound
                      = r.err().unwrap().downcast::<Error>().unwrap());
    }

    #[test]
    fn add_then_import_wrong_key() {
        let ctx = core::Context::configure("org.sequoia-pgp.tests")
            .ephemeral()
            .network_policy(core::NetworkPolicy::Offline)
            .ipc_policy(core::IPCPolicy::Internal)
            .build().unwrap();
        let store = Store::open(&ctx, "default").unwrap();
        let tpk = TPK::from_bytes(bytes!("testy.pgp")).unwrap();
        let fp = Fingerprint::from_bytes(b"bbbbbbbbbbbbbbbbbbbb");
        let binding = store.add("Mister B.", &fp).unwrap();
        let r = binding.import(&tpk);
        assert_match!(Error::Conflict
                      = r.err().unwrap().downcast::<Error>().unwrap());
    }

    #[test]
    fn add_then_add_different_key() {
        let ctx = core::Context::configure("org.sequoia-pgp.tests")
            .ephemeral()
            .network_policy(core::NetworkPolicy::Offline)
            .ipc_policy(core::IPCPolicy::Internal)
            .build().unwrap();
        let store = Store::open(&ctx, "default").unwrap();
        let b = Fingerprint::from_bytes(b"bbbbbbbbbbbbbbbbbbbb");
        store.add("Mister B.", &b).unwrap();
        let c = Fingerprint::from_bytes(b"cccccccccccccccccccc");
        assert_match!(Error::Conflict
                      = store.add("Mister B.", &c)
                      .err().unwrap().downcast::<Error>().unwrap());
    }

    #[test]
    fn delete_store_twice() {
        let ctx = core::Context::configure("org.sequoia-pgp.tests")
            .ephemeral()
            .network_policy(core::NetworkPolicy::Offline)
            .ipc_policy(core::IPCPolicy::Internal)
            .build().unwrap();
        let s0 = Store::open(&ctx, "default").unwrap();
        let s1 = Store::open(&ctx, "default").unwrap();
        s0.delete().unwrap();
        s1.delete().unwrap();
    }

    #[test]
    fn delete_store_then_use() {
        let ctx = core::Context::configure("org.sequoia-pgp.tests")
            .ephemeral()
            .network_policy(core::NetworkPolicy::Offline)
            .ipc_policy(core::IPCPolicy::Internal)
            .build().unwrap();
        let s0 = Store::open(&ctx, "default").unwrap();
        let s1 = Store::open(&ctx, "default").unwrap();
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
        let ctx = core::Context::configure("org.sequoia-pgp.tests")
            .ephemeral()
            .network_policy(core::NetworkPolicy::Offline)
            .ipc_policy(core::IPCPolicy::Internal)
            .build().unwrap();
        let store = Store::open(&ctx, "default").unwrap();
        let fp = Fingerprint::from_bytes(b"bbbbbbbbbbbbbbbbbbbb");
        let b0 = store.add("Mister B.", &fp).unwrap();
        let b1 = store.lookup("Mister B.").unwrap();
        b0.delete().unwrap();
        b1.delete().unwrap();
    }

    #[test]
    fn delete_binding_then_use() {
        let ctx = core::Context::configure("org.sequoia-pgp.tests")
            .ephemeral()
            .network_policy(core::NetworkPolicy::Offline)
            .ipc_policy(core::IPCPolicy::Internal)
            .build().unwrap();
        let store = Store::open(&ctx, "default").unwrap();
        let fp = Fingerprint::from_bytes(b"bbbbbbbbbbbbbbbbbbbb");
        let b0 = store.add("Mister B.", &fp).unwrap();
        let b1 = store.lookup("Mister B.").unwrap();
        b0.delete().unwrap();
        assert_match!(Error::NotFound
                      = b1.stats().err().unwrap().downcast::<Error>().unwrap());
        assert_match!(Error::NotFound
                      = b1.key().err().unwrap().downcast::<Error>().unwrap());
    }

    fn make_some_stores() -> core::Context {
        let ctx0 = core::Context::configure("org.sequoia-pgp.tests.foo")
            .ephemeral()
            .network_policy(core::NetworkPolicy::Offline)
            .ipc_policy(core::IPCPolicy::Internal)
            .build().unwrap();
        let store = Store::open(&ctx0, "default").unwrap();
        let fp = Fingerprint::from_bytes(b"bbbbbbbbbbbbbbbbbbbb");
        store.add("Mister B.", &fp).unwrap();
        store.add("B4", &fp).unwrap();

        Store::open(&ctx0, "another store").unwrap();

        let ctx1 = core::Context::configure("org.sequoia-pgp.tests.bar")
            .home(ctx0.home())
            .network_policy(core::NetworkPolicy::Offline)
            .ipc_policy(core::IPCPolicy::Internal)
            .build().unwrap();
        let store = Store::open(&ctx1, "default").unwrap();
        let fp = Fingerprint::from_bytes(b"cccccccccccccccccccc");
        store.add("Mister C.", &fp).unwrap();

        ctx0
    }

    #[test]
    fn stats() {
        let ctx = make_some_stores();
        let store = Store::open(&ctx, "default").unwrap();
        let fp = Fingerprint::from_bytes(b"bbbbbbbbbbbbbbbbbbbb");
        let binding = store.add("Mister B.", &fp).unwrap();

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
    fn store_iterator() {
        let ctx = make_some_stores();
        let mut iter = Store::list(&ctx, "org.sequoia-pgp.tests.f").unwrap();
        let (domain, name, network_policy, store) = iter.next().unwrap();
        assert_eq!(domain, "org.sequoia-pgp.tests.foo");
        assert_eq!(name, "default");
        assert_eq!(network_policy, core::NetworkPolicy::Offline);
        let fp = Fingerprint::from_bytes(b"bbbbbbbbbbbbbbbbbbbb");
        store.add("Mister B.", &fp).unwrap();
        let (domain, name, network_policy, store) = iter.next().unwrap();
        assert_eq!(domain, "org.sequoia-pgp.tests.foo");
        assert_eq!(name, "another store");
        assert_eq!(network_policy, core::NetworkPolicy::Offline);
        store.add("Mister B.", &fp).unwrap();
        assert!(iter.next().is_none());
    }

    #[test]
    fn binding_iterator() {
        let ctx = make_some_stores();
        let store = Store::open(&ctx, "default").unwrap();
        let mut iter = store.iter().unwrap();
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
        let ctx = make_some_stores();
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

