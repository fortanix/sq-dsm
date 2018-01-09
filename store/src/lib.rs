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
//! # use sequoia_core::Context;
//! # use sequoia_store::{Store, Result};
//! # fn main() { f().unwrap(); }
//! # fn f() -> Result<()> {
//! # let ctx = Context::configure("org.sequoia-pgp.demo.store")
//! #     .ephemeral().build()?;
//! let mut store = Store::open(&ctx, "default")?;
//!
//! let fp = Fingerprint::from_bytes(b"bbbbbbbbbbbbbbbbbbbb");
//! let binding = store.add("Mister B.", &fp)?;
//!
//! println!("Binding {:?}", binding.stats()?);
//! // prints:
//! // Binding Stats {
//! //     created: Some(SystemTime { tv_sec: 1513704042, tv_nsec: 0 }),
//! //     updated: None,
//! //     encryption: Stamps { count: 0, first: None, latest: None },
//! //     verification: Stamps { count: 0, first: None, latest: None }
//! // }
//! # Ok(())
//! # }
//! ```

extern crate capnp;
#[macro_use]
extern crate capnp_rpc;
extern crate futures;
extern crate rusqlite;
extern crate tokio_core;
extern crate tokio_io;

use std::cell::RefCell;
use std::fmt;
use std::io;
use std::time::{SystemTime, Duration, UNIX_EPOCH};

use capnp::capability::Promise;
use capnp_rpc::rpc_twoparty_capnp::Side;
use futures::{Future};
use tokio_core::reactor::Core;

extern crate openpgp;
#[allow(unused_imports)]
#[macro_use]
extern crate sequoia_core;
extern crate sequoia_net;

use openpgp::Fingerprint;
use openpgp::tpk::{self, TPK};
use sequoia_core as core;
use sequoia_core::Context;
use sequoia_net::ipc;

#[allow(dead_code)] mod store_protocol_capnp;
use store_protocol_capnp::node;

/// Macros managing requests and responses.
#[macro_use] mod macros;

/// Storage backend.
mod backend;

/// Returns the service descriptor.
#[doc(hidden)]
pub fn descriptor(c: &Context) -> ipc::Descriptor {
    ipc::Descriptor::new(
        c.home().to_path_buf(),
        c.home().join("S.keystore"),
        c.lib().join("keystore"),
        backend::factory,
    )
}

/// A public key store.
pub struct Store {
    name: String,
    core: RefCell<Core>,
    store: node::store::Client,
}

impl fmt::Debug for Store {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Store {{ name: {} }}", self.name)
    }
}

impl<'a> Store {
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
        let descriptor = descriptor(c);
        let mut core = tokio_core::reactor::Core::new()?;
        let handle = core.handle();

        let mut rpc_system
            = match descriptor.connect(&handle) {
                Ok(r) => r,
                Err(e) => return Err(e.into()),
            };

        let store: node::Client = rpc_system.bootstrap(Side::Server);
        handle.spawn(rpc_system.map_err(|_e| ()));

        let mut request = store.open_request();
        request.get().set_domain(c.domain());
        request.get().set_network_policy(c.network_policy().into());
        request.get().set_ephemeral(c.ephemeral());
        request.get().set_name(name);

        let store = make_request!(&mut core, request)?;
        Ok(Store{name: name.into(), core: RefCell::new(core), store: store})
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
    /// # use sequoia_core::Context;
    /// # use sequoia_store::{Store, Result};
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// # let ctx = Context::configure("org.sequoia-pgp.demo.store")
    /// #     .ephemeral().build()?;
    /// let mut store = Store::open(&ctx, "default")?;
    /// let fp = Fingerprint::from_bytes(b"bbbbbbbbbbbbbbbbbbbb");
    /// store.add("Mister B.", &fp)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn add(&'a mut self, label: &str, fingerprint: &Fingerprint) -> Result<Binding> {
        let mut request = self.store.add_request();
        request.get().set_label(label);
        request.get().set_fingerprint(fingerprint.to_hex().as_ref());
        let binding = make_request!(self.core.borrow_mut(), request)?;
        Ok(Binding::new(self, label, binding))
    }

    /// Imports a key into the store.
    ///
    /// # Example
    ///
    /// ```
    /// # extern crate openpgp;
    /// # extern crate sequoia_core;
    /// # extern crate sequoia_store;
    /// # use openpgp::tpk::TPK;
    /// # use sequoia_core::Context;
    /// # use sequoia_store::{Store, Result};
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// # let ctx = Context::configure("org.sequoia-pgp.demo.store")
    /// #     .ephemeral().build()?;
    /// # let tpk = TPK::from_bytes(
    /// #     include_bytes!("../../openpgp/tests/data/keys/testy.pgp")).unwrap();
    /// let mut store = Store::open(&ctx, "default")?;
    /// store.import("Testy McTestface", &tpk)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn import(&'a mut self, label: &str, tpk: &TPK) -> Result<TPK> {
        let fingerprint = tpk.fingerprint();
        let mut request = self.store.add_request();
        request.get().set_label(label);
        request.get().set_fingerprint(fingerprint.to_hex().as_ref());
        let binding = make_request!(self.core.borrow_mut(), request)?;
        let binding = Binding::new(self, label, binding);
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
    /// # use sequoia_core::Context;
    /// # use sequoia_store::{Store, Result};
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// # let ctx = Context::configure("org.sequoia-pgp.demo.store")
    /// #     .ephemeral().build()?;
    /// let mut store = Store::open(&ctx, "default")?;
    /// let fp = Fingerprint::from_bytes(b"bbbbbbbbbbbbbbbbbbbb");
    /// store.add("Mister B.", &fp)?;
    /// drop(store);
    /// // ...
    /// let mut store = Store::open(&ctx, "default")?;
    /// let binding = store.lookup("Mister B.")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn lookup(&'a mut self, label: &str) -> Result<Binding> {
        let mut request = self.store.lookup_request();
        request.get().set_label(label);
        let binding = make_request!(self.core.borrow_mut(), request)?;
        Ok(Binding::new(self, label, binding))
    }
}

/// Represents an entry in a Store.
///
/// Stores map labels to TPKs.  A `Binding` represents a pair in this
/// relation.  We make this explicit because we associate metadata
/// with these pairs.
pub struct Binding<'a> {
    label: String,
    store: &'a Store,
    binding: node::binding::Client,
}

impl<'a> fmt::Debug for Binding<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Binding {{ label: {} }}", self.label)
    }
}

impl<'a> Binding<'a> {
    fn new(store: &'a Store, label: &str, binding: node::binding::Client) -> Self {
        Binding{label: label.into(), store: store, binding: binding}
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
    /// # use sequoia_core::Context;
    /// # use sequoia_store::{Store, Result};
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// # let ctx = Context::configure("org.sequoia-pgp.demo.store")
    /// #     .ephemeral().build()?;
    /// let mut store = Store::open(&ctx, "default")?;
    ///
    /// let fp = Fingerprint::from_bytes(b"bbbbbbbbbbbbbbbbbbbb");
    /// let binding = store.add("Mister B.", &fp)?;
    ///
    /// println!("Binding {:?}", binding.stats()?);
    /// // prints:
    /// // Binding Stats {
    /// //     created: Some(SystemTime { tv_sec: 1513704042, tv_nsec: 0 }),
    /// //     updated: None,
    /// //     encryption: Stamps { count: 0, first: None, latest: None },
    /// //     verification: Stamps { count: 0, first: None, latest: None }
    /// // }
    /// # Ok(())
    /// # }
    /// ```
    pub fn stats(&self) -> Result<Stats> {
        make_stats_request!(self.store.core.borrow_mut(),
                            self.binding.stats_request())
    }

    /// Returns the `Key` of this binding.
    pub fn key(&self) -> Result<Key> {
        make_request_map!(self.store.core.borrow_mut(),
                          self.binding.key_request(),
                          |tpk| Ok(Key::new(self.store, tpk)))
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
    /// If the new key does not match the current key, but carries a
    /// valid signature from the current key, it replaces the current
    /// key.  This provides a natural way for key rotations.
    ///
    /// If the new key does not match the current key, and it does not
    /// carry a valid signature from the current key, an
    /// `Error::Conflict` is returned, and you have to resolve the
    /// conflict, either by ignoring the new key, or by using
    /// `TPK::rotate` to force a rotation.
    ///
    /// # Example
    ///
    /// ```
    /// # extern crate openpgp;
    /// # #[macro_use] extern crate sequoia_core;
    /// # extern crate sequoia_store;
    /// # use openpgp::tpk::TPK;
    /// # use sequoia_core::Context;
    /// # use sequoia_store::{Store, Result, Error};
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// # let ctx = Context::configure("org.sequoia-pgp.demo.store")
    /// #     .ephemeral().build()?;
    /// # let old = TPK::from_bytes(
    /// #     include_bytes!("../../openpgp/tests/data/keys/testy.pgp")).unwrap();
    /// # let new = TPK::from_bytes(
    /// #     include_bytes!("../../openpgp/tests/data/keys/testy-new.pgp")).unwrap();
    /// # let new_sig = TPK::from_bytes(
    /// #     include_bytes!("../../openpgp/tests/data/keys/testy-new-with-sig.pgp")).unwrap();
    /// let mut store = Store::open(&ctx, "default")?;
    /// store.import("Testy McTestface", &old)?;
    /// // later...
    /// let binding = store.lookup("Testy McTestface")?;
    /// let r = binding.import(&new);
    /// assert_match!(Err(Error::Conflict) = r); // no signature from old on new
    /// let r = binding.import(&new_sig)?;
    /// assert_eq!(new.fingerprint(), r.fingerprint());
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
            self.store.core.borrow_mut(),
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
    /// `TPK::import`.  Make sure that you have authenticated `tpk`
    /// properly.  How to do that depends on your thread model.  You
    /// could simply ask Alice to call her communication partner Bob
    /// and confirm that he rotated his keys.
    ///
    /// # Example
    ///
    /// ```
    /// # extern crate openpgp;
    /// # #[macro_use] extern crate sequoia_core;
    /// # extern crate sequoia_store;
    /// # use openpgp::tpk::TPK;
    /// # use sequoia_core::Context;
    /// # use sequoia_store::{Store, Result, Error};
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// # let ctx = Context::configure("org.sequoia-pgp.demo.store")
    /// #     .ephemeral().build()?;
    /// # let old = TPK::from_bytes(
    /// #     include_bytes!("../../openpgp/tests/data/keys/testy.pgp")).unwrap();
    /// # let new = TPK::from_bytes(
    /// #     include_bytes!("../../openpgp/tests/data/keys/testy-new.pgp")).unwrap();
    /// let mut store = Store::open(&ctx, "default")?;
    /// store.import("Testy McTestface", &old)?;
    /// // later...
    /// let binding = store.lookup("Testy McTestface")?;
    /// let r = binding.import(&new);
    /// assert_match!(Err(Error::Conflict) = r); // no signature from old on new
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
            self.store.core.borrow_mut(),
            request,
            |data| TPK::from_bytes(data).map_err(|e| e.into()))
    }

    fn register_encryption(&self) -> Result<Stats> {
        #![allow(dead_code)]     // XXX use
        make_stats_request!(
            self.store.core.borrow_mut(),
            self.binding.register_encryption_request())
    }

    fn register_verification(&self) -> Result<Stats> {
        #![allow(dead_code)]     // XXX use
        make_stats_request!(
            self.store.core.borrow_mut(),
            self.binding.register_verification_request())
    }
}

/// Represents a key in a store.
///
/// A `Key` is a handle to a stored TPK.  We make this explicit
/// because we associate metadata with TPKs.
pub struct Key<'a> {
    store: &'a Store,
    key: node::key::Client,
}

impl<'a> Key<'a> {
    fn new(store: &'a Store, key: node::key::Client) -> Self {
        Key{store: store, key: key}
    }

    /// Returns the TPK.
    pub fn tpk(&self) -> Result<TPK> {
        make_request_map!(self.store.core.borrow_mut(),
                          self.key.tpk_request(),
                          |tpk| TPK::from_bytes(tpk).map_err(|e| e.into()))
    }

    /// Returns stats for this key.
    pub fn stats(&self) -> Result<Stats> {
        make_stats_request!(self.store.core.borrow_mut(),
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
    /// # use openpgp::tpk::TPK;
    /// # use sequoia_core::Context;
    /// # use sequoia_store::{Store, Result, Error};
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// # let ctx = Context::configure("org.sequoia-pgp.demo.store")
    /// #     /*.ephemeral()*/.build()?;
    /// # let old = TPK::from_bytes(
    /// #     include_bytes!("../../openpgp/tests/data/keys/testy.pgp")).unwrap();
    /// # let new = TPK::from_bytes(
    /// #     include_bytes!("../../openpgp/tests/data/keys/testy-new.pgp")).unwrap();
    /// let mut store = Store::open(&ctx, "default")?;
    /// let fp = Fingerprint::from_hex("3E8877C877274692975189F5D03F6F865226FE8B").unwrap();
    /// let binding = store.add("Testy McTestface", &fp)?;
    /// let key = binding.key()?;
    /// let r = key.import(&old)?;
    /// assert_eq!(r.fingerprint(), old.fingerprint());
    /// let r = key.import(&new);
    /// assert_match!(Err(Error::Conflict) = r);
    /// # Ok(())
    /// # }
    /// ```
    pub fn import(&self, tpk: &TPK) -> Result<TPK> {
        let mut blob = vec![];
        tpk.serialize(&mut blob)?;
        let mut request = self.key.import_request();
        request.get().set_key(&blob);
        make_request_map!(
            self.store.core.borrow_mut(),
            request,
            |data| TPK::from_bytes(data).map_err(|e| e.into()))
    }
}


/// Returns `t` as SystemTime.
fn from_unix(t: i64) -> Option<SystemTime> {
    if t <= 0 {
        None
    } else {
        Some(UNIX_EPOCH + Duration::new(t as u64, 0))
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
    pub created: Option<SystemTime>,

    /// Records the time this item was last updated.
    pub updated: Option<SystemTime>,

    /// Records counters and timestamps of encryptions.
    pub encryption: Stamps,

    /// Records counters and timestamps of verifications.
    pub verification: Stamps,
}

/// Counter and timestamps.
#[derive(Debug)]
pub struct Stamps {
    /// Counts how many times this has been used.
    pub count: usize,

    /// Records the time when this has been used first.
    pub first:  Option<SystemTime>,

    /// Records the time when this has been used last.
    pub latest: Option<SystemTime>,
}

impl Stamps {
    fn new(count: i64, first: i64, latest: i64) -> Self {
        Stamps {
            count: count as usize,
            first: from_unix(first),
            latest: from_unix(latest),
        }
    }
}

/* Error handling.  */

/// Results for sequoia-store.
pub type Result<T> = ::std::result::Result<T, Error>;

/* Debug formatting and conversion from and to node::Error.  */

impl fmt::Debug for node::Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "node::Error::{}",
               match self {
                   &node::Error::Unspecified => "Unspecified",
                   &node::Error::NotFound => "NotFound",
                   &node::Error::Conflict => "Conflict",
                   &node::Error::SystemError => "SystemError",
                   &node::Error::MalformedKey => "MalformedKey",
                   &node::Error::NetworkPolicyViolationOffline =>
                       "NetworkPolicyViolation(Offline)",
                   &node::Error::NetworkPolicyViolationAnonymized =>
                       "NetworkPolicyViolation(Anonymized)",
                   &node::Error::NetworkPolicyViolationEncrypted =>
                       "NetworkPolicyViolation(Encrypted)",
                   &node::Error::NetworkPolicyViolationInsecure =>
                       "NetworkPolicyViolation(Insecure)",
               })
    }
}

impl From<Error> for node::Error {
    fn from(error: Error) -> Self {
        match error {
            Error::NotFound => node::Error::NotFound,
            Error::Conflict => node::Error::Conflict,
            Error::CoreError(e) => match e {
                core::Error::NetworkPolicyViolation(p) => match p {
                    core::NetworkPolicy::Offline =>
                        node::Error::NetworkPolicyViolationOffline,
                    core::NetworkPolicy::Anonymized =>
                        node::Error::NetworkPolicyViolationAnonymized,
                    core::NetworkPolicy::Encrypted =>
                        node::Error::NetworkPolicyViolationEncrypted,
                    core::NetworkPolicy::Insecure =>
                        node::Error::NetworkPolicyViolationInsecure,
                }
                _ => node::Error::SystemError,
            },
            Error::IoError(_) => node::Error::SystemError,
            Error::StoreError => node::Error::Unspecified,
            Error::ProtocolError => node::Error::SystemError,
            Error::MalformedKey => node::Error::MalformedKey,
            Error::TpkError(_) => node::Error::SystemError,
            Error::RpcError(_) => node::Error::SystemError,
            Error::SqlError(_) => node::Error::SystemError,
        }
    }
}

impl From<node::Error> for Error {
    fn from(error: node::Error) -> Self {
        match error {
            node::Error::Unspecified => Error::StoreError,
            node::Error::NotFound => Error::NotFound,
            node::Error::Conflict => Error::Conflict,
            node::Error::SystemError => Error::StoreError,
            node::Error::MalformedKey => Error::MalformedKey,
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


/// Errors returned from the store.
#[derive(Debug)]
pub enum Error {
    /// A requested key was not found.
    NotFound,
    /// The new key is in conflict with the current key.
    Conflict,
    /// A `sequoia_core::Error` occurred.
    CoreError(sequoia_core::Error),
    /// An `io::Error` occurred.
    IoError(io::Error),
    /// This is a catch-all for unspecified backend errors, and should
    /// go away soon.
    StoreError,
    /// A protocol error occurred.
    ProtocolError,
    /// A TPK is malformed.
    MalformedKey,
    /// A `openpgp::tpk::Error` occurred.
    TpkError(tpk::Error),
    /// A `capnp::Error` occurred.
    RpcError(capnp::Error),
    /// A `rusqlite::Error` occurred.
    SqlError(rusqlite::Error),
}

impl From<sequoia_core::Error> for Error {
    fn from(error: sequoia_core::Error) -> Self {
        Error::CoreError(error)
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::IoError(error)
    }
}

impl From<tpk::Error> for Error {
    fn from(error: tpk::Error) -> Self {
        Error::TpkError(error)
    }
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

impl From<rusqlite::Error> for Error {
    fn from(error: rusqlite::Error) -> Self {
        Error::SqlError(error)
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
            .build().unwrap();
        // Create store.
        Store::open(&ctx, "default").unwrap();

        let ctx2 = core::Context::configure("org.sequoia-pgp.tests")
            .home(ctx.home())
            .network_policy(core::NetworkPolicy::Encrypted)
            .build().unwrap();
        let store = Store::open(&ctx2, "default");
        assert_match!(Err(Error::CoreError(core::Error::NetworkPolicyViolation(_))) = store);
    }

    #[test]
    fn key_not_found() {
        let ctx = core::Context::configure("org.sequoia-pgp.tests")
            .ephemeral()
            .network_policy(core::NetworkPolicy::Offline)
            .build().unwrap();
        let mut store = Store::open(&ctx, "default").unwrap();
        let r = store.lookup("I do not exist");
        assert_match!(Err(Error::NotFound) = r);
    }

    #[test]
    fn add_then_import_wrong_key() {
        let ctx = core::Context::configure("org.sequoia-pgp.tests")
            .ephemeral()
            .network_policy(core::NetworkPolicy::Offline)
            .build().unwrap();
        let mut store = Store::open(&ctx, "default").unwrap();
        let tpk = TPK::from_bytes(bytes!("testy.pgp")).unwrap();
        let fp = Fingerprint::from_bytes(b"bbbbbbbbbbbbbbbbbbbb");
        let binding = store.add("Mister B.", &fp).unwrap();
        let r = binding.import(&tpk);
        assert_match!(Err(Error::Conflict) = r);
    }
}

