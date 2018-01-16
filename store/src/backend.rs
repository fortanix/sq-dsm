//! Storage backend.

use std::fmt;
use std::ops::Add;
use std::rc::Rc;
use std::time::{SystemTime, Duration, UNIX_EPOCH};

use capnp::capability::Promise;
use capnp;
use capnp_rpc::rpc_twoparty_capnp::Side;
use capnp_rpc::{self, RpcSystem, twoparty};
use rusqlite::Connection;
use rusqlite::types::{ToSql, ToSqlOutput};
use rusqlite;
use tokio_core;
use tokio_io::io::ReadHalf;

use openpgp::tpk::{self, TPK};
use sequoia_core as core;
use sequoia_net::ipc;

use store_protocol_capnp::node;

/// Makes backends.
#[doc(hidden)]
pub fn factory(descriptor: ipc::Descriptor) -> Option<Box<ipc::Handler>> {
    match Backend::new(descriptor) {
        Ok(backend) => Some(Box::new(backend)),
        Err(_) => None,
    }
}

struct Backend {
    store: node::Client,
}

impl Backend {
    fn new(descriptor: ipc::Descriptor) -> Result<Self> {
        Ok(Backend {
            store: node::ToClient::new(NodeServer::new(descriptor)?)
                .from_server::<capnp_rpc::Server>(),
        })
    }
}

impl ipc::Handler for Backend {
    fn handle(&self,
              network: twoparty::VatNetwork<ReadHalf<tokio_core::net::TcpStream>>)
              -> RpcSystem<Side> {
        RpcSystem::new(Box::new(network), Some(self.store.clone().client))
    }
}


struct NodeServer {
    _descriptor: ipc::Descriptor,
    c: Rc<Connection>,
}

impl NodeServer {
    fn new(descriptor: ipc::Descriptor) -> Result<Self> {
        let mut db_path = descriptor.home.clone();
        db_path.push("keystore.sqlite");

        let c = Connection::open(db_path)?;
        c.execute_batch("PRAGMA secure_delete = true;")?;
        c.execute_batch("PRAGMA foreign_keys = true;")?;
        Self::init(&c)?;

        Ok(NodeServer {
            _descriptor: descriptor,
            c: Rc::new(c),
        })
    }

    /// Initializes or migrates the database.
    fn init(c: &Connection) -> Result<()> {
        let v = c.query_row(
            "SELECT version FROM version WHERE id=1",
            &[], |row| row.get(0));

        if let Ok(v) = v {
            match v {
                1 => return Ok(()),
                _ => unimplemented!(),
            }
        }

        c.execute_batch(DB_SCHEMA_1)?;
        Ok(())
    }
}

impl node::Server for NodeServer {
    fn open(&mut self,
            params: node::OpenParams,
            mut results: node::OpenResults)
            -> Promise<(), capnp::Error> {
        bind_results!(results);
        let params = pry!(params.get());

        // XXX maybe check ephemeral and use in-core sqlite db

        let store = sry!(StoreServer::open(self.c.clone(),
                                           pry!(params.get_domain()),
                                           pry!(params.get_network_policy()).into(),
                                           pry!(params.get_name())));
        pry!(pry!(results.get().get_result()).set_ok(
            node::store::ToClient::new(store).from_server::<capnp_rpc::Server>()));
        Promise::ok(())
    }

    fn iter(&mut self,
            params: node::IterParams,
            mut results: node::IterResults)
            -> Promise<(), capnp::Error> {
        bind_results!(results);
        let prefix = pry!(pry!(params.get()).get_domain_prefix());
        let iter = StoreIterServer::new(self.c.clone(), prefix);
        pry!(pry!(results.get().get_result()).set_ok(
            node::store_iter::ToClient::new(iter).from_server::<capnp_rpc::Server>()));
        Promise::ok(())
    }

    fn iter_keys(&mut self,
                 _: node::IterKeysParams,
                 mut results: node::IterKeysResults)
                 -> Promise<(), capnp::Error> {
        bind_results!(results);
        let iter = KeyIterServer::new(self.c.clone());
        pry!(pry!(results.get().get_result()).set_ok(
            node::key_iter::ToClient::new(iter).from_server::<capnp_rpc::Server>()));
        Promise::ok(())
    }
}

struct StoreServer {
    c: Rc<Connection>,
    id: i64,
}

impl StoreServer {
    fn new(c: Rc<Connection>, id: i64) -> StoreServer {
        StoreServer{c: c, id: id}
    }

    fn open(c: Rc<Connection>, domain: &str, policy: core::NetworkPolicy, name: &str)
           -> Result<Self> {
        // We cannot implement ToSql and friends for
        // core::NetworkPolicy, hence we need to do it by foot.
        let p: u8 = (&policy).into();

        c.execute(
            "INSERT OR IGNORE INTO stores (domain, network_policy, name) VALUES (?1, ?2, ?3)",
            &[&domain, &p, &name])?;
        let (id, store_policy): (i64, i64) = c.query_row(
            "SELECT id, network_policy FROM stores WHERE domain = ?1 AND name = ?2",
            &[&domain, &name], |row| (row.get(0), row.get(1)))?;

        // We cannot implement FromSql and friends for
        // core::NetworkPolicy, hence we need to do it by foot.
        if store_policy < 0 || store_policy > 3 {
            return Err(node::Error::SystemError);
        }
        let store_policy = core::NetworkPolicy::from(store_policy as u8);

        if store_policy != policy {
            return Err(match store_policy {
                core::NetworkPolicy::Offline =>
                    node::Error::NetworkPolicyViolationOffline,
                core::NetworkPolicy::Anonymized =>
                    node::Error::NetworkPolicyViolationAnonymized,
                core::NetworkPolicy::Encrypted =>
                    node::Error::NetworkPolicyViolationEncrypted,
                core::NetworkPolicy::Insecure =>
                    node::Error::NetworkPolicyViolationInsecure,
            });
        }

        Ok(Self::new(c, id))
    }
}

impl node::store::Server for StoreServer {
    fn add(&mut self,
           params: node::store::AddParams,
           mut results: node::store::AddResults)
           -> Promise<(), capnp::Error> {
        bind_results!(results);
        let params = pry!(params.get());
        let fp = pry!(params.get_fingerprint());
        let label = pry!(params.get_label());

        let key_id = sry!(get_key_id(&self.c, fp));

        sry!(self.c.execute("INSERT OR IGNORE INTO bindings (store, label, key, created)
                             VALUES (?, ?, ?, ?)",
                            &[&self.id,
                              &label,
                              &key_id,
                              &Timestamp::now()]));
        let binding_id: i64 = sry!(self.c.query_row(
            "SELECT id FROM bindings WHERE store = ?1 AND label = ?2",
            &[&self.id, &label], |row| row.get(0)));

        pry!(pry!(results.get().get_result()).set_ok(
            node::binding::ToClient::new(
                BindingServer::new(self.c.clone(), binding_id))
                .from_server::<capnp_rpc::Server>()));
        Promise::ok(())
    }

    fn lookup(&mut self,
              params: node::store::LookupParams,
              mut results: node::store::LookupResults)
              -> Promise<(), capnp::Error> {
        bind_results!(results);
        let label = pry!(pry!(params.get()).get_label());

        let binding_id: i64 = sry!(
            self.c.query_row(
                "SELECT id FROM bindings WHERE store = ?1 AND label = ?2",
                &[&self.id, &label], |row| row.get(0)));

        pry!(pry!(results.get().get_result()).set_ok(
            node::binding::ToClient::new(
                BindingServer::new(self.c.clone(), binding_id))
                .from_server::<capnp_rpc::Server>()));
        Promise::ok(())
    }

    fn delete(&mut self,
              _: node::store::DeleteParams,
              mut results: node::store::DeleteResults)
              -> Promise<(), capnp::Error> {
        bind_results!(results);
        sry!(self.c.execute("DELETE FROM stores WHERE id = ?1",
                                     &[&self.id]));
        Promise::ok(())
    }

    fn iter(&mut self,
            _: node::store::IterParams,
            mut results: node::store::IterResults)
            -> Promise<(), capnp::Error> {
        bind_results!(results);
        let iter = BindingIterServer::new(self.c.clone(), self.id);
        pry!(pry!(results.get().get_result()).set_ok(
            node::binding_iter::ToClient::new(iter).from_server::<capnp_rpc::Server>()));
        Promise::ok(())
    }
}

struct BindingServer {
    c: Rc<Connection>,
    id: i64,
}

impl BindingServer {
    fn new(c: Rc<Connection>, id: i64) -> Self {
        BindingServer {
            c: c,
            id: id,
        }
    }

    fn key_id(&mut self) -> Result<i64> {
        self.query("key")
    }
}

trait Query {
    fn query(&mut self, column: &str) -> Result<i64>;
}

impl Query for BindingServer {
    fn query(&mut self, column: &str) -> Result<i64> {
        self.c.query_row(
            format!("SELECT {} FROM bindings WHERE id = ?1", column).as_ref(),
            &[&self.id], |row| row.get(0)).map_err(|e| e.into())
    }
}

impl node::binding::Server for BindingServer {
    fn stats(&mut self,
             _: node::binding::StatsParams,
             mut results: node::binding::StatsResults)
             -> Promise<(), capnp::Error> {
        bind_results!(results);
        sry!(compute_stats(self, pry!(results.get().get_result()).init_ok()));
        Promise::ok(())
    }

    fn key(&mut self,
           _: node::binding::KeyParams,
           mut results: node::binding::KeyResults)
           -> Promise<(), capnp::Error> {
        bind_results!(results);
        let key = sry!(self.key_id());

        pry!(pry!(results.get().get_result()).set_ok(
            node::key::ToClient::new(
                KeyServer::new(self.c.clone(), key)).from_server::<capnp_rpc::Server>()));
        Promise::ok(())
    }

    fn import(&mut self,
              params: node::binding::ImportParams,
              mut results: node::binding::ImportResults)
              -> Promise<(), capnp::Error> {
        bind_results!(results);
        let force = pry!(params.get()).get_force();

        // This is the key to import.
        let mut new = sry!(TPK::from_bytes(&pry!(pry!(params.get()).get_key())));

        // Check in the database for the current key.
        let key_id = sry!(self.key_id());
        let (fingerprint, key): (String, Option<Vec<u8>>)
            = sry!(self.c.query_row(
                "SELECT fingerprint, key FROM keys WHERE id = ?1",
                &[&key_id],
                |row| (row.get(0), row.get_checked(1).ok())));

        // If we found one, convert it to TPK.
        let current = if let Some(current) = key {
            let current = sry!(TPK::from_bytes(&current));
            if current.fingerprint().to_hex() != fingerprint {
                // Inconsistent database.
                fail!(node::Error::SystemError);
            }
            Some(current)
        } else {
            None
        };

        // Check for conflicts.
        if new.fingerprint().to_hex() != fingerprint {
            if force || (current.is_some() && new.is_signed_by(&current.unwrap())) {
                // Update binding, and retry.
                let key_id =
                    sry!(get_key_id(&self.c, new.fingerprint().to_hex().as_ref()));
                sry!(self.c.execute("UPDATE bindings SET key = ?1 WHERE id = ?2",
                                    &[&key_id, &self.id]));
                return self.import(params, results);
            } else {
                fail!(node::Error::Conflict);
            }
        }

        if current.is_some() {
            new = sry!(current.unwrap().merge(new));
        }

        // Write key back to the database.
        let mut blob = vec![];
        sry!(new.serialize(&mut blob));

        sry!(self.c.execute("UPDATE keys SET key = ?1 WHERE id = ?2",
                            &[&blob, &key_id]));

        pry!(pry!(results.get().get_result()).set_ok(&blob[..]));
        Promise::ok(())
    }

    fn delete(&mut self,
              _: node::binding::DeleteParams,
              mut results: node::binding::DeleteResults)
              -> Promise<(), capnp::Error> {
        bind_results!(results);
        sry!(self.c.execute("DELETE FROM bindings WHERE id = ?1",
                                     &[&self.id]));
        Promise::ok(())
    }

    fn register_encryption(&mut self,
                           _: node::binding::RegisterEncryptionParams,
                           mut results: node::binding::RegisterEncryptionResults)
                           -> Promise<(), capnp::Error> {
        bind_results!(results);
        let key = sry!(self.key_id());
        sry!(self.c
             .execute("UPDATE bindings SET encryption_count = encryption_count + 1 WHERE id = ?1",
                      &[&self.id]));
        sry!(self.c
             .execute("UPDATE keys SET encryption_count = encryption_count + 1 WHERE id = ?1",
                      &[&key]));

        sry!(compute_stats(self, pry!(results.get().get_result()).init_ok()));
        Promise::ok(())
    }

    fn register_verification(&mut self,
                             _: node::binding::RegisterVerificationParams,
                             mut results: node::binding::RegisterVerificationResults)
                             -> Promise<(), capnp::Error> {
        bind_results!(results);
        let key = sry!(self.key_id());
        sry!(self.c
             .execute("UPDATE bindings SET verification_count = verification_count + 1 WHERE id = ?1",
                      &[&self.id]));
        sry!(self.c
             .execute("UPDATE keys SET verification_count = verification_count + 1 WHERE id = ?1",
                      &[&key]));

        sry!(compute_stats(self, pry!(results.get().get_result()).init_ok()));
        Promise::ok(())
    }
}

struct KeyServer {
    c: Rc<Connection>,
    id: i64,
}

impl KeyServer {
    fn new(c: Rc<Connection>, id: i64) -> Self {
        KeyServer {
            c: c,
            id: id,
        }
    }
}

impl Query for KeyServer {
    fn query(&mut self, column: &str) -> Result<i64> {
        self.c.query_row(
            format!("SELECT {} FROM keys WHERE id = ?1", column).as_ref(),
            &[&self.id], |row| row.get(0)).map_err(|e| e.into())
    }
}

impl node::key::Server for KeyServer {
    fn stats(&mut self,
             _: node::key::StatsParams,
             mut results: node::key::StatsResults)
             -> Promise<(), capnp::Error> {
        bind_results!(results);
        sry!(compute_stats(self, pry!(results.get().get_result()).init_ok()));
        Promise::ok(())
    }

    fn tpk(&mut self,
           _: node::key::TpkParams,
           mut results: node::key::TpkResults)
           -> Promise<(), capnp::Error> {
        bind_results!(results);
        let key: Vec<u8> = sry!(
            self.c.query_row(
                "SELECT key FROM keys WHERE id = ?1",
                &[&self.id],
                |row| row.get_checked(0).unwrap_or(vec![])));
        pry!(pry!(results.get().get_result()).set_ok(key.as_slice()));
        Promise::ok(())
    }

    fn import(&mut self,
              params: node::key::ImportParams,
              mut results: node::key::ImportResults)
              -> Promise<(), capnp::Error> {
        bind_results!(results);
        let mut new = sry!(TPK::from_bytes(&pry!(pry!(params.get()).get_key())));

        let (fingerprint, key): (String, Option<Vec<u8>>)
            = sry!(self.c.query_row(
                "SELECT fingerprint, key FROM keys WHERE id = ?1",
                &[&self.id],
                |row| (row.get(0), row.get_checked(1).ok())));
        if let Some(current) = key {
            let current = sry!(TPK::from_bytes(&current));

            if current.fingerprint().to_hex() != fingerprint {
                // Inconsistent database.
                fail!(node::Error::SystemError);
            }

            if current.fingerprint() != new.fingerprint() {
                fail!(node::Error::Conflict);
            }

            new = sry!(current.merge(new));
        }

        // Write key back to the database.
        let mut blob = vec![];
        sry!(new.serialize(&mut blob));

        sry!(self.c.execute("UPDATE keys SET key = ?1 WHERE id = ?2",
                            &[&blob, &self.id]));

        pry!(pry!(results.get().get_result()).set_ok(&blob[..]));
        Promise::ok(())
    }
}

/* Iterators.  */

struct StoreIterServer {
    c: Rc<Connection>,
    prefix: String,
    n: i64,
}

impl StoreIterServer {
    fn new(c: Rc<Connection>, prefix: &str) -> Self {
        StoreIterServer{c: c, prefix: String::from(prefix) + "%", n: 0}
    }
}

impl node::store_iter::Server for StoreIterServer {
    fn next(&mut self,
            _: node::store_iter::NextParams,
            mut results: node::store_iter::NextResults)
            -> Promise<(), capnp::Error> {
        bind_results!(results);
        let (id, domain, name, network_policy): (i64, String, String, i64) =
            sry!(self.c.query_row(
                 "SELECT id, domain, name, network_policy FROM stores
                      WHERE id > ?1 AND domain like ?2
                      ORDER BY id LIMIT 1",
                &[&self.n, &self.prefix],
                |row| (row.get(0), row.get(1), row.get(2), row.get(3))));

        let count: i64 =
            sry!(self.c.query_row(
                "SELECT count(*) FROM bindings WHERE store = ?1",
                &[&id], |row| row.get(0)));
        assert!(count >= 0);

        // We cannot implement FromSql and friends for
        // core::NetworkPolicy, hence we need to do it by foot.
        if network_policy < 0 || network_policy > 3 {
            fail!(node::Error::SystemError);
        }
        let network_policy = core::NetworkPolicy::from(network_policy as u8);

        let mut entry = pry!(results.get().get_result()).init_ok();
        entry.set_domain(&domain);
        entry.set_name(&name);
        entry.set_network_policy(network_policy.into());
        entry.set_entries(count as u64);
        entry.set_store(node::store::ToClient::new(
            StoreServer::new(self.c.clone(), id)).from_server::<capnp_rpc::Server>());
        self.n = id;
        Promise::ok(())
    }
}

struct BindingIterServer {
    c: Rc<Connection>,
    store_id: i64,
    n: i64,
}

impl BindingIterServer {
    fn new(c: Rc<Connection>, store_id: i64) -> Self {
        BindingIterServer{c: c, store_id: store_id, n: 0}
    }
}

impl node::binding_iter::Server for BindingIterServer {
    fn next(&mut self,
            _: node::binding_iter::NextParams,
            mut results: node::binding_iter::NextResults)
            -> Promise<(), capnp::Error> {
        bind_results!(results);
        let (id, label, fingerprint): (i64, String, String) =
            sry!(self.c.query_row(
                 "SELECT bindings.id, bindings.label, keys.fingerprint FROM bindings
                      JOIN keys ON bindings.key = keys.id
                      WHERE bindings.id > ?1 AND bindings.store = ?2
                      ORDER BY bindings.id LIMIT 1",
                &[&self.n, &self.store_id],
                |row| (row.get(0), row.get(1), row.get(2))));

        let mut entry = pry!(results.get().get_result()).init_ok();
        entry.set_label(&label);
        entry.set_fingerprint(&fingerprint);
        entry.set_binding(node::binding::ToClient::new(
            BindingServer::new(self.c.clone(), id)).from_server::<capnp_rpc::Server>());
        self.n = id;
        Promise::ok(())
    }
}

struct KeyIterServer {
    c: Rc<Connection>,
    n: i64,
}

impl KeyIterServer {
    fn new(c: Rc<Connection>) -> Self {
        KeyIterServer{c: c, n: 0}
    }
}

impl node::key_iter::Server for KeyIterServer {
    fn next(&mut self,
            _: node::key_iter::NextParams,
            mut results: node::key_iter::NextResults)
            -> Promise<(), capnp::Error> {
        bind_results!(results);
        let (id, fingerprint): (i64, String) =
            sry!(self.c.query_row(
                 "SELECT id, fingerprint FROM keys
                      WHERE keys.id > ?1
                      ORDER BY id LIMIT 1",
                &[&self.n],
                |row| (row.get(0), row.get(1))));

        let count: i64 =
            sry!(self.c.query_row(
                "SELECT count(*) FROM bindings WHERE key = ?1",
                &[&id], |row| row.get(0)));
        assert!(count >= 0);

        let mut entry = pry!(results.get().get_result()).init_ok();
        entry.set_fingerprint(&fingerprint);
        entry.set_bindings(count as u64);
        entry.set_key(node::key::ToClient::new(
            KeyServer::new(self.c.clone(), id)).from_server::<capnp_rpc::Server>());
        self.n = id;
        Promise::ok(())
    }
}

/* Error handling.  */

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

/// Results for the backend.
type Result<T> = ::std::result::Result<T, node::Error>;

impl From<rusqlite::Error> for node::Error {
    fn from(error: rusqlite::Error) -> Self {
        match error {
            rusqlite::Error::SqliteFailure(f, _) => match f.code {
                rusqlite::ErrorCode::ConstraintViolation =>
                    node::Error::NotFound,
                _ => node::Error::SystemError,
            },
            rusqlite::Error::QueryReturnedNoRows =>
                node::Error::NotFound,
            _ => node::Error::SystemError,
        }
    }
}

impl From<tpk::Error> for node::Error {
    fn from(_: tpk::Error) -> Self {
        node::Error::MalformedKey
    }
}


/* Database schemata and migrations.  */

/* Version 1.  */
const DB_SCHEMA_1: &'static str = "
CREATE TABLE version (
    id INTEGER PRIMARY KEY,
    version INTEGER);

INSERT INTO version (id, version) VALUES (1, 1);

CREATE TABLE stores (
    id INTEGER PRIMARY KEY,
    domain TEXT NOT NULL,
    network_policy INTEGER NOT NULL,
    name TEXT NOT NULL,
    UNIQUE (domain, name));

CREATE TABLE bindings (
    id INTEGER PRIMARY KEY,
    store INTEGER NOT NULL,
    label TEXT NOT NULL,
    key INTEGER NOT NULL,

    created INTEGER NOT NULL,
    updated DEFAULT 0,

    encryption_count DEFAULT 0,
    encryption_first DEFAULT 0,
    encryption_last DEFAULT 0,
    verification_count DEFAULT 0,
    verification_first DEFAULT 0,
    verification_last DEFAULT 0,

    UNIQUE(store, label),
    FOREIGN KEY (store) REFERENCES stores(id) ON DELETE CASCADE,
    FOREIGN KEY (key) REFERENCES keys(id) ON DELETE CASCADE);

CREATE TABLE keys (
    id INTEGER PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    key BLOB,

    created INTEGER NOT NULL,
    updated DEFAULT 0,

    encryption_count DEFAULT 0,
    encryption_first DEFAULT 0,
    encryption_last DEFAULT 0,
    verification_count DEFAULT 0,
    verification_first DEFAULT 0,
    verification_last DEFAULT 0,

    UNIQUE (fingerprint));
";

/* Timestamps.  */

/// A serializable system time.
struct Timestamp(SystemTime);

impl Timestamp {
    fn now() -> Self {
        Timestamp(SystemTime::now())
    }
}

impl ToSql for Timestamp {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput> {
        match self.0.duration_since(UNIX_EPOCH) {
            Ok(n) => Ok(ToSqlOutput::from(n.as_secs() as i64)),
            Err(_) => Err(rusqlite::Error::IntegralValueOutOfRange(0, 0)),
        }
    }
}

impl Add<Duration> for Timestamp {
    type Output = Timestamp;

    fn add(self, other: Duration) -> Timestamp {
        Timestamp(self.0 + other)
    }
}

/* Miscellaneous.  */

/// Given a fingerprint, return the key id.
fn get_key_id(c: &Connection, fp: &str) -> Result<i64> {
    if let Ok(x) = c.query_row(
        "SELECT id FROM keys WHERE fingerprint = ?1",
        &[&fp], |row| row.get(0)) {
        Ok(x)
    } else {
        c.execute(
            "INSERT INTO keys (fingerprint, created) VALUES (?1, ?2)",
            &[&fp, &Timestamp::now()])?;
        c.query_row(
            "SELECT id FROM keys WHERE fingerprint = ?1",
            &[&fp], |row| row.get(0)).map_err(|e| e.into())
    }
}

fn compute_stats(q: &mut Query, mut stats: node::stats::Builder) -> Result<()> {
    let created = q.query("created")?;
    let updated = q.query("updated")?;
    let encryption_count = q.query("encryption_count")?;
    let encryption_first = q.query("encryption_first")?;
    let encryption_last = q.query("encryption_last")?;
    let verification_count = q.query("verification_count")?;
    let verification_first = q.query("verification_first")?;
    let verification_last = q.query("verification_last")?;
    stats.set_created(created);
    stats.set_updated(updated);
    stats.set_encryption_count(encryption_count);
    stats.set_encryption_first(encryption_first);
    stats.set_encryption_last(encryption_last);
    stats.set_verification_count(verification_count);
    stats.set_verification_first(verification_first);
    stats.set_verification_last(verification_last);
    Ok(())
}

impl<'a> From<&'a core::NetworkPolicy> for node::NetworkPolicy {
    fn from(policy: &core::NetworkPolicy) -> Self {
        match policy {
            &core::NetworkPolicy::Offline    => node::NetworkPolicy::Offline,
            &core::NetworkPolicy::Anonymized => node::NetworkPolicy::Anonymized,
            &core::NetworkPolicy::Encrypted  => node::NetworkPolicy::Encrypted,
            &core::NetworkPolicy::Insecure   => node::NetworkPolicy::Insecure,
        }
    }
}

impl From<core::NetworkPolicy> for node::NetworkPolicy {
    fn from(policy: core::NetworkPolicy) -> Self {
        (&policy).into()
    }
}

impl From<node::NetworkPolicy> for core::NetworkPolicy {
    fn from(policy: node::NetworkPolicy) -> Self {
        match policy {
            node::NetworkPolicy::Offline    => core::NetworkPolicy::Offline,
            node::NetworkPolicy::Anonymized => core::NetworkPolicy::Anonymized,
            node::NetworkPolicy::Encrypted  => core::NetworkPolicy::Encrypted,
            node::NetworkPolicy::Insecure   => core::NetworkPolicy::Insecure,
        }
    }
}
