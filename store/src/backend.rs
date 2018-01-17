//! Storage backend.

use std::cmp;
use std::fmt;
use std::io;
use std::ops::Add;
use std::rc::Rc;
use std::time::{SystemTime, Duration, UNIX_EPOCH};

use capnp::capability::Promise;
use capnp;
use capnp_rpc::rpc_twoparty_capnp::Side;
use capnp_rpc::{self, RpcSystem, twoparty};
use futures::Future;
use futures::future::{loop_fn, Loop};
use rand::distributions::{IndependentSample, Range};
use rand::thread_rng;
use rusqlite::Connection;
use rusqlite::types::{ToSql, ToSqlOutput};
use rusqlite;
use tokio_core::reactor::{Handle, Timeout};
use tokio_core;
use tokio_io::io::ReadHalf;

use openpgp;
use openpgp::tpk::{self, TPK};
use sequoia_core as core;
use sequoia_net as net;
use sequoia_net::ipc;

use store_protocol_capnp::node;

/* Configuration and policy.  */

/// Minimum sleep time.
fn min_sleep_time() -> Duration {
    Duration::new(60 * 5, 0) // 5 minutes.
}

/// Interval after which all keys should be refreshed once.
fn refresh_interval() -> Duration {
    Duration::new(60 * 60 * 24 * 7, 0) // A week.
}

/// Returns a value from the uniform distribution over [0, 2*d).
///
/// This function is used to randomize key refresh times.
fn random_duration(d: Duration) -> Duration {
    Duration::new(Range::new(0, 2 * d.as_secs()).ind_sample(&mut thread_rng()), 0)
}

/* Entry point.  */

/// Makes backends.
#[doc(hidden)]
pub fn factory(descriptor: ipc::Descriptor, handle: Handle) -> Option<Box<ipc::Handler>> {
    match Backend::new(descriptor, handle) {
        Ok(backend) => Some(Box::new(backend)),
        Err(_) => None,
    }
}

struct Backend {
    store: node::Client,
}

impl Backend {
    fn new(descriptor: ipc::Descriptor, handle: Handle) -> Result<Self> {
        Ok(Backend {
            store: node::ToClient::new(NodeServer::new(descriptor, handle)?)
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

/* Server implementation.  */

struct NodeServer {
    _descriptor: ipc::Descriptor,
    c: Rc<Connection>,
}

impl NodeServer {
    fn new(descriptor: ipc::Descriptor, handle: Handle) -> Result<Self> {
        let mut db_path = descriptor.home.clone();
        db_path.push("keystore.sqlite");

        let c = Connection::open(db_path)?;
        c.execute_batch("PRAGMA secure_delete = true;")?;
        c.execute_batch("PRAGMA foreign_keys = true;")?;
        Self::init(&c)?;

        let server = NodeServer {
            _descriptor: descriptor,
            c: Rc::new(c),
        };
        KeyServer::start_housekeeping(server.c.clone(), handle)?;
        Ok(server)
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

        let binding_id = sry!(
            BindingServer::lookup_or_create(&self.c, self.id, label, fp));

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


    /// Looks up a binding, creating a key if necessary.
    ///
    /// On success, the id of the binding is returned.
    fn lookup_or_create(c: &Connection, store: i64, label: &str, fp: &str)
                        -> Result<i64> {
        let key_id = KeyServer::lookup_or_create(c, fp)?;
        if let Ok((binding, key)) = c.query_row(
            "SELECT id, key FROM bindings WHERE store = ?1 AND label = ?2",
            &[&store, &label], |row| -> (i64, i64) {(row.get(0), row.get(1))}) {
            if key == key_id {
                Ok(binding)
            } else {
                Err(node::Error::Conflict)
            }
        } else {
            let r = c.execute(
                "INSERT INTO bindings (store, label, key, created)
                 VALUES (?, ?, ?, ?)",
                &[&store, &label, &key_id, &Timestamp::now()]);

            // Some other mutator might race us to the insertion.
            match r {
                Err(rusqlite::Error::SqliteFailure(f, _)) => match f.code {
                    // We lost.  Retry the lookup.
                    rusqlite::ErrorCode::ConstraintViolation => {
                        let (binding, key): (i64, i64) = c.query_row(
                            "SELECT id, key FROM bindings WHERE store = ?1 AND label = ?2",
                            &[&store, &label], |row| (row.get(0), row.get(1)))?;
                        if key == key_id {
                            Ok(binding)
                        } else {
                            Err(node::Error::Conflict)
                        }
                    },
                    // Raise otherwise.
                    _ => Err(node::Error::SystemError),
                },
                Err(_) => Err(node::Error::SystemError),
                Ok(_) => Ok(c.last_insert_rowid()),
            }.map_err(|e| e.into())
        }
    }
}

impl Query for BindingServer {
    fn table_name() -> &'static str {
        "bindings"
    }

    fn id(&self) -> i64 {
        self.id
    }

    fn connection(&self) -> Rc<Connection> {
        self.c.clone()
    }
}

impl node::binding::Server for BindingServer {
    fn stats(&mut self,
             _: node::binding::StatsParams,
             mut results: node::binding::StatsResults)
             -> Promise<(), capnp::Error> {
        bind_results!(results);
        sry!(self.query_stats(pry!(results.get().get_result()).init_ok()));
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
                    sry!(KeyServer::lookup_or_create(
                        &self.c, new.fingerprint().to_hex().as_ref()));
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

        sry!(self.query_stats( pry!(results.get().get_result()).init_ok()));
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

        sry!(self.query_stats( pry!(results.get().get_result()).init_ok()));
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

    /// Looks up a fingerprint, creating a key if necessary.
    ///
    /// On success, the id of the key is returned.
    fn lookup_or_create(c: &Connection, fp: &str) -> Result<i64> {
        if let Ok(x) = c.query_row(
            "SELECT id FROM keys WHERE fingerprint = ?1",
            &[&fp], |row| row.get(0)) {
            Ok(x)
        } else {
            let r = c.execute(
                "INSERT INTO keys (fingerprint, created, update_at) VALUES (?1, ?2, ?2)",
                &[&fp, &Timestamp::now()]);

            // Some other mutator might race us to the insertion.
            match r {
                Err(rusqlite::Error::SqliteFailure(f, e)) => match f.code {
                    // We lost.  Retry the lookup.
                    rusqlite::ErrorCode::ConstraintViolation =>
                        c.query_row(
                            "SELECT id FROM keys WHERE fingerprint = ?1",
                            &[&fp], |row| row.get(0)),
                    // Raise otherwise.
                    _ => Err(rusqlite::Error::SqliteFailure(f, e)),
                },
                Err(e) => Err(e),
                Ok(_) => Ok(c.last_insert_rowid()),
            }.map_err(|e| e.into())
        }
    }

    /// Merges other into this key updating the database.
    ///
    /// Returnes the merged key as blob.
    fn merge(&self, other: TPK) -> Result<Vec<u8>> {
        let mut new = other;

        // Get the current key from the database.
        let (fingerprint, key): (String, Option<Vec<u8>>)
            = self.c.query_row(
                "SELECT fingerprint, key FROM keys WHERE id = ?1",
                &[&self.id],
                |row| (row.get(0), row.get_checked(1).ok()))?;

        // If there was a key stored there, merge it.
        if let Some(current) = key {
            let current = TPK::from_bytes(&current)?;

            if current.fingerprint().to_hex() != fingerprint {
                // Inconsistent database.
                return Err(node::Error::SystemError);
            }

            if current.fingerprint() != new.fingerprint() {
                return Err(node::Error::Conflict);
            }

            new = current.merge(new)?;
        }

        // Write key back to the database.
        let mut blob = vec![];
        new.serialize(&mut blob)?;

        self.c.execute("UPDATE keys SET key = ?1 WHERE id = ?2",
                       &[&blob, &self.id])?;

        Ok(blob)
    }

    /// Records a successful key update.
    fn success(&self, message: &str, next: Duration) -> Result<()> {
        let logid = log(&self.c, &self.slug(), message)?;
        self.c.execute("UPDATE keys SET updated = ?2, log = ?3, update_at = ?4
                        WHERE id = ?1",
                       &[&self.id, &Timestamp::now(),
                         &logid,
                         &(Timestamp::now() + next)])?;
        Ok(())
    }

    /// Records an unsuccessful key update.
    fn error(&self, message: &str, err: &str, next: Duration) -> Result<()> {
        let logid = error(&self.c, &self.slug(), message, err)?;
        self.c.execute("UPDATE keys SET log = ?2, update_at = ?3
                        WHERE id = ?1",
                       &[&self.id, &logid,
                         &(Timestamp::now() + next)])?;
        Ok(())
    }

    /// Returns when the next key using the given policy should be updated.
    fn next_update_at(c: &Rc<Connection>, network_policy: core::NetworkPolicy)
                      -> Option<SystemTime> {
        let network_policy_u8 = u8::from(&network_policy);

        // Select the key that was updated least recently.
        let update_at: Option<i64> = c.query_row(
            "SELECT keys.update_at FROM keys
                 JOIN bindings on keys.id = bindings.key
                 JOIN stores on stores.id = bindings.store
                 WHERE stores.network_policy = ?1
                 ORDER BY keys.update_at LIMIT 1",
            &[&network_policy_u8], |row| row.get(0)).ok();
        update_at.map(|secs| UNIX_EPOCH + Duration::new(secs as u64, 0))
    }

    /// Returns the number of keys using the given policy.
    fn need_update(c: &Rc<Connection>, network_policy: core::NetworkPolicy)
                   -> Result<u32> {
        let network_policy_u8 = u8::from(&network_policy);

        let count: i64 = c.query_row(
            "SELECT COUNT(*) FROM keys
                 JOIN bindings on keys.id = bindings.key
                 JOIN stores on stores.id = bindings.store
                 WHERE stores.network_policy >= ?1",
            &[&network_policy_u8], |row| row.get(0))?;
        assert!(count >= 0);
        Ok(count as u32)
    }

    /// Updates the key that was least recently updated.
    fn update(c: &Rc<Connection>, network_policy: core::NetworkPolicy) -> Result<()> {
        assert!(network_policy != core::NetworkPolicy::Offline);
        let network_policy_u8 = u8::from(&network_policy);

        // Select the key that was updated least recently.
        let (id, fingerprint): (i64, String) = c.query_row(
            "SELECT keys.id, keys.fingerprint FROM keys
                 JOIN bindings on keys.id = bindings.key
                 JOIN stores on stores.id = bindings.store
                 WHERE stores.network_policy >= ?1
                   AND keys.update_at < ?2
                 ORDER BY keys.update_at LIMIT 1",
            &[&network_policy_u8, &Timestamp::now()], |row| (row.get(0), row.get(1)))?;
        let fingerprint = openpgp::Fingerprint::from_hex(&fingerprint)
            .ok_or(node::Error::SystemError)?;

        let key = KeyServer::new(c.clone(), id);
        let doit = || -> Result<()> {
            let ctx = core::Context::configure("org.sequoia-pgp.store")
                .network_policy(network_policy).build()?;
            let mut keyserver = net::KeyServer::sks_pool(&ctx)?;

            // Get key and merge it into the database.
            let tpk = keyserver.get(&fingerprint.to_keyid())?;
            key.merge(tpk)?;
            Ok(())
        };
        let next = refresh_interval() / Self::need_update(c, network_policy)?;
        if let Err(e) = doit() {
            key.error("Update unsuccessful", &format!("{:?}", e), next / 2).unwrap_or(());
        } else {
            key.success("Update successful", next).unwrap_or(());
        }
        Ok(())
    }

    /// Starts the periodic housekeeping.
    fn start_housekeeping(c: Rc<Connection>, handle: Handle) -> Result<()> {
        let h = handle.clone();

        let forever = loop_fn(0, move |_| {
            // For now, we only update keys with this network policy.
            let network_policy = core::NetworkPolicy::Encrypted;

            let now = SystemTime::now();
            let sleep_for =
                if let Some(at) = Self::next_update_at(&c, network_policy) {
                    if at <= now {
                        if let Err(e) = Self::update(&c, network_policy) {
                            #[cfg(debug_assertions)]
                            eprintln!("Odd. Updating failed: {:?}", e);
                        }
                        min_sleep_time()
                    } else {
                        assert!(at > now);
                        cmp::max(min_sleep_time(), at.duration_since(now).unwrap())
                    }
                } else {
                    min_sleep_time()
                };
            assert!(sleep_for > Duration::new(0, 0));

            Timeout::new(random_duration(sleep_for), &h)
                .unwrap() // XXX: May fail if the eventloop expired.
                .then(move |timeout| {
                    if timeout.is_ok() {
                        Ok(Loop::Continue(0))
                    } else {
                        Ok(Loop::Break(()))
                    }
                })
        });
        handle.spawn(forever);
        Ok(())
    }
}

impl Query for KeyServer {
    fn table_name() -> &'static str {
        "keys"
    }

    fn id(&self) -> i64 {
        self.id
    }

    fn connection(&self) -> Rc<Connection> {
        self.c.clone()
    }
}

impl node::key::Server for KeyServer {
    fn stats(&mut self,
             _: node::key::StatsParams,
             mut results: node::key::StatsResults)
             -> Promise<(), capnp::Error> {
        bind_results!(results);
        sry!(self.query_stats( pry!(results.get().get_result()).init_ok()));
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
        let new = sry!(TPK::from_bytes(&pry!(pry!(params.get()).get_key())));
        let blob = sry!(self.merge(new));
        pry!(pry!(results.get().get_result()).set_ok(&blob[..]));
        Promise::ok(())
    }
}

/// Common code for BindingServer and KeyServer.
trait Query {
    fn table_name() -> &'static str;
    fn id(&self) -> i64;
    fn connection(&self) -> Rc<Connection>;

    fn slug(&self) -> String {
        format!("{}::{}", Self::table_name(), self.id())
    }

    fn query(&mut self, column: &str) -> Result<i64> {
        self.connection().query_row(
            &format!("SELECT {} FROM {} WHERE id = ?1", column, Self::table_name()),
            &[&self.id()], |row| row.get(0)).map_err(|e| e.into())
    }

    fn query_stats(&mut self, mut stats: node::stats::Builder) -> Result<()> {
        let created = self.query("created")?;
        let updated = self.query("updated")?;
        let (timestamp, item, message, error): (i64, String, String, String)
            = self.connection().query_row(
                &format!("SELECT log.timestamp, log.item, log.message, log.error FROM log
                          JOIN {0} on log.id = {0}.log
                          WHERE {0}.id = ?1", Self::table_name()),
                &[&self.id()], |row| (row.get(0), row.get(1), row.get(2),
                                      row.get_checked(1).unwrap_or("".into())))
            .or_else(|err| match err {
                // No log messages.
                rusqlite::Error::QueryReturnedNoRows =>
                    Ok((0, "".into(), "".into(), "".into())),
                _ => Err(err),
            })?;
        let encryption_count = self.query("encryption_count")?;
        let encryption_first = self.query("encryption_first")?;
        let encryption_last = self.query("encryption_last")?;
        let verification_count = self.query("verification_count")?;
        let verification_first = self.query("verification_first")?;
        let verification_last = self.query("verification_last")?;
        stats.set_created(created);
        stats.set_updated(updated);
        stats.set_encryption_count(encryption_count);
        stats.set_encryption_first(encryption_first);
        stats.set_encryption_last(encryption_last);
        stats.set_verification_count(verification_count);
        stats.set_verification_first(verification_first);
        stats.set_verification_last(verification_last);
        let mut msg = stats.init_message();
        msg.set_timestamp(timestamp);
        msg.set_item(&item);
        msg.set_message(&message);
        msg.set_error(&error);
        Ok(())
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

impl From<core::Error> for node::Error {
    fn from(_: core::Error) -> Self {
        node::Error::SystemError
    }
}

impl From<net::Error> for node::Error {
    fn from(_: net::Error) -> Self {
        node::Error::SystemError
    }
}

impl From<io::Error> for node::Error {
    fn from(_: io::Error) -> Self {
        node::Error::SystemError
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

CREATE TABLE log (
    id INTEGER PRIMARY KEY,
    timestamp INTEGER NOT NULL,
    item TEXT NOT NULL,
    message TEXT NOT NULL,
    error TEXT NULL);

CREATE TABLE bindings (
    id INTEGER PRIMARY KEY,
    store INTEGER NOT NULL,
    label TEXT NOT NULL,
    key INTEGER NOT NULL,

    created INTEGER NOT NULL,
    updated DEFAULT 0,
    log INTEGER NULL,

    encryption_count DEFAULT 0,
    encryption_first DEFAULT 0,
    encryption_last DEFAULT 0,
    verification_count DEFAULT 0,
    verification_first DEFAULT 0,
    verification_last DEFAULT 0,

    UNIQUE(store, label),
    FOREIGN KEY (store) REFERENCES stores(id) ON DELETE CASCADE,
    FOREIGN KEY (key) REFERENCES keys(id) ON DELETE CASCADE
    FOREIGN KEY (log) REFERENCES log(id));

CREATE TABLE keys (
    id INTEGER PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    key BLOB,

    created INTEGER NOT NULL,
    updated DEFAULT 0,
    log INTEGER NULL,
    update_at INTEGER NOT NULL,

    encryption_count DEFAULT 0,
    encryption_first DEFAULT 0,
    encryption_last DEFAULT 0,
    verification_count DEFAULT 0,
    verification_first DEFAULT 0,
    verification_last DEFAULT 0,

    UNIQUE (fingerprint),
    FOREIGN KEY (log) REFERENCES log(id));
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

/* Logging.  */

/// Writes a log message to the log.
fn log(c: &Rc<Connection>, item: &str, message: &str) -> Result<i64> {
    c.execute("INSERT INTO log (timestamp, item, message) VALUES (?1, ?2, ?3)",
              &[&Timestamp::now(), &item, &message])?;
    Ok(c.last_insert_rowid())
}

/// Writes an error message to the log.
fn error(c: &Rc<Connection>, item: &str, message: &str, error: &str) -> Result<i64> {
    c.execute("INSERT INTO log (timestamp, item, message, error) VALUES (?1, ?2, ?3, ?4)",
              &[&Timestamp::now(), &item, &message, &error])?;
    Ok(c.last_insert_rowid())
}

/* Miscellaneous.  */

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
