//! Logging for the backend.

// XXX: Implement log levels and trim the log.

use super::{
    Timestamp, Connection, Rc, Result, node,
    StoreServer, BindingServer, KeyServer,
    Promise, capnp, capnp_rpc
};

/// Models entries referring to other objects.
pub struct Refers {
    store: Option<i64>,
    binding: Option<i64>,
    key: Option<i64>,
}

impl Refers {
    /// Builds an empty object.
    pub fn to() -> Self {
	Refers{store: None, binding: None, key: None}
    }

    /// Makes log refer a store.
    pub fn store(mut self, id: i64) -> Self {
        self.store = Some(id);
        self
    }

    /// Makes log refer a binding.
    pub fn binding(mut self, id: i64) -> Self {
        self.binding = Some(id);
        self
    }

    /// Makes log refer a key.
    pub fn key(mut self, id: i64) -> Self {
        self.key = Some(id);
        self
    }
}

/// Writes a log message to the log.
pub fn message(c: &Rc<Connection>, refers: Refers,
               slug: &str, message: &str)
               -> Result<i64> {
    log(c, refers, slug, message, None)
}

/// Writes an error message to the log.
pub fn error(c: &Rc<Connection>, refers: Refers,
             slug: &str, message: &str, error: &str)
             -> Result<i64> {
    log(c, refers, slug, message, Some(error))
}

/// Writes a log message to the log.
fn log(c: &Rc<Connection>, refers: Refers,
       slug: &str, message: &str, error: Option<&str>)
       -> Result<i64> {
    c.execute("INSERT INTO log
                   (timestamp, level, store, binding, key, slug, message, error)
                   VALUES (?1, 0, ?2, ?3, ?4, ?5, ?6, ?7)",
              &[&Timestamp::now(),
                &refers.store, &refers.binding, &refers.key,
                &slug, &message, &error])?;
    Ok(c.last_insert_rowid())
}

/// Selects log entries to iterate over.
pub enum Selector {
    All,
    Store(i64),
    Binding(i64),
    Key(i64),
}

/// Iterator for log entries.
pub struct IterServer {
    c: Rc<Connection>,
    selector: Selector,
    n: i64,
}

impl IterServer {
    pub fn new(c: Rc<Connection>, selector: Selector) -> Self {
        IterServer{c: c, selector: selector, n: ::std::i64::MAX}
    }
}

impl node::log_iter::Server for IterServer {
    fn next(&mut self,
            _: node::log_iter::NextParams,
            mut results: node::log_iter::NextResults)
            -> Promise<(), capnp::Error> {
        bind_results!(results);

        let (
            id, timestamp,
            store, binding, key,
            slug, message, error
        ): (
            i64, i64,
            Option<i64>, Option<i64>, Option<i64>,
            String, String, Option<String>
        ) = sry!(match self.selector {
            Selector::All =>
                self.c.query_row(
                    "SELECT id, timestamp,
                            store, binding, key,
                            slug, message, error
                         FROM log
                         WHERE id < ?1
                         ORDER BY id DESC LIMIT 1",
                    &[&self.n],
                    |row| (row.get(0), row.get(1),
                           row.get(2), row.get(3), row.get(4),
                           row.get(5), row.get(6), row.get(7))),

            Selector::Store(store) =>
                self.c.query_row(
                    "SELECT id, timestamp,
                            store, binding, key,
                            slug, message, error
                         FROM log
                         WHERE id < ?1
                           AND (store = ?2
                                OR binding IN (SELECT id FROM bindings WHERE store = ?2)
                                OR key IN (SELECT key FROM bindings WHERE store = ?2))
                         ORDER BY id DESC LIMIT 1",
                    &[&self.n, &store],
                    |row| (row.get(0), row.get(1),
                           row.get(2), row.get(3), row.get(4),
                           row.get(5), row.get(6), row.get(7))),

            Selector::Binding(binding) =>
                self.c.query_row(
                    "SELECT id, timestamp,
                            store, binding, key,
                            slug, message, error
                         FROM log
                         WHERE id < ?1
                           AND (binding = ?2
                                OR key IN (SELECT key FROM bindings WHERE id = ?2))
                         ORDER BY id DESC LIMIT 1",
                    &[&self.n, &binding],
                    |row| (row.get(0), row.get(1),
                           row.get(2), row.get(3), row.get(4),
                           row.get(5), row.get(6), row.get(7))),

            Selector::Key(key) =>
                self.c.query_row(
                    "SELECT id, timestamp,
                            store, binding, key,
                            slug, message, error
                         FROM log
                         WHERE id < ?1
                           AND key = ?2
                         ORDER BY id DESC LIMIT 1",
                    &[&self.n, &key],
                    |row| (row.get(0), row.get(1),
                           row.get(2), row.get(3), row.get(4),
                           row.get(5), row.get(6), row.get(7))),
        });

        let mut entry = pry!(results.get().get_result()).init_ok();
        entry.set_timestamp(timestamp);

        if let Some(store) = store {
            entry.set_store(node::store::ToClient::new(
                StoreServer::new(self.c.clone(), store))
                            .from_server::<capnp_rpc::Server>());
        }

        if let Some(binding) = binding {
            entry.set_binding(node::binding::ToClient::new(
                BindingServer::new(self.c.clone(), binding))
                            .from_server::<capnp_rpc::Server>());
        }

        if let Some(key) = key {
            entry.set_key(node::key::ToClient::new(
                KeyServer::new(self.c.clone(), key))
                            .from_server::<capnp_rpc::Server>());
        }

        entry.set_slug(&slug);
        entry.set_message(&message);
        if let Some(error) = error {
            entry.set_error(&error);
        }

        self.n = id;
        Promise::ok(())
    }
}
