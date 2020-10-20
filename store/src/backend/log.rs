//! Logging for the backend.

// XXX: Implement log levels and trim the log.
use rusqlite::{Connection, types::ToSql};
use super::{
    ID, Timestamp, Rc, Result, node,
    MappingServer, BindingServer, KeyServer,
    Promise, capnp, capnp_rpc
};

/// Models entries referring to other objects.
pub struct Refers {
    mapping: Option<ID>,
    binding: Option<ID>,
    key: Option<ID>,
}

impl Refers {
    /// Builds an empty object.
    pub fn to() -> Self {
	Refers{mapping: None, binding: None, key: None}
    }

    /// Makes log refer a mapping.
    pub fn mapping(mut self, id: ID) -> Self {
        self.mapping = Some(id);
        self
    }

    /// Makes log refer a binding.
    pub fn binding(mut self, id: ID) -> Self {
        self.binding = Some(id);
        self
    }

    /// Makes log refer a key.
    pub fn key(mut self, id: ID) -> Self {
        self.key = Some(id);
        self
    }
}

/// Writes a log message to the log.
pub fn message(c: &Rc<Connection>, refers: Refers,
               slug: &str, message: &str)
               -> Result<ID> {
    log(c, refers, slug, message, None)
}

/// Writes an error message to the log.
pub fn error(c: &Rc<Connection>, refers: Refers,
             slug: &str, message: &str, error: &str)
             -> Result<ID> {
    log(c, refers, slug, message, Some(error))
}

/// Writes a log message to the log.
fn log(c: &Rc<Connection>, refers: Refers,
       slug: &str, message: &str, error: Option<&str>)
       -> Result<ID> {
    c.execute("INSERT INTO log
                   (timestamp, level, mapping, binding, key, slug, message, error)
                   VALUES (?1, 0, ?2, ?3, ?4, ?5, ?6, ?7)",
              &[&Timestamp::now() as &dyn ToSql,
                &refers.mapping, &refers.binding, &refers.key,
                &slug, &message, &error])?;
    Ok(c.last_insert_rowid().into())
}

/// Selects log entries to iterate over.
pub enum Selector {
    All,
    Mapping(ID),
    Binding(ID),
    Key(ID),
}

/// Iterator for log entries.
pub struct IterServer {
    c: Rc<Connection>,
    selector: Selector,
    n: ID,
}

impl IterServer {
    pub fn new(c: Rc<Connection>, selector: Selector) -> Self {
        IterServer{c: c, selector: selector, n: ID::max()}
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
            mapping, binding, key,
            slug, message, error
        ): (
            ID, Timestamp,
            Option<ID>, Option<ID>, Option<ID>,
            String, String, Option<String>
        ) = sry!(match self.selector {
            Selector::All =>
                self.c.query_row(
                    "SELECT id, timestamp,
                            mapping, binding, key,
                            slug, message, error
                         FROM log
                         WHERE id < ?1
                         ORDER BY id DESC LIMIT 1",
                    &[&self.n],
                    |row| Ok((row.get(0)?, row.get(1)?,
                              row.get(2)?, row.get(3)?, row.get(4)?,
                              row.get(5)?, row.get(6)?, row.get(7)?))),

            Selector::Mapping(mapping) =>
                self.c.query_row(
                    "SELECT id, timestamp,
                            mapping, binding, key,
                            slug, message, error
                         FROM log
                         WHERE id < ?1
                           AND (mapping = ?2
                                OR binding IN (SELECT id FROM bindings WHERE mapping = ?2)
                                OR key IN (SELECT key FROM bindings WHERE mapping = ?2))
                         ORDER BY id DESC LIMIT 1",
                    &[&self.n, &mapping],
                    |row| Ok((row.get(0)?, row.get(1)?,
                              row.get(2)?, row.get(3)?, row.get(4)?,
                              row.get(5)?, row.get(6)?, row.get(7)?))),

            Selector::Binding(binding) =>
                self.c.query_row(
                    "SELECT id, timestamp,
                            mapping, binding, key,
                            slug, message, error
                         FROM log
                         WHERE id < ?1
                           AND (binding = ?2
                                OR key IN (SELECT key FROM bindings WHERE id = ?2))
                         ORDER BY id DESC LIMIT 1",
                    &[&self.n, &binding],
                    |row| Ok((row.get(0)?, row.get(1)?,
                              row.get(2)?, row.get(3)?, row.get(4)?,
                              row.get(5)?, row.get(6)?, row.get(7)?))),

            Selector::Key(key) =>
                self.c.query_row(
                    "SELECT id, timestamp,
                            mapping, binding, key,
                            slug, message, error
                         FROM log
                         WHERE id < ?1
                           AND key = ?2
                         ORDER BY id DESC LIMIT 1",
                    &[&self.n, &key],
                    |row| Ok((row.get(0)?, row.get(1)?,
                              row.get(2)?, row.get(3)?, row.get(4)?,
                              row.get(5)?, row.get(6)?, row.get(7)?))),
        });

        let mut entry = pry!(results.get().get_result()).init_ok();
        entry.set_timestamp(timestamp.unix());

        if let Some(mapping) = mapping {
            entry.set_mapping(capnp_rpc::new_client(
                MappingServer::new(self.c.clone(), mapping)));
        }

        if let Some(binding) = binding {
            entry.set_binding(capnp_rpc::new_client(
                BindingServer::new(self.c.clone(), binding)));
        }

        if let Some(key) = key {
            entry.set_key(capnp_rpc::new_client(
                KeyServer::new(self.c.clone(), key)));
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
