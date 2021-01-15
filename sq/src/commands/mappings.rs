use anyhow::Context;

use prettytable::{Table, Cell, Row, row, cell};

use sequoia_openpgp as openpgp;
use openpgp::{
    Result,
    cert::{
        Cert,
    },
    parse::Parse,
    serialize::Serialize,
};
use sequoia_store as store;
use store::{
    Mapping,
    LogIter,
};

use crate::{
    Config,
    help_warning,
    commands::dump::Convert,
    open_or_stdin,
    create_or_stdout,
};

pub fn dispatch_mapping(config: Config, m: &clap::ArgMatches) -> Result<()> {
    let mapping = Mapping::open(&config.context, config.network_policy,
                                &config.realm_name, &config.mapping_name)
        .context("Failed to open the mapping")?;

    match m.subcommand() {
        ("list",  Some(_)) => {
            list_bindings(&mapping, &config.realm_name, &config.mapping_name)?;
        },
        ("add",  Some(m)) => {
            let fp = m.value_of("fingerprint").unwrap().parse()
                .expect("Malformed fingerprint");
            mapping.add(m.value_of("label").unwrap(), &fp)?;
        },
        ("import",  Some(m)) => {
            let label = m.value_of("label").unwrap();
            help_warning(label);
            let mut input = open_or_stdin(m.value_of("input"))?;
            let cert = Cert::from_reader(&mut input)?;
            mapping.import(label, &cert)?;
        },
        ("export",  Some(m)) => {
            let cert = mapping.lookup(m.value_of("label").unwrap())?.cert()?;
            let mut output = create_or_stdout(m.value_of("output"),
                                              config.force)?;
            if m.is_present("binary") {
                cert.serialize(&mut output)?;
            } else {
                cert.armored().serialize(&mut output)?;
            }
        },
        ("delete",  Some(m)) => {
            if m.is_present("label") == m.is_present("the-mapping") {
                return Err(anyhow::anyhow!(
                    "Please specify either a label or --the-mapping."));
            }

            if m.is_present("the-mapping") {
                mapping.delete().context("Failed to delete the mapping")?;
            } else {
                let binding = mapping.lookup(m.value_of("label").unwrap())
                    .context("Failed to get key")?;
                binding.delete().context("Failed to delete the binding")?;
            }
        },
        ("stats",  Some(m)) => {
            mapping_print_stats(&mapping,
                                m.value_of("label").unwrap())?;
        },
        ("log",  Some(m)) => {
            if m.is_present("label") {
                let binding = mapping.lookup(m.value_of("label").unwrap())
                    .context("No such key")?;
                print_log(binding.log().context("Failed to get log")?, false);
            } else {
                print_log(mapping.log().context("Failed to get log")?, true);
            }
        },
        _ => unreachable!(),
    }

    Ok(())
}

pub fn dispatch_list(config: Config, m: &clap::ArgMatches) -> Result<()> {
    match m.subcommand() {
        ("mappings",  Some(m)) => {
            let mut table = Table::new();
            table.set_format(*prettytable::format::consts::FORMAT_NO_LINESEP_WITH_TITLE);
            table.set_titles(row!["realm", "name", "network policy"]);

            for (realm, name, network_policy, _)
                in Mapping::list(&config.context, m.value_of("prefix").unwrap_or(""))? {
                    table.add_row(Row::new(vec![
                        Cell::new(&realm),
                        Cell::new(&name),
                        Cell::new(&format!("{:?}", network_policy))
                    ]));
                }

            table.printstd();
        },
        ("bindings",  Some(m)) => {
            for (realm, name, _, mapping)
                in Mapping::list(&config.context, m.value_of("prefix").unwrap_or(""))? {
                    list_bindings(&mapping, &realm, &name)?;
                }
        },
        ("keys",  Some(_)) => {
            let mut table = Table::new();
            table.set_format(*prettytable::format::consts::FORMAT_NO_LINESEP_WITH_TITLE);
            table.set_titles(row!["fingerprint", "updated", "status"]);

            for (fingerprint, key) in store::Store::list_keys(&config.context)? {
                let stats = key.stats()
                    .context("Failed to get key stats")?;
                table.add_row(Row::new(vec![
                    Cell::new(&fingerprint.to_string()),
                    if let Some(t) = stats.updated {
                        Cell::new(&t.convert().to_string())
                    } else {
                        Cell::new("")
                    },
                    Cell::new("")
                ]));
            }

            table.printstd();
        },
        ("log",  Some(_)) => {
            print_log(store::Store::server_log(&config.context)?, true);
        },
        _ => unreachable!(),
    }

    Ok(())
}

fn list_bindings(mapping: &Mapping, realm: &str, name: &str)
                 -> Result<()> {
    if mapping.iter()?.count() == 0 {
        println!("No label-key bindings in the \"{}/{}\" mapping.",
                 realm, name);
        return Ok(());
    }

    println!("Realm: {:?}, mapping: {:?}:", realm, name);

    let mut table = Table::new();
    table.set_format(*prettytable::format::consts::FORMAT_NO_LINESEP_WITH_TITLE);
    table.set_titles(row!["label", "fingerprint"]);
    for (label, fingerprint, _) in mapping.iter()? {
        table.add_row(Row::new(vec![
            Cell::new(&label),
            Cell::new(&fingerprint.to_string())]));
    }
    table.printstd();
    Ok(())
}

fn print_log(iter: LogIter, with_slug: bool) {
    let mut table = Table::new();
    table.set_format(*prettytable::format::consts::FORMAT_NO_LINESEP_WITH_TITLE);
    let mut head = row!["timestamp", "message"];
    if with_slug {
        head.insert_cell(1, Cell::new("slug"));
    }
    table.set_titles(head);

    for entry in iter {
        let mut row = row![&entry.timestamp.convert().to_string(),
                           &entry.short()];
        if with_slug {
            row.insert_cell(1, Cell::new(&entry.slug));
        }
        table.add_row(row);
    }

    table.printstd();
}

pub fn mapping_print_stats(mapping: &store::Mapping, label: &str) -> Result<()> {
    fn print_stamps(st: &store::Stamps) -> Result<()> {
        println!("{} messages using this key", st.count);
        if let Some(t) = st.first {
            println!("    First: {}", t.convert());
        }
        if let Some(t) = st.last {
            println!("    Last: {}", t.convert());
        }
        Ok(())
    }

    fn print_stats(st: &store::Stats) -> Result<()> {
        if let Some(t) = st.created {
            println!("  Created: {}", t.convert());
        }
        if let Some(t) = st.updated {
            println!("  Updated: {}", t.convert());
        }
        print!("  Encrypted ");
        print_stamps(&st.encryption)?;
        print!("  Verified ");
        print_stamps(&st.verification)?;
        Ok(())
    }

    let binding = mapping.lookup(label)?;
    println!("Binding {:?}", label);
    print_stats(&binding.stats().context("Failed to get stats")?)?;
    let key = binding.key().context("Failed to get key")?;
    println!("Key");
    print_stats(&key.stats().context("Failed to get stats")?)?;
    Ok(())
}
