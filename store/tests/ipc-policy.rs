extern crate sequoia_core;
extern crate sequoia_store;

use std::env::current_exe;
use std::path::PathBuf;

use sequoia_core::{Context, NetworkPolicy, IPCPolicy};
use sequoia_store::{Mapping, REALM_CONTACTS};

#[test]
fn ipc_policy_external() {
    let ctx = Context::configure()
        .ephemeral()
        .lib(current_exe().unwrap().parent().unwrap().parent().unwrap())
        .network_policy(NetworkPolicy::Offline)
        .ipc_policy(IPCPolicy::External)
        .build().unwrap();
    Mapping::open(&ctx, REALM_CONTACTS, "default").unwrap();
}

#[test]
fn ipc_policy_internal() {
    let ctx = Context::configure()
        .ephemeral()
        .lib(PathBuf::from("/i/do/not/exist"))
        .network_policy(NetworkPolicy::Offline)
        .ipc_policy(IPCPolicy::Internal)
        .build().unwrap();
    Mapping::open(&ctx, REALM_CONTACTS, "default").unwrap();
}

#[test]
fn ipc_policy_robust() {
    let ctx = Context::configure()
        .ephemeral()
        .lib(current_exe().unwrap().parent().unwrap().parent().unwrap())
        .network_policy(NetworkPolicy::Offline)
        .ipc_policy(IPCPolicy::Robust)
        .build().unwrap();
    Mapping::open(&ctx, REALM_CONTACTS, "default").unwrap();

    let ctx = Context::configure()
        .ephemeral()
        .lib(PathBuf::from("/i/do/not/exist"))
        .network_policy(NetworkPolicy::Offline)
        .ipc_policy(IPCPolicy::Robust)
        .build().unwrap();
    Mapping::open(&ctx, REALM_CONTACTS, "default").unwrap();
}
