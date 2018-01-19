extern crate sequoia_core;
extern crate sequoia_store;

use std::env::current_exe;
use std::path::PathBuf;

use sequoia_core::{Context, NetworkPolicy, IPCPolicy};
use sequoia_store::Store;

#[test]
fn ipc_policy_external() {
    let ctx = Context::configure("org.sequoia-pgp.tests")
        .ephemeral()
        .lib(current_exe().unwrap().parent().unwrap().parent().unwrap())
        .network_policy(NetworkPolicy::Offline)
        .ipc_policy(IPCPolicy::External)
        .build().unwrap();
    Store::open(&ctx, "default").unwrap();
}

#[test]
fn ipc_policy_internal() {
    let ctx = Context::configure("org.sequoia-pgp.tests")
        .ephemeral()
        .lib(PathBuf::from("/i/do/not/exist"))
        .network_policy(NetworkPolicy::Offline)
        .ipc_policy(IPCPolicy::Internal)
        .build().unwrap();
    Store::open(&ctx, "default").unwrap();
}

#[test]
fn ipc_policy_robust() {
    let ctx = Context::configure("org.sequoia-pgp.tests")
        .ephemeral()
        .lib(current_exe().unwrap().parent().unwrap().parent().unwrap())
        .network_policy(NetworkPolicy::Offline)
        .ipc_policy(IPCPolicy::Robust)
        .build().unwrap();
    Store::open(&ctx, "default").unwrap();

    let ctx = Context::configure("org.sequoia-pgp.tests")
        .ephemeral()
        .lib(PathBuf::from("/i/do/not/exist"))
        .network_policy(NetworkPolicy::Offline)
        .ipc_policy(IPCPolicy::Robust)
        .build().unwrap();
    Store::open(&ctx, "default").unwrap();
}
