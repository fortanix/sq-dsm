
use std::env::current_exe;
use std::path::PathBuf;

use sequoia_ipc::core::{Context, IPCPolicy};
use sequoia_store::{Mapping, REALM_CONTACTS};
use sequoia_net as net;

const P: net::Policy = net::Policy::Offline;

#[test]
fn ipc_policy_external() {
    let ctx = Context::configure()
        .ephemeral()
        .lib(current_exe().unwrap().parent().unwrap().parent().unwrap())
        .ipc_policy(IPCPolicy::External)
        .build().unwrap();
    Mapping::open(&ctx, P, REALM_CONTACTS, "default").unwrap();
}

#[test]
fn ipc_policy_internal() {
    let ctx = Context::configure()
        .ephemeral()
        .lib(PathBuf::from("/i/do/not/exist"))
        .ipc_policy(IPCPolicy::Internal)
        .build().unwrap();
    Mapping::open(&ctx, P, REALM_CONTACTS, "default").unwrap();
}

#[test]
fn ipc_policy_robust() {
    let ctx = Context::configure()
        .ephemeral()
        .lib(current_exe().unwrap().parent().unwrap().parent().unwrap())
        .ipc_policy(IPCPolicy::Robust)
        .build().unwrap();
    Mapping::open(&ctx, P, REALM_CONTACTS, "default").unwrap();

    let ctx = Context::configure()
        .ephemeral()
        .lib(PathBuf::from("/i/do/not/exist"))
        .ipc_policy(IPCPolicy::Robust)
        .build().unwrap();
    Mapping::open(&ctx, P, REALM_CONTACTS, "default").unwrap();
}
