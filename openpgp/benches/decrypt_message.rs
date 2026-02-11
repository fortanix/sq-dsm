use std::sync::OnceLock;

use criterion::{
    criterion_group, criterion_main, BenchmarkId, Criterion, Throughput,
};

use sequoia_openpgp as openpgp;
use openpgp::cert::Cert;
use openpgp::parse::Parse;

use crate::common::{decrypt, encrypt};

static PASSWORD: &str = "password";

fn testy() -> &'static Cert {
    static CERT: OnceLock<Cert> = OnceLock::new();
    CERT.get_or_init(|| {
        Cert::from_bytes(
            &include_bytes!("../tests/data/keys/testy-private.pgp")[..])
            .unwrap()
    })
}

fn decrypt_cert(bytes: &[u8], cert: &Cert) {
    let mut sink = Vec::new();
    decrypt::decrypt_with_cert(&mut sink, bytes, cert).unwrap();
}

fn decrypt_password(bytes: &[u8]) {
    let mut sink = Vec::new();
    decrypt::decrypt_with_password(&mut sink, bytes, PASSWORD).unwrap();
}

fn bench_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("decrypt message");

    // Encrypt and decrypt with password
    encrypt::messages().for_each(|m| {
        let encrypted = encrypt::encrypt_with_password(m, PASSWORD).unwrap();
        group.throughput(Throughput::Bytes(encrypted.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("password", m.len()),
            &encrypted,
            |b, e| b.iter(|| decrypt_password(e)),
        );
    });

    // Encrypt and decrypt with a cert
    encrypt::messages().for_each(|m| {
        let encrypted = encrypt::encrypt_to_cert(m, testy()).unwrap();
        group.throughput(Throughput::Bytes(encrypted.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("cert", m.len()),
            &encrypted,
            |b, e| b.iter(|| decrypt_cert(e, testy())),
        );
    });

    group.finish();
}

criterion_group!(benches, bench_decrypt);
criterion_main!(benches);
