use criterion::{criterion_group, BenchmarkId, Criterion, Throughput};

use sequoia_openpgp as openpgp;
use openpgp::cert::Cert;
use openpgp::parse::Parse;

use crate::common::encrypt;

pub fn encrypt_to_donald_sign_by_ivanka(bytes: &[u8]) {
    let sender = Cert::from_bytes(
        &include_bytes!("../tests/data/keys/ivanka-private.pgp")[..],
    )
    .unwrap();
    let recipient = Cert::from_bytes(
        &include_bytes!("../tests/data/keys/the-donald-private.pgp")[..],
    )
    .unwrap();
    encrypt::encrypt_to_cert_and_sign(bytes, &sender, &recipient).unwrap();
}

fn bench_encrypt_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("encrypt and sign message");

    for message in encrypt::messages() {
        group.throughput(Throughput::Bytes(message.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("encrypt and sign", message.len()),
            &message,
            |b, m| b.iter(|| encrypt_to_donald_sign_by_ivanka(m)),
        );
    }
    group.finish();
}

criterion_group!(benches, bench_encrypt_sign);
