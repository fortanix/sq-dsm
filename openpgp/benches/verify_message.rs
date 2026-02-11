use criterion::{criterion_group, BenchmarkId, Criterion, Throughput};

use sequoia_openpgp as openpgp;
use openpgp::cert::Cert;

use crate::common::{decrypt, encrypt};

fn verify(bytes: &[u8], sender: &Cert) {
    let mut sink = Vec::new();
    decrypt::verify(&mut sink, bytes, sender).unwrap();
}

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify message");

    encrypt::messages()
        .for_each(|m| {
            let signed = encrypt::sign(m, encrypt::sender()).unwrap();
            group.throughput(Throughput::Bytes(signed.len() as u64));
            group.bench_with_input(
                BenchmarkId::new("verify", m.len()),
                &signed,
                |b, s| b.iter(|| verify(s, encrypt::sender())),
            );
        });

    group.finish();
}

criterion_group!(benches, bench_verify);
