use criterion::{
    criterion_group, criterion_main, BenchmarkId, Criterion, Throughput,
};

use sequoia_openpgp as openpgp;
use openpgp::cert::Cert;

use crate::common::{decrypt, encrypt};

fn decrypt_and_verify(bytes: &[u8], sender: &Cert, recipient: &Cert) {
    let mut sink = Vec::new();
    decrypt::decrypt_and_verify(&mut sink, bytes, sender, recipient).unwrap();
}

fn bench_decrypt_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("decrypt and verify message");

    encrypt::messages().for_each(|m| {
        let encrypted =
            encrypt::encrypt_to_cert_and_sign(m,
                                              encrypt::sender(),
                                              encrypt::recipient()).unwrap();
        group.throughput(Throughput::Bytes(encrypted.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("decrypt and verify", m.len()),
            &encrypted,
            |b, e| b.iter(|| decrypt_and_verify(e,
                                                encrypt::sender(),
                                                encrypt::recipient())),
        );
    });

    group.finish();
}

criterion_group!(benches, bench_decrypt_verify);
criterion_main!(benches);
