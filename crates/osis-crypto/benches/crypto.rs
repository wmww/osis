//! Benchmarks (notes/crypto.md, Implementation): sealed box seal/open, blob encryption per MB, Ed25519 verify.
//! Not gated. Run: `cargo bench -p osis-crypto`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use osis_crypto::{Domain, KemSecret, SeededRng, Secret32, SigningSecret, decrypt_blob, encrypt_blob, open_sealed, seal};
use std::hint::black_box;

fn boxes(c: &mut Criterion) {
    let mut rng = SeededRng::from_u64(1);
    let k = KemSecret::derive(&Secret32::from_bytes([1; 32]));
    let payload = [7u8; 64];
    c.bench_function("sealed box seal", |b| b.iter(|| seal(k.public(), b"ad", black_box(&payload), &mut rng).unwrap()));
    let sealed = seal(k.public(), b"ad", &payload, &mut rng).unwrap();
    c.bench_function("sealed box open", |b| b.iter(|| open_sealed(&k, b"ad", black_box(&sealed)).unwrap()));
    c.bench_function("kem keygen", |b| b.iter(|| KemSecret::derive(black_box(&Secret32::from_bytes([2; 32])))));
}

fn blobs(c: &mut Criterion) {
    let mut rng = SeededRng::from_u64(2);
    let data = vec![5u8; 1 << 20];
    let prefix = [1u8; 26];
    let mut g = c.benchmark_group("blob 1 MiB");
    g.throughput(Throughput::Bytes(data.len() as u64));
    g.bench_function("encrypt", |b| b.iter(|| encrypt_blob(&prefix, black_box(&data), &mut rng).unwrap()));
    let (key, blob) = encrypt_blob(&prefix, &data, &mut rng).unwrap();
    g.bench_function("decrypt", |b| b.iter(|| decrypt_blob(black_box(&blob), 26, &key).unwrap()));
    g.finish();
}

fn signatures(c: &mut Criterion) {
    let sk = SigningSecret::from_seed(&Secret32::from_bytes([3; 32]));
    let pk = sk.verifying_key();
    let sig = sk.sign(Domain::Commit, &[9; 32]);
    c.bench_function("ed25519 sign", |b| b.iter(|| sk.sign(Domain::Commit, black_box(&[9; 32]))));
    c.bench_function("ed25519 verify", |b| b.iter(|| pk.verify(Domain::Commit, black_box(&[9; 32]), &sig).unwrap()));
}

criterion_group!(benches, boxes, blobs, signatures);
criterion_main!(benches);
