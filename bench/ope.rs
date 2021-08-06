#[macro_use]
extern crate criterion;

use criterion::Criterion;
use hkdf::Hkdf;
use ope::OrderPreservingEncryption;
use rand::{prelude::ThreadRng, thread_rng, RngCore};
use sha2::{Digest, Sha256};

fn sha256(c: &mut Criterion) {
    let mut rng: ThreadRng = thread_rng();
    let mut input = [0u8; 32];
    rng.fill_bytes(&mut input);

    c.bench_function("sha256", move |b| {
        b.iter(|| {
            let mut hasher = Sha256::new();
            hasher.update(input);
            hasher.finalize();
        })
    });
}

fn hkdf_sha256(c: &mut Criterion) {
    let mut rng: ThreadRng = thread_rng();
    let mut input = [0u8; 32];
    rng.fill_bytes(&mut input);

    let mut key = [0u8; 32];
    rng.fill_bytes(&mut key);

    c.bench_function("hkdf_sha256", move |b| {
        b.iter(|| {
            let mut okm = vec![0u8; 32];
            let h = Hkdf::<Sha256>::from_prk(&key).unwrap();
            h.expand(&input, &mut okm).unwrap();
        })
    });
}

fn ope_encrypt(c: &mut Criterion) {
    let mut rng: ThreadRng = thread_rng();

    let ope = OrderPreservingEncryption::new(5);
    let key = ope.keygen(&mut rng);

    let input = rng.next_u64();

    c.bench_function("u64 encrypt with expansion factor = 5", move |b| {
        b.iter(|| ope.encrypt(&key, input.to_string()))
    });
}

criterion_group!(ope_benches, sha256, hkdf_sha256, ope_encrypt,);
criterion_main!(ope_benches);
