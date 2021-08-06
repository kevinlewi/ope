use crate::OrderPreservingEncryption;
use num_bigint::{BigUint, RandBigInt};
use serde::{Deserialize, Serialize};

use std::fs::File;
use std::io::prelude::*;
#[allow(non_snake_case)]
#[derive(Serialize, Deserialize)]
pub struct TestVectorParameters {
    pub key: String,
    pub input: String,
    pub expansion_factor: usize,
    pub ciphertext: String,
}

#[test]
fn generate_test_vectors() -> () {
    let mut test_vectors = vec![];
    let mut rng = rand::thread_rng();

    let num_expansion_factors = 4;
    let input_log_ranges = vec![8, 32, 64, 128, 256];

    for i in 0..num_expansion_factors {
        for &input_log_range in &input_log_ranges {
            let expansion_factor = i + 1;
            let ope = OrderPreservingEncryption::new(expansion_factor);
            let key = ope.keygen(&mut rng);
            let input: BigUint = rng.gen_biguint(input_log_range);
            let ciphertext = ope.encrypt(&key, input.to_string()).unwrap();

            let params = TestVectorParameters {
                key: hex::encode(key),
                input: input.to_string(),
                expansion_factor,
                ciphertext,
            };

            test_vectors.push(params);
        }
    }

    // Uncomment this out to print test vectors
    // println!("{}", serde_json::to_string_pretty(&test_vectors).unwrap());
    // assert!(false);
}

#[test]
fn check_test_vectors() -> () {
    let mut file = File::open("test_vectors.json").unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    let deserialized: Vec<TestVectorParameters> = serde_json::from_str(&contents).unwrap();

    for tv in deserialized {
        let ope = OrderPreservingEncryption::new(tv.expansion_factor);
        let key = hex::decode(tv.key).unwrap();

        let ciphertext = ope.encrypt(&key, tv.input).unwrap();
        assert_eq!(tv.ciphertext, ciphertext);
    }
}
