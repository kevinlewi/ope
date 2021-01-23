//! Implements order-preserving encryption via an ORE construction followed by a
//! conversion to OPE.
//!
//! An OPE struct is parameterized by two variables, `block_size` and `expansion_factor`.
//!
//! - Error probability is 1 - 2^(block_size * 8) / 2^(expansion_factor * 8)
//! - Ciphertext length is a multiplicative factor larger than input length by: expansion_factor / block_size
//! - Security goes down if block_size goes up
//!
//! This means that:
//! - Increasing `block_size` means slightly reduced correctness, reduced ciphertext length, decreased security
//! - Increasing `expansion_factor` means more correctness, increased ciphertext length

use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use std::string::String;

pub struct OrderPreservingEncryption {
    block_size: usize,
    expansion_factor: usize,
}

impl OrderPreservingEncryption {
    // d = 2 ** (BLOCK_SIZE * 8)
    // M = 2 ** (M_IN_BYTES * 8)
    pub fn new(block_size: usize, expansion_factor: usize) -> Self {
        Self {
            block_size,
            expansion_factor,
        }
    }

    // input length * log_2(M) / log_2(d)
    pub fn ciphertext_len_in_bytes(&self) -> usize {
        8 * self.expansion_factor / self.block_size
    }

    // 1 / failure rate
    // Failure rate is d / M
    pub fn inverted_log_failure_rate(&self) -> usize {
        (self.expansion_factor - 1) * 8
    }

    pub fn keygen<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Vec<u8> {
        let mut result = [0u8; 32];
        rng.fill_bytes(&mut result);
        result.to_vec()
    }

    pub fn encrypt(&self, key: &[u8], x: u64) -> String {
        //x.to_string()

        // FIXME assumes BLOCK_SIZE = 1 ( d = 256) below for loop

        let mut u_strings = vec![];
        let x_bytes = x.to_be_bytes();
        for (i, &elem) in x_bytes.iter().enumerate() {
            let input = [
                &[i as u8][..],
                &x_bytes[..i],
                &vec![0u8; x_bytes.len() - i][..],
            ]
            .concat();
            let r = Ciphertext::prf(&key, &input, self.expansion_factor);

            let mut z = vec![0u8; self.expansion_factor];
            z[self.expansion_factor - 1] = elem;

            let u = r.mod_add(&z, self.expansion_factor);
            u_strings.push(u.to_hex());
        }

        u_strings.join("")
    }
}

struct Ciphertext(Vec<u8>);

impl Ciphertext {
    fn prf(key: &[u8], input: &[u8], expansion_factor: usize) -> Self {
        let mut okm = vec![0u8; expansion_factor];
        let h = Hkdf::<Sha256>::from_prk(&key).unwrap();
        h.expand(input, &mut okm).unwrap();
        Self(okm.to_vec())
    }

    fn mod_add(&self, rhs: &[u8], expansion_factor: usize) -> Self {
        Ciphertext(add_two_vecs(&self.0, rhs, expansion_factor))
    }

    fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }
}

// Loses the carry bit of the first byte
pub(crate) fn add_two_vecs(lhs: &[u8], rhs: &[u8], length: usize) -> Vec<u8> {
    // Must be same length
    let mut result = vec![0u8; length];
    let mut carry: u16 = 0;
    let mut i = length - 1;
    loop {
        let mut added = (lhs[i] as u16) + (rhs[i] as u16) + carry;
        if added >= 256 {
            added -= 256;
            carry = 1;
        } else {
            carry = 0;
        }
        result[i] = added as u8;

        if i == 0 {
            break;
        }
        i -= 1;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_add_two_vecs() {
        let v1 = [1, 2, 3];
        let v2 = [4, 5, 6];
        assert_eq!(vec![5, 7, 9], add_two_vecs(&v1, &v2, v1.len()));
    }

    #[test]
    fn test_add_two_vecs_overflow() {
        let v1 = [1, 255];
        let v2 = [2, 255];
        assert_eq!(vec![4, 254], add_two_vecs(&v1, &v2, v1.len()));
    }

    #[test]
    fn test_encrypt() {
        let mut rng = OsRng;

        let ope = OrderPreservingEncryption::new(1, 5);

        let key = ope.keygen(&mut rng);
        let c = ope.encrypt(&key, 5);

        // Expect ciphertext length = input length * log_2(M) / log_2(d)
        // Error probability is 1 - d / M
        assert_eq!(c.len() / 2, ope.ciphertext_len_in_bytes());
    }
}
