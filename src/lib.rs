//! Implements order-preserving encryption via an ORE construction followed by a
//! conversion to OPE.
//!
//! An OPE struct is parameterized the variable `expansion_factor`.
//!
//! - Error probability is upper-bounded by: 1 - 2^8 / 2^(expansion_factor * 8)
//! - Ciphertext length is a multiplicative factor larger than input length by expansion_factor
//!
//! This means that:
//! - Increasing `expansion_factor` means more correctness, increased ciphertext length

pub mod errors;

#[cfg(test)]
mod test_vectors;

use crate::errors::OpeError;
use hkdf::Hkdf;
use num_bigint::BigUint;
use rand::{CryptoRng, RngCore};
use sha2::Sha256;
use std::string::String;

pub struct OrderPreservingEncryption {
    /// Number of bytes associated with the modulus M. The larger the expansion
    /// size, the smaller the probability of errors, but the longer the ciphertexts
    /// will be.
    expansion_factor: usize,
}

impl OrderPreservingEncryption {
    // The modulus M = 2 ^ (expansion_factor * 8)
    pub fn new(expansion_factor: usize) -> Self {
        Self { expansion_factor }
    }

    // 1 / failure rate
    // Failure rate is 2 ^ 8 / M
    pub fn inverted_log_failure_rate(&self) -> usize {
        (self.expansion_factor - 1) * 8
    }

    pub fn keygen<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Vec<u8> {
        let mut result = [0u8; 32];
        rng.fill_bytes(&mut result);
        result.to_vec()
    }

    pub fn encrypt(&self, key: &[u8], x: String) -> Result<String, OpeError> {
        let mut u_strings = vec![];
        let x_bytes = blockify_input(x)?;

        if x_bytes.len() >= u8::MAX as usize {
            // Will not handle such large inputs. However, note that this means the
            // input must be at least u8::MAX bytes long, which works for integers
            // in the range of [0, 2^2048 - 1]
            return Err(OpeError::InvalidInputError);
        }

        for (i, &elem) in x_bytes.iter().enumerate() {
            let input = [
                &[i as u8][..],
                &x_bytes[..i],
                &vec![0u8; x_bytes.len() - i][..],
            ]
            .concat();
            let prf_output = Ciphertext::prf(key, &input, self.expansion_factor);

            let mut z = vec![0u8; self.expansion_factor];
            z[self.expansion_factor - 1] = elem;

            let u = prf_output.mod_add(&z, self.expansion_factor);
            u_strings.push(u.to_hex());
        }

        Ok(u_strings.join(""))
    }
}

// Blockify an input number (encoded as a string) by turning
// it into a vector of bytes.
fn blockify_input(input: String) -> Result<Vec<u8>, OpeError> {
    let bytes = match BigUint::parse_bytes(input.as_bytes(), 10) {
        Some(x) => Ok(x.to_bytes_be()),
        None => Err(OpeError::InvalidInputError),
    }?;

    Ok(bytes)
}

struct Ciphertext(Vec<u8>);

impl Ciphertext {
    /// Computes a PRF with a key, an input, and with a specified output size
    fn prf(key: &[u8], input: &[u8], output_size_in_bytes: usize) -> Self {
        let mut okm = vec![0u8; output_size_in_bytes];
        let h = Hkdf::<Sha256>::from_prk(key).unwrap();
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
    fn test_encrypt() -> Result<(), OpeError> {
        let mut rng = rand::thread_rng();

        let ope = OrderPreservingEncryption::new(5);

        let key = ope.keygen(&mut rng);
        let c1 = ope.encrypt(&key, "123456".to_string())?;
        let c2 = ope.encrypt(&key, "123457".to_string())?;

        assert!(c1.to_string() < c2.to_string());

        Ok(())
    }
}
