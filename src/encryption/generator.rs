use num::bigint::ToBigInt;
use num_bigint::{BigInt, BigUint};
use num_integer::lcm;
use num_traits::{One, Zero};
use rand::Rng;

use crate::encryption::rsa::RSAKeys;

/// Can generate pairs of RSA keys
pub struct RSAKeysGenerator {
    key_size: u16
}

impl RSAKeysGenerator {
    /// Create a new generator that will create keys of the specified number of bits
    pub fn new(key_size: u16) -> Self {
        RSAKeysGenerator { key_size }
    }


    /// Faster than just generating keys, but the keys are unchecked and not guaranteed to be valid
    pub unsafe fn generate_keys_unchecked(&self) -> RSAKeys {
        let p = self.generate_prime_number();
        let q = self.generate_prime_number();
        let n = &p * &q;
        let z = lcm(&p - 1usize, &q - 1usize);



        let mut rand = rand::thread_rng();
        let e = loop {
            let random = rand.gen_range(&BigUint::one() + 1usize, &z);
            if num::integer::gcd(random.to_bigint().unwrap(), z.to_bigint().unwrap()) == BigInt::from(1) {
                break random;
            }
        };
        /*
        let mut d = BigUint::one();
        let mut k = e.clone();
        while (&d * &e) % &z != BigUint::one() {
            d = (BigUint::one() + &k * &z) / &e;
            k += BigUint::one();
        }

         */
        let d = modulo_inverse(e.to_bigint().unwrap(), z.to_bigint().unwrap())
            .unwrap()
            .to_biguint()
            .unwrap();
        RSAKeys::new_unchecked(e, d, n)
    }




    pub fn generate_keys(&self) -> RSAKeys {
        let output: RSAKeys = loop {
            unsafe {
                let keys = self.generate_keys_unchecked();
                if keys.valid() {
                    break keys;
                }
            }
        };
        output
    }

    /// Tests a number to see if it is prime. The number is not guaranteed
    /// to be prime. By increasing the k value, the more likely it is to be prime, however.
    ///
    ///
    fn is_prime_probabilistic(number: &BigUint, k: usize) -> bool {
        if number % 2usize == BigUint::zero() {
            return false;
        }
        let mut temp = number - 1usize;
        let mut r = 0;
        while &temp % 2usize == BigUint::zero() {
            temp /= 2usize;
            r += 1usize;
        }
        let d = temp;

        'WitnessLoop:
        for _ in 0..k {
            let mut rand = rand::thread_rng();
            let a = rand
                .gen_range(BigUint::from(2usize), number - BigUint::from(2usize));

            let mut x = a.modpow(&d, number);
            if x == BigUint::from(1usize) || x == number - BigUint::from(1usize) {
                continue 'WitnessLoop;
            }
            for _ in 0..(r - 1) {
                x = x.modpow(&BigUint::from(2usize), number);
                if x == number - BigUint::from(1usize) {
                    continue 'WitnessLoop;
                }
            }
            return false;
        }

        return true;
    }

    #[allow(unused)]
    fn is_prime(number: &BigUint) -> bool {
        let max = number.sqrt();
        for n in num_iter::range_inclusive(BigUint::from(2usize), max) {
            if number % n == BigUint::zero() {
                return false;
            }
        }
        true
    }


    /// Generates a candidate prime number, may not be prime
    fn generate_candidate_prime(&self) -> BigUint {
        let mut random = rand::thread_rng();
        let mut p = BigUint::zero();
        for _ in 0..(self.key_size / 2) {
            let bit =
                if random.gen_bool(0.5) { 1usize } else { 0usize };
            p <<= 1usize;
            p |= BigUint::from(bit);
        }
        p |= (BigUint::from(1usize) << (self.key_size / 2 - 1u16)) | BigUint::one();
        p
    }

    /// Generate a number with high probability it is prime
    fn generate_prime_number(&self) -> BigUint {
        loop {
            let p = self.generate_candidate_prime();
            if Self::is_prime_probabilistic(&p, 128) {
                return p;
            }
        }
    }
}



fn egcd(a: BigInt, b: BigInt, x: &mut BigInt, y: &mut BigInt) -> BigInt {
    if a == 0.into() {
        *x = 0.into();
        *y = 1.into();
        return b;
    }

    let mut x1 = BigInt::zero();
    let mut y1 = BigInt::zero();
    let gcd = egcd(&b % &a, a.clone(), &mut x1, &mut y1);
    *x = y1 - (&b / &a) * &x1;
    *y = x1;

    gcd
}

fn modulo_inverse(a: BigInt, m: BigInt) -> Option<BigInt> {
    let mut x = BigInt::zero();
    let mut y = BigInt::zero();
    let g = egcd(a.clone(), m.clone(), &mut x, &mut y);
    if g != 1.into() {
        None
    } else {
        Some((x % &m + &m) % m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prime_test_accurate() {
        let iterator = (2..6).into_iter().map(|i| 2u16.pow(i));
        for key_size in iterator {
            let generator = RSAKeysGenerator::new(key_size);
            for _ in 0..100 {
                let prime = generator.generate_candidate_prime();
                assert_eq!(RSAKeysGenerator::is_prime_probabilistic(&prime, 128), RSAKeysGenerator::is_prime(&prime));
            }
        }
    }

    #[test]
    fn generate_rsa_keys_big() {
        let iterator = (8..11).into_iter().map(|i| 2u16.pow(i));
        for key_size in iterator {
            let generator = RSAKeysGenerator::new(key_size);
            unsafe {
                let keys = generator.generate_keys_unchecked();
                assert!(keys.valid())
            }
        }
    }



    #[test]
    fn generate_rsa_keys_small() {
        let generator = RSAKeysGenerator::new(5);
        unsafe {
            let keys = generator.generate_keys_unchecked();
            assert!(keys.valid())
        }
    }

    #[test]
    fn inverse_modulo_correct() {
        let a = BigInt::from(3);
        let m = BigInt::from(11);

        assert_eq!(modulo_inverse(a, m), Some(BigInt::from(4)));
    }
}