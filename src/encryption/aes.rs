use std::error::Error;
use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;

use aes::{Aes128, Aes192, Aes256, BlockCipher, NewBlockCipher};
use aes::cipher::stream::generic_array::GenericArray;
use num::Num;
use num_bigint::{BigUint, ParseBigIntError};
use rand::random;
use aes::cipher::generic_array::functional::FunctionalSequence;

#[path="./aes_stream.rs"]
pub mod aes_stream;

#[derive(Debug, Clone)]
pub enum Key {
    Aes128(Aes128),
    Aes192(Aes192),
    Aes256(Aes256)
}

impl Key {

    pub fn aes128(&self) -> Option<&Aes128> {
        if let Key::Aes128(ret) = self {
            Some(ret)
        } else {
            None
        }
    }

    pub fn aes192(&self) -> Option<&Aes192> {
        if let Key::Aes192(ret) = self {
            Some(ret)
        } else {
            None
        }
    }

    pub fn aes256(&self) -> Option<&Aes256> {
        if let Key::Aes256(ret) = self {
            Some(ret)
        } else {
            None
        }
    }

    pub fn cipher_size(&self) -> KeySize {
        match self {
            Key::Aes128(_) => { KeySize::K128 }
            Key::Aes192(_) => { KeySize::K192 }
            Key::Aes256(_) => { KeySize::K256 }
        }
    }
}

#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum KeySize {
    K128 = 128,
    K192 = 192,
    K256 = 256
}

#[derive(Debug)]
pub struct AESManager {
    key_value: Vec<u8>,
    key: Key
}

impl AESManager {

    pub fn new(key_size: KeySize) -> Self {
        let (key, bytes) = generate_key(key_size);
        Self {
            key_value: bytes,
            key
        }
    }

    pub fn parsable_string(&self) -> String {
        let big_uint =  BigUint::from_bytes_be(&* self.key_value);
        format!("{:x}", big_uint)
    }

    pub fn encrypt<S : AsRef<[u8]>>(&self, message: S) -> Vec<[u8; 16]> {
        let string = message.as_ref();
        let bytes: Vec<u8> = string.to_vec();
        let mut vector = vec![];
        let total = bytes.len() / 16 + if bytes.len() % 16 > 0 { 1 } else { 0 };
        for i in 0..total {
            let mut array = [0u8; 16];
            for j in 0..16 {
                if let Some(byte) = bytes.get(i * 16 + j) {
                    array[j] = *byte;
                }
            }

            match &self.key {
                Key::Aes128(k) => {
                    let mut block = GenericArray::clone_from_slice(&array);
                    k.encrypt_block(&mut block);
                    array.clone_from_slice(block.as_slice());
                }
                Key::Aes192(k) => {
                    let mut block = GenericArray::clone_from_slice(&array);
                    k.encrypt_block(&mut block);
                    array.clone_from_slice(block.as_slice());
                }
                Key::Aes256(k) => {
                    let mut block = GenericArray::clone_from_slice(&array);
                    k.encrypt_block(&mut block);
                    array.clone_from_slice(block.as_slice());
                }
            }
            vector.push(array);
        }
        vector
    }

    pub fn decrypt<V : AsRef<[[u8; 16]]>>(&self, blocks: V) -> Vec<u8> {
        let blocks = blocks.as_ref();
        let mut output = vec![];
        for block in blocks {
            let mut block = GenericArray::clone_from_slice(block);
            match &self.key {
                Key::Aes128(k) => {
                    k.decrypt_block(&mut block);
                }
                Key::Aes192(k) => {
                    k.decrypt_block(&mut block);
                }
                Key::Aes256(k) => {
                    k.decrypt_block(&mut block);
                }
            }
            block.map(|b| output.push(b));
        }
        output
    }
}

#[derive(Debug)]
pub struct AESManagerParseError;

impl Display for AESManagerParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for AESManagerParseError { }

impl From<ParseBigIntError> for AESManagerParseError {
    fn from(_: ParseBigIntError) -> Self {
        AESManagerParseError
    }
}

impl FromStr for AESManager {
    type Err = AESManagerParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let big_uint: BigUint = BigUint::from_str_radix(s, 16)?;
        let bytes = big_uint.to_bytes_be();
        let key = match bytes.len() * 8 {
            128 => {
                Key::Aes128(Aes128::new_varkey(&* bytes).unwrap())
            },
            192 => {
                Key::Aes192(Aes192::new_varkey(&* bytes).unwrap())
            },
            256 => {
                Key::Aes256(Aes256::new_varkey(&* bytes).unwrap())
            },
            _ => {
                return Err(AESManagerParseError)
            }
        };
        Ok(Self {
            key_value: bytes,
            key
        })
    }
}




pub fn generate_key(key_size: KeySize) -> (Key, Vec<u8>) {
    let bits = key_size as u16;
    let mut bytes: Vec<u8> = Vec::with_capacity(bits as usize / 8);

    for _ in 0..(bits / 8) {
        let mut byte = 0u8;
        for _ in 0..8 {
            byte = byte << 1;
            let bit: bool = random();
            byte |= if bit { 1 } else { 0 };
        }
        bytes.push(byte)
    }
    (match key_size {
        KeySize::K128 => {
            Key::Aes128(Aes128::new_varkey(&* bytes).unwrap())
        }
        KeySize::K192 => {
            Key::Aes192(Aes192::new_varkey(&* bytes).unwrap())
        }
        KeySize::K256 => {
            Key::Aes256(Aes256::new_varkey(&* bytes).unwrap())
        }
    },
     bytes)
}


#[cfg(test)]
mod tests {
    use aes::BlockCipher;
    use aes::cipher::block::Block;
    use aes::cipher::stream::generic_array::GenericArray;

    use super::*;

    #[test]
    fn aes_test() {
        let (key, _) = generate_key(KeySize::K192);
        let clone = key.clone();
        let key192 = key.aes192().unwrap();

        let phrase = b"Hello, World!";
        let mut slice = [0u8; 16];
        for (a, b) in phrase.into_iter().zip(&mut slice) {
            *b = *a;
        }
        let mut block: Block<Aes192> = GenericArray::clone_from_slice(&slice);
        println!("Start: {:?}", block);
        key192.encrypt_block(&mut block);
        println!("Encrypted: {:?}", block);
        clone.aes192().unwrap().decrypt_block(&mut block);
        println!("Decrypted: {:?}", block);
        assert_eq!(block.as_slice(), slice);
    }

    #[test]
    fn propagate_key() {
        let key = AESManager::new(KeySize::K192);
        let string = key.parsable_string();
        let key2 = AESManager::from_str(string.as_str()).unwrap();
        let phrase = b"Hello, World!";
        let mut slice = [0u8; 16];
        for (a, b) in phrase.into_iter().zip(&mut slice) {
            *b = *a;
        }
        let mut block: Block<Aes192> = GenericArray::clone_from_slice(&slice);
        key.key.aes192().unwrap().encrypt_block(&mut block);
        key2.key.aes192().unwrap().decrypt_block(&mut block);
        assert_eq!(block.as_slice(), slice);
    }
}