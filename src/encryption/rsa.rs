use std::error::Error;
use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;
use std::string::FromUtf8Error;

use num_bigint::BigUint;
use rand::{random, Rng};

pub use generator::*;
pub use rsa_stream::*;

use crate::encryption::rsa::RSAMessage::Encrypted;

#[path= "generator.rs"]
mod generator;

#[path="rsa_stream.rs"]
mod rsa_stream;


#[derive(Debug, Clone)]
pub struct RSAKeys {
    public_key: BigUint,
    private_key: BigUint,
    n_value: BigUint
}

#[derive(Debug)]
pub struct InvalidRSAKey;

impl RSAKeys {

    pub fn new<E : Into<BigUint>, D : Into<BigUint>, N : Into<BigUint>>(public: E, private: D, n_value: N) -> Result<Self, InvalidRSAKey> {
        let ret = Self {
            public_key: public.into(),
            private_key: private.into(),
            n_value: n_value.into()
        };
        if ret.valid() {
            Ok(ret)
        } else {
            Err(InvalidRSAKey)
        }
    }

    pub unsafe fn new_unchecked<E : Into<BigUint>, D : Into<BigUint>, N : Into<BigUint>>(public: E, private: D, n_value: N) -> Self {
        Self {
            public_key: public.into(),
            private_key: private.into(),
            n_value: n_value.into()
        }
    }

    pub fn from_strings(e: String, d: String, n_value: String) -> Result<Self, Box<dyn Error>> {
        let public_key: BigUint = e.parse()?;
        let private_key: BigUint = d.parse()?;
        let n_value: BigUint = n_value.parse()?;
        Ok(Self {
            public_key,
            private_key,
            n_value
        })
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            key: self.public_key.clone(),
            n_value: self.n_value.clone()
        }
    }

    pub fn private_key(&self) -> PrivateKey {
        PrivateKey {
            parent: self,
            key: self.private_key.clone(),
            n_value: self.n_value.clone()
        }
    }

    pub fn valid(&self) -> bool {
        let test_message = BigUint::from(2usize);

        let message = RSAMessage::Decrypted(test_message.clone());
        let encrypted = message.encrypt(self.public_key());
        let decrypt = encrypted.decrypt(self.private_key());
        if let RSAMessage::Decrypted(de) = decrypt {
            de == test_message
        } else {
            false
        }
    }

    /// Maximum message size in bytes
    ///
    /// This is computed as the bits of the n value - 11 bytes
    pub fn max_message_size(&self) -> usize {
        let bits = self.n_value.bits();
        ((bits - 11 * 8) / 8) as usize
    }
}
#[derive(Debug, Clone)]
pub struct PublicKey {
    key: BigUint,
    n_value: BigUint
}

impl PublicKey {
    pub fn key(&self) -> &BigUint {
        &self.key
    }
    pub fn n_value(&self) -> &BigUint {
        &self.n_value
    }
    /// Maximum message size in bytes
    ///
    /// This is computed as the bits of the n value - 11 bytes
    pub fn max_message_size(&self) -> usize {
        (self.n_value.bits() - 1) as usize / 8
    }
}

impl <S : AsRef<str>> From<S> for PublicKey {
    /// Format is <n> <e>
    fn from(str: S) -> Self {
        let str = str.as_ref();
        let split = str.trim().split_whitespace().collect::<Vec<&str>>();
        let n: BigUint = split[0].parse().expect("Public Key in incorrect format, couldn't parse n value");
        let e: BigUint = split[1].parse().expect("Public key in incorrect format, couldn't parse e value");
        Self {
            key: e,
            n_value: n
        }
    }
}

impl FromStr for PublicKey {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        std::panic::catch_unwind(|| PublicKey::from(s)).map_err(|_| ())
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "({}, {})", self.n_value, self.key)
    }
}

/// Should only exist while parent structure exist to ensure no information is lost
#[derive(Debug, Clone)]
pub struct PrivateKey<'a> {
    parent: &'a RSAKeys,
    key: BigUint,
    n_value: BigUint
}

impl<'a> PrivateKey<'a> {
    pub fn key(&self) -> &BigUint {
        &self.key
    }
    pub fn n_value(&self) -> &BigUint {
        &self.n_value
    }
    /// Maximum message size in bytes
    ///
    /// This is computed as the bits of the n value - 11 bytes
    pub fn max_message_size(&self) -> usize {
        let bits = self.n_value.bits();
        ((bits - 11 * 8) / 8) as usize
    }
}


#[derive(PartialEq)]
pub enum RSAMessage { Decrypted(BigUint), Encrypted(BigUint) }




impl RSAMessage {

    pub fn from_message<S : AsRef<str>>(message: S) -> Self {
        let string = message.as_ref();
        let bytes = string.as_bytes();
        let big_int = BigUint::from_bytes_be(bytes);
        Self::Decrypted(big_int)
    }

    pub fn from_encrypted<S : AsRef<str>>(message: S) -> Self {
        let string = message.as_ref();
        let big_int = BigUint::from_str(string).unwrap();
        Self::Encrypted(big_int)
    }


    pub fn into_message(self) -> Option<Result<String, FromUtf8Error>> {
        match self {
            RSAMessage::Decrypted(msg) => {
                let bytes = BigUint::to_bytes_be(&msg);

                let string = String::from_utf8(bytes);
                Some(string)

                /*
                Some(match string {
                    Ok(o) => Ok(o),
                    Err(err_utf8) => {
                        let shorts = BigUint::
                        let string_utf16 = String::from_utf16()
                    }
                })

                 */
                //
            },
            RSAMessage::Encrypted(_) => None
        }
    }

    pub fn encrypt(self, public_key: PublicKey) -> Self {
        if let Self::Decrypted(message) = self {
            let n = public_key.n_value();
            let public = public_key.key();
            let encrypted = message.modpow(public, n);
            Self::Encrypted(encrypted)
        } else {
            self
        }
    }

    pub fn decrypt(self, private_key: PrivateKey<'_>) -> Self {
        if let Self::Encrypted(message) = self {
            let decrypted = message.modpow(private_key.key(), private_key.n_value());
            Self::Decrypted(decrypted)
        } else {
            self
        }
    }

    pub fn bytes_be(&self) -> Vec<u8> {
        match self {
            RSAMessage::Decrypted(d) => { d.to_bytes_be() }
            RSAMessage::Encrypted(d) => { d.to_bytes_be() }
        }
    }

    pub fn bytes_le(&self) -> Vec<u8> {
        match self {
            RSAMessage::Decrypted(d) => { d.to_bytes_le() }
            RSAMessage::Encrypted(d) => { d.to_bytes_le() }
        }
    }

    pub fn backing(&self) -> &BigUint {
        match self {
            RSAMessage::Decrypted(d) => { &d }
            RSAMessage::Encrypted(d) => { &d }
        }
    }

}

impl Display for RSAMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            RSAMessage::Decrypted(msg) => {
                let bytes = BigUint::to_bytes_be(msg);
                let str = String::from_utf8(bytes).ok().unwrap();
                write!(f, "{}", str)
            }
            Encrypted(e) => {
                write!(f, "{}", e)
            }
        }


    }
}

impl Debug for RSAMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let big_uint = match self {
            RSAMessage::Decrypted(d) => d,
            Encrypted(e) => e
        };
        let bytes = big_uint.to_bytes_be();
        match self {
            RSAMessage::Decrypted(_) => {
                write!(f, "Decrypted Bytes {:?}", bytes)
            }
            Encrypted(_) => {
                write!(f, "Encrypted Bytes {:?}", bytes)
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::encryption::rsa::RSAMessage::Decrypted;

    use super::*;

    #[test]
    fn encrypt_decrypt_string() {
        let keys = RSAKeys::new(
            BigUint::from_str("17").unwrap(),
            BigUint::from_str("23007684629148646756906525643803260929425988568377712958719677673223911563826959118691305515545947474352193971142705653569147874890271512718698434860942788447256496947873441922015372039914996733878511428986914233147419420896905149158058280986136552454949851658551925020589452550856772097621467137806204489084992764957408463860629019690651589458069671938434887733747737091608095470705059258630275593771332476191727827922616354141874577867737212730336126003942742175181787144146775994305944116564893840272587156238366140638407355907757723904225492447027321140244397255708153961693763533951058901408298379634438092165577").unwrap(),
            BigUint::from_str("27937902763966213919100781138903959700017271833030080021302465746057606898932736072696585268877221933141949822101856865048250990938186836872705242331144814543097174865274893762447237477039638891138192449484110140250437868231956252549070769768880099409581962728241623239287192383183223261397495810193248308174968618714138840723573109458396694728194068030986158066405257458242366433033601600488699894207235016550274240750117371497544517221155770036465087226878852084951029284929839124410295253804622459756950519030977873678384758784363213010850077730441582562331696947775369104249607475967178272053291116626854396933361").unwrap()
        ).unwrap();
        let string = "RSA ENCRYPTION TEST";
        let rsa_message = RSAMessage::from_message(string.clone());
        let encrypted = rsa_message.encrypt(keys.public_key());
        let decrypted = encrypted.decrypt(keys.private_key());
        if let Some(Ok(message)) = decrypted.into_message() {
            assert_eq!(message, string);
        } else {
            panic!("The encrypted messages could not be decrypted");
        }
    }

    #[test]
    fn encrypt_decrypt_number() {
        let keys = RSAKeys::new(
            BigUint::from_str("17").unwrap(),
            BigUint::from_str("23007684629148646756906525643803260929425988568377712958719677673223911563826959118691305515545947474352193971142705653569147874890271512718698434860942788447256496947873441922015372039914996733878511428986914233147419420896905149158058280986136552454949851658551925020589452550856772097621467137806204489084992764957408463860629019690651589458069671938434887733747737091608095470705059258630275593771332476191727827922616354141874577867737212730336126003942742175181787144146775994305944116564893840272587156238366140638407355907757723904225492447027321140244397255708153961693763533951058901408298379634438092165577").unwrap(),
            BigUint::from_str("27937902763966213919100781138903959700017271833030080021302465746057606898932736072696585268877221933141949822101856865048250990938186836872705242331144814543097174865274893762447237477039638891138192449484110140250437868231956252549070769768880099409581962728241623239287192383183223261397495810193248308174968618714138840723573109458396694728194068030986158066405257458242366433033601600488699894207235016550274240750117371497544517221155770036465087226878852084951029284929839124410295253804622459756950519030977873678384758784363213010850077730441582562331696947775369104249607475967178272053291116626854396933361").unwrap()
        ).unwrap();

        let rsa_message = RSAMessage::Decrypted(BigUint::from(12u64));
        let encrypted = rsa_message.encrypt(keys.public_key());
        if let Decrypted(_) = &encrypted {
            panic!("Did not encrypt")
        }
        let decrypted = encrypted.decrypt(keys.private_key());
        assert_eq!(decrypted, RSAMessage::Decrypted(BigUint::from(12u64)));
    }
    #[test]
    fn lifetime() {
        let public_key: PublicKey;
        let private_key: PrivateKey;
        let pair = RSAKeys::new(5u32, 29u32, 35u32).unwrap();
        {
            // let pair = RSAKeys::new(5u32, 29u32, 35u32); /* this test won't compile if this is here */
            public_key = pair.public_key();
            private_key = pair.private_key();
        }
        println!("Public: {:?}, Private: {:?}", public_key, private_key);
    }
}
