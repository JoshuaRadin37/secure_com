use crate::encryption::rsa::{PrivateKey, RSAMessage, PublicKey};
use std::io::{Read, BufReader, BufRead, Write};
use std::collections::VecDeque;
use num_bigint::BigUint;
use std::cell::RefCell;

pub struct RSAReader<'a, R>
    where R : Read
{
    private_key: PrivateKey<'a>,
    reader: RefCell<R>,
    buffer: VecDeque<u8>
}

impl<'a, R> RSAReader<'a, R> where R : Read {
    pub fn new(private_key: PrivateKey<'a>, reader: R) -> Self {
        RSAReader { private_key, reader: RefCell::new(reader), buffer: VecDeque::new() }
    }
}

impl<'a, R> Read for RSAReader<'a, R> where R : Read {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut ref_mut = self.reader.borrow_mut();
        let mut buffered_reader = BufReader::new(ref_mut.by_ref());

        let mut line = String::new();
        while buffered_reader.read_line(&mut line)? != 0 {
            let rsa_message = RSAMessage::from_encrypted(line.trim());
            let decrypted = rsa_message.decrypt(self.private_key.clone());
            if let RSAMessage::Decrypted(big) = decrypted {
                let bytes = big.to_bytes_be();
                for byte in bytes {
                    self.buffer.push_back(byte)
                }
            } else {
                unreachable!()
            }
            line.clear();
        }

        let mut index = 0;
        while index < buf.len() && self.buffer.len() > 0 {
            buf[index] = self.buffer.pop_front().unwrap();
            index += 1;
        }

        return Ok(index);
    }
}

pub struct RSAWriter<W>
where W : Write
{
    public_key: PublicKey,
    writer: W
}

impl<W> RSAWriter<W>
    where W : Write {
    pub fn new(public_key: PublicKey, writer: W) -> Self {
        RSAWriter { public_key, writer }
    }
}

impl <W> Write for RSAWriter<W> where W : Write {
    /// Writes the a message, split into multiple parts if required
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let max_bytes = self.public_key.max_message_size();
        let mut index = 0;
        let mut bytes = Vec::new();
        while index < buf.len() && index < max_bytes {
            let byte = buf[index];
            index += 1;
            bytes.push(byte);
        }
        let big_uint = BigUint::from_bytes_be(bytes.as_ref());
        let encrypted = RSAMessage::Decrypted(big_uint).encrypt(self.public_key.clone());
        let big_uint = encrypted.backing();
        writeln!(self.writer, "{}", big_uint)?;
        Ok(index)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        (&mut self.writer).flush()
    }
}

#[cfg(test)]
mod tests {
    use crate::encryption::rsa::{RSAKeysGenerator, RSAWriter, RSAReader};
    use std::io::{BufWriter, Cursor, Write, BufReader, Read};

    #[test]
    fn read_and_write_small() {
        let keys = RSAKeysGenerator::new(32).generate_keys();
        let mut inner: Vec<u8> = Vec::new();
        {
            let mut writer = RSAWriter::new(keys.public_key(), &mut inner);
            write!(writer, "Hello, World!").unwrap();
        }
        {
            let mut reader = RSAReader::new(keys.private_key(), &*inner);
            let mut buf_reader = BufReader::new(reader);
            let mut all = Vec::new();
            buf_reader.read_to_end(&mut all).unwrap();
            let string = String::from_utf8(all).unwrap();
            assert_eq!(string, "Hello, World!");
        }

    }
}

