use std::io::{Read, Write};
use crate::encryption::aes::AESManager;
use std::collections::VecDeque;

pub struct AESReader<'a, R : Read> {
    key_manager: &'a AESManager,
    inner: R,
    internal_buffer: VecDeque<u8>
}

impl<'a, R: Read> AESReader<'a, R> {
    pub fn new(key_manager: &'a AESManager, inner: R) -> Self {
        AESReader { key_manager, inner, internal_buffer: VecDeque::new() }
    }
}

impl<R : Read> Read for AESReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut internal_buffer = [0u8; 16];
        if self.inner.read(&mut internal_buffer)? == 0 {
            return Ok(0)
        }
        let bytes = self.key_manager.decrypt([internal_buffer]);
        for byte in bytes {
            self.internal_buffer.push_back(byte);
        }
        let mut index = 0;
        while index < buf.len() && !self.internal_buffer.is_empty() {
            let byte = self.internal_buffer.pop_front().unwrap();
            if byte == 0 {
                break;
            }
            buf[index] = byte;
            index += 1;
        }
        Ok(index)
    }
}

pub struct AESWriter<'a, W : Write> {
    key_manager: &'a AESManager,
    inner: W,
}

impl<'a, W: Write> AESWriter<'a, W> {
    pub fn new(key_manager: &'a AESManager, inner: W) -> Self {
        AESWriter { key_manager, inner }
    }
}

impl <W : Write> Write for AESWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let encrypted = self.key_manager.encrypt(buf);
        for block in &encrypted {
            self.inner.write_all(block)?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }


}

#[cfg(test)]
mod tests {
    use crate::encryption::aes::{AESManager, KeySize};
    use std::string::FromUtf8Error;
    use super::*;

    const TEST_MESSAGE: &str = "Hello World";

    #[test]
    fn read_and_write_128() {
        let key = AESManager::new(KeySize::K128);
        let mut array: Vec<u8> = Vec::new();
        {
            let mut writer = AESWriter::new(&key, &mut array);
            write!(writer, "{}", TEST_MESSAGE).unwrap();
        }
        match String::from_utf8(array.clone()) {
            Ok(o) => {
                assert_ne!(o, TEST_MESSAGE)
            }
            Err(_) => {}
        }
        let mut reader = AESReader::new(&key, &*array);
        let mut string = [0u8; 32];
        let length = reader.read(&mut string).unwrap();
        let string = String::from_utf8(
            Vec::from(
                &string[..length]
            )
        ).unwrap();
        assert_eq!(string, TEST_MESSAGE);

    }
}