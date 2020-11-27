use rand::random;
use std::io::{BufWriter, Write, Read, BufReader, BufRead};
use crate::encryption::aes::aes_stream::{AESWriter, AESReader};
use std::error::Error;
use crate::encryption::aes::AESManager;
use std::str::FromStr;
use crate::encryption::rsa::{RSAReader, RSAWriter};

pub mod encryption;

/// Creates a nonce with `nonce_size` amount of bytes to create a number
pub fn generate_nonce(nonce_size: usize) -> String {
    let mut ret = String::new();
    for _ in 0..nonce_size {
        let byte: u8 = random();
        ret = format!("{}{}", ret, byte);
    }
    ret
}

pub static HANDSHAKE_START_PHRASE: &str = "SECOP_BEGIN";

/// Client
pub fn handshake_start<W : Write>(my_nonce: &String, writer: &mut RSAWriter<W>) -> std::io::Result<()> {
    writeln!(writer, "{} {}", HANDSHAKE_START_PHRASE, my_nonce)
}

/// Client
pub fn receive_and_repeat<W : Write, R : Read>(my_nonce: &String, writer: &mut RSAWriter<W>, reader: &mut RSAReader<R>) -> Result<(), Box<dyn Error>> {
    let server_nonce = {
        let mut buf_reader = BufReader::new(reader);
        let mut line = String::new();
        buf_reader.read_line(&mut line)?;
        let mut split = line.split_whitespace();
        let my_nonce_recv = split.next().ok_or("Did not receive proper response")?;
        if my_nonce != my_nonce_recv {
            Err("Received nonce from server incorrect")?
        }
        split.next().ok_or("Did not receive the server's nonce")?.to_string()
    };
    writeln!(writer, "{}", server_nonce)?;
    Ok(())
}


/// Client
pub fn encryption_successful<R : Read>(reader: &mut RSAReader<R>) -> std::io::Result<bool> {
    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();
    buf_reader.read_line(&mut line)?;
    match &*line.trim() {
        "SUCCESS" => Ok(true),
        _ => Ok(false)
    }
}

/// Client
pub fn begin_aes_encryption_client<'a, R : Read, W1 : Write, W2: Write>(manager: &'a AESManager, rsa_writer: &mut RSAWriter<W1>, reader : R, writer: W2)
                                                                        -> Result<(AESReader<'a, R>, AESWriter<'a, W2>), Box<dyn Error>> {
    write!(rsa_writer, "AES_KEY:{}", manager.parsable_string())?;
    Ok((AESReader::new(manager, reader), AESWriter::new(manager, writer)))
}

/// Server
pub fn get_aes_key<R : Read, W : Write, R2 : Write>(rsa_reader: &mut RSAReader<R>)
                                                                     -> Result<AESManager, Box<dyn Error>> {
    let mut buf_reader = BufReader::new(rsa_reader);
    let mut line = String::new();
    buf_reader.read_line(&mut line)?;
    let split: Vec<&str> = line.split_whitespace().collect();
    if split[0] != "AES_KEY" {
        Err("Incorrect AES key format from client")?;
    }
    AESManager::from_str(split[1].as_ref()).map_err(|e| Box::new(e) as Box<dyn Error>)
}