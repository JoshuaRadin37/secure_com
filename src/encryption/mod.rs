//! This module handles the encryption aspect of the communications between clients
//! Connections will be established using asymmetric encryption, then continued using using
//! symmetric encryption
use std::error::Error;
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::str::FromStr;

use rand::random;

use crate::encryption::aes::aes_stream::{AESReader, AESWriter};
use crate::encryption::aes::AESManager;
use crate::encryption::rsa::{RSAReader, RSAWriter};
pub mod rsa;

pub mod aes;


/// Creates a nonce with `nonce_size` amount of bytes to create a number
pub fn generate_nonce(nonce_size: usize) -> String {
    let mut ret = String::new();
    for _ in 0..nonce_size {
        let byte: u8 = random();
        ret = format!("{}{}", ret, byte);
    }
    ret
}

pub mod unsecure {
    use super::*;
    use crate::encryption::rsa::PublicKey;

    static HANDSHAKE_START_PHRASE: &str = "COM_BEGIN";


    /// Client begins a handshake
    pub fn handshake_start<W : Write>(start_nonce: &String, writer: &mut W) -> std::io::Result<()> {
        writeln!(writer, "{} {}", HANDSHAKE_START_PHRASE, start_nonce)
    }

    /// Server acknowledges handshake and responds with nonce
    pub fn server_ack<W: Write, R: Read>(writer: &mut W, reader: &mut R) -> std::io::Result<()> {
        let mut buf_reader = BufReader::new(reader);
        let mut line = String::new();
        buf_reader.read_line(&mut line)?;
        let split: Vec<&str> = line.split_whitespace().collect();
        if split[0] == HANDSHAKE_START_PHRASE {
            writeln!(writer, "{}", split[1])
        } else {
            Ok(())
        }
    }

    /// Client confirms server responded with nonce
    pub fn receive_ack<R : Read>(start_nonce: &String, reader: &mut R) -> std::io::Result<bool> {
        let mut buf_reader = BufReader::new(reader);
        let mut line = String::new();
        buf_reader.read_line(&mut line)?;
        println!("Received {}, looking for {}", line.trim(), start_nonce);
        Ok(line.trim() == start_nonce)
    }

    /// Sends public key
    pub fn send_public_key<W : Write>(key: PublicKey, writer: &mut W) -> std::io::Result<()> {
        writeln!(writer, "RSA:{}", key)
    }

    /// Receive public key
    pub fn receive_public_key<R : Read>(reader: &mut R) -> Result<PublicKey, Box<dyn Error>> {
        let mut buf_reader = BufReader::new(reader);
        let mut line = String::new();
        buf_reader.read_line(&mut line)?;

        let split: Vec<&str> = line.trim().split(":").collect();
        if split[0] != "RSA" {
            Err("Incorrect AES key format from client")?;
        }
        let public_key_string = split[1];
        PublicKey::from_str(public_key_string).map_err(|e| Box::new(e) as Box<dyn Error>)
    }
}


pub mod secure {
    use super::*;

    static SECRET_HANDSHAKE_START_PHRASE: &str = "SECOP_BEGIN";

    /// Client
    pub fn handshake_start<W: Write>(my_nonce: &String, writer: &mut RSAWriter<W>) -> std::io::Result<()> {
        writeln!(writer, "{} {}", SECRET_HANDSHAKE_START_PHRASE, my_nonce)
    }

    /// Server
    pub fn server_ack<W: Write, R: Read>(server_nonce: &String, writer: &mut RSAWriter<W>, reader: &mut RSAReader<R>) -> std::io::Result<bool> {
        let mut buf_reader = BufReader::new(reader);
        let mut line = String::new();
        buf_reader.read_line(&mut line)?;
        let split: Vec<&str> = line.split_whitespace().collect();
        if split[0] != SECRET_HANDSHAKE_START_PHRASE {
            return Ok(false);
        }
        let client_nonce = split[1];
        writeln!(writer, "{} {}", client_nonce, server_nonce).map(|_| true)
    }

    /// Client
    pub fn receive_and_repeat<W: Write, R: Read>(my_nonce: &String, writer: &mut RSAWriter<W>, reader: &mut RSAReader<R>) -> Result<(), Box<dyn Error>> {
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

    /// Server
    pub fn client_repeat_correct<W: Write, R: Read>(server_nonce: &String, writer: &mut RSAWriter<W>, reader: &mut RSAReader<R>) -> std::io::Result<bool> {
        let mut buf_reader = BufReader::new(reader);
        let mut line = String::new();
        buf_reader.read_line(&mut line)?;
        let server_nonce_recv = line.trim();
        Ok(server_nonce == server_nonce_recv)
    }


    /// Client
    pub fn encryption_successful<R: Read>(reader: &mut RSAReader<R>) -> std::io::Result<bool> {
        let mut buf_reader = BufReader::new(reader);
        let mut line = String::new();
        buf_reader.read_line(&mut line)?;
        match &*line.trim() {
            "SUCCESS" => Ok(true),
            _ => Ok(false)
        }
    }

    /// Client
    pub fn begin_aes_encryption_client<W : Write>(manager: &AESManager, rsa_writer: &mut RSAWriter<W>)
                                                                          -> std::io::Result<()> {
        write!(rsa_writer, "AES_KEY:{}", manager.parsable_string())
    }

    /// Server
    pub fn get_aes_key<R: Read>(rsa_reader: &mut RSAReader<R>)
                                                     -> Result<AESManager, Box<dyn Error>> {
        let mut buf_reader = BufReader::new(rsa_reader);
        let mut line = String::new();
        buf_reader.read_line(&mut line)?;
        let split: Vec<&str> = line.trim().split(":").collect();
        if split[0] != "AES_KEY" {
            Err("Incorrect AES key format from client")?;
        }
        AESManager::from_str(split[1].as_ref()).map_err(|e| Box::new(e) as Box<dyn Error>)
    }
}

