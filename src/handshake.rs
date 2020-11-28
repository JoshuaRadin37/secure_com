use crate::encryption::aes::{AESManager, KeySize};
use std::io::{Write, Read};
use crate::encryption::aes::aes_stream::{AESWriter, AESReader};
use crate::encryption::generate_nonce;

use crate::encryption::{unsecure, secure};
use std::error::Error;
use crate::encryption::rsa::{RSAWriter, RSAKeys, RSAKeysGenerator, RSAReader};
use crate::encryption::unsecure::{send_public_key, receive_public_key, handshake_start};
use crate::encryption::secure::{receive_and_repeat, encryption_successful, begin_aes_encryption_client, client_repeat_correct, get_aes_key};

pub fn client_handshake<W: Write, R: Read>(mut writer: W, mut reader: R)
                                           -> Result<AESManager, Box<dyn Error>> {
    let first_nonce = generate_nonce(4);
    unsecure::handshake_start(&first_nonce, &mut writer)?;
    if !unsecure::receive_ack(&first_nonce, &mut reader)? {
        Err("Did not receive correct acknowlegement from server")?
    }


    let aes_manager = AESManager::new(KeySize::K256);
    { // RSA segment
        let key = RSAKeysGenerator::new(512).generate_keys();
        send_public_key(key.public_key(), &mut writer)?;
        let server_public_key = receive_public_key(&mut reader)?;

        let mut rsa_writer = RSAWriter::new(server_public_key, &mut writer);
        let mut rsa_reader = RSAReader::new(key.private_key(), &mut reader);

        let second_nonce = generate_nonce(16);
        secure::handshake_start(&second_nonce, &mut rsa_writer)?;
        receive_and_repeat(&second_nonce, &mut rsa_writer, &mut rsa_reader)?;

        if !encryption_successful(&mut rsa_reader)? {
            Err("Encrypted connection was not established")?
        }

        begin_aes_encryption_client(&aes_manager, &mut rsa_writer)?;
    };

    Ok(aes_manager)
}

pub fn server_handshake<'a, W: Write, R: Read>(mut writer: W, mut reader: R)
                                               -> Result<AESManager, Box<dyn Error>> {
    //let first_nonce = generate_nonce(4);
    unsecure::server_ack(&mut writer, &mut reader)?;

    let key = RSAKeysGenerator::new(512).generate_keys();
    let client_key = receive_public_key(&mut reader)?;
    send_public_key(key.public_key(), &mut writer)?;

    let mut rsa_writer = RSAWriter::new(client_key, &mut writer);
    let mut rsa_reader = RSAReader::new(key.private_key(), &mut reader);

    let nonce = generate_nonce(16);
    secure::server_ack(&nonce, &mut rsa_writer, &mut rsa_reader)?;
    if !client_repeat_correct(&nonce, &mut rsa_writer, &mut rsa_reader)? {
        Err("Client did not repeat correct nonce")?;
    }
    writeln!(rsa_writer, "SUCCESS")?;
    get_aes_key(&mut rsa_reader)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use crate::multi_file_stream::MultiFileReadWrite;
    use std::net::{TcpStream, TcpListener, SocketAddr};


    #[test]
    fn handshake_succeeds() {

        let client_thread = std::thread::spawn(||
            {
                let tcp_stream = TcpStream::connect("127.0.0.1:8000").unwrap();
                let multi = MultiFileReadWrite::new(tcp_stream);
                client_handshake(multi.clone(), multi).unwrap()
            }
        );
        let server_thread = std::thread::spawn( ||
            {
                let tcp_listener = TcpListener::bind("127.0.0.1:8000").unwrap();
                let tcp_stream = tcp_listener.accept().unwrap().0;
                let multi = MultiFileReadWrite::new(tcp_stream);
                server_handshake(multi.clone(), multi).unwrap()
            }
        );


        let server_key = server_thread.join().unwrap();
        let client_key = client_thread.join().unwrap();

        assert_eq!(client_key, server_key, "Handshake failed to create matching AES keys");

    }
}