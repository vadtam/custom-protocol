#![allow(
    dead_code,
)]

use std::net::TcpStream;
use std::io::{Read, Write};
use aes_gcm::aead::generic_array::{GenericArray, typenum::U12};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::Aead;
use aes_gcm::KeyInit;
use std::sync::Arc;
use serde::{Serialize, Deserialize};
use rand::Rng;


#[derive(Serialize, Deserialize)]
struct Payload {
    nonce_precursor: u64,
    encrypted_data: Vec<u8>, // bytes
}

impl Payload {
    fn from(data: &[u8], protocol: &CustomProtocol) -> Payload {
        let mut rng = rand::thread_rng();
        let nonce_precursor = rng.gen::<u64>();
        let nonce = Payload::get_nonce(nonce_precursor);
        let encrypted_data = protocol.encryption.encrypt(&nonce, data).expect("Encryption failed");
        Payload {
            nonce_precursor,
            encrypted_data,
        }
    }

    fn get_nonce(nonce_precursor: u64) -> GenericArray<u8, U12> {
        let mut nonce_precursor_bytes = [0u8; 12];
        nonce_precursor_bytes[..8].copy_from_slice(&nonce_precursor.to_be_bytes());
        Nonce::from_slice(&nonce_precursor_bytes).to_owned()
    }
}

/// Custom protocol structure
struct CustomProtocol {
    latency_reduction: bool,
    encryption: Arc<Aes256Gcm>,
}

impl CustomProtocol {
    const BUFFER_SIZE: usize = 1024;
    const ENCRYPTION_KEY: &[u8; 32] = b"exampleKey012345abcde012345abcde";

    // Initialize protocol with optional latency reduction
    fn new(latency_reduction: bool) -> Self {
        let key: &Key<Aes256Gcm> = Key::<Aes256Gcm>::from_slice(Self::ENCRYPTION_KEY);
        let encryption = Aes256Gcm::new(key);
        CustomProtocol {
            latency_reduction,
            encryption: Arc::new(encryption),
        }
    }

    // Method to send encrypted data over TCP
    fn send_data(&self, stream: &mut TcpStream, data: &[u8]) {
        let payload = Payload::from(data, self);
        let serialized_payload = bincode::serialize(&payload).expect("Failed to serialize message");

        if self.latency_reduction {
            // Mock latency reduction (e.g., batch sending)
            stream.write_all(&serialized_payload).expect("Failed to send data");
        } else {
            stream.write_all(&serialized_payload).expect("Failed to send data");
        }
    }

    // Method to receive data over TCP
    fn receive_data(&self, stream: &mut TcpStream) -> Vec<u8> {
        let mut buffer = [0; Self::BUFFER_SIZE];
        let amt = stream.read(&mut buffer).expect("Failed to receive data");
        let payload: Payload = bincode::deserialize(&buffer[..amt]).expect("Failed to deserialize message");
        let nonce = Payload::get_nonce(payload.nonce_precursor);
        self.encryption.decrypt(&nonce, &payload.encrypted_data[..]).expect("Decryption failed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::net::TcpListener;

    #[test]
    fn tcp_test() {
        // Create a listener in a separate thread to simulate server behavior
        let listener_thread = thread::spawn(|| {
            let listener = TcpListener::bind("127.0.0.1:8082").expect("Could not bind");
            let (mut stream, _addr) = listener.accept().expect("Failed to accept connection");

            let protocol = CustomProtocol::new(true);
            let received_data = protocol.receive_data(&mut stream);
            assert_eq!("Hello, secure peer-to-peer world!", std::str::from_utf8(&received_data).unwrap());
        });

        // Create a client to simulate sending data
        let client_thread = thread::spawn(|| {
            let mut stream = TcpStream::connect("127.0.0.1:8082").expect("Failed to connect");
            let protocol = CustomProtocol::new(true);
            let data = "Hello, secure peer-to-peer world!";
            protocol.send_data(&mut stream, data.as_bytes());
        });

        listener_thread.join().expect("Listener thread failed");
        client_thread.join().expect("Client thread failed");
    }
}
