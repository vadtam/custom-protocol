#![allow(
    dead_code,
)]

use std::net::{UdpSocket, SocketAddr};
use std::time::Duration;
use aes_gcm::aead::generic_array::{GenericArray, typenum::U12};
use aes_gcm::{Aes256Gcm, Key, Nonce}; // Encryption for secure communication
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
        let mut nonce_precursor_bytes = [0u8; 12]; // Initialize a 12-byte array
        nonce_precursor_bytes[..8].copy_from_slice(&nonce_precursor.to_be_bytes());
        Nonce::from_slice(&nonce_precursor_bytes).to_owned()
    }
}


/// Custom protocol structure
//#[derive(Debug)]
struct CustomProtocol {
    latency_reduction: bool,
    peer_addr: SocketAddr,
    peer_socket: UdpSocket,
    encryption: Arc<Aes256Gcm>,
}

impl CustomProtocol {
    // Constants for optimization and encryption setup    
    const BUFFER_SIZE: usize = 1024;
    const ENCRYPTION_KEY: &[u8; 32] = b"exampleKey012345abcde012345abcde";  // NB: key length must be 32

    // Initialize protocol with optional latency reduction
    fn new(peer_addr: &str, latency_reduction: bool) -> Self {
        let key: &Key<Aes256Gcm> = Key::<Aes256Gcm>::from_slice(Self::ENCRYPTION_KEY);
        let encryption = Aes256Gcm::new(key);
        let peer_addr: SocketAddr = peer_addr.parse().expect("Invalid peer address");
        let peer_socket = UdpSocket::bind(peer_addr).expect("Couldn't bind to address");
        peer_socket.set_read_timeout(Some(Duration::from_secs(1))).expect("Failed to set timeout");
        CustomProtocol {
            latency_reduction,
            peer_addr,
            peer_socket,
            encryption: Arc::new(encryption),
        }
    }

    // Method to send encrypted data, simulating lower latency and secure communication
    fn send_data(&self, data: &[u8]) {
        // Encrypt data for secure transfer
        let payload = Payload::from(data, self);
        let serialized_payload = bincode::serialize(&payload).expect("Failed to serialize message");

        if self.latency_reduction {
            // Mock latency reduction optimization (e.g., reduced retransmission, batch sending)
            self.peer_socket.send_to(&serialized_payload, self.peer_addr).expect("Failed to send data");
        } else {
            // Standard transmission for comparison
            self.peer_socket.send_to(&serialized_payload, self.peer_addr).expect("Failed to send data");
        }
    }

    // Method to receive data
    fn receive_data(&self) -> Vec<u8> {
        let mut buffer = [0; Self::BUFFER_SIZE];
        let (amt, _src) = self.peer_socket.recv_from(&mut buffer).expect("Failed to receive data");
        let payload:Payload = bincode::deserialize(&buffer[..amt]).unwrap();
        let nonce = Payload::get_nonce(payload.nonce_precursor);
        self.encryption.decrypt(&nonce, &payload.encrypted_data[..]).expect("Decryption failed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_test() {
        let protocol = CustomProtocol::new("127.0.0.1:8082", true);
        let data = "Hello, secure peer-to-peer world!";
        protocol.send_data(data.as_bytes());
        let received_data = protocol.receive_data();
        assert_eq!(data, std::str::from_utf8(&received_data).unwrap());
    }
}
