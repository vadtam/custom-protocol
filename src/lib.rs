#![allow(
    dead_code,
    // unused_variables,
)]

use std::net::{UdpSocket, SocketAddr};
use std::time::{Instant, Duration};
use aes_gcm::{Aes256Gcm, Key, Nonce}; // Encryption for secure communication
use aes_gcm::aead::Aead;
use aes_gcm::KeyInit;
use std::sync::Arc;


// Custom protocol structure
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
        let start = Instant::now();

        // Encrypt data for secure transfer
        let nonce = Nonce::from_slice(b"unique_nonce"); // In production, use unique nonce per message
        let encrypted_data = self.encryption.encrypt(nonce, data).expect("Encryption failed");

        if self.latency_reduction {
            // Mock latency reduction optimization (e.g., reduced retransmission, batch sending)
            self.peer_socket.send_to(&encrypted_data, self.peer_addr).expect("Failed to send data");
        } else {
            // Standard transmission for comparison
            self.peer_socket.send_to(data, self.peer_addr).expect("Failed to send data");
        }

        let duration = Instant::now() - start;
        println!("Data sent in {:?} with {} encryption", duration, if self.latency_reduction { "optimized" } else { "standard" });
    }

    // Method to receive data
    fn receive_data(&self) -> Vec<u8> {
        let mut buffer = [0; Self::BUFFER_SIZE];
        let (amt, _src) = self.peer_socket.recv_from(&mut buffer).expect("Failed to receive data");

        // Decrypt data
        let nonce = Nonce::from_slice(b"unique_nonce"); // Match nonce used during encryption
        self.encryption.decrypt(nonce, &buffer[..amt]).expect("Decryption failed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let protocol = CustomProtocol::new("127.0.0.1:8082", true);
        let data = "Hello, secure peer-to-peer world!";
        protocol.send_data(data.as_bytes());
        let received_data = protocol.receive_data();
        assert_eq!(data, std::str::from_utf8(&received_data).unwrap());
    }
}
