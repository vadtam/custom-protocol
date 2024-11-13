#![allow(dead_code)]

use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use aes_gcm::aead::generic_array::{GenericArray, typenum::U12};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, Error as AeadError};
use aes_gcm::KeyInit;
use std::sync::Arc;
use serde::{Serialize, Deserialize};
use rand::Rng;
use thiserror::Error;
use log::{error, info};
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicU64, Ordering};
use x25519_dalek::{EphemeralSecret, PublicKey as DhPublicKey};

struct LatencyTracker {
    latencies: VecDeque<Duration>,
    max_samples: usize,
}

impl LatencyTracker {
    fn new(max_samples: usize) -> Self {
        Self {
            latencies: VecDeque::with_capacity(max_samples),
            max_samples,
        }
    }

    fn add_sample(&mut self, duration: Duration) {
        if self.latencies.len() == self.max_samples {
            self.latencies.pop_front();
        }
        self.latencies.push_back(duration);
    }

    fn average_latency(&self) -> Option<Duration> {
        if self.latencies.is_empty() {
            None
        } else {
            Some(self.latencies.iter().copied().sum::<Duration>() / self.latencies.len() as u32)
        }
    }
}


#[derive(Serialize, Deserialize)]
struct Payload {
    version: u8,
    nonce_precursor: u64,
    encrypted_data: Vec<u8>, // bytes
}

impl Payload {
    const CURRENT_VERSION: u8 = 1;

    fn from(data: &[u8], protocol: &CustomProtocol, encryption: &Arc<Aes256Gcm>) -> Result<Payload, CustomProtocolError> {
        let nonce_precursor = protocol.nonce_counter.fetch_add(1, Ordering::Relaxed);
        let nonce = Payload::get_nonce(nonce_precursor);
        let encrypted_data = encryption.encrypt(&nonce, data)
            .map_err(CustomProtocolError::EncryptionFailed)?;
        Ok(Payload {
            version: Payload::CURRENT_VERSION,
            nonce_precursor,
            encrypted_data,
        })
    }

    fn get_nonce(nonce_precursor: u64) -> GenericArray<u8, U12> {
        let mut nonce_precursor_bytes = [0u8; 12];
        nonce_precursor_bytes[..8].copy_from_slice(&nonce_precursor.to_be_bytes());
        Nonce::from_slice(&nonce_precursor_bytes).to_owned()
    }
}

#[derive(Error, Debug)]
enum CustomProtocolError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(AeadError),
    #[error("I/O error occurred: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] bincode::Error),
    #[error("Handshake error")]
    HandshakeError,
}

/// Custom protocol structure
struct CustomProtocol {
    nonce_counter: AtomicU64,
    latency_reduction: bool,
    // encryption: Arc<Aes256Gcm>,
}

impl CustomProtocol {
    const BUFFER_SIZE: usize = 1024;
    //const ENCRYPTION_KEY: &[u8; 32] = b"exampleKey012345abcde012345abcde";

    // Initialize protocol with optional latency reduction
    fn new(latency_reduction: bool) -> Self {
        //let key: &Key<Aes256Gcm> = Key::<Aes256Gcm>::from_slice(Self::ENCRYPTION_KEY);
        //let encryption = Aes256Gcm::new(key);
        let mut rng = rand::thread_rng();
        let nonce_counter_start_value = rng.gen::<u64>();
        CustomProtocol {
            nonce_counter: AtomicU64::new(nonce_counter_start_value),
            latency_reduction,
           // encryption: Arc::new(encryption),
        }
    }

    async fn handshake(stream: &mut TcpStream) -> Result<Arc<Aes256Gcm>, CustomProtocolError> {
        // Generate ephemeral DH key pair
        let rng = rand::thread_rng();
        let private_key = EphemeralSecret::random_from_rng(rng);
        let public_key = DhPublicKey::from(&private_key);

        // Send public key to the peer
        stream.write_all(public_key.as_bytes()).await?;

        // Receive peer's public key
        let mut peer_public_key_bytes = [0u8; 32];
        stream.read_exact(&mut peer_public_key_bytes).await?;
        let peer_public_key = DhPublicKey::from(peer_public_key_bytes);

        // Calculate shared secret
        let shared_secret = private_key.diffie_hellman(&peer_public_key);
        let session_key = Key::<Aes256Gcm>::from_slice(&shared_secret.as_bytes()[..32]);
        let encryption = Aes256Gcm::new(session_key);

        Ok(Arc::new(encryption))
    }

    // Asynchronous method to send encrypted data over TCP
    async fn send_data(&self, stream: &mut TcpStream, data: &[u8]) -> Result<(), CustomProtocolError> {
        let encryption = CustomProtocol::handshake(stream).await.unwrap();
        let payload = Payload::from(data, self, &encryption)?;
        let serialized_payload = bincode::serialize(&payload)?;

        if self.latency_reduction {
            info!("Sending data with latency reduction.");
            stream.write_all(&serialized_payload).await?;
        } else {
            info!("Sending data without latency reduction.");
            stream.write_all(&serialized_payload).await?;
        }

        Ok(())
    }

    // Asynchronous method to receive data over TCP
    async fn receive_data(&self, stream: &mut TcpStream) -> Result<Vec<u8>, CustomProtocolError> {
        let encryption = CustomProtocol::handshake(stream).await.unwrap();
        let mut buffer = [0; Self::BUFFER_SIZE];
        let amt = stream.read(&mut buffer).await?;
        let payload: Payload = bincode::deserialize(&buffer[..amt])?;
        let nonce = Payload::get_nonce(payload.nonce_precursor);
        let decrypted_data = encryption.decrypt(&nonce, &*payload.encrypted_data)
            .map_err(CustomProtocolError::EncryptionFailed)?;
        Ok(decrypted_data)
    }

    async fn send_data_with_latency(&self, stream: &mut TcpStream, data: &[u8], tracker: &mut LatencyTracker) -> Result<(), CustomProtocolError> {
        let start_time = Instant::now();
        self.send_data(stream, data).await?;
        let elapsed_time = start_time.elapsed();
        tracker.add_sample(elapsed_time);
        info!("Data sent in {:?}", elapsed_time);
        Ok(())
    }

    fn packet_loss_rate(&self, sent_packets: usize, acked_packets: usize) -> f64 {
        if sent_packets == 0 {
            0.0
        } else {
            (sent_packets - acked_packets) as f64 / sent_packets as f64 * 100.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use tokio::task;
    
    #[tokio::test]
    async fn tcp_test() {
        // Initialize logging for testing
        env_logger::init();

        // Spawn a listener task to simulate server behavior
        let listener_task = task::spawn(async {
            let listener = TcpListener::bind("127.0.0.1:8082").await.expect("Could not bind");
            let (mut stream, _addr) = listener.accept().await.expect("Failed to accept connection");

            let protocol = CustomProtocol::new(true);
            match protocol.receive_data(&mut stream).await {
                Ok(received_data) => {
                    assert_eq!("Hello, secure peer-to-peer world!", std::str::from_utf8(&received_data).unwrap());
                },
                Err(e) => error!("Failed to receive data: {}", e),
            }
        });

        // Spawn a client task to simulate sending data
        let client_task = task::spawn(async {
            let mut stream = TcpStream::connect("127.0.0.1:8082").await.expect("Failed to connect");
            let protocol = CustomProtocol::new(true);
            let data = "Hello, secure peer-to-peer world!";
            if let Err(e) = protocol.send_data(&mut stream, data.as_bytes()).await {
                error!("Failed to send data: {}", e);
            }
        });

        let tasks = [client_task, listener_task];
        let _ = futures::future::join_all(tasks).await;
    }

    #[test]
    fn atomic_wrap_test() {
        let val = AtomicU64::new(u64::MAX);
        val.fetch_add(1, Ordering::Relaxed);
        assert_eq!(val.fetch_add(1, Ordering::Relaxed), 0);
    }
}
