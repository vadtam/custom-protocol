#![allow(dead_code)]

use tokio::sync::Mutex;
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
struct  PayloadData {
    payload_data_type: PayloadDataType,
    decrypted_data: Vec<u8>, // Bytes
}

#[derive(Serialize, Deserialize)]
enum PayloadDataType {
    ACK,
    DATA,
}


#[derive(Serialize, Deserialize)]
struct Payload {
    version: u8,
    nonce_precursor: u64,
    packet_id: u64, // Unique packet ID for acknowledgment
    encrypted_data: Vec<u8>, // Bytes
}

impl Payload {
    const CURRENT_VERSION: u8 = 1;

    fn from(data: &PayloadData, protocol: &CustomProtocol,
            encryption: &Arc<Aes256Gcm>, packet_id: u64) -> Result<Payload, CustomProtocolError> {
        let nonce_precursor = protocol.nonce_counter.fetch_add(1, Ordering::Relaxed);
        let nonce = Payload::get_nonce(nonce_precursor);
        let data = bincode::serialize(data).unwrap();
        let encrypted_data = encryption.encrypt(&nonce, &*data)
            .map_err(CustomProtocolError::EncryptionFailed)?;
        Ok(Payload {
            version: Payload::CURRENT_VERSION,
            nonce_precursor,
            packet_id,
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
    packet_id_counter: AtomicU64,
    unacknowledged_packets: Arc<Mutex<VecDeque<(u64, Vec<u8>, Instant)>>>, // Stores packet_id, data, and timestamp
    retransmit_unacknowledged: bool,
}

impl CustomProtocol {
    const BUFFER_SIZE: usize = 1024;

    // Initialize protocol with optional latency reduction
    fn new(latency_reduction: bool) -> Self {
        let mut rng = rand::thread_rng();
        let nonce_counter_start_value = rng.gen::<u64>();
        CustomProtocol {
            nonce_counter: AtomicU64::new(nonce_counter_start_value),
            latency_reduction,
            packet_id_counter: AtomicU64::new(0),
            unacknowledged_packets: Arc::new(Mutex::new(VecDeque::new())),
            retransmit_unacknowledged: true,
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
    async fn send_data(&self, stream: &mut TcpStream, data: &PayloadData) -> Result<(), CustomProtocolError> {
        let encryption = CustomProtocol::handshake(stream).await.unwrap();
        let packet_id = self.packet_id_counter.fetch_add(1, Ordering::Relaxed);
        let payload = Payload::from(data, self, &encryption, packet_id)?;
        let serialized_payload = bincode::serialize(&payload)?;

        // Track unacknowledged packets
        let timestamp = Instant::now();
        self.unacknowledged_packets.lock().await.push_back((packet_id, serialized_payload.clone(), timestamp));

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
    async fn receive_data(&self, stream: &mut TcpStream) -> Result<PayloadData, CustomProtocolError> {
        let encryption = CustomProtocol::handshake(stream).await.unwrap();
        let mut buffer = [0; Self::BUFFER_SIZE];
        let amt = stream.read(&mut buffer).await?;
        let payload: Payload = bincode::deserialize(&buffer[..amt])?;
        let nonce = Payload::get_nonce(payload.nonce_precursor);
        let decrypted_data = encryption.decrypt(&nonce, &*payload.encrypted_data)
            .map_err(CustomProtocolError::EncryptionFailed)?;
        let data: PayloadData = bincode::deserialize(&decrypted_data[..])?;
        match data.payload_data_type {
            PayloadDataType::ACK => {
                let ack_packet_id: u64 = bincode::deserialize(&data.decrypted_data[..]).unwrap();
                self.handle_ack(ack_packet_id).await;
            },
            PayloadDataType::DATA => {
                // Send ACK
                let ack_payload = bincode::serialize(&payload.packet_id)?;
                stream.write_all(&ack_payload).await?;
            }
        }

        Ok(data)
    }

    async fn handle_ack(&self, ack_packet_id: u64) {
        let mut unacked_packets = self.unacknowledged_packets.lock().await;
        unacked_packets.retain(|(packet_id, _, _)| *packet_id != ack_packet_id);
    }

    async fn send_data_with_latency(&self, stream: &mut TcpStream, data: &PayloadData, tracker: &mut LatencyTracker) -> Result<(), CustomProtocolError> {
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

    async fn retransmit_unacknowledged(&self, stream: &mut TcpStream, timeout: Duration) -> Result<(), CustomProtocolError> {
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let mut unacked_packets = self.unacknowledged_packets.lock().await;
            let now = Instant::now();
    
            for (packet_id, data, timestamp) in unacked_packets.iter_mut() {
                if now.duration_since(*timestamp) > timeout {
                    info!("Retransmitting packet with ID {}", packet_id);
                    stream.write_all(data).await?;
                    *timestamp = now;
                }
            }
            if !self.retransmit_unacknowledged {
                info!("Retransmitting loop exited.");
                return Ok(());
            }
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
                    assert_eq!("Hello, secure peer-to-peer world!", std::str::from_utf8(&received_data.decrypted_data).unwrap());
                },
                Err(e) => error!("Failed to receive data: {}", e),
            }
        });

        // Spawn a client task to simulate sending data
        let client_task = task::spawn(async {
            let mut stream = TcpStream::connect("127.0.0.1:8082").await.expect("Failed to connect");
            let protocol = CustomProtocol::new(true);
            let data = PayloadData {payload_data_type: PayloadDataType::DATA, decrypted_data: "Hello, secure peer-to-peer world!".as_bytes().to_vec()};
            if let Err(e) = protocol.send_data(&mut stream, &data).await {
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
