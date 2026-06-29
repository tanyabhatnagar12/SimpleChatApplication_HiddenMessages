use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum MessageKind {
    Pub,
    Msg,
    System,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Payload {
    PublicKey { hex_key: String },
    Encrypted { nonce_hex: String, cipher_hex: String },
    Empty,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Message {
    pub kind:      MessageKind,
    pub to:        String,
    pub from:      String,
    pub timestamp: u64,
    pub content:   Option<String>,   // hidden XOR payload lives here when content.is_some()
    pub payload:   Payload,
}

impl Message {
    pub fn send_to(&self, stream: &mut impl Write) -> std::io::Result<()> {
        let encoded = bincode::serialize(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        let len = (encoded.len() as u32).to_be_bytes();
        stream.write_all(&len)?;
        stream.write_all(&encoded)
    }

    pub fn recv_from(stream: &mut impl Read) -> std::io::Result<Self> {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf)?;
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut data = vec![0u8; len];
        stream.read_exact(&mut data)?;
        bincode::deserialize(&data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }
}