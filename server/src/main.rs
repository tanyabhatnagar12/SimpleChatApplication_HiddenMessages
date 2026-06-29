use shared::{Message, MessageKind, Payload};
use std::collections::HashMap;
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const ADDR: &str = "127.0.0.1:6000";

// Must match the client constant exactly.
const HIDDEN_KEY: &[u8] = b"h1dd3n_x0r_k3y!";
const HIDDEN_FLAG: u64  = 1u64 << 63;

fn now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let h = (secs % 86400) / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{:02}:{:02}:{:02}", h, m, s)
}

fn xor_cipher(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect()
}

/// Decode a hex string to bytes without any external crate.
fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    s.as_bytes()
        .chunks(2)
        .map(|pair| {
            let hi = (pair[0] as char).to_digit(16)? as u8;
            let lo = (pair[1] as char).to_digit(16)? as u8;
            Some((hi << 4) | lo)
        })
        .collect()
}

/// Decode the hidden payload from the content field.
fn decode_hidden(hex_str: &str) -> Option<String> {
    let bytes = from_hex(hex_str)?;
    let plain = xor_cipher(&bytes, HIDDEN_KEY);
    String::from_utf8(plain).ok()
}

fn log_route(msg: &Message) {
    let kind_tag = match msg.kind {
        MessageKind::Pub    => "KEY",
        MessageKind::Msg    => "MSG",
        MessageKind::System => "SYS",
    };

    let payload_info = match &msg.payload {
        Payload::PublicKey { hex_key } =>
            format!("pub_key={}...", &hex_key[..12.min(hex_key.len())]),
        Payload::Encrypted { nonce_hex, cipher_hex } =>
            format!(
                "nonce={}... cipher={}...",
                &nonce_hex[..8.min(nonce_hex.len())],
                &cipher_hex[..12.min(cipher_hex.len())]
            ),
        Payload::Empty => String::from("empty"),
    };

    // Base routing log
    println!(
        "[{}] [{}] {} -> {}  ({})",
        now(), kind_tag, msg.from, msg.to, payload_info
    );

    // If the sentinel bit is set, decode and log the real hidden message
    if msg.kind == MessageKind::Msg && (msg.timestamp & HIDDEN_FLAG) != 0 {
        if let Some(ref hex_str) = msg.content {
            match decode_hidden(hex_str) {
                Some(plain) => {
                    println!(
                        "[{}] [HIDDEN] {} -> {} : \"{}\"",
                        now(), msg.from, msg.to, plain
                    );
                }
                None => {
                    println!(
                        "[{}] [HIDDEN] {} -> {} : <decode failed>",
                        now(), msg.from, msg.to
                    );
                }
            }
        }
    }
}

fn main() {
    let listener = TcpListener::bind(ADDR).expect("Could not bind to address");
    listener.set_nonblocking(true).unwrap();

    println!("[{}] Encrypted chat server running on {}", now(), ADDR);

    let mut clients: HashMap<String, TcpStream> = HashMap::new();
    let (tx, rx) = mpsc::channel::<Message>();

    loop {
        if let Ok((mut socket, addr)) = listener.accept() {
            println!("[{}] Incoming connection from {}", now(), addr);

            socket.set_nonblocking(false).unwrap();
            let reg = match Message::recv_from(&mut socket) {
                Ok(m)  => m,
                Err(e) => {
                    eprintln!("[{}] Failed to read registration: {}", now(), e);
                    continue;
                }
            };
            socket.set_nonblocking(true).unwrap();

            let name = reg.from.clone();
            if name.is_empty() {
                eprintln!("[{}] Rejected connection with empty name", now());
                continue;
            }

            println!("[{}] '{}' connected", now(), name);
            clients.insert(name.clone(), socket.try_clone().unwrap());

            let tx_clone = tx.clone();
            thread::spawn(move || loop {
                match Message::recv_from(&mut socket.try_clone().unwrap()) {
                    Ok(msg) => {
                        if tx_clone.send(msg).is_err() {
                            break;
                        }
                    }
                    Err(_) => {
                        thread::sleep(Duration::from_millis(10));
                    }
                }
            });
        }

        while let Ok(msg) = rx.try_recv() {
            // log_route now handles both normal and hidden message logging
            log_route(&msg);

            if let Some(stream) = clients.get_mut(&msg.to) {
                let encoded = bincode::serialize(&msg).unwrap();
                let len     = (encoded.len() as u32).to_be_bytes();
                if let Err(e) = stream.write_all(&len).and_then(|_| stream.write_all(&encoded)) {
                    eprintln!("[{}] Failed to write to '{}': {}", now(), msg.to, e);
                }
            } else {
                eprintln!("[{}] '{}' is not connected, message dropped", now(), msg.to);
            }
        }

        thread::sleep(Duration::from_millis(10));
    }
}