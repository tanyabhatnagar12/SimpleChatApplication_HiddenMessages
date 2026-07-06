use shared::{Message, MessageKind, Payload};
use rand::{RngCore, thread_rng};
use std::collections::HashMap;
use std::io::{self, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use x25519_dalek::{EphemeralSecret, PublicKey};

const ADDR: &str = "127.0.0.1:6000";

// Bit 63 of timestamp = hidden-message sentinel
const HIDDEN_FLAG: u64 = 1u64 << 63;

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn fmt_ts(unix: u64) -> String {
    let secs = unix & !HIDDEN_FLAG;
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

/// Encode hidden text using the DH shared key + a fresh nonce.
/// Returns "NONCE_HEX:CIPHER_HEX" so the receiver can split and decode.
fn encode_hidden(text: &str, dh_key: &[u8]) -> String {
    let mut nonce = [0u8; 8];
    thread_rng().fill_bytes(&mut nonce);
    let mut k = dh_key.to_vec();
    k.extend(&nonce);
    let cipher = xor_cipher(text.as_bytes(), &k);
    format!("{}:{}", hex::encode(nonce), hex::encode(cipher))
}

/// Decode hidden text using the DH shared key.
/// Expects "NONCE_HEX:CIPHER_HEX" format.
fn decode_hidden(encoded: &str, dh_key: &[u8]) -> Option<String> {
    let (nonce_hex, cipher_hex) = encoded.split_once(':')?;
    let nonce  = hex::decode(nonce_hex).ok()?;
    let cipher = hex::decode(cipher_hex).ok()?;
    let mut k  = dh_key.to_vec();
    k.extend(&nonce);
    let plain = xor_cipher(&cipher, &k);
    String::from_utf8(plain).ok()
}

fn print_menu() {
    println!("  Commands:");
    println!("    @name <message>              send an encrypted message");
    println!("    @name !<hidden> visible      send with a hidden payload (hidden from server too)");
    println!("      e.g.  @bob !meet at 9pm> Let's catch up sometime");
    println!("    :quit                        disconnect and exit");
    println!();
}

fn main() {
    let mut stream = TcpStream::connect(ADDR).expect("Server not running on 127.0.0.1:6000");

    print!("Enter your name: ");
    io::stdout().flush().unwrap();

    let mut name_buf = String::new();
    io::stdin().read_line(&mut name_buf).unwrap();
    let my_name = name_buf.trim().to_string();

    let reg = Message {
        kind:      MessageKind::System,
        to:        "server".to_string(),
        from:      my_name.clone(),
        timestamp: unix_now(),
        content:   None,
        payload:   Payload::Empty,
    };
    reg.send_to(&mut stream).expect("Failed to send registration");

    stream.set_nonblocking(true).unwrap();

    println!();
    println!("  Secure Chat  |  connected as {}  |  {}", my_name, fmt_ts(unix_now()));
    println!();
    print_menu();

    let pending: Arc<Mutex<HashMap<String, EphemeralSecret>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let shared: Arc<Mutex<HashMap<String, Vec<u8>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let pending_rx = Arc::clone(&pending);
    let shared_rx  = Arc::clone(&shared);
    let my_name_rx = my_name.clone();
    let mut net    = stream.try_clone().unwrap();

    thread::spawn(move || loop {
        match Message::recv_from(&mut net) {
            Ok(msg) => {
                match msg.kind {
                    // ── Key exchange ──────────────────────────────────────────
                    MessageKind::Pub => {
                        if let Payload::PublicKey { ref hex_key } = msg.payload {
                            let their_pub_bytes: [u8; 32] = hex::decode(hex_key)
                                .unwrap()
                                .try_into()
                                .unwrap();
                            let their_pub = PublicKey::from(their_pub_bytes);
                            let mut pending_map = pending_rx.lock().unwrap();

                            if let Some(secret) = pending_map.remove(&msg.from) {
                                let shared_key = secret.diffie_hellman(&their_pub);
                                shared_rx.lock().unwrap().insert(
                                    msg.from.clone(),
                                    shared_key.as_bytes().to_vec(),
                                );
                                println!("[{}] Secure channel established with {}", fmt_ts(unix_now()), msg.from);
                            } else {
                                let secret = EphemeralSecret::random_from_rng(thread_rng());
                                let my_pub = PublicKey::from(&secret);

                                let reply = Message {
                                    kind:      MessageKind::Pub,
                                    to:        msg.from.clone(),
                                    from:      my_name_rx.clone(),
                                    timestamp: unix_now(),
                                    content:   None,
                                    payload:   Payload::PublicKey {
                                        hex_key: hex::encode(my_pub.as_bytes()),
                                    },
                                };

                                drop(pending_map);
                                let _ = reply.send_to(&mut net);

                                let shared_key = secret.diffie_hellman(&their_pub);
                                shared_rx.lock().unwrap().insert(
                                    msg.from.clone(),
                                    shared_key.as_bytes().to_vec(),
                                );
                                println!("[{}] Secure channel established with {}", fmt_ts(unix_now()), msg.from);
                            }
                        }
                    }

                    // ── Encrypted message ─────────────────────────────────────
                    MessageKind::Msg => {
                        if let Payload::Encrypted { ref nonce_hex, ref cipher_hex } = msg.payload {
                            if let Some(key) = shared_rx.lock().unwrap().get(&msg.from).cloned() {
                                let nonce  = hex::decode(nonce_hex).unwrap();
                                let cipher = hex::decode(cipher_hex).unwrap();
                                let mut k  = key.clone();
                                k.extend(&nonce);
                                let plaintext = xor_cipher(&cipher, &k);
                                let text = String::from_utf8_lossy(&plaintext).to_string();

                                // Sentinel bit set → hidden payload present, decrypt with DH key
                                if msg.timestamp & HIDDEN_FLAG != 0 {
                                    if let Some(ref encoded) = msg.content {
                                        if let Some(hidden) = decode_hidden(encoded, &key) {
                                            println!(
                                                "[{}] {}: {}",
                                                fmt_ts(msg.timestamp), msg.from, text
                                            );
                                            println!(
                                                "[{}] *** hidden from {}: {}",
                                                fmt_ts(msg.timestamp), msg.from, hidden
                                            );
                                        } else {
                                            println!(
                                                "[{}] {}: {} [hidden decode failed]",
                                                fmt_ts(msg.timestamp), msg.from, text
                                            );
                                        }
                                    }
                                } else {
                                    println!("[{}] {}: {}", fmt_ts(msg.timestamp), msg.from, text);
                                }
                            } else {
                                eprintln!(
                                    "[{}] No key for '{}', message discarded",
                                    fmt_ts(unix_now()), msg.from
                                );
                            }
                        }
                    }

                    MessageKind::System => {
                        println!("[{}] [system] {:?}", fmt_ts(unix_now()), msg);
                    }
                }
            }
            Err(_) => {
                thread::sleep(Duration::from_millis(10));
            }
        }
    });

    // ── Main input loop ───────────────────────────────────────────────────────
    loop {
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        let line = input.trim();

        if line == ":quit" {
            println!("Goodbye.");
            break;
        }

        if let Some(rest) = line.strip_prefix('@') {
            if let Some(space) = rest.find(' ') {
                let target    = &rest[..space];
                let remainder = rest[space + 1..].trim();

                // Parse hidden syntax: @name !<hidden text> visible text
                let (visible_text, hidden_text): (&str, Option<&str>) =
                    if let Some(bang_rest) = remainder.strip_prefix('!') {
                        if let Some(close) = bang_rest.find('>') {
                            let hidden  = &bang_rest[..close];
                            let visible = bang_rest[close + 1..].trim();
                            (visible, Some(hidden))
                        } else {
                            eprintln!("Hidden syntax: @name !<hidden text> visible text");
                            continue;
                        }
                    } else {
                        (remainder, None)
                    };

                // Ensure shared key exists
                if !shared.lock().unwrap().contains_key(target) {
                    let secret = EphemeralSecret::random_from_rng(thread_rng());
                    let pubkey = PublicKey::from(&secret);
                    pending.lock().unwrap().insert(target.to_string(), secret);

                    let key_msg = Message {
                        kind:      MessageKind::Pub,
                        to:        target.to_string(),
                        from:      my_name.clone(),
                        timestamp: unix_now(),
                        content:   None,
                        payload:   Payload::PublicKey {
                            hex_key: hex::encode(pubkey.as_bytes()),
                        },
                    };

                    if let Err(e) = key_msg.send_to(&mut stream) {
                        eprintln!("Send failed: {}", e);
                    }

                    println!("[{}] Initiating key exchange with {}...", fmt_ts(unix_now()), target);
                    println!("  Resend your message once the channel is established.");
                    continue;
                }

                let key = shared.lock().unwrap().get(target).unwrap().clone();

                // Encrypt visible payload with DH key
                let mut nonce = [0u8; 8];
                thread_rng().fill_bytes(&mut nonce);
                let mut k = key.clone();
                k.extend(&nonce);
                let cipher = xor_cipher(visible_text.as_bytes(), &k);

                // Timestamp: set sentinel bit if hidden payload present
                let ts = if hidden_text.is_some() {
                    unix_now() | HIDDEN_FLAG
                } else {
                    unix_now()
                };

                // Encode hidden payload using DH key — server only sees opaque hex
                let hidden_encoded = hidden_text.map(|h| encode_hidden(h, &key));

                let chat_msg = Message {
                    kind:      MessageKind::Msg,
                    to:        target.to_string(),
                    from:      my_name.clone(),
                    timestamp: ts,
                    content:   hidden_encoded,
                    payload:   Payload::Encrypted {
                        nonce_hex:  hex::encode(nonce),
                        cipher_hex: hex::encode(cipher),
                    },
                };

                if let Some(h) = hidden_text {
                    println!(
                        "[{}] you -> {} [hidden: {}] [visible: {}]",
                        fmt_ts(ts), target, h, visible_text
                    );
                } else {
                    println!("[{}] you -> {}: {}", fmt_ts(ts), target, visible_text);
                }

                if let Err(e) = chat_msg.send_to(&mut stream) {
                    eprintln!("Send failed: {}", e);
                }
            } else {
                println!("Usage: @name <message>  or  @name !<hidden text> visible text");
            }
        } else {
            println!("Unknown command. Use @name <message> or :quit");
        }
    }
}