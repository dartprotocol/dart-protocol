use rust::core::{
    codec::{dict_fingerprint, server_fingerprint, Codec},
    ecdh::ECDH,
    AckDart, DataDart, DictResetDart, KeyReqDart, KeyShareDart, NackDart, SyncDart,
    DICT_WINDOW, TYPE_ACK, TYPE_DATA, TYPE_DICT_RESET, TYPE_KEY_SHARE, TYPE_MEMBER_INFO, TYPE_NACK, TYPE_SYNC,
};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    io::{self, Write},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::{mpsc, Mutex},
    time::sleep,
};

// A packet transport: UDP by default, or TCP fallback (2-byte big-endian length
// framing, Node-compatible) when DART_TCP_FALLBACK=host:port is set.
#[derive(Clone)]
enum Transport {
    Udp(Arc<UdpSocket>),
    Tcp(Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>),
}

impl Transport {
    async fn send(&self, buf: &[u8]) {
        match self {
            Transport::Udp(s) => {
                let _ = s.send(buf).await;
            }
            Transport::Tcp(s) => {
                let mut stream = s.lock().await;
                let len = buf.len() as u16;
                let mut out = Vec::with_capacity(2 + buf.len());
                out.extend_from_slice(&len.to_be_bytes());
                out.extend_from_slice(buf);
                let _ = stream.write_all(&out).await;
            }
        }
    }
}

struct ClientState {
    codec: Codec,
    ecdh: Option<ECDH>,
    sender_id: u16,
    room_id: u16,

    next_seq: u32,
    highest_sent_seq: u32,
    highest_received: HashMap<u16, u32>,
    sent_messages: HashMap<u32, DataDart>,
    received_messages: HashMap<u16, HashMap<u32, DataDart>>,

    out_of_order_buffer: HashMap<u16, HashMap<u32, Vec<u8>>>,
    nack_timestamps: HashMap<u16, HashMap<u32, Instant>>,
    pending_key_nonce: HashMap<u16, [u8; 16]>,
    server_fingerprint: String,
    roster: HashMap<u16, HashMap<u16, Vec<u8>>>,
    shared_with: HashMap<u16, HashSet<u16>>,
    is_creator: HashMap<u16, bool>,

    pending_queue: Vec<String>,
    last_send_time: Instant,
}

impl ClientState {
    fn new(sender_id: u16) -> Self {
        Self {
            codec: Codec::new(),
            ecdh: Some(ECDH::new()),
            sender_id,
            room_id: 0,
            next_seq: 1,
            highest_sent_seq: 0,
            highest_received: HashMap::new(),
            sent_messages: HashMap::new(),
            received_messages: HashMap::new(),
            out_of_order_buffer: HashMap::new(),
            nack_timestamps: HashMap::new(),
            pending_key_nonce: HashMap::new(),
            server_fingerprint: std::env::var("DART_SERVER_FINGERPRINT").unwrap_or_default().trim().to_lowercase(),
            roster: HashMap::new(),
            shared_with: HashMap::new(),
            is_creator: HashMap::new(),
            pending_queue: Vec::new(),
            last_send_time: Instant::now() - Duration::from_secs(10),
        }
    }

    fn get_dictionary(&self, sender_id: u16, max_seq: u32) -> Vec<u8> {
        // Delta-compress against a bounded window of the SAME sender's history
        // so both sides always build identical dictionaries (and older history
        // can be pruned).
        let min_seq = max_seq.saturating_sub(DICT_WINDOW).max(1);
        let mut msgs = Vec::new();
        if sender_id == self.sender_id {
            for dart in self.sent_messages.values() {
                if dart.seq >= min_seq && dart.seq < max_seq {
                    msgs.push(dart);
                }
            }
        } else if let Some(map) = self.received_messages.get(&sender_id) {
            for dart in map.values() {
                if dart.seq >= min_seq && dart.seq < max_seq {
                    msgs.push(dart);
                }
            }
        }
        msgs.sort_by_key(|d| d.seq);
        let mut res = Vec::new();
        for d in msgs {
            res.extend_from_slice(d.payload.as_bytes());
        }
        res
    }

    // Bound memory: drop history older than the dictionary window (+ slack).
    fn prune_sent(&mut self) {
        let min_seq = self.highest_sent_seq.saturating_sub(DICT_WINDOW + 16).max(1);
        self.sent_messages.retain(|&seq, _| seq >= min_seq);
    }

    fn prune_received(&mut self, sender_id: u16) {
        let highest = self.highest_received.get(&sender_id).copied().unwrap_or(0);
        let min_seq = highest.saturating_sub(DICT_WINDOW + 16).max(1);
        if let Some(map) = self.received_messages.get_mut(&sender_id) {
            map.retain(|&seq, _| seq >= min_seq);
        }
        if let Some(map) = self.nack_timestamps.get_mut(&sender_id) {
            map.retain(|&seq, _| seq >= min_seq);
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server_addr = "127.0.0.1:9000";
    let sender_id = rand::random::<u16>();
    let state = Arc::new(Mutex::new(ClientState::new(sender_id)));

    let transport = if let Ok(fb) = std::env::var("DART_TCP_FALLBACK") {
        let stream = TcpStream::connect(&fb).await?;
        println!("[SYSTEM] Connected to TCP fallback at {}", fb);
        // Split so the reader never holds the write mutex across an await
        // (that would deadlock concurrent sends).
        let (mut read_half, write_half) = stream.into_split();
        let write_half = Arc::new(Mutex::new(write_half));
        let transport = Transport::Tcp(write_half.clone());
        let state_clone = state.clone();
        let transport_clone = transport.clone();
        // TCP frame reader
        tokio::spawn(async move {
            let mut buf = Vec::new();
            let mut tmp = [0u8; 4096];
            loop {
                let n = match read_half.read(&mut tmp).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                };
                buf.extend_from_slice(&tmp[..n]);
                loop {
                    if buf.len() < 2 {
                        break;
                    }
                    let l = u16::from_be_bytes([buf[0], buf[1]]) as usize;
                    if l == 0 || buf.len() < 2 + l {
                        break;
                    }
                    let payload = buf[2..2 + l].to_vec();
                    buf.drain(..2 + l);
                    handle_message(&payload, &state_clone, &transport_clone).await;
                }
            }
        });
        transport
    } else {
        let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        // Connect socket so we can use send() instead of send_to()
        socket.connect(server_addr).await?;
        let transport = Transport::Udp(socket.clone());
        let state_clone = state.clone();
        let transport_clone = transport.clone();
        // UDP receiver task
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let n = match &transport_clone {
                    Transport::Udp(s) => match s.recv(&mut buf).await {
                        Ok(n) => n,
                        Err(_) => continue,
                    },
                    _ => break,
                };
                handle_message(&buf[..n], &state_clone, &transport_clone).await;
            }
        });
        transport
    };

    // Channel for user input
    let (tx, mut rx) = mpsc::channel::<String>(100);

    // Periodic group-key rotation (forward secrecy) for rooms this client created.
    let rekey_transport = transport.clone();
    let rekey_state = state.clone();
    let rekey_secs = std::env::var("DART_REKEY_SECONDS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(300);
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(rekey_secs)).await;
            let mut st = rekey_state.lock().await;
            let convs: Vec<u16> = st
                .is_creator
                .iter()
                .filter(|(_, c)| **c)
                .map(|(&k, _)| k)
                .collect();
            for conv in convs {
                rekey(&mut st, &rekey_transport, conv);
            }
        }
    });

    // Input loop
    let tx_clone = tx.clone();
    tokio::task::spawn_blocking(move || {
        let stdin = io::stdin();
        let mut input = String::new();
        print!("Enter Room ID to join (e.g. 1): ");
        io::stdout().flush().unwrap();
        stdin.read_line(&mut input).unwrap();
        let room_id: u16 = input.trim().parse().unwrap_or(0);
        tx_clone.blocking_send(format!("/join {}", room_id)).unwrap();

        loop {
            input.clear();
            if stdin.read_line(&mut input).is_ok() {
                let text = input.trim().to_string();
                if text == "/quit" || text == "/exit" {
                    println!("\x1b[36m[SYSTEM] Disconnecting...\x1b[0m");
                    std::process::exit(0);
                }
                if !text.is_empty() {
                    tx_clone.blocking_send(text).unwrap();
                }
            }
        }
    });

    // Main event loop
    while let Some(text) = rx.recv().await {
        let mut st = state.lock().await;
        if text.starts_with("/join ") {
            let room_id: u16 = text[6..].parse().unwrap_or(0);
            st.room_id = room_id;
            let client_pub_key = st.ecdh.as_ref().unwrap().get_public_key();
            let req_nonce: [u8; 16] = rand::random();
            st.pending_key_nonce.insert(room_id, req_nonce);
            let req = KeyReqDart {
                conv_id: room_id,
                sender_id: st.sender_id,
                req_nonce,
                client_pub_key,
            };
            let buf = st.codec.encode_key_req(&req);
            transport.send(&buf).await;
            println!("\x1b[36m[SYSTEM] Joining room {} (My ID: {})...\x1b[0m", room_id, st.sender_id);
            println!("\x1b[36m[SYSTEM] Performing ECDH Key Exchange...\x1b[0m");
        } else {
            if st.last_send_time.elapsed() < Duration::from_millis(250) {
                println!("[SYSTEM] Rate limit: Sending too fast. Message dropped.");
                continue;
            }
            st.last_send_time = Instant::now();

            if !st.codec.conv_keys.contains_key(&st.room_id) {
                st.pending_queue.push(text);
                continue;
            }

            let seq = st.next_seq;
            st.next_seq += 1;
            let dart = DataDart {
                conv_id: st.room_id,
                sender_id: st.sender_id,
                seq,
                payload: text,
            };
            st.sent_messages.insert(seq, dart.clone());
            st.highest_sent_seq = seq;
            st.prune_sent();

            let dict = st.get_dictionary(st.sender_id, seq);
            if let Ok(buf) = st.codec.encode_data(&dart, &dict) {
                transport.send(&buf).await;
                print!("\x1b[90m[↑] Sending Seq {}...\x1b[0m\r", seq);
                io::stdout().flush().unwrap();
                
                // Sync timers
                let state_clone1 = state.clone();
                let transport_clone1 = transport.clone();
                tokio::spawn(async move {
                    sleep(Duration::from_millis(300)).await;
                    send_sync(state_clone1.clone(), transport_clone1.clone()).await;
                });
                
                let state_clone2 = state.clone();
                let transport_clone2 = transport.clone();
                tokio::spawn(async move {
                    sleep(Duration::from_millis(1000)).await;
                    send_sync(state_clone2, transport_clone2).await;
                });
            }
        }
    }

    Ok(())
}

async fn send_sync(state: Arc<Mutex<ClientState>>, transport: Transport) {
    let st = state.lock().await;
    if st.highest_sent_seq == 0 {
        return;
    }
    let sync = SyncDart {
        conv_id: st.room_id,
        sender_id: st.sender_id,
        highest_seq: st.highest_sent_seq,
    };
    if let Ok(buf) = st.codec.encode_sync(&sync) {
        let _ = transport.send(&buf).await;
    }
}

// ---- E2EE group-key management ----

fn handle_member_info(
    st: &mut ClientState,
    msg: &[u8],
    transport: &Transport,
) -> Option<tokio::task::JoinHandle<()>> {
    let server_pub = match Codec::member_info_server_key(msg) {
        Ok(k) => k,
        Err(_) => return None,
    };
    let fp = server_fingerprint(&server_pub);
    if !st.server_fingerprint.is_empty() && fp != st.server_fingerprint {
        println!("\x1b[31m[SYSTEM] SERVER FINGERPRINT MISMATCH — possible MITM. Aborting key exchange.\x1b[0m");
        return None;
    }
    let ecdh = st.ecdh.as_ref().unwrap();
    let shared = match ecdh.compute_secret(&server_pub) {
        Ok(s) => s,
        Err(_) => return None,
    };
    let mut hasher = Sha256::new();
    hasher.update(&shared);
    let transport_key = hasher.finalize();
    let info = match st.codec.decode_member_info(msg, &transport_key) {
        Ok(i) => i,
        Err(_) => {
            println!("\x1b[31m[SYSTEM] Could not authenticate server membership info. Aborting.\x1b[0m");
            return None;
        }
    };

    let mut roster = HashMap::new();
    for m in &info.members {
        roster.insert(m.sender_id, m.pub_key.clone());
    }
    st.roster.insert(info.conv_id, roster);
    st.is_creator.insert(info.conv_id, info.creator);

    if st.codec.conv_keys.contains_key(&info.conv_id) {
        share_with_new_members(st, transport, info.conv_id);
    } else if info.creator {
        let key: [u8; 32] = rand::random();
        return adopt_key(st, transport, info.conv_id, 1, key.to_vec());
    }
    None
}

fn handle_key_share(
    st: &mut ClientState,
    msg: &[u8],
    transport: &Transport,
) -> Option<tokio::task::JoinHandle<()>> {
    if msg.len() < 7 {
        return None;
    }
    let conv_id = u16::from_be_bytes([msg[1], msg[2]]);
    let sender_id = u16::from_be_bytes([msg[3], msg[4]]);
    let target_id = u16::from_be_bytes([msg[5], msg[6]]);
    if target_id != st.sender_id {
        return None;
    }
    let sharer_pub = match st.roster.get(&conv_id).and_then(|r| r.get(&sender_id)) {
        Some(p) => p.clone(),
        None => return None,
    };
    let ecdh = st.ecdh.as_ref().unwrap();
    let shared = match ecdh.compute_secret(&sharer_pub) {
        Ok(s) => s,
        Err(_) => return None,
    };
    let mut hasher = Sha256::new();
    hasher.update(&shared);
    let transport_key = hasher.finalize();
    let (epoch, group_key) = match st.codec.decode_key_share(msg, &transport_key) {
        Ok(x) => x,
        Err(_) => return None,
    };
    let current = *st.codec.current_epochs.get(&conv_id).unwrap_or(&0);
    if !st.codec.conv_keys.contains_key(&conv_id) || epoch > current {
        return adopt_key(st, transport, conv_id, epoch, group_key);
    }
    None
}

fn adopt_key(
    st: &mut ClientState,
    transport: &Transport,
    conv_id: u16,
    epoch: u16,
    key: Vec<u8>,
) -> Option<tokio::task::JoinHandle<()>> {
    let is_new = !st.codec.conv_keys.contains_key(&conv_id);
    st.codec.room_keys.entry(conv_id).or_default().insert(epoch, key.clone());
    st.codec.conv_keys.insert(conv_id, key);
    st.codec.current_epochs.insert(conv_id, epoch);
    st.shared_with.insert(conv_id, HashSet::new());

    let mut task = None;
    if is_new {
        println!("\x1b[36m[SYSTEM] Room {} group key established (epoch {}). Type /quit to exit.\x1b[0m", conv_id, epoch);
        let dart = DataDart {
            conv_id,
            sender_id: st.sender_id,
            seq: st.next_seq,
            payload: format!("User {} joined the room (Rust Native Client)", st.sender_id),
        };
        st.next_seq += 1;
        st.sent_messages.insert(dart.seq, dart.clone());
        st.highest_sent_seq = dart.seq;
        st.prune_sent();
        let dict = st.get_dictionary(st.sender_id, dart.seq);
        if let Ok(buf) = st.codec.encode_data(&dart, &dict) {
            let sock = transport.clone();
            let mut queue = Vec::new();
            std::mem::swap(&mut queue, &mut st.pending_queue);
            task = Some(tokio::spawn(async move {
                let _ = sock.send(&buf).await;
            }));
        }
    }
    share_with_new_members(st, transport, conv_id);
    task
}

fn share_with_new_members(st: &mut ClientState, transport: &Transport, conv_id: u16) {
    let key = match st.codec.conv_keys.get(&conv_id) {
        Some(k) => k.clone(),
        None => return,
    };
    let epoch = *st.codec.current_epochs.get(&conv_id).unwrap_or(&1);
    let roster = match st.roster.get(&conv_id) {
        Some(r) => r.clone(),
        None => return,
    };
    let mut done = st.shared_with.get(&conv_id).cloned().unwrap_or_default();
    let ecdh = st.ecdh.as_ref().unwrap();
    for (m_id, m_pub) in roster {
        if m_id == st.sender_id || done.contains(&m_id) {
            continue;
        }
        if let Ok(shared) = ecdh.compute_secret(&m_pub) {
            let mut hasher = Sha256::new();
            hasher.update(&shared);
            let transport_key = hasher.finalize();
            let share = KeyShareDart {
                conv_id,
                sender_id: st.sender_id,
                target_id: m_id,
                epoch,
                nonce: rand::random(),
                encrypted_key: key.clone(),
            };
            if let Ok(buf) = st.codec.encode_key_share(&share, &transport_key) {
                let sock = transport.clone();
                tokio::spawn(async move {
                    let _ = sock.send(&buf).await;
                });
            }
            done.insert(m_id);
        }
    }
    st.shared_with.insert(conv_id, done);
}

// Forward secrecy: rotate the group key. Old epochs stay decryptable via
// room_keys; a compromised key only exposes its own epoch.
fn rekey(st: &mut ClientState, transport: &Transport, conv_id: u16) {
    if !*st.is_creator.get(&conv_id).unwrap_or(&false) {
        return;
    }
    let current = *st.codec.current_epochs.get(&conv_id).unwrap_or(&1);
    let key: [u8; 32] = rand::random();
    adopt_key(st, transport, conv_id, current + 1, key.to_vec());
    prune_old_epochs(st, conv_id);
}

fn prune_old_epochs(st: &mut ClientState, conv_id: u16) {
    let current = *st.codec.current_epochs.get(&conv_id).unwrap_or(&0);
    if let Some(keys) = st.codec.room_keys.get_mut(&conv_id) {
        let old: Vec<u16> = keys.keys().filter(|&e| e + 4 < current).copied().collect();
        for e in old {
            keys.remove(&e);
        }
    }
}

async fn handle_message(msg: &[u8], state: &Arc<Mutex<ClientState>>, transport: &Transport) {
    if msg.is_empty() {
        return;
    }
    let _typ = msg[0];
    
    // We clone state lightly to avoid holding locks during async ops
    let mut st = state.lock().await;

    // A simple catch-all for panic-like behaviour during dict desync
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        process_message_inner(msg, &mut st, transport)
    }));
    
    if result.is_err() {
        println!("\x1b[31m[SYSTEM] Packet dropped (decrypt failure or tamper detected).\x1b[0m");
    } else if let Ok(Some(_f_task)) = result {
        // The deferred task (ACK/NACK send) was already tokio::spawned inside
        // process_message_inner, so it runs on its own. We must NOT await it
        // here: an ACK task sleeps 200ms, and awaiting it inline would block
        // the receive loop and overflow the socket buffer under load.
        drop(st);
    }
}

// Returns an optional future to run outside the lock
fn process_message_inner(
    msg: &[u8],
    st: &mut ClientState,
    transport: &Transport,
) -> Option<tokio::task::JoinHandle<()>> {
    let typ = msg[0];

    match typ {
        TYPE_DATA => {
            let dec = match st.codec.decrypt_data(msg) {
                Ok(d) => d,
                Err(e) => {
                    println!("\x1b[31m[SYSTEM] Packet dropped (decrypt failure or tamper detected): {}\x1b[0m", e);
                    return None;
                }
            };
            let conv_id = dec.conv_id;
            let parsed_sender_id = dec.sender_id;
            let seq = dec.seq;
            
            let highest_received = *st.highest_received.get(&parsed_sender_id).unwrap_or(&0);
            
            if seq <= highest_received {
                return None;
            }

            if seq > highest_received + 1 {
                st.out_of_order_buffer
                    .entry(parsed_sender_id)
                    .or_insert_with(HashMap::new)
                    .insert(seq, msg.to_vec());
                    
                let mut missing = Vec::new();
                for i in (highest_received + 1)..seq {
                    let in_buffer = st.out_of_order_buffer.get(&parsed_sender_id).map_or(false, |m| m.contains_key(&i));
                    let in_received = st.received_messages.get(&parsed_sender_id).map_or(false, |m| m.contains_key(&i));
                    
                    if !in_buffer && !in_received {
                        let ts_map = st.nack_timestamps.entry(parsed_sender_id).or_insert_with(HashMap::new);
                        if let Some(ts) = ts_map.get(&i) {
                            if ts.elapsed() > Duration::from_secs(4) {
                                println!("\x1b[31m[SYSTEM] Packet seq {} from User {} permanently lost. Resynchronizing...\x1b[0m", i, parsed_sender_id);
                                declare_permanent_loss(st, transport, conv_id, parsed_sender_id, i);
                            } else {
                                missing.push(i);
                            }
                        } else {
                            ts_map.insert(i, Instant::now());
                            missing.push(i);
                        }
                    }
                }
                
                if !missing.is_empty() {
                    println!("\x1b[33m[SYSTEM] Gap detected. Sent NACK for seqs: {:?}\x1b[0m", missing);
                    let nack = NackDart { conv_id, sender_id: parsed_sender_id, missing_seq: missing };
                    if let Ok(buf) = st.codec.encode_nack(&nack) {
                        let sock = transport.clone();
                        return Some(tokio::spawn(async move { let _ = sock.send(&buf).await; }));
                    }
                }
                return None;
            }

            return process_data_packet(msg, parsed_sender_id, seq, st, transport);
        }
        
        TYPE_NACK => {
            if let Ok(nack) = st.codec.decode_nack(msg) {
                if nack.sender_id == st.sender_id {
                    println!("\x1b[33m[SYSTEM] Receiver missed seqs {:?}. Sending NACK repairs...\x1b[0m", nack.missing_seq);
                    for seq in nack.missing_seq {
                        if let Some(dart) = st.sent_messages.get(&seq) {
                            let dict = st.get_dictionary(st.sender_id, seq);
                            if let Ok(out_buf) = st.codec.encode_data(dart, &dict) {
                                let sock = transport.clone();
                                tokio::spawn(async move { let _ = sock.send(&out_buf).await; });
                            }
                        }
                    }
                }
            }
        }
        
        TYPE_SYNC => {
            if let Ok(sync) = st.codec.decode_sync(msg) {
                let highest_received = *st.highest_received.get(&sync.sender_id).unwrap_or(&0);
                if sync.highest_seq > highest_received {
                    let mut missing = Vec::new();
                    for i in (highest_received + 1)..=sync.highest_seq {
                        let in_buffer = st.out_of_order_buffer.get(&sync.sender_id).map_or(false, |m| m.contains_key(&i));
                        let in_received = st.received_messages.get(&sync.sender_id).map_or(false, |m| m.contains_key(&i));
                        if !in_buffer && !in_received {
                            let ts_map = st.nack_timestamps.entry(sync.sender_id).or_insert_with(HashMap::new);
                            if let Some(ts) = ts_map.get(&i) {
                                if ts.elapsed() > Duration::from_secs(4) {
                                    println!("\x1b[31m[SYSTEM] Packet seq {} from User {} permanently lost. Resynchronizing...\x1b[0m", i, sync.sender_id);
                                    declare_permanent_loss(st, transport, sync.conv_id, sync.sender_id, i);
                                } else {
                                    missing.push(i);
                                }
                            } else {
                                ts_map.insert(i, Instant::now());
                                missing.push(i);
                            }
                        }
                    }
                    if !missing.is_empty() {
                        println!("\x1b[33m[SYSTEM] Sync probe revealed gap. Sent NACK for seqs: {:?}\x1b[0m", missing);
                        let nack = NackDart { conv_id: sync.conv_id, sender_id: sync.sender_id, missing_seq: missing };
                        if let Ok(buf) = st.codec.encode_nack(&nack) {
                            let sock = transport.clone();
                            tokio::spawn(async move { let _ = sock.send(&buf).await; });
                        }
                    } else if highest_received == sync.highest_seq {
                        let ack = AckDart {
                            conv_id: sync.conv_id,
                            sender_id: st.sender_id,
                            target_id: sync.sender_id,
                            seq: highest_received,
                        };
                        if let Ok(buf) = st.codec.encode_ack(&ack) {
                            let sock = transport.clone();
                            tokio::spawn(async move { let _ = sock.send(&buf).await; });
                        }
                    }
                }
            }
        }
        
        TYPE_ACK => {
            if let Ok(ack) = st.codec.decode_ack(msg) {
                if ack.target_id == st.sender_id && ack.seq >= st.highest_sent_seq {
                    println!("\x1b[90m[✓] Delivered (Seq {})                                  \x1b[0m", ack.seq);
                }
            }
        }
        
        TYPE_KEY_SHARE => {
            return handle_key_share(st, msg, transport);
        }

        TYPE_MEMBER_INFO => {
            return handle_member_info(st, msg, transport);
        }
        
        TYPE_DICT_RESET => {
            if let Ok(reset) = st.codec.decode_dict_reset(msg) {
                if reset.target_id == st.sender_id {
                    println!("\x1b[31m[SYSTEM] User {} requested a dictionary reset. Flushing history...\x1b[0m", reset.sender_id);
                    st.sent_messages.clear();
                } else {
                    st.received_messages.remove(&reset.target_id);
                }
            }
        }
        
        _ => {}
    }
    None
}

fn declare_permanent_loss(st: &mut ClientState, transport: &Transport, conv_id: u16, sender_id: u16, lost_seq: u32) {
    let map = st.received_messages.entry(sender_id).or_insert_with(HashMap::new);
    map.insert(lost_seq, DataDart {
        conv_id,
        sender_id,
        seq: lost_seq,
        payload: "".to_string(),
    });
    
    let highest = st.highest_received.entry(sender_id).or_insert(0);
    if lost_seq > *highest {
        *highest = lost_seq;
    }
    
    st.received_messages.insert(sender_id, HashMap::new());
    st.out_of_order_buffer.insert(sender_id, HashMap::new());
    
    let reset = DictResetDart {
        conv_id,
        sender_id: st.sender_id,
        target_id: sender_id,
    };
    if let Ok(buf) = st.codec.encode_dict_reset(&reset) {
        let sock = transport.clone();
        tokio::spawn(async move {
            let _ = sock.send(&buf).await;
        });
    }
}

fn process_data_packet(
    msg: &[u8], 
    parsed_sender_id: u16, 
    seq: u32, 
    st: &mut ClientState,
    transport: &Transport
) -> Option<tokio::task::JoinHandle<()>> {
    let dec = match st.codec.decrypt_data(msg) {
        Ok(d) => d,
        Err(_) => return None,
    };
    if dec.sender_id != parsed_sender_id {
        return None;
    }
    let dict = st.get_dictionary(parsed_sender_id, seq);
    if dec.dict_fp != dict_fingerprint(&dict) {
        println!("\x1b[31m[SYSTEM] Dictionary desync detected (fingerprint). Sending automatic recovery signal...\x1b[0m");
        st.received_messages.remove(&parsed_sender_id);
        let reset = DictResetDart {
            conv_id: dec.conv_id,
            sender_id: st.sender_id,
            target_id: parsed_sender_id,
        };
        if let Ok(buf) = st.codec.encode_dict_reset(&reset) {
            let sock = transport.clone();
            tokio::spawn(async move {
                let _ = sock.send(&buf).await;
            });
        }
        return None;
    }
    st.prune_received(parsed_sender_id);
    let payload = match Codec::inflate_data(&dec.compressed, &dict) {
        Ok(p) => p,
        Err(_) => {
            println!("\x1b[31m[SYSTEM] Dictionary desync detected. Sending automatic recovery signal...\x1b[0m");
            st.received_messages.remove(&parsed_sender_id);
            let reset = DictResetDart {
                conv_id: dec.conv_id,
                sender_id: st.sender_id,
                target_id: parsed_sender_id,
            };
            if let Ok(buf) = st.codec.encode_dict_reset(&reset) {
                let sock = transport.clone();
                tokio::spawn(async move {
                    let _ = sock.send(&buf).await;
                });
            }
            return None;
        }
    };
    let dart = DataDart {
        conv_id: dec.conv_id,
        sender_id: parsed_sender_id,
        seq,
        payload,
    };
    {
        let highest = st.highest_received.entry(dart.sender_id).or_insert(0);
        let map = st.received_messages.entry(dart.sender_id).or_insert_with(HashMap::new);
        
        if !map.contains_key(&dart.seq) {
            map.insert(dart.seq, dart.clone());
            if dart.seq > *highest {
                *highest = dart.seq;
            }
            
            if dart.payload.starts_with("User ") && dart.payload.contains(" joined ") {
                println!("\x1b[36m[SYSTEM] {}\x1b[0m", dart.payload);
            } else if !dart.payload.is_empty() {
                println!("\x1b[32m[User {}]: {}\x1b[0m", dart.sender_id, dart.payload);
            }
            
            // Process buffered packets synchronously in this stack frame for simplicity
            let mut next_seq = *highest + 1;
            while let Some(buffered) = st.out_of_order_buffer.get_mut(&dart.sender_id).and_then(|m| m.remove(&next_seq)) {
                let b_dec = match st.codec.decrypt_data(&buffered) {
                    Ok(d) => d,
                    Err(_) => break,
                };
                let dict = st.get_dictionary(dart.sender_id, next_seq);
                if b_dec.dict_fp == dict_fingerprint(&dict) {
                    if let Ok(payload) = Codec::inflate_data(&b_dec.compressed, &dict) {
                        let b_dart = DataDart {
                            conv_id: b_dec.conv_id,
                            sender_id: b_dec.sender_id,
                            seq: next_seq,
                            payload,
                        };
                        st.received_messages.get_mut(&dart.sender_id).unwrap().insert(b_dart.seq, b_dart.clone());
                        if b_dart.seq > *st.highest_received.get(&dart.sender_id).unwrap() {
                            st.highest_received.insert(dart.sender_id, b_dart.seq);
                        }
                        if !b_dart.payload.is_empty() {
                            println!("\x1b[32m[User {}]: {}\x1b[0m", b_dart.sender_id, b_dart.payload);
                        }
                    }
                }
                next_seq += 1;
            }
            
            let sock = transport.clone();
            let ack = AckDart {
                conv_id: dart.conv_id,
                sender_id: st.sender_id,
                target_id: dart.sender_id,
                seq: dart.seq,
            };
            let ack = AckDart {
                conv_id: dart.conv_id,
                sender_id: st.sender_id,
                target_id: dart.sender_id,
                seq: dart.seq,
            };
            
            // Schedule the ACK after 200ms
            if let Ok(buf) = st.codec.encode_ack(&ack) {
                let sock = transport.clone();
                return Some(tokio::spawn(async move {
                    sleep(Duration::from_millis(200)).await;
                    let _ = sock.send(&buf).await;
                }));
            }
        }
    }
    None
}
