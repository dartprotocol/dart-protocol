use rust::core::{
    codec::{advance_chain, dict_fingerprint, server_fingerprint, Codec},
    ecdh::ECDH,
    seq_delta, seq_next,
    AckDart, ChainShareDart, ChainState, DataDart, DecryptedData, DictResetDart, KeyReqDart, KeyShareDart, NackDart, SyncDart,
    DICT_WINDOW, SEQ_MOD, TYPE_ACK, TYPE_CHAIN_SHARE, TYPE_DATA, TYPE_DICT_RESET, TYPE_KEY_SHARE, TYPE_MEMBER_INFO, TYPE_NACK, TYPE_SYNC,
};
use hmac::{Hmac, KeyInit, Mac};
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

// Per-sender control-frame authentication: HMAC-SHA256 keyed with an ECDH
// derived pairwise key (SHA-256(ECDH(priv, peerPub))). Only the sender and the
// intended peer can derive it, so a third member cannot forge a frame.
type HmacSha256 = Hmac<Sha256>;

fn sign_control(frame: &[u8], key: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(frame);
    let tag = mac.finalize().into_bytes();
    let mut out = frame.to_vec();
    out.extend_from_slice(&tag);
    out
}

fn verify_control(frame: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    if frame.len() < 32 {
        return None;
    }
    let (payload, mac) = frame.split_at(frame.len() - 32);
    let mut m = HmacSha256::new_from_slice(key).ok()?;
    m.update(payload);
    let expected = m.finalize().into_bytes();
    if expected.as_slice() != mac {
        return None;
    }
    Some(payload.to_vec())
}

fn strip_control(frame: &[u8]) -> Option<Vec<u8>> {
    if frame.len() < 32 {
        return None;
    }
    Some(frame[..frame.len() - 32].to_vec())
}

fn pair_key(st: &ClientState, peer_pub: &[u8]) -> Option<Vec<u8>> {
    st.ecdh.as_ref()?.pairwise_key(peer_pub).ok()
}

fn sign_for_server(st: &ClientState, frame: &[u8]) -> Option<Vec<u8>> {
    let server_pub = st.server_pub_key.as_ref()?;
    let key = pair_key(st, server_pub)?;
    Some(sign_control(frame, &key))
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
    // Server public key (from MEMBER_INFO), used to key the server-verified
    // SYNC / Dict-Reset frames.
    server_pub_key: Option<Vec<u8>>,
    roster: HashMap<u16, HashMap<u16, Vec<u8>>>,
    shared_with: HashMap<u16, HashSet<u16>>,
    is_creator: HashMap<u16, bool>,

    // Per-sender ratchet chains: convId -> epoch -> senderId -> chain state.
    sender_chains: HashMap<u16, HashMap<u16, HashMap<u16, ChainState>>>,
    chain_shared_with: HashMap<u16, HashSet<u16>>,
    // Cached per-message keys (and chain index) by seq, for retransmission.
    message_keys: HashMap<u32, (Vec<u8>, u32)>,
    acked_seq: HashMap<u16, u32>,
    // Index-0 chain state per epoch, so a receiver that lost the chain share
    // can be given a state that reaches back to the epoch start.
    chain_seeds: HashMap<u16, HashMap<u16, ChainState>>,

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
            server_pub_key: None,
            roster: HashMap::new(),
            shared_with: HashMap::new(),
            is_creator: HashMap::new(),
            sender_chains: HashMap::new(),
            chain_shared_with: HashMap::new(),
            message_keys: HashMap::new(),
            acked_seq: HashMap::new(),
            chain_seeds: HashMap::new(),
            pending_queue: Vec::new(),
            last_send_time: Instant::now() - Duration::from_secs(10),
        }
    }

    fn get_dictionary(&self, sender_id: u16, max_seq: u32) -> Vec<u8> {
        // Delta-compress against a bounded window of the SAME sender's history
        // so both sides always build identical dictionaries (and older history
        // can be pruned). The window is selected in the modular 24-bit space
        // so it stays correct across a sequence-number wrap.
        let mut msgs = Vec::new();
        if sender_id == self.sender_id {
            for dart in self.sent_messages.values() {
                let dist = seq_delta(dart.seq, max_seq);
                if dist >= 1 && dist <= DICT_WINDOW {
                    msgs.push(dart);
                }
            }
        } else if let Some(map) = self.received_messages.get(&sender_id) {
            for dart in map.values() {
                let dist = seq_delta(dart.seq, max_seq);
                if dist >= 1 && dist <= DICT_WINDOW {
                    msgs.push(dart);
                }
            }
        }
        // Oldest-first (largest distance behind max_seq) so all
        // implementations build byte-identical dictionaries across a wrap.
        msgs.sort_by_key(|d| std::cmp::Reverse(seq_delta(d.seq, max_seq)));
        let mut res = Vec::new();
        for d in msgs {
            res.extend_from_slice(d.payload.as_bytes());
        }
        res
    }

    // Bound memory: drop history older than the dictionary window (+ slack).
    fn prune_sent(&mut self) {
        self.sent_messages.retain(|&seq, _| seq_delta(seq, self.highest_sent_seq) <= DICT_WINDOW + 16);
        self.message_keys.retain(|&seq, _| seq_delta(seq, self.highest_sent_seq) <= DICT_WINDOW + 16);
    }

    fn prune_received(&mut self, sender_id: u16) {
        let highest = self.highest_received.get(&sender_id).copied().unwrap_or(0);
        if let Some(map) = self.received_messages.get_mut(&sender_id) {
            map.retain(|&seq, _| seq_delta(seq, highest) <= DICT_WINDOW + 16);
        }
        if let Some(map) = self.nack_timestamps.get_mut(&sender_id) {
            map.retain(|&seq, _| seq_delta(seq, highest) <= DICT_WINDOW + 16);
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
            // Retry: each KeyReq makes the server re-notify the roster, which
            // is how members refresh stale pubkeys (MEMBER_INFO has no other
            // retry).
            for delay_ms in [1000u64, 2000, 3000] {
                let transport2 = transport.clone();
                let mut retry_req = req.clone();
                tokio::spawn(async move {
                    sleep(Duration::from_millis(delay_ms)).await;
                    retry_req.req_nonce = rand::random();
                    let buf2 = Codec::new().encode_key_req(&retry_req);
                    let _ = transport2.send(&buf2).await;
                });
            }
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
            let room_id = st.room_id;
            let (message_key, idx) = match send_step(&mut st, room_id) {
                Some(pair) => pair,
                None => {
                    st.pending_queue.push(text);
                    continue;
                }
            };

            let seq = st.next_seq;
            st.next_seq = seq_next(st.next_seq);
            let dart = DataDart {
                conv_id: st.room_id,
                sender_id: st.sender_id,
                seq,
                payload: text,
            };
            st.sent_messages.insert(seq, dart.clone());
            st.message_keys.insert(seq, (message_key.clone(), idx));
            st.highest_sent_seq = seq;
            st.prune_sent();

            let dict = st.get_dictionary(st.sender_id, seq);
            if let Ok(buf) = st.codec.encode_data(&dart, &dict, &message_key, idx, None) {
                transport.send(&buf).await;
                print!("\x1b[90m[↑] Sending Seq {}...\x1b[0m\r", seq);
                io::stdout().flush().unwrap();
                
                // Re-arming sync probe: while the most recent message stays
                // unacknowledged, keep probing so SYNC-driven NACK repair
                // retries under loss instead of stalling until the next rekey.
                let state_clone1 = state.clone();
                let transport_clone1 = transport.clone();
                tokio::spawn(async move {
                    sleep(Duration::from_millis(300)).await;
                    start_sync_probe(state_clone1, transport_clone1);
                });
            }
        }
    }

    Ok(())
}

fn start_sync_probe(state: Arc<Mutex<ClientState>>, transport: Transport) {
    tokio::spawn(async move {
        loop {
            let keep_going = {
                let st = state.lock().await;
                if st.highest_sent_seq == 0 {
                    false
                } else {
                    // Keep probing while the latest message stays unacknowledged.
                    seq_delta(st.highest_sent_seq, *st.acked_seq.get(&st.room_id).unwrap_or(&0)) >= SEQ_MOD / 2
                }
            };
            send_sync(state.clone(), transport.clone()).await;
            if !keep_going {
                break;
            }
            sleep(Duration::from_millis(1000)).await;
        }
    });
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
    if let Ok(buf) = st.codec.encode_sync(&sync, None) {
        if let Some(signed) = sign_for_server(&st, &buf) {
            let _ = transport.send(&signed).await;
        }
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
    if let Some(prev) = st.roster.get(&info.conv_id) {
        // A member whose pubkey changed (reconnect with a fresh ECDH keypair)
        // needs fresh group-key and chain shares under the new key; drop the
        // shared-with flags so the shares are re-sent.
        for (sid, key) in &roster {
            if let Some(prev_pub) = prev.get(sid) {
                if prev_pub != key {
                    if let Some(done) = st.shared_with.get_mut(&info.conv_id) {
                        done.remove(sid);
                    }
                    if let Some(done) = st.chain_shared_with.get_mut(&info.conv_id) {
                        done.remove(sid);
                    }
                }
            }
        }
    }
    st.roster.insert(info.conv_id, roster);
    st.server_pub_key = Some(server_pub);
    let prev_creator = *st.is_creator.get(&info.conv_id).unwrap_or(&false);
    st.is_creator.insert(info.conv_id, info.creator);

    if st.codec.conv_keys.contains_key(&info.conv_id) {
        share_with_new_members(st, transport, info.conv_id);
    } else if info.creator {
        let key: [u8; 32] = rand::random();
        return adopt_key(st, transport, info.conv_id, 1, key.to_vec());
    }
    // If I just became the creator (successor election after the previous
    // creator left), rotate immediately so the departed member loses access.
    if info.creator && !prev_creator && st.codec.conv_keys.contains_key(&info.conv_id) {
        rekey(st, transport, info.conv_id);
    }
    // Share my ratchet chain with any members that just joined.
    let epoch = *st.codec.current_epochs.get(&info.conv_id).unwrap_or(&1);
    share_chain_with_members(st, transport, info.conv_id, epoch);
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
    let cur_key = st.codec.conv_keys.get(&conv_id).cloned();
    // Adopt on first join, on a newer epoch, or on an equal epoch with a
    // DIFFERENT key (a restarted creator re-uses epoch 1 with a fresh key).
    if !st.codec.conv_keys.contains_key(&conv_id) || epoch > current
        || (epoch == current && cur_key.map(|k| k != group_key).unwrap_or(false))
    {
        return adopt_key(st, transport, conv_id, epoch, group_key);
    }
    None
}

// ---- Per-sender ratchet chain management ----

fn get_chain(st: &ClientState, conv_id: u16, epoch: u16, sender_id: u16) -> Option<ChainState> {
    st.sender_chains.get(&conv_id)?.get(&epoch)?.get(&sender_id).cloned()
}

fn set_chain(st: &mut ClientState, conv_id: u16, epoch: u16, sender_id: u16, state: ChainState) {
    st.sender_chains.entry(conv_id).or_default()
        .entry(epoch).or_default()
        .insert(sender_id, state);
}

// Derive a per-message key from my own chain (advancing it) for a send.
fn send_step(st: &mut ClientState, conv_id: u16) -> Option<(Vec<u8>, u32)> {
    let epoch = *st.codec.current_epochs.get(&conv_id).unwrap_or(&1);
    let chain = get_chain(st, conv_id, epoch, st.sender_id)?;
    let idx = chain.index;
    let (message_key, state) = advance_chain(&chain, idx);
    set_chain(st, conv_id, epoch, st.sender_id, state);
    Some((message_key, idx))
}

// Generate a fresh chain seed for my own sends in `epoch` and share it with
// every member (so they can decrypt my future messages).
fn init_own_chain(st: &mut ClientState, transport: &Transport, conv_id: u16, epoch: u16) {
    let seed: [u8; 32] = rand::random();
    set_chain(st, conv_id, epoch, st.sender_id, ChainState { key: seed.to_vec(), index: 0 });
    st.chain_seeds.entry(conv_id).or_default().insert(epoch, ChainState { key: seed.to_vec(), index: 0 });
    st.chain_shared_with.insert(conv_id, HashSet::new());
    share_chain_with_members(st, transport, conv_id, epoch);
}

fn share_chain_with_members(st: &mut ClientState, transport: &Transport, conv_id: u16, epoch: u16) {
    let my_chain = match get_chain(st, conv_id, epoch, st.sender_id) {
        Some(c) => c,
        None => return,
    };
    let roster = match st.roster.get(&conv_id) {
        Some(r) => r.clone(),
        None => return,
    };
    let mut targets = Vec::new();
    {
        let done = st.chain_shared_with.entry(conv_id).or_default();
        for m_id in roster.keys() {
            if *m_id == st.sender_id || done.contains(m_id) {
                continue;
            }
            targets.push(*m_id);
            done.insert(*m_id);
        }
    }
    if targets.is_empty() {
        return;
    }
    let ecdh = st.ecdh.as_ref().unwrap();
    let mut bufs = Vec::new();
    for m_id in &targets {
        let m_pub = &roster[m_id];
        if let Some(buf) = build_chain_share(st, ecdh, conv_id, epoch, *m_id, m_pub, &my_chain.key, my_chain.index) {
            bufs.push(buf);
        }
    }
    // Send now, then retry a couple of times with the SAME bytes (idempotent):
    // the shares go over UDP and a receiver that misses its only copy can
    // never decrypt this sender's messages.
    let send_all = {
        let sock = transport.clone();
        let bs = bufs.clone();
        tokio::spawn(async move {
            for b in bs {
                let s = sock.clone();
                tokio::spawn(async move { let _ = s.send(&b).await; });
            }
        })
    };
    let _ = send_all;
    for ms in [300u64, 1000] {
        let bs = bufs.clone();
        let sock = transport.clone();
        tokio::spawn(async move {
            sleep(Duration::from_millis(ms)).await;
            for b in bs {
                let s = sock.clone();
                tokio::spawn(async move { let _ = s.send(&b).await; });
            }
        });
    }
}

fn build_chain_share(
    st: &ClientState,
    ecdh: &ECDH,
    conv_id: u16,
    epoch: u16,
    target_id: u16,
    target_pub: &[u8],
    chain_key: &[u8],
    chain_index: u32,
) -> Option<Vec<u8>> {
    let shared = ecdh.compute_secret(target_pub).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&shared);
    let transport_key = hasher.finalize();
    let share = ChainShareDart {
        conv_id,
        sender_id: st.sender_id,
        target_id,
        epoch,
        nonce: rand::random(),
        chain_key: chain_key.to_vec(),
        chain_index,
    };
    st.codec.encode_chain_share(&share, &transport_key).ok()
}

fn handle_chain_share(st: &mut ClientState, msg: &[u8]) {
    if msg.len() < 7 {
        return;
    }
    let conv_id = u16::from_be_bytes([msg[1], msg[2]]);
    let sender_id = u16::from_be_bytes([msg[3], msg[4]]);
    let target_id = u16::from_be_bytes([msg[5], msg[6]]);
    if target_id != st.sender_id {
        return;
    }
    let sharer_pub = match st.roster.get(&conv_id).and_then(|r| r.get(&sender_id)) {
        Some(p) => p.clone(),
        None => return,
    };
    let ecdh = match st.ecdh.as_ref() {
        Some(e) => e,
        None => return,
    };
    let shared = match ecdh.compute_secret(&sharer_pub) {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut hasher = Sha256::new();
    hasher.update(&shared);
    let transport_key = hasher.finalize();
    let decoded = match st.codec.decode_chain_share(msg, &transport_key) {
        Ok(d) => d,
        Err(_) => return,
    };
    set_chain(st, conv_id, decoded.epoch, decoded.sender_id, ChainState { key: decoded.chain_key, index: decoded.chain_index });
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
    // Start a fresh per-sender ratchet chain for this epoch and share it.
    init_own_chain(st, transport, conv_id, epoch);

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
        if let Some((message_key, idx)) = send_step(st, conv_id) {
            if let Ok(buf) = st.codec.encode_data(&dart, &dict, &message_key, idx, None) {
                let sock = transport.clone();
                let mut queue = Vec::new();
                std::mem::swap(&mut queue, &mut st.pending_queue);
                task = Some(tokio::spawn(async move {
                    let _ = sock.send(&buf).await;
                }));
            }
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
    let mut targets = Vec::new();
    for (m_id, m_pub) in &roster {
        if *m_id == st.sender_id || done.contains(m_id) {
            continue;
        }
        targets.push((*m_id, m_pub.clone()));
        done.insert(*m_id);
    }
    st.shared_with.insert(conv_id, done);
    if targets.is_empty() {
        return;
    }
    let mut bufs = Vec::new();
    for (m_id, m_pub) in &targets {
        if let Ok(shared) = ecdh.compute_secret(m_pub) {
            let mut hasher = Sha256::new();
            hasher.update(&shared);
            let transport_key = hasher.finalize();
            let share = KeyShareDart {
                conv_id,
                sender_id: st.sender_id,
                target_id: *m_id,
                epoch,
                nonce: rand::random(),
                encrypted_key: key.clone(),
            };
            if let Ok(buf) = st.codec.encode_key_share(&share, &transport_key) {
                bufs.push(buf);
            }
        }
    }
    // Send now, then retry a couple of times with the SAME bytes (idempotent):
    // the group-key share goes over UDP and can be lost; a member that misses
    // it can't adopt the key or join the room.
    let send_all = {
        let sock = transport.clone();
        let bs = bufs.clone();
        tokio::spawn(async move {
            for b in bs {
                let s = sock.clone();
                tokio::spawn(async move { let _ = s.send(&b).await; });
            }
        })
    };
    let _ = send_all;
    for ms in [300u64, 1000] {
        let bs = bufs.clone();
        let sock = transport.clone();
        tokio::spawn(async move {
            sleep(Duration::from_millis(ms)).await;
            for b in bs {
                let s = sock.clone();
                tokio::spawn(async move { let _ = s.send(&b).await; });
            }
        });
    }
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
            if msg.len() < 7 + 24 || msg[6] < 24 {
                return None;
            }
            let conv_id = u16::from_be_bytes([msg[1], msg[2]]);
            let seq = (msg[3] as u32) << 16 | (msg[4] as u32) << 8 | (msg[5] as u32);
            let parsed_sender_id = u16::from_be_bytes([msg[7], msg[8]]);

            let has_baseline = st.highest_received.contains_key(&parsed_sender_id);
            let highest_received = *st.highest_received.get(&parsed_sender_id).unwrap_or(&0);
            
            // Modular gap test: 0 = duplicate, >= SEQ_MOD/2 = stale, 1 = exact
            // next. A receiver with no baseline yet treats the first packet as
            // its baseline, except when the first seq is within the recoverable
            // window: then NACK the real gap instead of an out-of-order start.
            let ahead = if has_baseline {
                seq_delta(highest_received, seq)
            } else if seq >= 1 && seq <= DICT_WINDOW {
                seq
            } else {
                1
            };
            if ahead == 0 || ahead >= SEQ_MOD / 2 {
                return None;
            }

            if ahead > 1 {
                st.out_of_order_buffer
                    .entry(parsed_sender_id)
                    .or_insert_with(HashMap::new)
                    .insert(seq, msg.to_vec());
                    
                let mut missing = Vec::new();
                for k in 1..ahead {
                    let i = (highest_received + k) & 0xFFFFFF;
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
                    let nack = NackDart { conv_id, sender_id: st.sender_id, target_id: parsed_sender_id, missing_seq: missing };
                    if let Ok(buf) = st.codec.encode_nack(&nack, None) {
                        if let Some(peer_pub) = st.roster.get(&conv_id).and_then(|r| r.get(&parsed_sender_id)).cloned() {
                            if let Some(key) = pair_key(st, &peer_pub) {
                                let signed = sign_control(&buf, &key);
                                let sock = transport.clone();
                                return Some(tokio::spawn(async move { let _ = sock.send(&signed).await; }));
                            }
                        }
                    }
                }
                return None;
            }

            // Exact next packet: decrypt in order, then drain the buffer.
            return match decrypt_data_in_order(st, msg, parsed_sender_id) {
                Some(dec) => process_data_packet(msg, dec, parsed_sender_id, seq, st, transport),
                None => None,
            };
        }

        TYPE_CHAIN_SHARE => {
            handle_chain_share(st, msg);
        }
        
        TYPE_NACK => {
            if msg.len() < 7 {
                return None;
            }
            let nack_conv_id = u16::from_be_bytes([msg[1], msg[2]]);
            let nack_sender_id = u16::from_be_bytes([msg[3], msg[4]]);
            let nack_target_id = u16::from_be_bytes([msg[5], msg[6]]);
            if nack_target_id != st.sender_id {
                return None;
            }
            // Verify the sender's per-sender MAC so a group member can't forge
            // another member's NACK.
            let peer_pub = match st.roster.get(&nack_conv_id).and_then(|r| r.get(&nack_sender_id)) {
                Some(p) => p.clone(),
                None => return None,
            };
            let key = match pair_key(st, &peer_pub) {
                Some(k) => k,
                None => return None,
            };
            let stripped = match verify_control(msg, &key) {
                Some(s) => s,
                None => return None,
            };
            if let Ok(nack) = st.codec.decode_nack(&stripped) {
                println!("\x1b[33m[SYSTEM] Receiver missed seqs {:?}. Sending NACK repairs...\x1b[0m", nack.missing_seq);
                for seq in nack.missing_seq {
                    if let Some(dart) = st.sent_messages.get(&seq) {
                        if let Some((message_key, idx)) = st.message_keys.get(&seq).cloned() {
                            let dict = st.get_dictionary(st.sender_id, seq);
                            if let Ok(out_buf) = st.codec.encode_data(dart, &dict, &message_key, idx, None) {
                                let sock = transport.clone();
                                tokio::spawn(async move { let _ = sock.send(&out_buf).await; });
                            }
                        }
                    }
                }
                // The NACKer likely missed the chain share too (it can't
                // decrypt my stream without one). Re-share the chain SEED
                // (index 0) so it can reach back and decrypt the whole epoch,
                // not just future messages.
                let epoch = *st.codec.current_epochs.get(&nack_conv_id).unwrap_or(&1);
                if let Some(seed) = st.chain_seeds.get(&nack_conv_id).and_then(|m| m.get(&epoch)) {
                    let seed = seed.clone();
                    if let Some(share_buf) = build_chain_share(
                        st, &st.ecdh.as_ref().unwrap().clone(), nack_conv_id, epoch,
                        nack_sender_id, &peer_pub, &seed.key, seed.index,
                    ) {
                        let sock = transport.clone();
                        tokio::spawn(async move { let _ = sock.send(&share_buf).await; });
                    }
                }
            }
        }
        
        TYPE_SYNC => {
            // SYNC is keyed to the relay server, which verified and relayed it.
            let stripped = match strip_control(msg) {
                Some(s) => s,
                None => return None,
            };
            if let Ok(sync) = st.codec.decode_sync(&stripped) {
                let has_baseline = st.highest_received.contains_key(&sync.sender_id);
                let highest_received = *st.highest_received.get(&sync.sender_id).unwrap_or(&0);
                // Fresh receiver: NACK the whole reported range; otherwise only
                // the modular distance ahead of what we've seen (handles wraps).
                let ahead = if has_baseline { seq_delta(highest_received, sync.highest_seq) } else { sync.highest_seq };
                if ahead > 0 && ahead < SEQ_MOD / 2 {
                    let mut missing = Vec::new();
                    for k in 1..=ahead {
                        let i = (highest_received + k) & 0xFFFFFF;
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
                        let nack = NackDart { conv_id: sync.conv_id, sender_id: st.sender_id, target_id: sync.sender_id, missing_seq: missing };
                        if let Ok(buf) = st.codec.encode_nack(&nack, None) {
                            if let Some(peer_pub) = st.roster.get(&sync.conv_id).and_then(|r| r.get(&sync.sender_id)).cloned() {
                                if let Some(key) = pair_key(st, &peer_pub) {
                                    let signed = sign_control(&buf, &key);
                                    let sock = transport.clone();
                                    tokio::spawn(async move { let _ = sock.send(&signed).await; });
                                }
                            }
                        }
                    }
                }
            }
        }
        
        TYPE_ACK => {
            if msg.len() < 7 {
                return None;
            }
            let ack_conv_id = u16::from_be_bytes([msg[1], msg[2]]);
            let ack_sender_id = u16::from_be_bytes([msg[3], msg[4]]);
            let ack_target_id = u16::from_be_bytes([msg[5], msg[6]]);
            if ack_target_id != st.sender_id {
                return None;
            }
            let peer_pub = match st.roster.get(&ack_conv_id).and_then(|r| r.get(&ack_sender_id)) {
                Some(p) => p.clone(),
                None => return None,
            };
            let key = match pair_key(st, &peer_pub) {
                Some(k) => k,
                None => return None,
            };
            let stripped = match verify_control(msg, &key) {
                Some(s) => s,
                None => return None,
            };
            if let Ok(ack) = st.codec.decode_ack(&stripped) {
                if seq_delta(st.highest_sent_seq, ack.seq) < SEQ_MOD / 2 {
                    st.acked_seq.insert(ack.conv_id, ack.seq);
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
            // Dict-Reset is keyed to the relay server, which verified it.
            let stripped = match strip_control(msg) {
                Some(s) => s,
                None => return None,
            };
            if let Ok(reset) = st.codec.decode_dict_reset(&stripped) {
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
    let d = seq_delta(*highest, lost_seq);
    if d > 0 && d < SEQ_MOD / 2 {
        *highest = lost_seq;
    }
    
    st.received_messages.insert(sender_id, HashMap::new());
    st.out_of_order_buffer.insert(sender_id, HashMap::new());
    
    let reset = DictResetDart {
        conv_id,
        sender_id: st.sender_id,
        target_id: sender_id,
    };
    if let Ok(buf) = st.codec.encode_dict_reset(&reset, None) {
        if let Some(signed) = sign_for_server(st, &buf) {
            let sock = transport.clone();
            tokio::spawn(async move {
                let _ = sock.send(&signed).await;
            });
        }
    }
}

// Decrypts a data packet with the sender's ratchet chain, advancing the chain
// to the packet's message index. Commits the advanced state only after a
// successful decrypt.
fn decrypt_data_in_order(st: &mut ClientState, msg: &[u8], sender_id: u16) -> Option<DecryptedData> {
    let epoch = u16::from_be_bytes([msg[21], msg[22]]);
    let idx = u32::from_be_bytes([msg[27], msg[28], msg[29], msg[30]]);
    let conv_id = u16::from_be_bytes([msg[1], msg[2]]);
    let chain = get_chain(st, conv_id, epoch, sender_id)?;
    if idx < chain.index {
        return None;
    }
    let (message_key, state) = advance_chain(&chain, idx);
    match st.codec.decrypt_data(msg, &message_key) {
        Ok(dec) => {
            set_chain(st, conv_id, epoch, sender_id, state);
            Some(dec)
        }
        Err(_) => None,
    }
}

fn process_data_packet(
    msg: &[u8],
    dec: DecryptedData,
    parsed_sender_id: u16, 
    seq: u32, 
    st: &mut ClientState,
    transport: &Transport
) -> Option<tokio::task::JoinHandle<()>> {
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
        if let Ok(buf) = st.codec.encode_dict_reset(&reset, None) {
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
            if let Ok(buf) = st.codec.encode_dict_reset(&reset, None) {
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
        let has_baseline = st.highest_received.contains_key(&dart.sender_id);
        let highest = st.highest_received.entry(dart.sender_id).or_insert(0);
        let map = st.received_messages.entry(dart.sender_id).or_insert_with(HashMap::new);
        
        if !map.contains_key(&dart.seq) {
            map.insert(dart.seq, dart.clone());
            let d = if has_baseline { seq_delta(*highest, dart.seq) } else { 1 };
            if d > 0 && d < SEQ_MOD / 2 {
                *highest = dart.seq;
            }
            
            if dart.payload.starts_with("User ") && dart.payload.contains(" joined ") {
                println!("\x1b[36m[SYSTEM] {}\x1b[0m", dart.payload);
            } else if !dart.payload.is_empty() {
                println!("\x1b[32m[User {}]: {}\x1b[0m", dart.sender_id, dart.payload);
            }
            
            // Process buffered packets synchronously in this stack frame for simplicity
            let mut next_seq = seq_next(*highest);
            loop {
                let buffered = {
                    let buf = st.out_of_order_buffer.get_mut(&dart.sender_id).and_then(|m| m.remove(&next_seq));
                    match buf {
                        Some(b) => b,
                        None => break,
                    }
                };
                let b_dec = match decrypt_data_in_order(st, &buffered, dart.sender_id) {
                    Some(d) => d,
                    None => break,
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
                        let h = *st.highest_received.get(&dart.sender_id).unwrap();
                        let bd = seq_delta(h, b_dart.seq);
                        if bd > 0 && bd < SEQ_MOD / 2 {
                            st.highest_received.insert(dart.sender_id, b_dart.seq);
                        }
                        if !b_dart.payload.is_empty() {
                            println!("\x1b[32m[User {}]: {}\x1b[0m", b_dart.sender_id, b_dart.payload);
                        }
                    }
                }
                next_seq = seq_next(next_seq);
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
            if let Ok(buf) = st.codec.encode_ack(&ack, None) {
                if let Some(peer_pub) = st.roster.get(&dart.conv_id).and_then(|r| r.get(&dart.sender_id)).cloned() {
                    if let Some(key) = pair_key(st, &peer_pub) {
                        let signed = sign_control(&buf, &key);
                        let sock = transport.clone();
                        return Some(tokio::spawn(async move {
                            sleep(Duration::from_millis(200)).await;
                            let _ = sock.send(&signed).await;
                        }));
                    }
                }
            }
        }
    }
    None
}
