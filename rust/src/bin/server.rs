use rust::core::{
    codec::{server_fingerprint, Codec},
    ecdh::ECDH,
    seq_delta,
    Member, MemberInfo,
    SEQ_MOD, TYPE_ACK, TYPE_CHAIN_SHARE, TYPE_DATA, TYPE_DICT_RESET, TYPE_KEY_REQ, TYPE_KEY_SHARE, TYPE_MEMBER_INFO, TYPE_NACK, TYPE_SYNC,
};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{RwLock, mpsc},
};
use rand::Rng;
use futures_util::{StreamExt, SinkExt};
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;

// Per-sender control-frame authentication: HMAC-SHA256 keyed with an ECDH
// derived pairwise key. The server is keyed into every SYNC / Dict-Reset frame
// (sender -> server) and verifies them before relaying, so a group member
// can't forge another member's broadcast control frames.
type HmacSha256 = Hmac<Sha256>;

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

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum PeerId {
    Udp(SocketAddr),
    Ws(SocketAddr),
    Tcp(SocketAddr),
}

struct ServerState {
    ecdh: ECDH,
    rooms: HashMap<u16, HashSet<PeerId>>,
    client_map: HashMap<u16, HashMap<u16, PeerId>>,
    peer_ids: HashMap<PeerId, u16>,
    members: HashMap<u16, HashMap<u16, Vec<u8>>>, // blind: public membership only
    creator: HashMap<u16, u16>,                   // first member (generates/rotates the key)
    message_cache: HashMap<u16, HashMap<u16, HashMap<u32, Vec<u8>>>>,
    highest_seq: HashMap<u16, HashMap<u16, u32>>,
    conv_keys: HashMap<u16, [u8; 32]>,
    rate_limits: HashMap<PeerId, (Instant, u32)>,
    stream_peers: HashMap<PeerId, mpsc::UnboundedSender<Vec<u8>>>,
}

impl ServerState {
    fn new(ecdh: ECDH) -> Self {
        Self {
            ecdh,
            rooms: HashMap::new(),
            client_map: HashMap::new(),
            peer_ids: HashMap::new(),
            members: HashMap::new(),
            creator: HashMap::new(),
            message_cache: HashMap::new(),
            highest_seq: HashMap::new(),
            conv_keys: HashMap::new(),
            rate_limits: HashMap::new(),
            stream_peers: HashMap::new(),
        }
    }
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

// load_or_create_server_key loads the server's long-term ECDH key from disk
// (hex of the 32-byte P-256 scalar) so its public-key fingerprint is stable
// across restarts — required for clients to pin it.
fn load_or_create_server_key() -> ECDH {
    let key_file = std::env::var("DART_SERVER_KEY_FILE").unwrap_or_else(|_| "dart_server.key".to_string());
    if let Ok(data) = std::fs::read_to_string(&key_file) {
        if let Some(bytes) = from_hex(data.trim()) {
            if let Ok(ecdh) = ECDH::from_private_key(&bytes) {
                return ecdh;
            }
        }
        println!("Could not load server key from {}; generating a new one.", key_file);
    }
    let ecdh = ECDH::new();
    let _ = std::fs::write(&key_file, to_hex(&ecdh.private_key_bytes()));
    ecdh
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let port = 9000;
    
    let udp_socket = Arc::new(UdpSocket::bind(format!("0.0.0.0:{}", port)).await?);
    println!("Dart Protocol Rust Server listening on UDP {}", port);

    let server_ecdh = load_or_create_server_key();
    let fp = server_fingerprint(&server_ecdh.get_public_key());
    println!("Server key fingerprint: {}", fp);
    println!("  -> Pin it in clients (e.g. DART_SERVER_FINGERPRINT={}) to prevent MITM on key exchange.", fp);

    let ws_listener = TcpListener::bind("0.0.0.0:9002").await?;
    println!("Dart Protocol Rust Server listening on TCP (WebSocket) 9002");

    let tcp_fallback_listener = TcpListener::bind("0.0.0.0:9001").await?;
    println!("Dart Protocol Rust Server listening on TCP fallback 9001");

    let state = Arc::new(RwLock::new(ServerState::new(server_ecdh)));

    // UDP Listener Task
    let udp_sock_clone = Arc::clone(&udp_socket);
    let state_clone = Arc::clone(&state);
    
    tokio::spawn(async move {
        let mut buf = [0u8; 65535];
        loop {
            if let Ok((len, addr)) = udp_sock_clone.recv_from(&mut buf).await {
                let msg = buf[..len].to_vec();
                if !msg.is_empty() {
                    let s = Arc::clone(&state_clone);
                    let sock = Arc::clone(&udp_sock_clone);
                    tokio::spawn(async move {
                        handle_message(msg, PeerId::Udp(addr), s, sock).await;
                    });
                }
            }
        }
    });

    // TCP fallback listener: 2-byte big-endian length framing (Node-compatible)
    let state_tcp = Arc::clone(&state);
    let sock_tcp = Arc::clone(&udp_socket);
    tokio::spawn(async move {
        loop {
            let (stream, addr) = match tcp_fallback_listener.accept().await {
                Ok(x) => x,
                Err(_) => continue,
            };
            let s = Arc::clone(&state_tcp);
            let u = Arc::clone(&sock_tcp);
            tokio::spawn(async move {
                handle_tcp_conn(stream, addr, s, u).await;
            });
        }
    });

    // TCP/WebSocket Listener Task
    let state_ws = Arc::clone(&state);
    let sock_ws = Arc::clone(&udp_socket);
    tokio::spawn(async move {
        loop {
            let (stream, addr) = match ws_listener.accept().await {
                Ok(x) => x,
                Err(_) => continue,
            };
            let state_ws2 = Arc::clone(&state_ws);
            let sock_ws2 = Arc::clone(&sock_ws);
            tokio::spawn(async move {
                if let Ok(ws_stream) = accept_async(stream).await {
                    let peer_id = PeerId::Ws(addr);
                    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
                    
                    {
                        let mut s = state_ws2.write().await;
                        s.stream_peers.insert(peer_id.clone(), tx);
                    }
                    
                    let (mut write, mut read) = ws_stream.split();
                    
                    // WS Writer task
                    let peer_id_clone = peer_id.clone();
                    let state_writer = Arc::clone(&state_ws2);
                    let sock_writer = Arc::clone(&sock_ws2);
                    tokio::spawn(async move {
                        while let Some(msg) = rx.recv().await {
                            if write.send(Message::Binary(msg)).await.is_err() {
                                break;
                            }
                        }
                        // Cleanup on disconnect
                        cleanup_peer(&peer_id_clone, &state_writer, &sock_writer).await;
                    });

                    // WS Reader loop
                    while let Some(Ok(msg)) = read.next().await {
                        if let Message::Binary(bin) = msg {
                            let s = Arc::clone(&state_ws2);
                            let u = Arc::clone(&sock_ws2);
                            let p = peer_id.clone();
                            tokio::spawn(async move {
                                handle_message(bin, p, s, u).await;
                            });
                        }
                    }
                }
            });
        }
    });

    // Keep the process alive
    loop {
        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
}

// TCP fallback connection: reads 2-byte big-endian length-prefixed frames and
// feeds them through the normal message path as a Tcp peer.
async fn handle_tcp_conn(
    stream: TcpStream,
    addr: SocketAddr,
    state: Arc<RwLock<ServerState>>,
    socket: Arc<UdpSocket>,
) {
    let peer_id = PeerId::Tcp(addr);
    let (mut read, mut write) = stream.into_split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    {
        let mut s = state.write().await;
        s.stream_peers.insert(peer_id.clone(), tx);
    }

    // Writer task: 2-byte big-endian length prefix + payload
    let peer_id_w = peer_id.clone();
    let state_w = Arc::clone(&state);
    let sock_w = Arc::clone(&socket);
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let len = msg.len() as u16;
            let mut out = Vec::with_capacity(2 + msg.len());
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(&msg);
            if write.write_all(&out).await.is_err() {
                break;
            }
        }
        cleanup_peer(&peer_id_w, &state_w, &sock_w).await;
    });

    // Reader loop
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        match read.read(&mut tmp).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
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
                    let s = Arc::clone(&state);
                    let u = Arc::clone(&socket);
                    let p = peer_id.clone();
                    tokio::spawn(async move {
                        handle_message(payload, p, s, u).await;
                    });
                }
            }
        }
    }

    cleanup_peer(&peer_id, &state, &socket).await;
}

// Removes a peer on disconnect and notifies remaining members so they re-key.
async fn cleanup_peer(peer_id: &PeerId, state: &Arc<RwLock<ServerState>>, socket: &Arc<UdpSocket>) {
    let removed = {
        let mut s = state.write().await;
        s.stream_peers.remove(peer_id);
        let mut convs = Vec::new();
        for (conv, peers) in s.rooms.iter_mut() {
            if peers.remove(peer_id) {
                convs.push(*conv);
            }
        }
        if let Some(sid) = s.peer_ids.remove(peer_id) {
            for conv in &convs {
                if let Some(mems) = s.members.get_mut(conv) {
                    mems.remove(&sid);
                }
                // If the creator left, elect a successor (the smallest remaining
                // senderId) so key rotation continues after the creator is gone.
                if s.creator.get(conv) == Some(&sid) {
                    let remaining: Vec<u16> = s.members.get(conv).map(|m| m.keys().copied().collect()).unwrap_or_default();
                    if remaining.is_empty() {
                        s.creator.remove(conv);
                    } else {
                        let successor = remaining.into_iter().min().unwrap();
                        s.creator.insert(*conv, successor);
                    }
                }
            }
        }
        convs
    };
    for conv in removed {
        notify_members(conv, state, socket).await;
    }
}

async fn send_to_peer(
    msg: &[u8],
    peer: &PeerId,
    state: &Arc<RwLock<ServerState>>,
    socket: &Arc<UdpSocket>,
) {
    match peer {
        PeerId::Udp(addr) => {
            let _ = socket.send_to(msg, *addr).await;
        }
        PeerId::Ws(_) | PeerId::Tcp(_) => {
            let s = state.read().await;
            if let Some(tx) = s.stream_peers.get(peer) {
                let _ = tx.send(msg.to_vec());
            }
        }
    }
}

// Broadcasts the current roster (encrypted per member) to every member.
async fn notify_members(conv_id: u16, state: &Arc<RwLock<ServerState>>, socket: &Arc<UdpSocket>) {
    let (server_pub, roster) = {
        let s = state.read().await;
        let ecdh = s.ecdh.clone();
        let pubk = ecdh.get_public_key();
        let mems = match s.members.get(&conv_id) {
            Some(m) => m.clone(),
            None => return,
        };
        let roster: Vec<Member> = mems
            .iter()
            .map(|(&sid, pk)| Member { sender_id: sid, pub_key: pk.clone() })
            .collect();
        (pubk, roster)
    };
    for (m_sender_id, m_pub) in {
        let s = state.read().await;
        s.members.get(&conv_id).cloned().unwrap_or_default()
    } {
        let shared = match state.read().await.ecdh.compute_secret(&m_pub) {
            Ok(x) => x,
            Err(_) => continue,
        };
        let mut hasher = Sha256::new();
        hasher.update(&shared);
        let transport_key = hasher.finalize();
        let creator = {
            let s = state.read().await;
            s.creator.get(&conv_id) == Some(&m_sender_id)
        };
        let info = MemberInfo {
            conv_id,
            sender_id: m_sender_id,
            server_pub_key: server_pub.clone(),
            creator,
            members: roster.clone(),
        };
        let codec = Codec::new();
        if let Ok(out) = codec.encode_member_info(&info, &transport_key, None) {
            let target = {
                let s = state.read().await;
                s.client_map.get(&conv_id).and_then(|m| m.get(&m_sender_id)).cloned()
            };
            if let Some(p) = target {
                send_to_peer(&out, &p, state, socket).await;
            }
        }
    }
}

async fn handle_message(
    msg: Vec<u8>,
    peer_id: PeerId,
    state: Arc<RwLock<ServerState>>,
    socket: Arc<UdpSocket>,
) {
    if msg.is_empty() {
        return;
    }

    {
        let mut s = state.write().await;
        let now = Instant::now();
        let entry = s.rate_limits.entry(peer_id.clone()).or_insert((now, 0));
        if now.duration_since(entry.0) > Duration::from_secs(1) {
            entry.0 = now;
            entry.1 = 0;
        }
        entry.1 += 1;
        if entry.1 > 500 {
            return;
        }
    }

    let typ = msg[0];
    if msg.len() < 3 {
        return;
    }
    let conv_id = u16::from_be_bytes([msg[1], msg[2]]);

    let mut codec = Codec::new();
    {
        let s = state.read().await;
        if let Some(key) = s.conv_keys.get(&conv_id) {
            codec.conv_keys.insert(conv_id, key.to_vec());
        }
    }

    {
        let mut s = state.write().await;
        s.rooms.entry(conv_id).or_default().insert(peer_id.clone());
        if typ != TYPE_DATA && msg.len() >= 5 {
            let sender_id = u16::from_be_bytes([msg[3], msg[4]]);
            s.peer_ids.insert(peer_id.clone(), sender_id);
            s.client_map
                .entry(conv_id)
                .or_default()
                .insert(sender_id, peer_id.clone());
        }
    }

    match typ {
        TYPE_DATA => {
            if msg.len() < 7 {
                return;
            }
            let sender_id = {
                let s = state.read().await;
                match s.peer_ids.get(&peer_id) {
                    Some(&sid) => sid,
                    None => {
                        println!("[Server] Dropping DataDart from unknown peer {:?} (no key exchange seen).", peer_id);
                        return;
                    }
                }
            };
            let seq = (msg[3] as u32) << 16 | (msg[4] as u32) << 8 | (msg[5] as u32);
            println!("[Server] DataDart Conv:{} Sender:{} Seq:{}", conv_id, sender_id, seq);

            let mut group = Vec::new();
            
            {
                let mut s = state.write().await;
                
                let has_baseline = s.highest_seq.get(&conv_id).map_or(false, |m| m.contains_key(&sender_id));
                let current_highest = *s.highest_seq.entry(conv_id).or_default().entry(sender_id).or_default();
                s.message_cache.entry(conv_id).or_default().entry(sender_id).or_default().insert(seq, msg.clone());

                // Modular gap test: 0 = duplicate, >= SEQ_MOD/2 = stale, 1 = exact
                // next. A fresh server (no baseline yet) treats the first packet
                // as its baseline so joining mid-conversation (even near a wrap)
                // still works.
                let ahead = if has_baseline { seq_delta(current_highest, seq) } else { 1 };

                // GC: keep the last 200 packets around the modularly-newer seq
                // so pruning stays correct across a wrap.
                let ref_seq = if ahead >= SEQ_MOD / 2 { current_highest } else { seq };
                let cache = s.message_cache.get_mut(&conv_id).unwrap().get_mut(&sender_id).unwrap();
                cache.retain(|&k, _| seq_delta(k, ref_seq) <= 200);

                // The server is blind (no group key / no member signing key), so
                // it does not originate NACKs; loss recovery happens through
                // member-signed NACKs, which the server repairs from cache or
                // relays verbatim.
                if ahead > 0 && ahead < SEQ_MOD / 2 {
                    s.highest_seq.get_mut(&conv_id).unwrap().insert(sender_id, seq);
                }

                if let Some(room_peers) = s.rooms.get(&conv_id) {
                    for p in room_peers {
                        if *p != peer_id {
                            group.push(p.clone());
                        }
                    }
                }
            }

            for p in group {
                send_to_peer(&msg, &p, &state, &socket).await;
            }
        }

        TYPE_KEY_REQ => {
            let req = match codec.decode_key_req(&msg) {
                Ok(r) => r,
                Err(_) => return,
            };
            println!("[Server] KeyReq Conv:{} Sender:{}", req.conv_id, req.sender_id);

            // The server is BLIND: it never sees or stores group keys. It only
            // tracks public membership and relays opaque key shares.
            let server_ecdh = state.read().await.ecdh.clone();
            {
                let mut s = state.write().await;
                let first = s.members.get(&req.conv_id).map_or(true, |m| m.is_empty());
                if first {
                    s.creator.insert(req.conv_id, req.sender_id);
                }
                s.members.entry(req.conv_id).or_default().insert(req.sender_id, req.client_pub_key.clone());
            }
            notify_members(req.conv_id, &state, &socket).await;
        }

        TYPE_KEY_SHARE | TYPE_CHAIN_SHARE => {
            // Relay the (opaque, encrypted) key / ratchet-chain share to its target.
            if msg.len() < 7 {
                return;
            }
            let target_id = u16::from_be_bytes([msg[5], msg[6]]);
            let target_peer = {
                let s = state.read().await;
                s.client_map.get(&conv_id).and_then(|m| m.get(&target_id)).cloned()
            };
            if let Some(p) = target_peer {
                send_to_peer(&msg, &p, &state, &socket).await;
            }
        }

        TYPE_NACK => {
            let stripped = match strip_control(&msg) {
                Some(s) => s,
                None => return,
            };
            let nack = match codec.decode_nack(&stripped) {
                Ok(n) => n,
                Err(_) => return,
            };
            println!("[Server] NACK Conv:{} Sender:{} Target:{} Missing:{:?} from Peer", nack.conv_id, nack.sender_id, nack.target_id, nack.missing_seq);

            let mut missing_from_server = Vec::new();
            let mut to_send = Vec::new();
            let mut group = Vec::new();

            {
                let s = state.read().await;
                if let Some(cache_room) = s.message_cache.get(&nack.conv_id) {
                    if let Some(cache_sender) = cache_room.get(&nack.target_id) {
                        for seq in &nack.missing_seq {
                            if let Some(cached) = cache_sender.get(seq) {
                                to_send.push(cached.clone());
                            } else {
                                missing_from_server.push(*seq);
                            }
                        }
                    } else {
                        missing_from_server.extend_from_slice(&nack.missing_seq);
                    }
                } else {
                    missing_from_server.extend_from_slice(&nack.missing_seq);
                }

                if let Some(room_peers) = s.rooms.get(&nack.conv_id) {
                    for p in room_peers {
                        if *p != peer_id {
                            group.push(p.clone());
                        }
                    }
                }
            }

            for cached in to_send {
                println!("[Server] Satisfying NACK from cache for peer");
                send_to_peer(&cached, &peer_id, &state, &socket).await;
            }

            if !missing_from_server.is_empty() {
                // Relay the original member-signed NACK verbatim so the target
                // member (and any peer holding the messages) can act on it.
                println!("[Server] Relaying NACK for missing seqs {:?}", missing_from_server);
                for p in group {
                    send_to_peer(&msg, &p, &state, &socket).await;
                }
            }
        }

        TYPE_SYNC => {
            // The server is keyed into every SYNC (sender -> server). Verify
            // before relaying so a group member can't forge another member's
            // SYNC.
            let sync_conv_id = u16::from_be_bytes([msg[1], msg[2]]);
            let sync_sender_id = u16::from_be_bytes([msg[3], msg[4]]);
            let member_pub = {
                let s = state.read().await;
                s.members.get(&sync_conv_id).and_then(|m| m.get(&sync_sender_id)).cloned()
            };
            let member_pub = match member_pub {
                Some(p) => p,
                None => return,
            };
            let key = match state.read().await.ecdh.pairwise_key(&member_pub) {
                Ok(k) => k,
                Err(_) => return,
            };
            if verify_control(&msg, &key).is_none() {
                return;
            }

            let mut group = Vec::new();
            {
                let s = state.read().await;
                if let Some(room_peers) = s.rooms.get(&sync_conv_id) {
                    for p in room_peers {
                        if *p != peer_id {
                            group.push(p.clone());
                        }
                    }
                }
            }
            for p in group {
                send_to_peer(&msg, &p, &state, &socket).await;
            }
        }

        TYPE_DICT_RESET => {
            // Keyed to the server (sender -> server); verify before relaying so
            // a group member can't forge another member's Dict-Reset.
            let reset_conv_id = u16::from_be_bytes([msg[1], msg[2]]);
            let reset_sender_id = u16::from_be_bytes([msg[3], msg[4]]);
            let member_pub = {
                let s = state.read().await;
                s.members.get(&reset_conv_id).and_then(|m| m.get(&reset_sender_id)).cloned()
            };
            let member_pub = match member_pub {
                Some(p) => p,
                None => return,
            };
            let key = match state.read().await.ecdh.pairwise_key(&member_pub) {
                Ok(k) => k,
                Err(_) => return,
            };
            if verify_control(&msg, &key).is_none() {
                return;
            }

            let mut group = Vec::new();
            {
                let s = state.read().await;
                if let Some(room_peers) = s.rooms.get(&reset_conv_id) {
                    for p in room_peers {
                        if *p != peer_id {
                            group.push(p.clone());
                        }
                    }
                }
            }
            for p in group {
                send_to_peer(&msg, &p, &state, &socket).await;
            }
        }

        TYPE_ACK => {
            if msg.len() < 7 {
                return;
            }
            let target_id = u16::from_be_bytes([msg[5], msg[6]]);
            let mut target_peer = None;
            {
                let s = state.read().await;
                if let Some(clients) = s.client_map.get(&conv_id) {
                    if let Some(p) = clients.get(&target_id) {
                        target_peer = Some(p.clone());
                    }
                }
            }
            if let Some(p) = target_peer {
                send_to_peer(&msg, &p, &state, &socket).await;
            }
        }

        _ => {}
    }
}
