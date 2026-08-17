import { Codec, TYPE_DATA, TYPE_NACK, TYPE_SYNC, TYPE_KEY_REQ, TYPE_KEY_SHARE, TYPE_MEMBER_INFO, TYPE_CHAIN_SHARE, TYPE_ACK, DICT_WINDOW, dictFingerprint, DataDart, NackDart, SyncDart, KeyReqDart, KeyShareDart, ChainShareDart, AckDart, DecryptedData, ChainState, seqDelta, seqNext, SEQ_MOD, advanceChain, pairwiseKey, signControlFrame, verifyControlFrame, stripControlFrame } from './core';
import * as crypto from 'crypto';
import * as dgram from 'dgram';

// Optional pinned server fingerprint (SHA-256 hex). Set DART_SERVER_FINGERPRINT
// or hardcode a value here to authenticate the server against MITM attacks.
const SERVER_FINGERPRINT = (process.env.DART_SERVER_FINGERPRINT || '').trim().toLowerCase();

class ElectronDartClient {
  public socket?: dgram.Socket;
  private ws?: WebSocket;
  public senderId: number;
  public serverHost: string = 'daebak.init3.ro';
  public serverPort: number = 9000;
  public transport: 'ws' | 'udp' = 'udp';
  
  private nextSeq = 1;
  private highestReceivedSeq = new Map<number, number>(); // senderId -> seq
  private highestSentSeq = 0;
  
  private sentMessages = new Map<number, DataDart>();
  private receivedMessages = new Map<number, Map<number, DataDart>>(); // senderId -> seq -> DataDart
  
  public stats = { packetsSent: 0, packetsReceived: 0, nacksSent: 0, nacksReceived: 0, retransmits: 0, bytesSent: 0 };
  
  private syncTimers: any[] = [];
  private ackedSeq = new Map<number, number>();
  private ackTimers = new Map<number, any>(); // targetId -> timer

  private clientECDH!: crypto.ECDH;
  public currentRoomId: number = 1;
  private lastSendTime: number = 0;
  
  // E2EE group-key management
  private roster = new Map<number, Map<number, Buffer>>();
  private sharedWith = new Map<number, Set<number>>();
  private rekeyTimer: any = null;
  private isCreator = new Map<number, boolean>();

  // Server public key per conversation (from MEMBER_INFO), used to key the
  // server-verified SYNC / Dict-Reset frames.
  private serverPubKeys = new Map<number, Buffer>();

  // Per-sender ratchet chains: convId -> epoch -> senderId -> chain state.
  private senderChains = new Map<number, Map<number, Map<number, ChainState>>>();
  private chainSharedWith = new Map<number, Set<number>>();
  private messageKeys = new Map<number, { key: Buffer; idx: number }>();
  private chainSeeds = new Map<number, Map<number, ChainState>>(); // convId -> epoch -> index-0 chain state
  // The epoch this client has adopted (per-client, unlike the shared codec
  // globals) so each member creates its own ratchet chain.
  private adoptedEpochs = new Map<number, number>();
  private roomKeys = new Map<number, Map<number, Buffer>>();
  private currentEpochs = new Map<number, number>();

  private getCurrentKey(convId: number): Buffer | undefined {
    return this.roomKeys.get(convId)?.get(this.currentEpochs.get(convId) || 1);
  }
  
  // senderId -> seq -> raw buffer
  private outOfOrderBuffer = new Map<number, Map<number, Buffer>>();
  
  // senderId -> seq -> timestamp first NACKed
  private nackTimestamps = new Map<number, Map<number, number>>(); 
  
  // Pending messages waiting for Key Exchange to finish
  private pendingQueue: {convId: number, payload: string}[] = [];

  constructor() {
    this.senderId = Math.floor(Math.random() * 65535);
    this.updateUI();
  }

  private resetSession() {
    this.nextSeq = 1;
    this.highestReceivedSeq = new Map();
    this.highestSentSeq = 0;
    this.sentMessages = new Map();
    this.receivedMessages = new Map();
    this.pendingQueue = [];
    this.nackTimestamps = new Map();
    this.outOfOrderBuffer = new Map();
    this.roster = new Map();
    this.sharedWith = new Map();
    this.serverPubKeys = new Map();
    this.senderChains = new Map();
    this.chainSharedWith = new Map();
    this.messageKeys = new Map();
    this.adoptedEpochs = new Map();
    this.roomKeys = new Map();
    this.currentEpochs = new Map();
    this.isCreator = new Map();
    this.clientECDH = crypto.createECDH('prime256v1');
    this.clientECDH.generateKeys();
    (document.getElementById('msgInput') as HTMLInputElement).disabled = true;
    (document.getElementById('sendBtn') as HTMLButtonElement).disabled = true;
  }

  private closeTransports() {
    if (this.ws) {
      try { this.ws.onclose = null; this.ws.close(); } catch (e) {}
      this.ws = undefined;
    }
    if (this.socket) {
      try { this.socket.close(); } catch (e) {}
      this.socket = undefined;
    }
  }

  public connectAndJoin(roomId: number) {
    this.currentRoomId = roomId;
    this.resetSession();
    this.closeTransports();
    this.updateUI();

    if (this.transport === 'ws') {
      const url = this.wsUrl();
      this.appendSysMsg(`Connecting ${url} …`);
      this.ws = new WebSocket(url);
      this.ws.binaryType = 'arraybuffer';
      this.ws.onopen = () => {
        this.appendSysMsg(`WebSocket open. Joining room ${roomId}.`);
        this.sendKeyReq(roomId);
      };
      this.ws.onmessage = (event) => {
        this.stats.packetsReceived++;
        this.handleMessage(Buffer.from(event.data as ArrayBuffer));
        this.updateUI();
      };
      this.ws.onerror = () => this.appendSysMsg('WebSocket error.');
      this.ws.onclose = () => this.appendSysMsg('Disconnected.');
      return;
    }

    this.socket = dgram.createSocket('udp4');
    this.socket.on('message', (msg) => {
      this.stats.packetsReceived++;
      this.handleMessage(msg);
      this.updateUI();
    });
    this.socket.on('error', (err) => this.appendSysMsg(`UDP error: ${err.message}`));
    this.socket.bind(0, () => {
      this.sendKeyReq(roomId);
      this.appendSysMsg(`Joining room ${roomId} at ${this.serverHost}:${this.serverPort} (UDP)…`);
    });
  }

  private wsUrl(): string {
    const host = this.serverHost.trim();
    if (host.startsWith('ws://') || host.startsWith('wss://')) return host;
    if (host === '127.0.0.1' || host === 'localhost') return `ws://${host}:9002`;
    return `wss://${host}/dart/ws/`;
  }
  
  private getDictionary(senderId: number, maxSeq: number): Buffer {
      // Delta-compress against a bounded window of the SAME sender's history so
      // both sides always build identical dictionaries (and older history can
      // be pruned). Since packets from a single sender are strictly ordered by
      // seq, the window is guaranteed to match when no loss has occurred. The
      // window is selected in the modular 24-bit space so it stays correct
      // across a sequence-number wrap.
      const msgsToConcat: DataDart[] = [];
      
      if (senderId === this.senderId) {
          for (const dart of this.sentMessages.values()) {
              const dist = seqDelta(dart.seq, maxSeq);
              if (dist >= 1 && dist <= DICT_WINDOW) {
                  msgsToConcat.push(dart);
              }
          }
      } else {
          const msgs = this.receivedMessages.get(senderId);
          if (msgs) {
              for (const dart of msgs.values()) {
                  const dist = seqDelta(dart.seq, maxSeq);
                  if (dist >= 1 && dist <= DICT_WINDOW) {
                      msgsToConcat.push(dart);
                  }
              }
          }
      }
      
      // Sort oldest-first (largest modular distance from maxSeq) so all
      // implementations build byte-identical dictionaries regardless of
      // arrival order, and correctly across a wrap.
      msgsToConcat.sort((a, b) => seqDelta(b.seq, maxSeq) - seqDelta(a.seq, maxSeq));
      
      const bufs: Buffer[] = [];
      for (const dart of msgsToConcat) {
          bufs.push(Buffer.from(dart.payload, 'utf-8'));
      }
      return Buffer.concat(bufs);
  }

  // Bound memory: drop history older than the dictionary window (+ slack).
  private pruneSent() {
      for (const k of this.sentMessages.keys()) {
          if (seqDelta(k, this.highestSentSeq) > DICT_WINDOW + 16) {
            this.sentMessages.delete(k);
            this.messageKeys.delete(k);
          }
      }
  }

  private pruneReceived(senderId: number) {
      const highest = this.highestReceivedSeq.get(senderId) || 0;
      const msgs = this.receivedMessages.get(senderId);
      if (msgs) {
          for (const k of msgs.keys()) {
              if (seqDelta(k, highest) > DICT_WINDOW + 16) msgs.delete(k);
          }
      }
      const nacks = this.nackTimestamps.get(senderId);
      if (nacks) {
          for (const k of nacks.keys()) {
              if (seqDelta(k, highest) > DICT_WINDOW + 16) nacks.delete(k);
          }
      }
  }

  sendData(convId: number, payload: string) {
    const now = Date.now();
    if (now - this.lastSendTime < 250) {
        this.appendSysMsg("Rate limit: Sending too fast. Message dropped.");
        return;
    }
    this.lastSendTime = now;
    
    if (!this.getCurrentKey(convId)) {
        this.pendingQueue.push({ convId, payload });
        return;
    }
    const epoch = this.currentEpochs.get(convId) || 1;
    const myChain = this.getChain(convId, epoch, this.senderId);
    if (!myChain) {
        this.pendingQueue.push({ convId, payload });
        return;
    }
    const idx = myChain.index;
    const { messageKey, state } = advanceChain(myChain, idx);
    this.setChain(convId, epoch, this.senderId, state);
    const seq = this.nextSeq;
    this.nextSeq = seqNext(this.nextSeq);
    const dart: DataDart = { type: TYPE_DATA, convId, senderId: this.senderId, seq, payload };
    this.sentMessages.set(seq, dart);
    this.messageKeys.set(seq, { key: messageKey, idx });
    this.highestSentSeq = seq;
    this.pruneSent();
    
    const dict = this.getDictionary(this.senderId, seq);
    const buf = Codec.encodeDataHelper(dart, dict, messageKey, idx, epoch);
    this.broadcast(buf);
    
    this.clearSyncTimers();
    this.syncProbe(convId);
  }
  
  private syncProbe(convId: number) {
      this.syncTimers.push(setTimeout(() => {
          this.sendSync(convId);
          // Re-arm while the latest message stays unacknowledged so SYNC-driven
          // NACK repair keeps retrying under loss.
          const acked = this.ackedSeq.get(convId) || 0;
          if (seqDelta(this.highestSentSeq, acked) >= SEQ_MOD / 2) {
              this.syncProbe(convId);
          }
      }, 300));
  }
  
  private clearSyncTimers() {
      for (const t of this.syncTimers) clearTimeout(t);
      this.syncTimers = [];
  }

  public joinRoom(roomId: number) {
      this.connectAndJoin(roomId);
  }

  private sendKeyReq(roomId: number) {
      const req: KeyReqDart = {
          type: TYPE_KEY_REQ,
          convId: roomId,
          senderId: this.senderId,
          reqNonce: crypto.randomBytes(16),
          clientPubKey: this.clientECDH.getPublicKey()
      };
      this.broadcast(Codec.encodeKeyReq(req));
      // Retry: each KeyReq makes the server re-notify the roster, which is
      // how members refresh stale pubkeys (MEMBER_INFO has no other retry).
      setTimeout(() => this.broadcast(Codec.encodeKeyReq({ ...req, reqNonce: crypto.randomBytes(16) })), 1000);
      setTimeout(() => this.broadcast(Codec.encodeKeyReq({ ...req, reqNonce: crypto.randomBytes(16) })), 2000);
      setTimeout(() => this.broadcast(Codec.encodeKeyReq({ ...req, reqNonce: crypto.randomBytes(16) })), 3000);
  }
  
  private broadcast(buf: Buffer) {
    this.stats.packetsSent++;
    this.stats.bytesSent += buf.length;
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(new Uint8Array(buf));
    } else if (this.socket) {
      this.socket.send(buf, this.serverPort, this.serverHost);
    }
    this.updateUI();
  }

  private handleMessage(buf: Buffer) {
    try {
      const type = buf.readUInt8(0);
      
      if (type === TYPE_DATA) {
        const convId = buf.readUInt16BE(1);
        const seq = buf.readUIntBE(3, 3);
        const extLen = buf.readUInt8(6);
        if (extLen < 24) return;
        const parsedSenderId = buf.readUInt16BE(7);
        
        const hasBaseline = this.highestReceivedSeq.has(parsedSenderId);
        const highestReceived = this.highestReceivedSeq.get(parsedSenderId) || 0;
        // Modular gap test: 0 = duplicate, >= SEQ_MOD/2 = stale, 1 = exact next.
        // A receiver with no baseline yet treats the first packet as its
        // baseline, except when the first seq is within the recoverable window:
        // then NACK the real gap instead of accepting an out-of-order start.
        const ahead = hasBaseline ? seqDelta(highestReceived, seq) : (seq >= 1 && seq <= DICT_WINDOW ? seq : 1);
        if (ahead === 0 || ahead >= SEQ_MOD / 2) return; // Already processed
        
        if (ahead > 1) {
            // Gap detected! Buffer it.
            if (!this.outOfOrderBuffer.has(parsedSenderId)) this.outOfOrderBuffer.set(parsedSenderId, new Map());
            this.outOfOrderBuffer.get(parsedSenderId)!.set(seq, buf);
            
            const missing = [];
            for (let k = 1; k < ahead; k++) {
                const i = (highestReceived + k) & 0xFFFFFF;
                if (!this.outOfOrderBuffer.get(parsedSenderId)!.has(i) && !this.receivedMessages.get(parsedSenderId)?.has(i)) {
                    let ts = 0;
                    if (!this.nackTimestamps.has(parsedSenderId)) this.nackTimestamps.set(parsedSenderId, new Map());
                    if (!this.nackTimestamps.get(parsedSenderId)!.has(i)) {
                        this.nackTimestamps.get(parsedSenderId)!.set(i, Date.now());
                    } else {
                        ts = this.nackTimestamps.get(parsedSenderId)!.get(i)!;
                    }
                    
                    if (ts > 0 && Date.now() - ts > 4000) {
                        this.appendSysMsg(`Packet seq ${i} from User ${parsedSenderId} permanently lost. Resynchronizing dictionary gracefully...`);
                        this.declarePermanentLoss(convId, parsedSenderId, i);
                    } else {
                        missing.push(i);
                    }
                }
            }
            if (missing.length > 0) {
                this.sendNack(convId, parsedSenderId, missing);
            }
            return; // Buffered, do not process yet!
        }
        
        // Exact next packet: decrypt in order, process, then drain the buffer.
        const dec = this.decryptDataInOrder(buf, parsedSenderId);
        if (dec) {
            this.processDataPacket(buf, dec, parsedSenderId, seq);
            this.processBufferedPackets(parsedSenderId);
        }
        
      } else if (type === TYPE_CHAIN_SHARE) {
        this.handleChainShare(buf);
      } else if (type === TYPE_NACK) {
        this.stats.nacksReceived++;
        const nackConvId = buf.readUInt16BE(1);
        const nackSenderId = buf.readUInt16BE(3);
        const nackTargetId = buf.readUInt16BE(5);
        if (nackTargetId !== this.senderId) return;
        // Verify the sender's per-sender MAC so a group member can't forge
        // another member's NACK.
        const nackPeerPub = this.roster.get(nackConvId)?.get(nackSenderId);
        const nackStripped = nackPeerPub ? verifyControlFrame(buf, pairwiseKey(this.clientECDH, nackPeerPub)) : null;
        if (!nackStripped) return;
        const nackKey = this.getCurrentKey(nackConvId);
        if (!nackKey) return;
        const nack = Codec.decodeNack(nackStripped, nackKey);
        for (const seq of nack.missingSeq) {
          const dart = this.sentMessages.get(seq);
          const mk = this.messageKeys.get(seq);
          if (dart && mk) {
            this.stats.retransmits++;
            const dict = this.getDictionary(this.senderId, seq);
            const outBuf = Codec.encodeDataHelper(dart, dict, mk.key, mk.idx, this.currentEpochs.get(dart.convId) || 1);
            this.broadcast(outBuf);
          }
        }
        // The NACKer likely missed the chain share too (it can't decrypt my
        // stream without one). Re-share the current chain state: it's
        // deterministic, so receiving it is always safe.
        const epoch = this.currentEpochs.get(nackConvId) || 1;
        const myChain = this.getChain(nackConvId, epoch, this.senderId);
        if (myChain) {
          const seed = this.chainSeeds.get(nackConvId)?.get(epoch);
          if (seed) {
            this.sendChainShare(nackConvId, epoch, nackSenderId, seed.key, seed.index);
          }
        }
      } else if (type === TYPE_SYNC) {
        // SYNC is keyed to the relay server, which verified and relayed it.
        const syncStripped = stripControlFrame(buf);
        if (!syncStripped) return;
        const syncKey = this.getCurrentKey(syncStripped.readUInt16BE(1));
        if (!syncKey) return;
        const sync = Codec.decodeSync(syncStripped, syncKey);
        const hasBaseline = this.highestReceivedSeq.has(sync.senderId);
        const highestReceived = this.highestReceivedSeq.get(sync.senderId) || 0;
        // Fresh receiver: NACK the whole reported range; otherwise only the
        // modular distance ahead of what we've seen (handles wraps).
        const ahead = hasBaseline ? seqDelta(highestReceived, sync.highestSeq) : sync.highestSeq;
        if (ahead > 0 && ahead < SEQ_MOD / 2) {
            const missing = [];
            if (!this.receivedMessages.has(sync.senderId)) this.receivedMessages.set(sync.senderId, new Map());
            for (let k = 1; k <= ahead; k++) {
                const i = (highestReceived + k) & 0xFFFFFF;
                if (!this.outOfOrderBuffer.get(sync.senderId)?.has(i) && !this.receivedMessages.get(sync.senderId)!.has(i)) {
                    let ts = 0;
                    if (!this.nackTimestamps.has(sync.senderId)) this.nackTimestamps.set(sync.senderId, new Map());
                    if (!this.nackTimestamps.get(sync.senderId)!.has(i)) {
                        this.nackTimestamps.get(sync.senderId)!.set(i, Date.now());
                    } else {
                        ts = this.nackTimestamps.get(sync.senderId)!.get(i)!;
                    }
                    
                    if (ts > 0 && Date.now() - ts > 4000) {
                        this.appendSysMsg(`Packet seq ${i} from User ${sync.senderId} permanently lost. Resynchronizing dictionary gracefully...`);
                        this.declarePermanentLoss(sync.convId, sync.senderId, i);
                        this.processBufferedPackets(sync.senderId);
                    } else {
                        missing.push(i);
                    }
                }
            }
            if (missing.length > 0) {
                this.sendNack(sync.convId, sync.senderId, missing);
            }
        }
      } else if (type === TYPE_ACK) {
          const ackConvId = buf.readUInt16BE(1);
          const ackSenderId = buf.readUInt16BE(3);
          const ackTargetId = buf.readUInt16BE(5);
          if (ackTargetId !== this.senderId) return;
          const ackPeerPub = this.roster.get(ackConvId)?.get(ackSenderId);
          const ackStripped = ackPeerPub ? verifyControlFrame(buf, pairwiseKey(this.clientECDH, ackPeerPub)) : null;
          if (!ackStripped) return;
          const ackKey = this.getCurrentKey(ackConvId);
          if (!ackKey) return;
          const ack = Codec.decodeAck(ackStripped, ackKey);
          if (seqDelta(this.highestSentSeq, ack.seq) < SEQ_MOD / 2) {
              // Record the ACK; the re-arming sync probe stops on its own once
              // the latest message is acknowledged (clearing it here on a stale
              // ACK would silence repair probes prematurely).
              this.ackedSeq.set(ackConvId, ack.seq);
          }
      } else if (type === TYPE_KEY_SHARE) {
        this.handleKeyShare(buf);
      } else if (type === TYPE_MEMBER_INFO) {
        this.handleMemberInfo(buf);
      } else if (type === 0x06) {
          // Dict-Reset is keyed to the relay server, which verified it.
          const resetStripped = stripControlFrame(buf);
          if (!resetStripped) return;
          const resetKey = this.getCurrentKey(resetStripped.readUInt16BE(1));
          if (!resetKey) return;
          const reset = Codec.decodeDictReset(resetStripped, resetKey);
          if (reset.targetId === this.senderId) {
              this.appendSysMsg(`User ${reset.senderId} requested a dictionary reset. Flushing history to recover stream...`);
              this.sentMessages.clear();
          } else {
              if (this.receivedMessages.has(reset.targetId)) {
                  this.receivedMessages.get(reset.targetId)!.clear();
              }
          }
      } else {
        console.warn('Unknown packet type:', type);
      }
    } catch (e) {
        console.error("Packet drop / decrypt fail", e);
        this.appendSysMsg("Packet dropped (decrypt failure or tamper detected).");
    }
  }
  
  private handleMemberInfo(buf: Buffer) {
      let serverPubKey: Buffer;
      try {
          serverPubKey = Codec.memberInfoServerKey(buf);
      } catch (e) {
          return;
      }
      const fp = Codec.serverFingerprint(serverPubKey);
      if (SERVER_FINGERPRINT && fp !== SERVER_FINGERPRINT) {
          this.appendSysMsg("SERVER FINGERPRINT MISMATCH — possible MITM. Aborting key exchange.");
          return;
      }
      const sharedSecret = this.clientECDH.computeSecret(serverPubKey);
      const transportKey = crypto.createHash('sha256').update(sharedSecret).digest();
      let info;
      try {
          info = Codec.decodeMemberInfo(buf, transportKey);
      } catch (e) {
          this.appendSysMsg("Could not authenticate server membership info. Aborting.");
          return;
      }

      const rosterMap = new Map<number, Buffer>();
      for (const m of info.members) rosterMap.set(m.senderId, m.pubKey);
      const prevRoster = this.roster.get(info.convId);
      this.roster.set(info.convId, rosterMap);
      if (prevRoster) {
        // A member whose pubkey changed (reconnect with a fresh ECDH keypair)
        // needs fresh group-key and chain shares under the new key; drop the
        // shared-with flags so the shares are re-sent.
        const keyDone = this.sharedWith.get(info.convId);
        const chainDone = this.chainSharedWith.get(info.convId);
        for (const [mId, pub] of rosterMap) {
          const prev = prevRoster.get(mId);
          if (prev && !prev.equals(pub)) {
            keyDone?.delete(mId);
            chainDone?.delete(mId);
          }
        }
      }
      this.serverPubKeys.set(info.convId, serverPubKey);
      const prevCreator = this.isCreator.get(info.convId) || false;
      this.isCreator.set(info.convId, info.creator);

      const myEpoch = this.adoptedEpochs.get(info.convId) || 0;
      if (info.creator && !myEpoch) {
          this.adoptKey(info.convId, 1, crypto.randomBytes(32));
      } else if (myEpoch) {
          this.shareWithNewMembers(info.convId);
      }
      // If I just became the creator (successor election after the previous
      // creator left), rotate immediately so the departed member loses access.
      if (info.creator && !prevCreator && myEpoch) {
          this.rekey(info.convId);
      }
      // Share my ratchet chain with any members that just joined.
      this.shareChainWithMembers(info.convId, this.currentEpochs.get(info.convId) || 1);
      this.scheduleRekey(info.convId);
  }

  private handleKeyShare(buf: Buffer) {
      const convId = buf.readUInt16BE(1);
      const senderId = buf.readUInt16BE(3);
      const targetId = buf.readUInt16BE(5);
      if (targetId !== this.senderId) return;
      const sharerPubKey = this.roster.get(convId)?.get(senderId);
      if (!sharerPubKey) return;
      const sharedSecret = this.clientECDH.computeSecret(sharerPubKey);
      const transportKey = crypto.createHash('sha256').update(sharedSecret).digest();
      let decoded;
      try {
          decoded = Codec.decodeKeyShare(buf, transportKey);
      } catch (e) {
          return;
      }
      const myEpoch = this.adoptedEpochs.get(convId) || 0;
      const curKey = this.getCurrentKey(convId);
      // Adopt on first join, on a newer epoch, or on an equal epoch with a
      // DIFFERENT key (a restarted creator re-uses epoch 1 with a fresh key).
      if (!myEpoch || decoded.epoch > myEpoch ||
          (decoded.epoch === myEpoch && curKey && !curKey.equals(decoded.groupKey))) {
          this.adoptKey(convId, decoded.epoch, decoded.groupKey);
      }
  }

  private adoptKey(convId: number, epoch: number, key: Buffer) {
      const isNew = !this.adoptedEpochs.get(convId);
      if (!this.roomKeys.has(convId)) this.roomKeys.set(convId, new Map());
      this.roomKeys.get(convId)!.set(epoch, key);
      this.currentEpochs.set(convId, epoch);
      this.adoptedEpochs.set(convId, epoch);
      this.sharedWith.set(convId, new Set());
      // Start a fresh per-sender ratchet chain for this epoch and share it.
      this.initOwnChain(convId, epoch);
      if (isNew) {
          (document.getElementById('msgInput') as HTMLInputElement).disabled = false;
          (document.getElementById('sendBtn') as HTMLButtonElement).disabled = false;
          this.appendSysMsg(`Joined Room ${convId} securely (group key, epoch ${epoch}).`);
          this.sendData(convId, `User ${this.senderId} joined the room`);
          for (const pending of this.pendingQueue) {
              this.sendData(pending.convId, pending.payload);
          }
          this.pendingQueue = [];
      }
      this.shareWithNewMembers(convId);
      this.scheduleRekey(convId);
  }

  private shareWithNewMembers(convId: number) {
      const key = this.getCurrentKey(convId);
      if (!key) return;
      const epoch = this.currentEpochs.get(convId) || 1;
      const roster = this.roster.get(convId);
      if (!roster) return;
      const done = this.sharedWith.get(convId) || new Set<number>();
      const targets: number[] = [];
      for (const [mId] of roster) {
          if (mId === this.senderId || done.has(mId)) continue;
          targets.push(mId);
          done.add(mId);
      }
      this.sharedWith.set(convId, done);
      if (targets.length === 0) return;
      const doShare = () => {
          for (const mId of targets) {
              const targetPubKey = roster.get(mId)!;
              const sharedSecret = this.clientECDH.computeSecret(targetPubKey);
              const transportKey = crypto.createHash('sha256').update(sharedSecret).digest();
              const share: KeyShareDart = {
                  type: TYPE_KEY_SHARE,
                  convId,
                  senderId: this.senderId,
                  targetId: mId,
                  epoch,
                  nonce: crypto.randomBytes(12),
                  encryptedKey: key
              };
              this.broadcast(Codec.encodeKeyShare(share, transportKey));
          }
      };
      doShare();
      // Retry a couple of times: the group-key share goes over UDP and can be
      // lost; a member that misses it can't adopt the key or join the room.
      setTimeout(doShare, 300);
      setTimeout(doShare, 1000);
  }

  private rekey(convId: number) {
      if (!this.isCreator.get(convId)) return;
      const current = this.currentEpochs.get(convId) || 1;
      this.adoptKey(convId, current + 1, crypto.randomBytes(32));
      this.pruneOldEpochs(convId);
  }

  // ---- Per-sender ratchet chain management ----

  private getChain(convId: number, epoch: number, senderId: number): ChainState | undefined {
      return this.senderChains.get(convId)?.get(epoch)?.get(senderId);
  }

  private setChain(convId: number, epoch: number, senderId: number, state: ChainState) {
      if (!this.senderChains.has(convId)) this.senderChains.set(convId, new Map());
      const epochs = this.senderChains.get(convId)!;
      if (!epochs.has(epoch)) epochs.set(epoch, new Map());
      epochs.get(epoch)!.set(senderId, state);
  }

  private initOwnChain(convId: number, epoch: number) {
      const seed = crypto.randomBytes(32);
      this.setChain(convId, epoch, this.senderId, { key: seed, index: 0 });
      if (!this.chainSeeds.has(convId)) this.chainSeeds.set(convId, new Map());
      this.chainSeeds.get(convId)!.set(epoch, { key: seed, index: 0 });
      this.chainSharedWith.set(convId, new Set());
      this.shareChainWithMembers(convId, epoch);
  }

  private shareChainWithMembers(convId: number, epoch: number) {
      const myChain = this.getChain(convId, epoch, this.senderId);
      const roster = this.roster.get(convId);
      if (!myChain || !roster) return;
      const done = this.chainSharedWith.get(convId) || new Set<number>();
      const targets: number[] = [];
      for (const [mId] of roster) {
          if (mId === this.senderId || done.has(mId)) continue;
          targets.push(mId);
          done.add(mId);
      }
      this.chainSharedWith.set(convId, done);
      if (targets.length === 0) return;
      const doShare = () => {
          for (const mId of targets) {
              this.sendChainShare(convId, epoch, mId, myChain.key, myChain.index);
          }
      };
      doShare();
      // Retry a couple of times: the shares go over UDP and a receiver that
      // misses its only copy can never decrypt this sender's messages.
      setTimeout(doShare, 300);
      setTimeout(doShare, 1000);
  }

  private sendChainShare(convId: number, epoch: number, targetId: number, chainKey: Buffer, chainIndex: number) {
      const targetPubKey = this.roster.get(convId)?.get(targetId);
      if (!targetPubKey) return;
      const sharedSecret = this.clientECDH.computeSecret(targetPubKey);
      const transportKey = crypto.createHash('sha256').update(sharedSecret).digest();
      const share: ChainShareDart = {
          type: TYPE_CHAIN_SHARE,
          convId,
          senderId: this.senderId,
          targetId,
          epoch,
          nonce: crypto.randomBytes(12),
          chainKey,
          chainIndex
      };
      this.broadcast(Codec.encodeChainShare(share, transportKey));
  }

  private handleChainShare(buf: Buffer) {
      const convId = buf.readUInt16BE(1);
      const senderId = buf.readUInt16BE(3);
      const targetId = buf.readUInt16BE(5);
      if (targetId !== this.senderId) return;
      const sharerPubKey = this.roster.get(convId)?.get(senderId);
      if (!sharerPubKey) return;
      const sharedSecret = this.clientECDH.computeSecret(sharerPubKey);
      const transportKey = crypto.createHash('sha256').update(sharedSecret).digest();
      let decoded;
      try {
          decoded = Codec.decodeChainShare(buf, transportKey);
      } catch (e) {
          return;
      }
      this.setChain(convId, decoded.epoch, decoded.senderId, { key: decoded.chainKey, index: decoded.chainIndex });
  }

  private scheduleRekey(convId: number) {
      if (this.rekeyTimer) clearTimeout(this.rekeyTimer);
      const secs = parseInt(process.env.DART_REKEY_SECONDS || '300', 10);
      this.rekeyTimer = setTimeout(() => this.rekey(convId), secs * 1000);
  }

  private pruneOldEpochs(convId: number) {
      const current = this.currentEpochs.get(convId) || 0;
      const keys = this.roomKeys.get(convId);
      if (!keys) return;
      for (const [epoch] of keys) {
          if (epoch + 4 < current) keys.delete(epoch);
      }
  }

  private decryptDataInOrder(buf: Buffer, senderId: number): DecryptedData | null {
      const epoch = buf.readUInt16BE(21);
      const idx = buf.readUInt32BE(27);
      const convId = buf.readUInt16BE(1);
      const chain = this.getChain(convId, epoch, senderId);
      if (!chain || idx < chain.index) return null;
      const { messageKey, state } = advanceChain(chain, idx);
      try {
          const dec = Codec.decryptData(buf, messageKey);
          this.setChain(convId, epoch, senderId, state);
          return dec;
      } catch (e) {
          return null;
      }
  }

  private processDataPacket(buf: Buffer, dec: DecryptedData, parsedSenderId: number, seq: number) {
      if (dec.senderId !== parsedSenderId) return;
      
      const dict = this.getDictionary(parsedSenderId, seq);
      if (!dec.dictFp.equals(dictFingerprint(dict))) {
          // Dictionary fingerprint mismatch = lost history. Recover immediately.
          this.appendSysMsg("Dictionary desync detected (fingerprint). Sending automatic recovery signal...");
          if (this.receivedMessages.has(parsedSenderId)) {
              this.receivedMessages.get(parsedSenderId)!.clear();
          }
          this.sendDictReset(dec.convId, parsedSenderId);
          return;
      }
      let payload: string;
      try {
          payload = Codec.inflateData(dec.compressed, dict);
      } catch (e) {
          // Dictionary desync detected at inflate time (senderId is known here).
          this.appendSysMsg("Dictionary desync detected. Sending automatic recovery signal...");
          if (this.receivedMessages.has(parsedSenderId)) {
              this.receivedMessages.get(parsedSenderId)!.clear();
          }
          this.sendDictReset(dec.convId, parsedSenderId);
          return;
      }
      const dart: DataDart = { type: TYPE_DATA, convId: dec.convId, senderId: parsedSenderId, seq, payload };
      
      const highestReceived = this.highestReceivedSeq.get(dart.senderId) || 0;
      if (!this.receivedMessages.has(dart.senderId)) this.receivedMessages.set(dart.senderId, new Map());
      
      if (!this.receivedMessages.get(dart.senderId)!.has(dart.seq)) {
          this.receivedMessages.get(dart.senderId)!.set(dart.seq, dart);
          const d = this.highestReceivedSeq.has(dart.senderId) ? seqDelta(highestReceived, dart.seq) : 1;
          if (d > 0 && d < SEQ_MOD / 2) {
              this.highestReceivedSeq.set(dart.senderId, dart.seq);
          }
          this.pruneReceived(dart.senderId);
          
          if (dart.payload.startsWith("User ") && dart.payload.includes(" joined ")) {
              this.appendSysMsg(dart.payload);
          } else if (dart.payload !== "") {
              this.appendChat(`User ${dart.senderId}: ${dart.payload}`);
          }
          
          // Schedule lightweight Positive ACK for silence
          if (this.ackTimers.has(dart.senderId)) clearTimeout(this.ackTimers.get(dart.senderId));
          this.ackTimers.set(dart.senderId, setTimeout(() => {
              this.sendAck(dart.convId, dart.senderId, dart.seq);
          }, 200));
      }
  }
  
  private processBufferedPackets(senderId: number) {
      let nextSeq = seqNext(this.highestReceivedSeq.get(senderId) || 0);
      const bufferMap = this.outOfOrderBuffer.get(senderId);
      if (!bufferMap) return;
      
      while (bufferMap.has(nextSeq)) {
          const buf = bufferMap.get(nextSeq)!;
          bufferMap.delete(nextSeq);
          try {
              const dec = this.decryptDataInOrder(buf, senderId);
              if (dec && dec.senderId === senderId) {
                  this.processDataPacket(buf, dec, senderId, nextSeq);
              }
          } catch (e) {
              // Bad buffered packet
          }
          nextSeq = seqNext(nextSeq);
      }
  }
  
  private declarePermanentLoss(convId: number, senderId: number, lostSeq: number) {
      if (!this.receivedMessages.has(senderId)) this.receivedMessages.set(senderId, new Map());
      this.receivedMessages.get(senderId)!.set(lostSeq, { type: TYPE_DATA, convId, senderId, seq: lostSeq, payload: "" });
      
      const highestReceived = this.highestReceivedSeq.get(senderId) || 0;
      const d = seqDelta(highestReceived, lostSeq);
      if (d > 0 && d < SEQ_MOD / 2) {
          this.highestReceivedSeq.set(senderId, lostSeq);
      }
      
      this.receivedMessages.get(senderId)!.clear();
      this.outOfOrderBuffer.get(senderId)?.clear();
      this.sendDictReset(convId, senderId);
  }
  
  private sendDictReset(convId: number, targetId: number) {
      const reset = { type: 0x06, convId, senderId: this.senderId, targetId };
      const convKey = this.getCurrentKey(convId);
      const serverPub = this.serverPubKeys.get(convId);
      if (!convKey || !serverPub) return;
      const buf = Codec.encodeDictReset(reset, convKey);
      this.broadcast(signControlFrame(buf, pairwiseKey(this.clientECDH, serverPub)));
  }
  
  private sendAck(convId: number, targetId: number, seq: number) {
      const ack = { type: TYPE_ACK, convId, senderId: this.senderId, targetId, seq };
      const convKey = this.getCurrentKey(convId);
      const peerPub = this.roster.get(convId)?.get(targetId);
      if (!convKey || !peerPub) return;
      const buf = Codec.encodeAck(ack, convKey);
      this.broadcast(signControlFrame(buf, pairwiseKey(this.clientECDH, peerPub)));
  }
  
  private sendNack(convId: number, targetId: number, missingSeq: number[]) {
    this.stats.nacksSent++;
    const nack: NackDart = { type: TYPE_NACK, convId, senderId: this.senderId, targetId, missingSeq };
    const convKey = this.getCurrentKey(convId);
    const peerPub = this.roster.get(convId)?.get(targetId);
    if (!convKey || !peerPub) return;
    const buf = Codec.encodeNack(nack, convKey);
    this.broadcast(signControlFrame(buf, pairwiseKey(this.clientECDH, peerPub)));
  }
  
  private sendSync(convId: number) {
      if (this.highestSentSeq === 0) return;
      const sync: SyncDart = { type: TYPE_SYNC, convId, senderId: this.senderId, highestSeq: this.highestSentSeq };
      const convKey = this.getCurrentKey(convId);
      const serverPub = this.serverPubKeys.get(convId);
      if (!convKey || !serverPub) return;
      const buf = Codec.encodeSync(sync, convKey);
      this.broadcast(signControlFrame(buf, pairwiseKey(this.clientECDH, serverPub)));
  }
  
  private appendChat(text: string) {
      const chat = document.getElementById('chat')!;
      const div = document.createElement('div');
      div.className = 'msg';
      div.textContent = text;
      chat.appendChild(div);
      chat.scrollTop = chat.scrollHeight;
  }
  
  private appendSysMsg(text: string) {
      const chat = document.getElementById('chat')!;
      const div = document.createElement('div');
      div.className = 'sys-msg';
      div.textContent = `[SYSTEM] ${text}`;
      chat.appendChild(div);
      chat.scrollTop = chat.scrollHeight;
  }
  
  public updateUI() {
      const el = document.getElementById('status');
      if (el) el.textContent = `id ${this.senderId} · ${this.stats.packetsSent}↑ ${this.stats.packetsReceived}↓`;
  }
}

let client = new ElectronDartClient();

function applyForm() {
    const host = document.getElementById('host') as HTMLInputElement;
    const transport = document.getElementById('transport') as HTMLSelectElement;
    if (host && host.value.trim()) client.serverHost = host.value.trim();
    if (transport) client.transport = transport.value === 'udp' ? 'udp' : 'ws';
}

document.getElementById('joinBtn')!.addEventListener('click', () => {
    applyForm();
    const input = document.getElementById('room') as HTMLInputElement;
    const roomId = parseInt(input.value);
    if (isNaN(roomId)) return;
    document.getElementById('chat')!.innerHTML = '';
    client.connectAndJoin(roomId);
});

document.getElementById('sendBtn')!.addEventListener('click', () => {
    const input = document.getElementById('msgInput') as HTMLInputElement;
    if (input.value.trim() !== "") {
        client.sendData(client.currentRoomId, input.value);
        
        const chat = document.getElementById('chat')!;
        const div = document.createElement('div');
        div.className = 'msg';
        div.style.color = 'blue';
        div.textContent = `Me: ${input.value}`;
        chat.appendChild(div);
        chat.scrollTop = chat.scrollHeight;
        
        input.value = "";
    }
});

document.getElementById('msgInput')!.addEventListener('keyup', (event) => {
    if (event.key === 'Enter') {
        document.getElementById('sendBtn')!.click();
    }
});
