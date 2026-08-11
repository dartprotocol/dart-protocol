import { Codec, TYPE_DATA, TYPE_NACK, TYPE_SYNC, TYPE_KEY_REQ, TYPE_KEY_SHARE, TYPE_MEMBER_INFO, TYPE_ACK, DICT_WINDOW, dictFingerprint, roomKeys, currentEpochs, DataDart, NackDart, SyncDart, KeyReqDart, KeyShareDart, AckDart, convKeys } from './core';
import * as crypto from 'crypto';

// Optional pinned server fingerprint (SHA-256 hex). Set this to the value the
// server prints at startup to authenticate it against MITM attacks.
const SERVER_FINGERPRINT = '';

// We need a lightweight version of the client that works with WebSocket instead of UDP
class WebDartClient {
  public ws: WebSocket;
  public senderId: number;
  
  private nextSeq = 1;
  private highestReceivedSeq = new Map<number, number>(); // senderId -> seq
  private highestSentSeq = 0;
  
  private sentMessages = new Map<number, DataDart>();
  private receivedMessages = new Map<number, Map<number, DataDart>>(); // senderId -> seq -> DataDart
  
  public stats = { packetsSent: 0, packetsReceived: 0, nacksSent: 0, nacksReceived: 0, retransmits: 0, bytesSent: 0 };
  
  private syncTimers: any[] = [];
  private ackTimers = new Map<number, any>(); // targetId -> timer

  private clientECDH!: crypto.ECDH;
  public currentRoomId: number = 1;
  private serverUrl: string;
  private lastSendTime: number = 0;
  
  // E2EE group-key management
  private roster = new Map<number, Map<number, Buffer>>();
  private sharedWith = new Map<number, Set<number>>();
  private rekeyTimer: any = null;
  private isCreator = new Map<number, boolean>();
  
  // senderId -> seq -> raw buffer
  private outOfOrderBuffer = new Map<number, Map<number, Buffer>>();
  
  // senderId -> seq -> timestamp first NACKed
  private nackTimestamps = new Map<number, Map<number, number>>(); 
  
  // Pending messages waiting for Key Exchange to finish
  private pendingQueue: {convId: number, payload: string}[] = [];

  constructor(url: string) {
    this.serverUrl = url;
    this.senderId = Math.floor(Math.random() * 65535); // Random senderId for web clients
    document.getElementById('myClientId')!.innerText = this.senderId.toString();
    this.ws = {} as WebSocket; // assigned in connect
    this.connect();
  }
  
  public connect() {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.ws.close();
    }
    
    this.nextSeq = 1;
    this.highestReceivedSeq = new Map();
    this.highestSentSeq = 0;
    this.sentMessages = new Map();
    this.receivedMessages = new Map();
    this.pendingQueue = [];
    this.nackTimestamps = new Map();
    this.outOfOrderBuffer = new Map();
    
    this.clientECDH = crypto.createECDH('prime256v1');
    this.clientECDH.generateKeys();
    
    this.ws = new WebSocket(this.serverUrl);
    this.ws.binaryType = "arraybuffer";
    
    this.ws.onopen = () => {
        this.joinRoom(this.currentRoomId);
    };
    
    this.ws.onmessage = async (event) => {
      this.stats.packetsReceived++;
      const buf = Buffer.from(event.data);
      this.handleMessage(buf);
      this.updateUI();
    };
    
    this.ws.onclose = () => {
        this.appendSysMsg("Connection lost. Please click Reconnect.");
    };
  }
  
  private getDictionary(senderId: number, maxSeq: number): Buffer {
      // Delta-compress against a bounded window of the SAME sender's history so
      // both sides always build identical dictionaries (and older history can
      // be pruned). Since packets from a single sender are strictly ordered by
      // seq, the window is guaranteed to match when no loss has occurred.
      const minSeq = Math.max(1, maxSeq - DICT_WINDOW);
      const msgsToConcat: DataDart[] = [];
      
      if (senderId === this.senderId) {
          for (const dart of this.sentMessages.values()) {
              if (dart.seq >= minSeq && dart.seq < maxSeq) {
                  msgsToConcat.push(dart);
              }
          }
      } else {
          const msgs = this.receivedMessages.get(senderId);
          if (msgs) {
              for (const dart of msgs.values()) {
                  if (dart.seq >= minSeq && dart.seq < maxSeq) {
                      msgsToConcat.push(dart);
                  }
              }
          }
      }
      
      // Sort strictly by seq to guarantee identical dictionary construction regardless of arrival order
      msgsToConcat.sort((a, b) => a.seq - b.seq);
      
      const bufs: Buffer[] = [];
      for (const dart of msgsToConcat) {
          bufs.push(Buffer.from(dart.payload, 'utf-8'));
      }
      return Buffer.concat(bufs);
  }

  // Bound memory: drop history older than the dictionary window (+ slack).
  private pruneSent() {
      const minSeq = Math.max(1, this.highestSentSeq - DICT_WINDOW - 16);
      for (const k of this.sentMessages.keys()) {
          if (k < minSeq) this.sentMessages.delete(k);
      }
  }

  private pruneReceived(senderId: number) {
      const highest = this.highestReceivedSeq.get(senderId) || 0;
      const minSeq = Math.max(1, highest - DICT_WINDOW - 16);
      const msgs = this.receivedMessages.get(senderId);
      if (msgs) {
          for (const k of msgs.keys()) {
              if (k < minSeq) msgs.delete(k);
          }
      }
      const nacks = this.nackTimestamps.get(senderId);
      if (nacks) {
          for (const k of nacks.keys()) {
              if (k < minSeq) nacks.delete(k);
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
    
    if (!convKeys.has(convId)) {
        this.pendingQueue.push({ convId, payload });
        return;
    }
    const seq = this.nextSeq++;
    const dart: DataDart = { type: TYPE_DATA, convId, senderId: this.senderId, seq, payload };
    this.sentMessages.set(seq, dart);
    this.highestSentSeq = seq;
    this.pruneSent();
    
    const dict = this.getDictionary(this.senderId, seq);
    const buf = Codec.encodeDataHelper(dart, dict);
    this.broadcast(buf);
    
    this.clearSyncTimers();
    this.syncTimers.push(setTimeout(() => {
        this.sendSync(convId);
    }, 300));
    this.syncTimers.push(setTimeout(() => {
        this.sendSync(convId);
    }, 1000));
  }
  
  private clearSyncTimers() {
      for (const t of this.syncTimers) clearTimeout(t);
      this.syncTimers = [];
  }

  public joinRoom(roomId: number) {
      this.currentRoomId = roomId;
      const req: KeyReqDart = {
          type: TYPE_KEY_REQ,
          convId: roomId,
          senderId: this.senderId,
          reqNonce: crypto.randomBytes(16),
          clientPubKey: this.clientECDH.getPublicKey()
      };
      if (this.ws.readyState === WebSocket.OPEN) {
          this.ws.send(new Uint8Array(Codec.encodeKeyReq(req)));
      }
      this.appendSysMsg(`Joining room ${roomId}...`);
  }
  
  private broadcast(buf: Buffer) {
    this.stats.packetsSent++;
    this.stats.bytesSent += buf.length;
    if (this.ws.readyState === WebSocket.OPEN) {
        this.ws.send(new Uint8Array(buf));
    }
    this.updateUI();
  }

  private handleMessage(buf: Buffer) {
    try {
      const type = buf.readUInt8(0);
      
      if (type === TYPE_DATA) {
        const dec = Codec.decryptData(buf);
        const parsedSenderId = dec.senderId;
        const seq = dec.seq;
        const convId = dec.convId;
        
        const highestReceived = this.highestReceivedSeq.get(parsedSenderId) || 0;
        if (seq <= highestReceived) return; // Already processed
        
        if (seq > highestReceived + 1) {
            // Gap detected! Buffer it.
            if (!this.outOfOrderBuffer.has(parsedSenderId)) this.outOfOrderBuffer.set(parsedSenderId, new Map());
            this.outOfOrderBuffer.get(parsedSenderId)!.set(seq, buf);
            
            const missing = [];
            for (let i = highestReceived + 1; i < seq; i++) {
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
        
        // Exact next packet
        this.processDataPacket(buf, parsedSenderId, seq);
        this.processBufferedPackets(parsedSenderId);
        
      } else if (type === TYPE_NACK) {
        this.stats.nacksReceived++;
        const nack = Codec.decodeNack(buf);
        if (nack.senderId !== this.senderId) return;
        for (const seq of nack.missingSeq) {
          const dart = this.sentMessages.get(seq);
          if (dart) {
            this.stats.retransmits++;
            const dict = this.getDictionary(this.senderId, seq);
            const outBuf = Codec.encodeDataHelper(dart, dict);
            this.broadcast(outBuf);
          }
        }
      } else if (type === TYPE_SYNC) {
        const sync = Codec.decodeSync(buf);
        const highestReceived = this.highestReceivedSeq.get(sync.senderId) || 0;
        if (sync.highestSeq > highestReceived) {
            const missing = [];
            if (!this.receivedMessages.has(sync.senderId)) this.receivedMessages.set(sync.senderId, new Map());
            for (let i = highestReceived + 1; i <= sync.highestSeq; i++) {
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
            } else if (highestReceived === sync.highestSeq) {
                // Sender is probing but we have everything. Send a positive ACK!
                this.sendAck(sync.convId, sync.senderId, highestReceived);
            }
        }
      } else if (type === TYPE_ACK) {
          const ack = Codec.decodeAck(buf);
          if (ack.targetId === this.senderId && ack.seq >= this.highestSentSeq) {
              // Message confirmed! Cancel aggressive sync probes.
              this.clearSyncTimers();
          }
      } else if (type === TYPE_KEY_SHARE) {
        this.handleKeyShare(buf);
      } else if (type === TYPE_MEMBER_INFO) {
        this.handleMemberInfo(buf);
      } else if (type === 0x06) {
          const reset = Codec.decodeDictReset(buf);
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
      this.roster.set(info.convId, rosterMap);
      this.isCreator.set(info.convId, info.creator);

      const key = convKeys.get(info.convId);
      if (info.creator && !key) {
          this.adoptKey(info.convId, 1, crypto.randomBytes(32));
      } else if (key) {
          this.shareWithNewMembers(info.convId);
      }
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
      const currentEpoch = currentEpochs.get(convId) || 0;
      if (!convKeys.get(convId) || decoded.epoch > currentEpoch) {
          this.adoptKey(convId, decoded.epoch, decoded.groupKey);
      }
  }

  private adoptKey(convId: number, epoch: number, key: Buffer) {
      const isNew = !convKeys.has(convId);
      if (!roomKeys.has(convId)) roomKeys.set(convId, new Map());
      roomKeys.get(convId)!.set(epoch, key);
      convKeys.set(convId, key);
      currentEpochs.set(convId, epoch);
      this.sharedWith.set(convId, new Set());
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
      const key = convKeys.get(convId);
      if (!key) return;
      const epoch = currentEpochs.get(convId) || 1;
      const roster = this.roster.get(convId);
      if (!roster) return;
      const done = this.sharedWith.get(convId) || new Set<number>();
      for (const [mId] of roster) {
          if (mId === this.senderId || done.has(mId)) continue;
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
          done.add(mId);
      }
      this.sharedWith.set(convId, done);
  }

  private rekey(convId: number) {
      if (!this.isCreator.get(convId)) return;
      const current = currentEpochs.get(convId) || 1;
      this.adoptKey(convId, current + 1, crypto.randomBytes(32));
      this.pruneOldEpochs(convId);
  }

  private scheduleRekey(convId: number) {
      if (this.rekeyTimer) clearTimeout(this.rekeyTimer);
      const secs = parseInt(process.env.DART_REKEY_SECONDS || '300', 10);
      this.rekeyTimer = setTimeout(() => this.rekey(convId), secs * 1000);
  }

  private pruneOldEpochs(convId: number) {
      const current = currentEpochs.get(convId) || 0;
      const keys = roomKeys.get(convId);
      if (!keys) return;
      for (const [epoch] of keys) {
          if (epoch + 4 < current) keys.delete(epoch);
      }
  }

  private processDataPacket(buf: Buffer, parsedSenderId: number, seq: number) {
      const dec = Codec.decryptData(buf);
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
          if (dart.seq > highestReceived) {
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
      let nextSeq = (this.highestReceivedSeq.get(senderId) || 0) + 1;
      const bufferMap = this.outOfOrderBuffer.get(senderId);
      if (!bufferMap) return;
      
      while (bufferMap.has(nextSeq)) {
          const buf = bufferMap.get(nextSeq)!;
          bufferMap.delete(nextSeq);
          this.processDataPacket(buf, senderId, nextSeq);
          nextSeq++;
      }
  }
  
  private declarePermanentLoss(convId: number, senderId: number, lostSeq: number) {
      if (!this.receivedMessages.has(senderId)) this.receivedMessages.set(senderId, new Map());
      this.receivedMessages.get(senderId)!.set(lostSeq, { type: TYPE_DATA, convId, senderId, seq: lostSeq, payload: "" });
      
      const highestReceived = this.highestReceivedSeq.get(senderId) || 0;
      if (lostSeq > highestReceived) {
          this.highestReceivedSeq.set(senderId, lostSeq);
      }
      
      this.receivedMessages.get(senderId)!.clear();
      this.outOfOrderBuffer.get(senderId)?.clear();
      this.sendDictReset(convId, senderId);
  }
  
  private sendDictReset(convId: number, targetId: number) {
      const reset = { type: 0x06, convId, senderId: this.senderId, targetId };
      const buf = Codec.encodeDictReset(reset);
      this.broadcast(buf);
  }
  
  private sendAck(convId: number, targetId: number, seq: number) {
      const ack = { type: TYPE_ACK, convId, senderId: this.senderId, targetId, seq };
      this.broadcast(Codec.encodeAck(ack));
  }
  
  private sendNack(convId: number, senderId: number, missingSeq: number[]) {
    this.stats.nacksSent++;
    const nack: NackDart = { type: TYPE_NACK, convId, senderId, missingSeq };
    const buf = Codec.encodeNack(nack);
    this.broadcast(buf);
  }
  
  private sendSync(convId: number) {
      if (this.highestSentSeq === 0) return;
      const sync: SyncDart = { type: TYPE_SYNC, convId, senderId: this.senderId, highestSeq: this.highestSentSeq };
      const buf = Codec.encodeSync(sync);
      this.broadcast(buf);
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
      document.getElementById('pktsSent')!.innerText = this.stats.packetsSent.toString();
      document.getElementById('bytesSent')!.innerText = this.stats.bytesSent.toString();
      document.getElementById('nacksSent')!.innerText = this.stats.nacksSent.toString();
      document.getElementById('retransmits')!.innerText = this.stats.retransmits.toString();
  }
}

const protocol = window.location.protocol === 'https:' ? 'wss://' : 'ws://';
const wsUrl = protocol + window.location.host + '/dart/ws/';
let client = new WebDartClient(wsUrl);

document.getElementById('joinBtn')!.addEventListener('click', () => {
    const input = document.getElementById('roomInput') as HTMLInputElement;
    const roomId = parseInt(input.value);
    if (!isNaN(roomId)) {
        client.joinRoom(roomId);
        document.getElementById('chat')!.innerHTML = ''; // Clear chat on room switch
    }
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

document.getElementById('reconnectBtn')!.addEventListener('click', () => {
    client.connect();
});
