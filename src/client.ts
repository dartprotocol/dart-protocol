import * as dgram from 'dgram';
import * as crypto from 'crypto';
import { Codec, TYPE_DATA, TYPE_NACK, TYPE_SYNC, TYPE_KEY_REQ, TYPE_KEY_SHARE, TYPE_MEMBER_INFO, DICT_WINDOW, dictFingerprint, roomKeys, currentEpochs, DataDart, NackDart, SyncDart, KeyReqDart, KeyShareDart, DecryptedData, convKeys } from './core';

export class DartClient {
  public socket: dgram.Socket;
  public port: number;
  public senderId: number;
  
  private nextSeq = 1;
  private highestReceivedSeq = new Map<number, number>(); // senderId -> seq
  private highestSentSeq = 0;
  
  private sentMessages = new Map<number, DataDart>();
  private receivedMessages = new Map<number, Map<number, DataDart>>(); // senderId -> seq -> DataDart
  private outOfOrderBuffer = new Map<number, Map<number, Buffer>>(); // senderId -> seq -> raw buf
  private messageStatus = new Map<number, 'sent' | 'assumed_delivered'>();
  
  private peers: { address: string, port: number }[] = [];
  
  public simulateLossPercent = 0.0;
  public stats = { packetsSent: 0, packetsReceived: 0, bytesSent: 0, bytesReceived: 0, nacksSent: 0, nacksReceived: 0, retransmits: 0, syncsSent: 0 };
  
  private probeTimer: NodeJS.Timeout | null = null;
  private optimisticTimers = new Map<number, NodeJS.Timeout>();
  
  private tcpSocket?: any; // require('net').Socket
  public useFallback = false;
  
  private clientECDH: crypto.ECDH;
  
  // E2EE group-key management
  private roster = new Map<number, Map<number, Buffer>>();
  private sharedWith = new Map<number, Set<number>>();
  private rekeyTimer: any = null;
  private isCreator = new Map<number, boolean>();
  
  // Optional pinned server fingerprint; empty = do not verify.
  private serverFingerprint = '';

  setServerFingerprint(fp: string) {
    this.serverFingerprint = fp.trim().toLowerCase();
  }

  constructor(port: number, senderId?: number) {
    this.port = port;
    this.senderId = senderId || port; // default to port
    this.socket = dgram.createSocket('udp4');
    this.socket.bind(port);
    
    this.clientECDH = crypto.createECDH('prime256v1');
    this.clientECDH.generateKeys();
    
    this.socket.on('message', (msg, rinfo) => {
      if (Math.random() < this.simulateLossPercent) {
        return;
      }
      this.stats.packetsReceived++;
      this.stats.bytesReceived += msg.length;
      this.handleMessage(msg, rinfo);
    });
  }
  
  addPeer(address: string, port: number) {
    this.peers.push({ address, port });
  }
  
  joinConversation(convId: number) {
    const req: KeyReqDart = {
      type: TYPE_KEY_REQ,
      convId,
      senderId: this.senderId,
      reqNonce: crypto.randomBytes(16),
      clientPubKey: this.clientECDH.getPublicKey()
    };
    this.broadcast(Codec.encodeKeyReq(req));
  }

  private handleMemberInfo(buf: Buffer) {
    let serverPubKey: Buffer;
    try {
      serverPubKey = Codec.memberInfoServerKey(buf);
    } catch (e) {
      return;
    }
    if (this.serverFingerprint && Codec.serverFingerprint(serverPubKey) !== this.serverFingerprint) {
      return; // server fingerprint mismatch
    }
    const sharedSecret = this.clientECDH.computeSecret(serverPubKey);
    const transportKey = crypto.createHash('sha256').update(sharedSecret).digest();
    let info;
    try {
      info = Codec.decodeMemberInfo(buf, transportKey);
    } catch (e) {
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
    if (!roomKeys.has(convId)) roomKeys.set(convId, new Map());
    roomKeys.get(convId)!.set(epoch, key);
    convKeys.set(convId, key);
    currentEpochs.set(convId, epoch);
    this.sharedWith.set(convId, new Set());
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
  }

  sendData(convId: number, payload: string) {
    const seq = this.nextSeq++;
    
    // Build dictionary using messages up to seq - 1
    const dict = this.getDictionary(this.senderId, seq);
    
    this.highestSentSeq = seq;
    const dart: DataDart = { type: TYPE_DATA, convId, senderId: this.senderId, seq, payload };
    this.sentMessages.set(seq, dart);
    this.pruneSent();
    this.messageStatus.set(seq, 'sent');
    
    const buf = Codec.encodeDataHelper(dart, dict);
    this.broadcast(buf);
    
    // Restart probe timer
    if (this.probeTimer) clearTimeout(this.probeTimer);
    this.probeTimer = setTimeout(() => {
        this.sendSync(convId);
    }, 400); // Send sync if no new messages sent for 400ms

    // Optimistic delivery timer
    const t = setTimeout(() => {
        this.messageStatus.set(seq, 'assumed_delivered');
    }, 600); // After 600ms without NACK, assume delivered
    this.optimisticTimers.set(seq, t);
  }

  private broadcast(buf: Buffer) {
    this.stats.packetsSent++;
    this.stats.bytesSent += buf.length;
    if (this.useFallback && this.tcpSocket) {
        const out = Buffer.alloc(2 + buf.length);
        out.writeUInt16BE(buf.length, 0);
        buf.copy(out, 2);
        this.tcpSocket.write(out);
    } else {
        for (const peer of this.peers) {
          this.socket.send(buf, peer.port, peer.address);
        }
    }
  }

  private handleMessage(buf: Buffer, rinfo: dgram.RemoteInfo) {
    try {
      const type = buf.readUInt8(0);
      
      if (type === TYPE_DATA) {
        const dec = Codec.decryptData(buf);
        const parsedSenderId = dec.senderId;
        const seq = dec.seq;
        
        const highestReceived = this.highestReceivedSeq.get(parsedSenderId) || 0;
        if (seq <= highestReceived) return; // already processed

        if (seq > highestReceived + 1) {
          // Gap detected: buffer the out-of-order packet and NACK the gap.
          if (!this.outOfOrderBuffer.has(parsedSenderId)) this.outOfOrderBuffer.set(parsedSenderId, new Map());
          this.outOfOrderBuffer.get(parsedSenderId)!.set(seq, buf);
          const missing = [];
          for (let i = highestReceived + 1; i < seq; i++) {
            if (!this.outOfOrderBuffer.get(parsedSenderId)!.has(i) && !this.receivedMessages.get(parsedSenderId)?.has(i)) {
              missing.push(i);
            }
          }
          if (missing.length > 0) {
            this.sendNack(dec.convId, parsedSenderId, missing);
          }
          return; // buffered, not processed yet
        }

        // Exact next packet: process it, then drain the buffer.
        this.processDataPacket(buf, dec, parsedSenderId, seq);
        this.processBufferedPackets(parsedSenderId);
        
      } else if (type === TYPE_NACK) {
        this.stats.nacksReceived++;
        const nack = Codec.decodeNack(buf);
        if (nack.senderId !== this.senderId) return; // Not for me
        for (const seq of nack.missingSeq) {
          const dart = this.sentMessages.get(seq);
          if (dart) {
            this.stats.retransmits++;
            const dict = this.getDictionary(this.senderId, seq);
            const outBuf = Codec.encodeDataHelper(dart, dict);
            this.broadcast(outBuf);
            
            // Reset optimistic timer
            this.messageStatus.set(seq, 'sent');
            if (this.optimisticTimers.has(seq)) {
                clearTimeout(this.optimisticTimers.get(seq)!);
            }
            const t = setTimeout(() => {
                this.messageStatus.set(seq, 'assumed_delivered');
            }, 600);
            this.optimisticTimers.set(seq, t);
          }
        }
      } else if (type === TYPE_KEY_SHARE) {
        this.handleKeyShare(buf);
      } else if (type === TYPE_MEMBER_INFO) {
        this.handleMemberInfo(buf);
      } else if (type === TYPE_SYNC) {
        const sync = Codec.decodeSync(buf);
        const highestReceived = this.highestReceivedSeq.get(sync.senderId) || 0;
        if (sync.highestSeq > highestReceived) {
            const missing = [];
            if (!this.receivedMessages.has(sync.senderId)) this.receivedMessages.set(sync.senderId, new Map());
            for (let i = highestReceived + 1; i <= sync.highestSeq; i++) {
                if (!this.receivedMessages.get(sync.senderId)!.has(i)) missing.push(i);
            }
            if (missing.length > 0) {
                this.sendNack(sync.convId, sync.senderId, missing);
            }
        }
      } else if (type === 0x06) {
        const reset = Codec.decodeDictReset(buf);
        if (reset.targetId === this.senderId) {
          this.sentMessages.clear(); // I'm the target: flush my history
        } else if (this.receivedMessages.has(reset.targetId)) {
          this.receivedMessages.get(reset.targetId)!.clear();
        }
      } else if (type === 0x07) {
        const ack = Codec.decodeAck(buf);
        if (ack.targetId === this.senderId && ack.seq >= this.highestSentSeq) {
          if (this.probeTimer) clearTimeout(this.probeTimer);
        }
      }
    } catch (e) {
        // Bad packet
    }
  }

  private processDataPacket(buf: Buffer, dec: DecryptedData, parsedSenderId: number, seq: number) {
    const dict = this.getDictionary(parsedSenderId, seq);
    if (!dec.dictFp.equals(dictFingerprint(dict))) {
      // Dictionary fingerprint mismatch = lost history; mirror real-client recovery.
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
      return; // dictionary desync: drop
    }
    const dart: DataDart = { type: TYPE_DATA, convId: dec.convId, senderId: parsedSenderId, seq, payload };
    if (!this.receivedMessages.has(dart.senderId)) this.receivedMessages.set(dart.senderId, new Map());
    if (!this.receivedMessages.get(dart.senderId)!.has(dart.seq)) {
      this.receivedMessages.get(dart.senderId)!.set(dart.seq, dart);
      this.pruneReceived(dart.senderId);
      if (dart.seq > (this.highestReceivedSeq.get(dart.senderId) || 0)) {
        this.highestReceivedSeq.set(dart.senderId, dart.seq);
      }
    }
  }

  private processBufferedPackets(senderId: number) {
    let nextSeq = (this.highestReceivedSeq.get(senderId) || 0) + 1;
    const bufferMap = this.outOfOrderBuffer.get(senderId);
    if (!bufferMap) return;
    while (bufferMap.has(nextSeq)) {
      const raw = bufferMap.get(nextSeq)!;
      bufferMap.delete(nextSeq);
      try {
        const dec = Codec.decryptData(raw);
        if (dec.senderId === senderId) {
          this.processDataPacket(raw, dec, senderId, nextSeq);
        }
      } catch (e) {
        // Bad buffered packet
      }
      nextSeq++;
    }
  }

  private sendDictReset(convId: number, targetId: number) {
    const reset = { type: 0x06, convId, senderId: this.senderId, targetId };
    this.broadcast(Codec.encodeDictReset(reset));
  }
  
  private sendNack(convId: number, senderId: number, missingSeq: number[]) {
    this.stats.nacksSent++;
    const nack: NackDart = { type: TYPE_NACK, convId, senderId, missingSeq };
    const buf = Codec.encodeNack(nack);
    this.broadcast(buf);
  }
  
  private sendSync(convId: number) {
      if (this.highestSentSeq === 0) return;
      this.stats.syncsSent++;
      const sync: SyncDart = { type: TYPE_SYNC, convId, senderId: this.senderId, highestSeq: this.highestSentSeq };
      const buf = Codec.encodeSync(sync);
      this.broadcast(buf);
  }
  
  close() {
    if (this.probeTimer) clearTimeout(this.probeTimer);
    if (this.rekeyTimer) clearTimeout(this.rekeyTimer);
    for (const timer of this.optimisticTimers.values()) clearTimeout(timer);
    if (this.tcpSocket) {
        this.tcpSocket.destroy();
    }
    this.socket.close();
  }
  
  enableFallback(host: string, port: number) {
      if (this.useFallback) return;
      this.useFallback = true;
      const net = require('net');
      this.tcpSocket = net.connect(port, host, () => {
          console.log(`Client ${this.port} connected to TCP fallback`);
      });
      let buffer = Buffer.alloc(0);
      this.tcpSocket.on('data', (data: Buffer) => {
          buffer = Buffer.concat([buffer, data]);
          while (buffer.length >= 2) {
              const len = buffer.readUInt16BE(0);
              if (buffer.length >= 2 + len) {
                  const payload = buffer.subarray(2, 2 + len);
                  buffer = buffer.subarray(2 + len);
                  this.stats.packetsReceived++;
                  this.stats.bytesReceived += payload.length;
                  this.handleMessage(payload, { address: host, port: this.port } as any); // fake rinfo
              } else {
                  break;
              }
          }
      });
  }
  
  disableFallback() {
      this.useFallback = false;
      if (this.tcpSocket) {
          this.tcpSocket.destroy();
          this.tcpSocket = undefined;
      }
  }

  getStatus(seq: number) {
      return this.messageStatus.get(seq);
  }
}
