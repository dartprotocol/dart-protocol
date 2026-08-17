import * as dgram from 'dgram';
import * as crypto from 'crypto';
import { Codec, TYPE_DATA, TYPE_NACK, TYPE_SYNC, TYPE_KEY_REQ, TYPE_KEY_SHARE, TYPE_MEMBER_INFO, TYPE_CHAIN_SHARE, TYPE_ACK, DICT_WINDOW, dictFingerprint, DataDart, NackDart, SyncDart, KeyReqDart, KeyShareDart, ChainShareDart, DecryptedData, ChainState, seqDelta, seqNext, SEQ_MOD, advanceChain, pairwiseKey, signControlFrame, verifyControlFrame, stripControlFrame } from './core';

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
  private ackedSeq = new Map<number, number>(); // convId -> highest acked seq
  private seenSeq = new Map<number, number>(); // senderId -> highest seq seen (any packet)
  private nackRetryTimers = new Map<number, NodeJS.Timeout>(); // senderId -> retry timer
  private optimisticTimers = new Map<number, NodeJS.Timeout>();
  private ackTimers = new Map<number, NodeJS.Timeout>();
  
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

  // Server public key per conversation (from MEMBER_INFO). Used to key the
  // server-verified SYNC / Dict-Reset frames.
  private serverPubKeys = new Map<number, Buffer>();

  // Per-sender ratchet chains: convId -> epoch -> senderId -> chain state.
  private senderChains = new Map<number, Map<number, Map<number, ChainState>>>();
  // Members I've shared my chain with this epoch (reset on adoptKey).
  private chainSharedWith = new Map<number, Set<number>>();
  // Cached per-message keys (and their chain index) by seq, for retransmission.
  private messageKeys = new Map<number, { key: Buffer; idx: number; epoch: number }>();
  // Initial chain state (index 0) per epoch, so a receiver that lost the
  // chain share can be given a state that reaches back to the epoch start.
  private chainSeeds = new Map<number, Map<number, ChainState>>();
  // The epoch this client has adopted so each member creates its own ratchet chain.
  private adoptedEpochs = new Map<number, number>();

  // Per-client group-key state. Must not be shared across in-process clients
  // (a module-level map would leak keys between test peers).
  private roomKeys = new Map<number, Map<number, Buffer>>();
  private currentEpochs = new Map<number, number>();
  private closed = false;

  getCurrentKey(convId: number): Buffer | undefined {
    return this.roomKeys.get(convId)?.get(this.currentEpochs.get(convId) || 1);
  }

  currentEpoch(convId: number): number {
    return this.currentEpochs.get(convId) || 0;
  }

  hasJoined(convId: number): boolean {
    return !!this.getCurrentKey(convId) && this.roster.has(convId);
  }

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
    // Retry: each KeyReq makes the server re-notify the roster, which is how
    // members refresh stale pubkeys (MEMBER_INFO has no other retry). Without
    // this, a member that lost the roster update can never verify another
    // member's NACKs or decode their shares again.
    setTimeout(() => this.broadcast(Codec.encodeKeyReq({ ...req, reqNonce: crypto.randomBytes(16) })), 1000);
    setTimeout(() => this.broadcast(Codec.encodeKeyReq({ ...req, reqNonce: crypto.randomBytes(16) })), 2000);
    setTimeout(() => this.broadcast(Codec.encodeKeyReq({ ...req, reqNonce: crypto.randomBytes(16) })), 3000);
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
    // Share my ratchet chain with any members that just joined (so they can
    // decrypt my future messages).
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
    // DIFFERENT key (a restarted creator re-uses epoch 1 with a fresh key and
    // members must switch, or they keep encrypting controls with a dead key).
    if (!myEpoch || decoded.epoch > myEpoch ||
        (decoded.epoch === myEpoch && curKey && !curKey.equals(decoded.groupKey))) {
      this.adoptKey(convId, decoded.epoch, decoded.groupKey);
    }
  }

  private adoptKey(convId: number, epoch: number, key: Buffer) {
    if (!this.roomKeys.has(convId)) this.roomKeys.set(convId, new Map());
    this.roomKeys.get(convId)!.set(epoch, key);
    this.currentEpochs.set(convId, epoch);
    this.adoptedEpochs.set(convId, epoch);
    this.sharedWith.set(convId, new Set());
    this.shareWithNewMembers(convId);
    // Start a fresh per-sender ratchet chain for this epoch and share it with
    // the group (on join and on every re-key).
    this.initOwnChain(convId, epoch);
    this.scheduleRekey(convId);
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

  // Generate a fresh chain seed for my own sends in `epoch` and share it with
  // every member, so they can decrypt my future messages (but no history).
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
    // misses its only copy can never decrypt this sender's messages. A stale
    // share is safe (the chain is deterministic and advances to the same keys).
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
    // The chain is deterministic: any valid state (at any index) advances to
    // the same keys, so storing the shared state is always safe.
    this.setChain(convId, decoded.epoch, decoded.senderId, { key: decoded.chainKey, index: decoded.chainIndex });
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
      if (epoch + 4 < current) {
        keys.delete(epoch);
        this.chainSeeds.get(convId)?.delete(epoch);
      }
    }
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
  }

  sendData(convId: number, payload: string) {
    const seq = this.nextSeq;
    this.nextSeq = seqNext(this.nextSeq);
    
    // Build dictionary using messages up to seq - 1
    const dict = this.getDictionary(this.senderId, seq);
    
    // Derive the per-message key from my ratchet chain and advance it.
    const epoch = this.currentEpochs.get(convId) || 1;
    const myChain = this.getChain(convId, epoch, this.senderId);
    if (!myChain) return; // key exchange not complete yet
    const idx = myChain.index;
    const { messageKey, state } = advanceChain(myChain, idx);
    this.setChain(convId, epoch, this.senderId, state);
    
    this.highestSentSeq = seq;
    const dart: DataDart = { type: TYPE_DATA, convId, senderId: this.senderId, seq, payload };
    this.sentMessages.set(seq, dart);
    this.messageKeys.set(seq, { key: messageKey, idx, epoch });
    this.pruneSent();
    this.messageStatus.set(seq, 'sent');
    
    const buf = Codec.encodeDataHelper(dart, dict, messageKey, idx, epoch);
    this.broadcast(buf);
    
    // Restart probe timer
    this.scheduleProbe(convId);

    // Optimistic delivery timer
    const t = setTimeout(() => {
        this.messageStatus.set(seq, 'assumed_delivered');
    }, 600); // After 600ms without NACK, assume delivered
    this.optimisticTimers.set(seq, t);
  }

  private scheduleProbe(convId: number) {
    if (this.probeTimer) clearTimeout(this.probeTimer);
    this.probeTimer = setTimeout(() => {
        this.sendSync(convId);
        // Re-arm while the most recent message is still unacknowledged, so
        // SYNC-driven NACK repair keeps retrying under loss instead of
        // stalling silently until the next rekey.
        const acked = this.ackedSeq.get(convId) || 0;
        if (seqDelta(this.highestSentSeq, acked) >= SEQ_MOD / 2) {
          this.scheduleProbe(convId);
        }
    }, 400); // Send sync if no new messages sent for 400ms
  }

  private broadcast(buf: Buffer) {
    if (this.closed) return;
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
        const convId = buf.readUInt16BE(1);
        const seq = buf.readUIntBE(3, 3);
        const extLen = buf.readUInt8(6);
        if (extLen < 24) return;
        const parsedSenderId = buf.readUInt16BE(7);
        
        const hasBaseline = this.highestReceivedSeq.has(parsedSenderId);
        const highestReceived = this.highestReceivedSeq.get(parsedSenderId) || 0;
        const seen = this.seenSeq.get(parsedSenderId) || 0;
        if (seqDelta(seen, seq) > 0 && seqDelta(seen, seq) < SEQ_MOD / 2) {
          this.seenSeq.set(parsedSenderId, seq);
        } else if (!this.seenSeq.has(parsedSenderId)) {
          this.seenSeq.set(parsedSenderId, seq);
        }
        // Modular gap test: ahead is how many steps `seq` is beyond the highest
        // we've seen. 0 = duplicate, >= SEQ_MOD/2 = stale, 1 = exact next.
        // A receiver with no baseline yet treats the first packet as its
        // baseline (so joining mid-conversation, even near a wrap, works),
        // except when the first seq is within the recoverable window: then the
        // gap is real and NACKing it beats accepting an out-of-order start.
        const ahead = hasBaseline ? seqDelta(highestReceived, seq) : (seq >= 1 && seq <= DICT_WINDOW ? seq : 1);
        if (ahead === 0 || ahead >= SEQ_MOD / 2) return; // already processed / stale

        if (ahead > 1) {
          // Gap detected: buffer the out-of-order packet and NACK the gap.
          if (!this.outOfOrderBuffer.has(parsedSenderId)) this.outOfOrderBuffer.set(parsedSenderId, new Map());
          this.outOfOrderBuffer.get(parsedSenderId)!.set(seq, buf);
          const missing = [];
          for (let k = 1; k < ahead; k++) {
            const i = (highestReceived + k) & 0xFFFFFF;
            if (!this.outOfOrderBuffer.get(parsedSenderId)!.has(i) && !this.receivedMessages.get(parsedSenderId)?.has(i)) {
              missing.push(i);
            }
          }
          if (missing.length > 0) {
            this.sendNack(convId, parsedSenderId, missing);
            this.scheduleNackRetry(convId, parsedSenderId);
          }
          return; // buffered, not processed yet
        }

        // Exact next packet: decrypt in order, process it, then drain the buffer.
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
        if (nackTargetId !== this.senderId) return; // Not for me
        // Verify the sender's per-sender MAC so a group member can't forge
        // another member's NACK.
        const nackPeerPub = this.roster.get(nackConvId)?.get(nackSenderId);
        const nackStripped = nackPeerPub ? verifyControlFrame(buf, pairwiseKey(this.clientECDH, nackPeerPub)) : null;
        if (!nackStripped) return;
        const convKey = this.getCurrentKey(nackConvId);
        if (!convKey) return;
        const nack = Codec.decodeNack(nackStripped, convKey);
        for (const seq of nack.missingSeq) {
          const dart = this.sentMessages.get(seq);
          const mk = this.messageKeys.get(seq);
          if (dart && mk) {
            this.stats.retransmits++;
            const dict = this.getDictionary(this.senderId, seq);
            const outBuf = Codec.encodeDataHelper(dart, dict, mk.key, mk.idx, mk.epoch);
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
        // The NACKer likely missed the chain share too (it can't decrypt my
        // stream without one). Re-share the chain SEED (index 0) so it can
        // reach back and decrypt the whole epoch, not just future messages.
        const epoch = this.currentEpochs.get(nackConvId) || 1;
        const seed = this.chainSeeds.get(nackConvId)?.get(epoch);
        if (seed) {
          this.sendChainShare(nackConvId, epoch, nackSenderId, seed.key, seed.index);
        }
      } else if (type === TYPE_KEY_SHARE) {
        this.handleKeyShare(buf);
      } else if (type === TYPE_MEMBER_INFO) {
        this.handleMemberInfo(buf);
      } else if (type === TYPE_SYNC) {
        // SYNC is keyed to the relay server, which verified and relayed it.
        const syncStripped = stripControlFrame(buf);
        if (!syncStripped) return;
        const syncKey = this.getCurrentKey(syncStripped.readUInt16BE(1));
        if (!syncKey) return;
        const sync = Codec.decodeSync(syncStripped, syncKey);
        const seen = this.seenSeq.get(sync.senderId) || 0;
        if (seqDelta(seen, sync.highestSeq) > 0 && seqDelta(seen, sync.highestSeq) < SEQ_MOD / 2) {
          this.seenSeq.set(sync.senderId, sync.highestSeq);
        } else if (!this.seenSeq.has(sync.senderId)) {
          this.seenSeq.set(sync.senderId, sync.highestSeq);
        }
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
                if (!this.receivedMessages.get(sync.senderId)!.has(i)) missing.push(i);
            }
            if (missing.length > 0) {
                this.sendNack(sync.convId, sync.senderId, missing);
                this.scheduleNackRetry(sync.convId, sync.senderId);
            }
        }
      } else if (type === 0x06) {
        // Dict-Reset is keyed to the relay server, which verified it.
        const resetStripped = stripControlFrame(buf);
        if (!resetStripped) return;
        const resetKey = this.getCurrentKey(resetStripped.readUInt16BE(1));
        if (!resetKey) return;
        const reset = Codec.decodeDictReset(resetStripped, resetKey);
        if (reset.targetId === this.senderId) {
          this.sentMessages.clear(); // I'm the target: flush my history
        } else if (this.receivedMessages.has(reset.targetId)) {
          this.receivedMessages.get(reset.targetId)!.clear();
        }
      } else if (type === 0x07) {
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
          this.ackedSeq.set(ackConvId, ack.seq);
        }
      }
    } catch (e) {
        // Bad packet
    }
  }

  // Decrypt a data packet using the sender's ratchet chain, advancing the chain
  // to the packet's message index. Only commits the advanced state after a
  // successful decrypt, so a failed attempt doesn't burn chain keys.
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
      const hasBaseline = this.highestReceivedSeq.has(dart.senderId);
      const h = this.highestReceivedSeq.get(dart.senderId) || 0;
      const d = hasBaseline ? seqDelta(h, dart.seq) : 1;
      if (d > 0 && d < SEQ_MOD / 2) {
        this.highestReceivedSeq.set(dart.senderId, dart.seq);
      }
      this.pruneReceived(dart.senderId);
      if (this.ackTimers.has(parsedSenderId)) clearTimeout(this.ackTimers.get(parsedSenderId)!);
      this.ackTimers.set(parsedSenderId, setTimeout(() => {
        this.sendAck(dec.convId, parsedSenderId, seq);
      }, 200));
    }
  }

  private processBufferedPackets(senderId: number) {
    let nextSeq = seqNext(this.highestReceivedSeq.get(senderId) || 0);
    const bufferMap = this.outOfOrderBuffer.get(senderId);
    if (!bufferMap) return;
    while (bufferMap.has(nextSeq)) {
      const raw = bufferMap.get(nextSeq)!;
      bufferMap.delete(nextSeq);
      try {
        const dec = this.decryptDataInOrder(raw, senderId);
        if (dec && dec.senderId === senderId) {
          this.processDataPacket(raw, dec, senderId, nextSeq);
        }
      } catch (e) {
        // Bad buffered packet
      }
      nextSeq = seqNext(nextSeq);
    }
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

  // Re-NACK the outstanding gap on a timer while it persists. A NACK is only
  // sent on incoming packets, so without this a single lost repair round would
  // stall recovery forever (no further packets, no further NACKs).
  private scheduleNackRetry(convId: number, senderId: number) {
    if (this.nackRetryTimers.has(senderId)) return;
    const t = setTimeout(() => {
      this.nackRetryTimers.delete(senderId);
      const seen = this.seenSeq.get(senderId);
      const hasBaseline = this.highestReceivedSeq.has(senderId);
      const highest = this.highestReceivedSeq.get(senderId) || 0;
      if (!hasBaseline || seen === undefined) return;
      const missing: number[] = [];
      const ahead = seqDelta(highest, seen);
      for (let k = 1; k < ahead && k <= DICT_WINDOW; k++) {
        const i = (highest + k) & 0xFFFFFF;
        if (!this.outOfOrderBuffer.get(senderId)?.has(i) && !this.receivedMessages.get(senderId)?.has(i)) {
          missing.push(i);
        }
      }
      if (missing.length > 0) {
        this.sendNack(convId, senderId, missing);
        this.scheduleNackRetry(convId, senderId);
      }
    }, 800);
    this.nackRetryTimers.set(senderId, t);
  }
  
  private sendSync(convId: number) {
      if (this.highestSentSeq === 0) return;
      this.stats.syncsSent++;
      const sync: SyncDart = { type: TYPE_SYNC, convId, senderId: this.senderId, highestSeq: this.highestSentSeq };
      const convKey = this.getCurrentKey(convId);
      const serverPub = this.serverPubKeys.get(convId);
      if (!convKey || !serverPub) return;
      const buf = Codec.encodeSync(sync, convKey);
      this.broadcast(signControlFrame(buf, pairwiseKey(this.clientECDH, serverPub)));
  }
  
  close() {
    this.closed = true;
    if (this.probeTimer) clearTimeout(this.probeTimer);
    if (this.rekeyTimer) clearTimeout(this.rekeyTimer);
    for (const timer of this.optimisticTimers.values()) clearTimeout(timer);
    for (const timer of this.ackTimers.values()) clearTimeout(timer);
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
