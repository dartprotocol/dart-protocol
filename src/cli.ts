import * as dgram from 'dgram';
import * as crypto from 'crypto';
import * as readline from 'readline';
import { Codec, TYPE_DATA, TYPE_NACK, TYPE_SYNC, TYPE_KEY_REQ, TYPE_KEY_SHARE, TYPE_MEMBER_INFO, TYPE_CHAIN_SHARE, TYPE_ACK, DICT_WINDOW, dictFingerprint, roomKeys, currentEpochs, DataDart, NackDart, SyncDart, KeyReqDart, KeyShareDart, ChainShareDart, DecryptedData, ChainState, convKeys, seqDelta, seqNext, SEQ_MOD, advanceChain, pairwiseKey, signControlFrame, verifyControlFrame, stripControlFrame } from './core';

class NativeDartClient {
    public socket: dgram.Socket;
    public senderId: number;
    public currentRoomId: number = 0;
    
    private nextSeq = 1;
    private highestReceivedSeq = new Map<number, number>(); 
    private highestSentSeq = 0;
    
    private sentMessages = new Map<number, DataDart>();
    private receivedMessages = new Map<number, Map<number, DataDart>>(); 
    
    private syncTimers: any[] = [];
    private ackTimers = new Map<number, any>();
    
    private clientECDH!: crypto.ECDH;
    private lastSendTime: number = 0;
    
    // Optional pinned server fingerprint (SSH-style host-key verification).
    private serverFingerprint = (process.env.DART_SERVER_FINGERPRINT || '').trim().toLowerCase();
    
    private outOfOrderBuffer = new Map<number, Map<number, Buffer>>();
    private nackTimestamps = new Map<number, Map<number, number>>(); 
    private pendingQueue: {convId: number, payload: string}[] = [];
    
    private serverPort = 9000;
    private serverHost = '127.0.0.1';

    constructor() {
        this.senderId = Math.floor(Math.random() * 65535);
        this.socket = dgram.createSocket('udp4');
        
        this.socket.on('message', (msg, rinfo) => {
            this.handleMessage(msg);
        });
        
        this.socket.on('close', () => {
            console.log("\n[SYSTEM] Socket closed.");
        });
        
        this.connect();
    }
    
    public connect() {
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
                if (dist >= 1 && dist <= DICT_WINDOW) msgsToConcat.push(dart);
            }
        } else {
            const msgs = this.receivedMessages.get(senderId);
            if (msgs) {
                for (const dart of msgs.values()) {
                    const dist = seqDelta(dart.seq, maxSeq);
                    if (dist >= 1 && dist <= DICT_WINDOW) msgsToConcat.push(dart);
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

    // Bound memory: drop history older than the dictionary window (+ slack) so
    // the compression dictionary and retransmit buffers stay small.
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

    public sendData(convId: number, payload: string) {
        const now = Date.now();
        if (now - this.lastSendTime < 250) {
            console.log("[SYSTEM] Rate limit: Sending too fast. Message dropped.");
            return;
        }
        this.lastSendTime = now;
        
        if (!convKeys.has(convId)) {
            this.pendingQueue.push({ convId, payload });
            return;
        }
        const epoch = currentEpochs.get(convId) || 1;
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
        const buf = Codec.encodeDataHelper(dart, dict, messageKey, idx);
        this.broadcast(buf);
        
        process.stdout.write(`\x1b[90m[↑] Sending Seq ${seq}...\x1b[0m\r`);
        
        this.clearSyncTimers();
        this.syncTimers.push(setTimeout(() => this.sendSync(convId), 300));
        this.syncTimers.push(setTimeout(() => this.sendSync(convId), 1000));
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
        const buf = Codec.encodeKeyReq(req);
        this.broadcast(buf);
        console.log(`\x1b[36m[SYSTEM] Joining room ${roomId} (My ID: ${this.senderId})...\x1b[0m`);
        console.log(`\x1b[36m[SYSTEM] Performing ECDH Key Exchange...\x1b[0m`);
    }
    
    private broadcast(buf: Buffer) {
        this.socket.send(buf, this.serverPort, this.serverHost);
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
                // baseline, except when the first seq is within the recoverable
                // window: then NACK the real gap instead of an out-of-order start.
                const ahead = hasBaseline ? seqDelta(highestReceived, seq) : (seq >= 1 && seq <= DICT_WINDOW ? seq : 1);
                if (ahead === 0 || ahead >= SEQ_MOD / 2) return; 
                
                if (ahead > 1) {
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
                                console.log(`\x1b[31m[SYSTEM] Packet seq ${i} from User ${parsedSenderId} permanently lost. Resynchronizing dictionary gracefully...\x1b[0m`);
                                this.declarePermanentLoss(convId, parsedSenderId, i);
                            } else {
                                missing.push(i);
                            }
                        }
                    }
                    if (missing.length > 0) {
                        console.log(`\x1b[33m[SYSTEM] Gap detected. Sent NACK for seqs: ${missing.join(', ')}\x1b[0m`);
                        this.sendNack(convId, parsedSenderId, missing);
                    }
                    return; 
                }
                
                const dec = this.decryptDataInOrder(buf, parsedSenderId);
                if (dec) {
                    this.processDataPacket(buf, dec, parsedSenderId, seq);
                    this.processBufferedPackets(parsedSenderId);
                }
                
            } else if (type === TYPE_CHAIN_SHARE) {
                this.handleChainShare(buf);
            } else if (type === TYPE_NACK) {
                const nackConvId = buf.readUInt16BE(1);
                const nackSenderId = buf.readUInt16BE(3);
                const nackTargetId = buf.readUInt16BE(5);
                if (nackTargetId !== this.senderId) return;
                // Verify the sender's per-sender MAC so a group member can't
                // forge another member's NACK.
                const nackPeerPub = this.roster.get(nackConvId)?.get(nackSenderId);
                const nackStripped = nackPeerPub ? verifyControlFrame(buf, pairwiseKey(this.clientECDH, nackPeerPub)) : null;
                if (!nackStripped) return;
                const nack = Codec.decodeNack(nackStripped);
                console.log(`\x1b[33m[SYSTEM] Receiver missed seqs ${nack.missingSeq.join(', ')}. Sending NACK repairs...\x1b[0m`);
                for (const seq of nack.missingSeq) {
                    const dart = this.sentMessages.get(seq);
                    const mk = this.messageKeys.get(seq);
                    if (dart && mk) {
                        const dict = this.getDictionary(this.senderId, seq);
                        const outBuf = Codec.encodeDataHelper(dart, dict, mk.key, mk.idx);
                        this.broadcast(outBuf);
                    }
                }
            } else if (type === TYPE_SYNC) {
                // SYNC is keyed to the relay server, which verified and relayed it.
                const syncStripped = stripControlFrame(buf);
                if (!syncStripped) return;
                const sync = Codec.decodeSync(syncStripped);
                const hasBaseline = this.highestReceivedSeq.has(sync.senderId);
                const highestReceived = this.highestReceivedSeq.get(sync.senderId) || 0;
                // Fresh receiver: NACK the whole reported range; otherwise only
                // the modular distance ahead of what we've seen (handles wraps).
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
                                console.log(`\x1b[31m[SYSTEM] Packet seq ${i} from User ${sync.senderId} permanently lost. Resynchronizing dictionary gracefully...\x1b[0m`);
                                this.declarePermanentLoss(sync.convId, sync.senderId, i);
                                this.processBufferedPackets(sync.senderId);
                            } else {
                                missing.push(i);
                            }
                        }
                    }
                    if (missing.length > 0) {
                        console.log(`\x1b[33m[SYSTEM] Sync probe revealed gap. Sent NACK for seqs: ${missing.join(', ')}\x1b[0m`);
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
                const ack = Codec.decodeAck(ackStripped);
                if (seqDelta(this.highestSentSeq, ack.seq) < SEQ_MOD / 2) {
                    this.clearSyncTimers();
                    process.stdout.write(`\x1b[90m[✓] Delivered (Seq ${ack.seq})                                  \x1b[0m\n`);
                }
            } else if (type === TYPE_KEY_SHARE) {
                this.handleKeyShare(buf);
            } else if (type === TYPE_MEMBER_INFO) {
                this.handleMemberInfo(buf);
            } else if (type === 0x06) {
                // Dict-Reset is keyed to the relay server, which verified it.
                const resetStripped = stripControlFrame(buf);
                if (!resetStripped) return;
                const reset = Codec.decodeDictReset(resetStripped);
                if (reset.targetId === this.senderId) {
                    console.log(`\x1b[31m[SYSTEM] User ${reset.senderId} requested a dictionary reset. Flushing history to recover stream...\x1b[0m`);
                    this.sentMessages.clear();
                } else {
                    if (this.receivedMessages.has(reset.targetId)) {
                        this.receivedMessages.get(reset.targetId)!.clear();
                    }
                }
            } else {
                console.warn('\x1b[31mUnknown packet type:\x1b[0m', type);
            }
        } catch (e) {
            console.log("\x1b[31m[SYSTEM] Packet dropped (decrypt failure or tamper detected).\x1b[0m");
        }
    }
    
    // ---- E2EE group-key management ----
    private roster = new Map<number, Map<number, Buffer>>(); // convId -> senderId -> pubkey
    private sharedWith = new Map<number, Set<number>>(); // convId -> members we shared the current key with
    private rekeyTimer: any = null;
    private isCreator = new Map<number, boolean>();

    // Server public key per conversation (from MEMBER_INFO), used to key the
    // server-verified SYNC / Dict-Reset frames.
    private serverPubKeys = new Map<number, Buffer>();

    // Per-sender ratchet chains: convId -> epoch -> senderId -> chain state.
    private senderChains = new Map<number, Map<number, Map<number, ChainState>>>();
    private chainSharedWith = new Map<number, Set<number>>();
    private messageKeys = new Map<number, { key: Buffer; idx: number }>();
    // The epoch this client has adopted (per-client, unlike the shared codec
    // globals) so each member creates its own ratchet chain.
    private adoptedEpochs = new Map<number, number>();

    private handleMemberInfo(buf: Buffer) {
        // The server embeds its public key in the packet; we verify the pin,
        // then derive the transport key and decrypt the roster. Decrypting
        // successfully authenticates the server.
        let serverPubKey: Buffer;
        try {
            serverPubKey = Codec.memberInfoServerKey(buf);
        } catch (e) {
            return;
        }
        const fp = Codec.serverFingerprint(serverPubKey);
        if (this.serverFingerprint && fp !== this.serverFingerprint) {
            console.log("\x1b[31m[SYSTEM] SERVER FINGERPRINT MISMATCH — possible MITM. Aborting key exchange.\x1b[0m");
            return;
        }
        const sharedSecret = this.clientECDH.computeSecret(serverPubKey);
        const transportKey = crypto.createHash('sha256').update(sharedSecret).digest();
        let info;
        try {
            info = Codec.decodeMemberInfo(buf, transportKey);
        } catch (e) {
            console.log("\x1b[31m[SYSTEM] Could not authenticate server membership info. Aborting.\x1b[0m");
            return;
        }

        const rosterMap = new Map<number, Buffer>();
        for (const m of info.members) rosterMap.set(m.senderId, m.pubKey);
        this.roster.set(info.convId, rosterMap);
        this.serverPubKeys.set(info.convId, serverPubKey);
        const prevCreator = this.isCreator.get(info.convId) || false;
        this.isCreator.set(info.convId, info.creator);

        const myEpoch = this.adoptedEpochs.get(info.convId) || 0;
        if (info.creator && !myEpoch) {
            // I created the room: generate the group key (epoch 1).
            this.adoptKey(info.convId, 1, crypto.randomBytes(32));
        } else if (myEpoch) {
            // I already have the key: share it with any members I haven't yet.
            this.shareWithNewMembers(info.convId);
        }
        // If I just became the creator (successor election after the previous
        // creator left), rotate immediately so the departed member loses access.
        if (info.creator && !prevCreator && myEpoch) {
            this.rekey(info.convId);
        }
        // Share my ratchet chain with any members that just joined.
        this.shareChainWithMembers(info.convId, currentEpochs.get(info.convId) || 1);
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
            return; // not for us / bad share
        }
        const myEpoch = this.adoptedEpochs.get(convId) || 0;
        if (!myEpoch || decoded.epoch > myEpoch) {
            this.adoptKey(convId, decoded.epoch, decoded.groupKey);
        }
    }

    private adoptKey(convId: number, epoch: number, key: Buffer) {
        const isNew = !this.adoptedEpochs.get(convId);
        if (!roomKeys.has(convId)) roomKeys.set(convId, new Map());
        roomKeys.get(convId)!.set(epoch, key);
        convKeys.set(convId, key);
        currentEpochs.set(convId, epoch);
        this.adoptedEpochs.set(convId, epoch);
        this.sharedWith.set(convId, new Set());
        // Start a fresh per-sender ratchet chain for this epoch and share it.
        this.initOwnChain(convId, epoch);
        if (isNew) {
            console.log(`\x1b[36m[SYSTEM] Room ${convId} group key established (epoch ${epoch}). Type /quit to exit.\x1b[0m`);
            this.sendData(convId, `User ${this.senderId} joined the room (Native Client)`);
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

    // Forward secrecy: rotate the group key. Old epochs stay decryptable via
    // roomKeys; a compromised key only exposes its own epoch.
    private rekey(convId: number) {
        if (!this.isCreator.get(convId)) return;
        const current = currentEpochs.get(convId) || 1;
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
        const current = currentEpochs.get(convId) || 0;
        const keys = roomKeys.get(convId);
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
            console.log("\x1b[31m[SYSTEM] Dictionary desync detected (fingerprint). Sending automatic recovery signal...\x1b[0m");
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
            console.log("\x1b[31m[SYSTEM] Dictionary desync detected. Sending automatic recovery signal...\x1b[0m");
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
                console.log(`\x1b[36m[SYSTEM] ${dart.payload}\x1b[0m`);
            } else if (dart.payload !== "") {
                console.log(`\x1b[32m[User ${dart.senderId}]: ${dart.payload}\x1b[0m`);
            }
            
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
        const buf = Codec.encodeDictReset(reset);
        const serverPub = this.serverPubKeys.get(convId);
        if (!serverPub) return;
        this.broadcast(signControlFrame(buf, pairwiseKey(this.clientECDH, serverPub)));
    }
    
    private sendAck(convId: number, targetId: number, seq: number) {
        const ack = { type: TYPE_ACK, convId, senderId: this.senderId, targetId, seq };
        const buf = Codec.encodeAck(ack);
        const peerPub = this.roster.get(convId)?.get(targetId);
        if (!peerPub) return;
        this.broadcast(signControlFrame(buf, pairwiseKey(this.clientECDH, peerPub)));
    }
    
    private sendNack(convId: number, targetId: number, missingSeq: number[]) {
        const nack: NackDart = { type: TYPE_NACK, convId, senderId: this.senderId, targetId, missingSeq };
        const buf = Codec.encodeNack(nack);
        const peerPub = this.roster.get(convId)?.get(targetId);
        if (!peerPub) return;
        this.broadcast(signControlFrame(buf, pairwiseKey(this.clientECDH, peerPub)));
    }
    
    private sendSync(convId: number) {
        if (this.highestSentSeq === 0) return;
        const sync: SyncDart = { type: TYPE_SYNC, convId, senderId: this.senderId, highestSeq: this.highestSentSeq };
        const buf = Codec.encodeSync(sync);
        const serverPub = this.serverPubKeys.get(convId);
        if (!serverPub) return;
        this.broadcast(signControlFrame(buf, pairwiseKey(this.clientECDH, serverPub)));
    }
}

const client = new NativeDartClient();
const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

rl.question('Enter Room ID to join (e.g. 1): ', (answer) => {
    const roomId = parseInt(answer.trim(), 10);
    if (!isNaN(roomId)) {
        client.joinRoom(roomId);
        
        rl.on('line', (line) => {
            const text = line.trim();
            if (text === '/quit' || text === '/exit') {
                console.log("\x1b[36m[SYSTEM] Disconnecting...\x1b[0m");
                process.exit(0);
            }
            if (text !== "") {
                client.sendData(client.currentRoomId, text);
            }
        });
        
        rl.on('SIGINT', () => {
            console.log("\x1b[36m\n[SYSTEM] Caught interrupt signal. Disconnecting...\x1b[0m");
            process.exit(0);
        });
    } else {
        console.log("\x1b[31mInvalid Room ID. Exiting.\x1b[0m");
        process.exit(1);
    }
});
