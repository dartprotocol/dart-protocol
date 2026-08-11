import * as dgram from 'dgram';
import * as crypto from 'crypto';
import * as readline from 'readline';
import { Codec, TYPE_DATA, TYPE_NACK, TYPE_SYNC, TYPE_KEY_REQ, TYPE_KEY_SHARE, TYPE_MEMBER_INFO, TYPE_ACK, DICT_WINDOW, dictFingerprint, roomKeys, currentEpochs, DataDart, NackDart, SyncDart, KeyReqDart, KeyShareDart, convKeys } from './core';

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
        // seq, the window is guaranteed to match when no loss has occurred.
        const minSeq = Math.max(1, maxSeq - DICT_WINDOW);
        const msgsToConcat: DataDart[] = [];
        
        if (senderId === this.senderId) {
            for (const dart of this.sentMessages.values()) {
                if (dart.seq >= minSeq && dart.seq < maxSeq) msgsToConcat.push(dart);
            }
        } else {
            const msgs = this.receivedMessages.get(senderId);
            if (msgs) {
                for (const dart of msgs.values()) {
                    if (dart.seq >= minSeq && dart.seq < maxSeq) msgsToConcat.push(dart);
                }
            }
        }
        
        msgsToConcat.sort((a, b) => a.seq - b.seq);
        const bufs: Buffer[] = [];
        for (const dart of msgsToConcat) {
            bufs.push(Buffer.from(dart.payload, 'utf-8'));
        }
        return Buffer.concat(bufs);
    }

    // Bound memory: drop history older than the dictionary window (+ slack) so
    // the compression dictionary and retransmit buffers stay small.
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
        
        const seq = this.nextSeq++;
        const dart: DataDart = { type: TYPE_DATA, convId, senderId: this.senderId, seq, payload };
        this.sentMessages.set(seq, dart);
        this.highestSentSeq = seq;
        this.pruneSent();
        
        const dict = this.getDictionary(this.senderId, seq);
        const buf = Codec.encodeDataHelper(dart, dict);
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
                const dec = Codec.decryptData(buf);
                const parsedSenderId = dec.senderId;
                const seq = dec.seq;
                const convId = dec.convId;
                
                const highestReceived = this.highestReceivedSeq.get(parsedSenderId) || 0;
                if (seq <= highestReceived) return; 
                
                if (seq > highestReceived + 1) {
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
                
                this.processDataPacket(buf, parsedSenderId, seq);
                this.processBufferedPackets(parsedSenderId);
                
            } else if (type === TYPE_NACK) {
                const nack = Codec.decodeNack(buf);
                if (nack.senderId !== this.senderId) return;
                console.log(`\x1b[33m[SYSTEM] Receiver missed seqs ${nack.missingSeq.join(', ')}. Sending NACK repairs...\x1b[0m`);
                for (const seq of nack.missingSeq) {
                    const dart = this.sentMessages.get(seq);
                    if (dart) {
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
                    } else if (highestReceived === sync.highestSeq) {
                        this.sendAck(sync.convId, sync.senderId, highestReceived);
                    }
                }
            } else if (type === TYPE_ACK) {
                const ack = Codec.decodeAck(buf);
                if (ack.targetId === this.senderId && ack.seq >= this.highestSentSeq) {
                    this.clearSyncTimers();
                    process.stdout.write(`\x1b[90m[✓] Delivered (Seq ${ack.seq})                                  \x1b[0m\n`);
                }
            } else if (type === TYPE_KEY_SHARE) {
                this.handleKeyShare(buf);
            } else if (type === TYPE_MEMBER_INFO) {
                this.handleMemberInfo(buf);
            } else if (type === 0x06) {
                const reset = Codec.decodeDictReset(buf);
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
        this.isCreator.set(info.convId, info.creator);

        const key = convKeys.get(info.convId);
        if (info.creator && !key) {
            // I created the room: generate the group key (epoch 1).
            this.adoptKey(info.convId, 1, crypto.randomBytes(32));
        } else if (key) {
            // I already have the key: share it with any members I haven't yet.
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
            return; // not for us / bad share
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

    // Forward secrecy: rotate the group key. Old epochs stay decryptable via
    // roomKeys; a compromised key only exposes its own epoch.
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
            if (dart.seq > highestReceived) {
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
