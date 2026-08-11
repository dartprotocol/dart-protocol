import * as dgram from 'dgram';
import * as net from 'net';
import * as http from 'http';
import * as fs from 'fs';
const express = require('express');
import * as WebSocket from 'ws';
import * as crypto from 'crypto';
import { Codec, TYPE_DATA, TYPE_NACK, TYPE_SYNC, TYPE_KEY_REQ, TYPE_KEY_SHARE, TYPE_MEMBER_INFO, DataDart, NackDart, SyncDart, KeyReqDart, MemberInfo } from './core';

interface Peer {
    id: string; // "ip:port" or "tcp:..." or "ws:..."
    type: 'udp' | 'tcp' | 'ws';
    address?: string;
    port?: number;
    tcpSocket?: net.Socket;
    ws?: any;
    lastPacketTime?: number;
    packetCount?: number;
}

export class DartGroupServer {
    public udpSocket: dgram.Socket;
    public tcpServer: net.Server;
    public httpServer: http.Server;
    public wss: WebSocket.Server;
    
    // convId -> list of peers
    private groups = new Map<number, Peer[]>();
    
    // convId -> senderId -> Peer
    private clientMap = new Map<number, Map<number, Peer>>();
    
    // convId -> senderId -> public key (the server is blind: it never holds
    // group keys, only public membership info)
    private members = new Map<number, Map<number, Buffer>>();
    
    // convId -> creator senderId (first member; generates and rotates the key)
    private creator = new Map<number, number>();
    
    // transport peer id -> senderId (learned from KeyReq / control packets)
    private peerIdentity = new Map<string, number>();
    
    // Server ECDH Keypair
    private serverECDH: crypto.ECDH;
    
    // Loads (or generates and persists) the server's long-term ECDH key so its
    // public-key fingerprint is stable across restarts — required for pinning.
    private loadOrCreateServerKey(): crypto.ECDH {
        const keyFile = process.env.DART_SERVER_KEY_FILE || 'dart_server.key';
        const ecdh = crypto.createECDH('prime256v1');
        if (fs.existsSync(keyFile)) {
            const hex = fs.readFileSync(keyFile, 'utf-8').trim();
            ecdh.setPrivateKey(Buffer.from(hex, 'hex'));
        } else {
            ecdh.generateKeys();
            fs.writeFileSync(keyFile, ecdh.getPrivateKey().toString('hex'), { mode: 0o600 });
        }
        return ecdh;
    }

    // Exposes the server's static public key so tests can pin the fingerprint.
    getServerFingerprint(): Buffer {
        return this.serverECDH.getPublicKey();
    }
    
    // convId -> senderId -> seq -> Buffer
    private messageCache = new Map<number, Map<number, Map<number, Buffer>>>();
    
    // convId -> senderId -> highestSeq
    private highestSeq = new Map<number, Map<number, number>>();

    public stats = { packetsReceived: 0, packetsSent: 0, nacksReceived: 0, nacksSent: 0, repairsSent: 0 };

    constructor(port: number) {
        this.serverECDH = this.loadOrCreateServerKey();
        const fingerprint = Codec.serverFingerprint(this.serverECDH.getPublicKey());
        console.log(`[Server] Server key fingerprint: ${fingerprint}`);
        console.log(`[Server]   -> Pin it in clients (e.g. DART_SERVER_FINGERPRINT=${fingerprint}) to prevent MITM on key exchange.`);
        
        // UDP Server
        this.udpSocket = dgram.createSocket('udp4');
        this.udpSocket.bind(port);
        this.udpSocket.on('message', (msg, rinfo) => {
            this.stats.packetsReceived++;
            const peerId = `udp:${rinfo.address}:${rinfo.port}`;
            this.handleMessage(msg, { id: peerId, type: 'udp', address: rinfo.address, port: rinfo.port });
        });

        // TCP Server
        this.tcpServer = net.createServer((socket) => {
            const peerId = `tcp:${socket.remoteAddress}:${socket.remotePort}`;
            let buffer = Buffer.alloc(0);
            
            socket.on('data', (data) => {
                buffer = Buffer.concat([buffer, data as Buffer]);
                // Simple framing: 2-byte length + payload
                while (buffer.length >= 2) {
                    const len = buffer.readUInt16BE(0);
                    if (buffer.length >= 2 + len) {
                        const payload = buffer.subarray(2, 2 + len);
                        buffer = buffer.subarray(2 + len);
                        this.stats.packetsReceived++;
                        this.handleMessage(payload, { id: peerId, type: 'tcp', tcpSocket: socket });
                    } else {
                        break;
                    }
                }
            });
            
            socket.on('close', () => this.removePeer(peerId));
            socket.on('error', () => {});
        });
        this.tcpServer.listen(port + 1); // TCP on port+1

        // HTTP / WS Server for Web Demo
        const app = express();
        app.use(express.static('public'));
        this.httpServer = http.createServer(app);
        
        this.wss = new WebSocket.Server({ server: this.httpServer });
        this.wss.on('connection', (ws, req) => {
            const peerId = `ws:${req.socket.remoteAddress}:${req.socket.remotePort}`;
            ws.on('message', (data: Buffer) => {
                this.stats.packetsReceived++;
                this.handleMessage(data, { id: peerId, type: 'ws', ws });
            });
            ws.on('close', () => this.removePeer(peerId));
        });
        this.httpServer.listen(port + 2); // HTTP/WS on port+2
    }

    joinGroup(convId: number, peer: Peer) {
        if (!this.groups.has(convId)) {
            this.groups.set(convId, []);
        }
        const group = this.groups.get(convId)!;
        if (!group.find(p => p.id === peer.id)) {
            group.push(peer);
        }
    }
    
    private removePeer(peerId: string) {
        const leftConvs: number[] = [];
        for (const [convId, group] of this.groups.entries()) {
            const before = group.length;
            this.groups.set(convId, group.filter(p => p.id !== peerId));
            if (group.length !== before) {
                leftConvs.push(convId);
            }
        }
        // Remove the departed member and notify the remaining members so they
        // can re-key (forward secrecy on member departure).
        const senderId = this.peerIdentity.get(peerId);
        for (const convId of leftConvs) {
            const mems = this.members.get(convId);
            if (mems && senderId !== undefined) {
                mems.delete(senderId);
                this.notifyMembers(convId);
            }
        }
    }

    // Broadcasts the current roster (encrypted per member) to every member.
    private notifyMembers(convId: number) {
        const mems = this.members.get(convId);
        if (!mems) return;
        const roster = [...mems.entries()].map(([senderId, pubKey]) => ({ senderId, pubKey }));
        for (const [mSenderId, mPubKey] of mems.entries()) {
            const sharedSecret = this.serverECDH.computeSecret(mPubKey);
            const transportKey = crypto.createHash('sha256').update(sharedSecret).digest();
            const info: MemberInfo = {
                type: TYPE_MEMBER_INFO,
                convId,
                senderId: mSenderId,
                serverPubKey: this.serverECDH.getPublicKey(),
                creator: this.creator.get(convId) === mSenderId,
                members: roster
            };
            const targetPeer = this.clientMap.get(convId)?.get(mSenderId);
            if (targetPeer) {
                this.sendToPeer(Codec.encodeMemberInfo(info, transportKey), targetPeer);
            }
        }
    }
    
    private sendToPeer(buf: Buffer, peer: Peer) {
        this.stats.packetsSent++;
        if (peer.type === 'udp' && peer.address && peer.port) {
            this.udpSocket.send(buf, peer.port, peer.address);
        } else if (peer.type === 'tcp' && peer.tcpSocket) {
            const out = Buffer.alloc(2 + buf.length);
            out.writeUInt16BE(buf.length, 0);
            buf.copy(out, 2);
            peer.tcpSocket.write(out);
        } else if (peer.type === 'ws' && peer.ws && peer.ws.readyState === WebSocket.OPEN) {
            peer.ws.send(buf);
        }
    }
    
    private handleMessage(buf: Buffer, peer: Peer) {
        const now = Date.now();
        if (!peer.lastPacketTime) {
             peer.lastPacketTime = now;
             peer.packetCount = 0;
        }
        if (now - peer.lastPacketTime > 1000) {
             peer.lastPacketTime = now;
             peer.packetCount = 0;
        }
        peer.packetCount++;
        if (peer.packetCount > 100) {
             console.log(`[Server] Rate limit exceeded for ${peer.id}. Dropping packet.`);
             return; // Drop packet to prevent flood
        }

        console.log(`[Server] Received ${buf.length} bytes from ${peer.id}`);
        try {
            const type = buf.readUInt8(0);
            const convId = buf.readUInt16BE(1);
            
            // Auto-join the peer to the conversation group
            this.joinGroup(convId, peer);
            
            // Track senderId to peer mapping for targeted routing (like ACKs).
            // Data darts no longer carry a cleartext senderId (7-byte header), so
            // identity is learned from control packets (KeyReq/NACK/SYNC/ACK) and
            // remembered per transport peer.
            if (type !== TYPE_DATA && buf.length >= 5) {
                const senderId = buf.readUInt16BE(3);
                this.peerIdentity.set(peer.id, senderId);
                if (!this.clientMap.has(convId)) this.clientMap.set(convId, new Map());
                this.clientMap.get(convId)!.set(senderId, peer);
            }
            
            if (type === TYPE_DATA) {
                const senderId = this.peerIdentity.get(peer.id);
                if (senderId === undefined) {
                    console.log(`[Server] Dropping DataDart from unknown peer ${peer.id} (no key exchange seen).`);
                    return;
                }
                const seq = buf.readUIntBE(3, 3);
                console.log(`[Server] DataDart Conv:${convId} Sender:${senderId} Seq:${seq}`);
                
                if (!this.messageCache.has(convId)) this.messageCache.set(convId, new Map());
                if (!this.messageCache.get(convId)!.has(senderId)) this.messageCache.get(convId)!.set(senderId, new Map());
                
                const cacheMap = this.messageCache.get(convId)!.get(senderId)!;
                cacheMap.set(seq, buf);
                
                if (!this.highestSeq.has(convId)) this.highestSeq.set(convId, new Map());
                const currentHighest = this.highestSeq.get(convId)!.get(senderId) || 0;
                
                // GC Sliding Window: keep only the last 200 packets to prevent memory leaks
                const minSeq = Math.max(1, Math.max(seq, currentHighest) - 200);
                for (const k of cacheMap.keys()) {
                    if (k < minSeq) cacheMap.delete(k);
                }
                
                if (seq > currentHighest + 1) {
                    const missing = [];
                    for (let i = currentHighest + 1; i < seq; i++) {
                        if (!this.messageCache.get(convId)!.get(senderId)!.has(i)) missing.push(i);
                    }
                    if (missing.length > 0) {
                        this.sendNack(convId, senderId, missing, peer);
                    }
                }
                
                if (seq > currentHighest) {
                    this.highestSeq.get(convId)!.set(senderId, seq);
                }
                
                const group = this.groups.get(convId) || [];
                let fanned = 0;
                for (const p of group) {
                    if (p.id !== peer.id) {
                        this.sendToPeer(buf, p);
                        fanned++;
                    }
                }
                console.log(`[Server] Fanned out to ${fanned} peers (total group size ${group.length})`);
            } else if (type === TYPE_KEY_REQ) {
                const req = Codec.decodeKeyReq(buf);
                console.log(`[Server] KeyReq Conv:${req.convId} Sender:${req.senderId}`);

                // The server is BLIND: it never sees or stores the group key.
                // It only tracks membership (public keys) and relays encrypted
                // key shares. The group key is created by the first member
                // (creator) and shared member-to-member.
                if (!this.members.has(req.convId)) {
                    this.members.set(req.convId, new Map());
                    this.creator.set(req.convId, req.senderId);
                }
                this.members.get(req.convId)!.set(req.senderId, req.clientPubKey);

                // Notify every member (including the joiner) with the roster.
                this.notifyMembers(req.convId);
            } else if (type === TYPE_KEY_SHARE) {
                // Relay the (opaque, encrypted) group-key share to its target.
                const targetId = buf.readUInt16BE(5);
                const targetPeer = this.clientMap.get(convId)?.get(targetId);
                if (targetPeer) {
                    this.sendToPeer(buf, targetPeer);
                }
            } else if (type === TYPE_NACK) {
                this.stats.nacksReceived++;
                const nack = Codec.decodeNack(buf);
                
                const missingFromServer = [];
                for (const seq of nack.missingSeq) {
                    const cached = this.messageCache.get(nack.convId)?.get(nack.senderId)?.get(seq);
                    if (cached) {
                        this.stats.repairsSent++;
                        this.sendToPeer(cached, peer);
                    } else {
                        missingFromServer.push(seq);
                    }
                }
                
                if (missingFromServer.length > 0) {
                    for (const p of (this.groups.get(nack.convId) || [])) {
                        if (p.id !== peer.id) {
                            this.sendNack(nack.convId, nack.senderId, missingFromServer, p);
                        }
                    }
                }
            } else if (type === TYPE_SYNC) {
                const sync = Codec.decodeSync(buf);
                const group = this.groups.get(sync.convId) || [];
                
                const currentHighest = this.highestSeq.get(sync.convId)?.get(sync.senderId) || 0;
                if (sync.highestSeq > currentHighest) {
                    const missing = [];
                    for (let i = currentHighest + 1; i <= sync.highestSeq; i++) {
                        if (!this.messageCache.get(sync.convId)?.get(sync.senderId)?.has(i)) missing.push(i);
                    }
                    if (missing.length > 0) {
                        this.sendNack(sync.convId, sync.senderId, missing, peer);
                    }
                }
                
                for (const p of group) {
                    if (p.id !== peer.id) {
                        this.sendToPeer(buf, p);
                    }
                }
            } else if (type === 0x06) {
                // TYPE_DICT_RESET
                console.log(`[Server] DictReset Conv:${convId}`);
                const group = this.groups.get(convId) || [];
                for (const p of group) {
                    if (p.id !== peer.id) {
                        this.sendToPeer(buf, p);
                    }
                }
            } else if (type === 0x07) {
                // TYPE_ACK - Route specifically to targetId to prevent O(N^2) fanout
                const targetId = buf.readUInt16BE(5);
                const targetPeer = this.clientMap.get(convId)?.get(targetId);
                if (targetPeer) {
                    this.sendToPeer(buf, targetPeer);
                }
            }
        } catch (e) {
            // Bad packet
        }
    }
    
    private sendNack(convId: number, senderId: number, missingSeq: number[], peer: Peer) {
        this.stats.nacksSent++;
        const nack: NackDart = { type: TYPE_NACK, convId, senderId, missingSeq };
        const buf = Codec.encodeNack(nack);
        this.sendToPeer(buf, peer);
    }
    
    close() {
        this.udpSocket.close();
        this.tcpServer.close();
        this.wss.close();
        this.httpServer.close();
    }
}
