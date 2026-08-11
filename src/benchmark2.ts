import * as fs from 'fs';

const PKT_LOSS_RATES = [0.0, 0.1, 0.3];
const MSGS_TO_SEND = 10000;
// We simulate bursts of 10 messages. 
// Hybrid Dart sends 1 cumulative ACK at the end of each burst.
const BURST_SIZE = 10; 
const LATENCY = 50; // ms one-way

function runSim(protocol: 'dart-udp' | 'dart-ws' | 'baseline', peers: number, loss: number) {
    let packets = 0;
    let bytes = 0;
    let latencies: number[] = [];

    // Protocol overheads
    // dart-udp: 43 bytes data, 10 bytes ack
    // dart-ws: ~50 bytes data (ws framing), ~17 bytes ack + implicit TCP ACKs (we add +1 pkt for TCP ACK)
    const dataSize = protocol === 'dart-ws' ? 50 : 43;
    const ackSize = protocol === 'dart-ws' ? 17 : 10;
    const extraTcpAck = protocol === 'dart-ws' ? 1 : 0;

    for (let i = 0; i < MSGS_TO_SEND; i++) {
        let maxLatency = 0;
        let isEndOfBurst = (i % BURST_SIZE === BURST_SIZE - 1);
        
        // Sender -> Server
        let senderPkts = 1 + extraTcpAck;
        let senderBytes = dataSize;
        let s2sLoss = Math.random() < loss;
        
        for (let p = 0; p < peers; p++) {
            let time = 0;
            
            if (protocol.startsWith('dart')) {
                // Server -> Peer
                packets += (1 + extraTcpAck); 
                bytes += dataSize; 
                let s2pLoss = Math.random() < loss;
                
                if (!s2sLoss && !s2pLoss) {
                    time = LATENCY * 2; 
                } else {
                    time = 100 + (LATENCY * 2); 
                    packets += 2 * (1 + extraTcpAck); 
                    bytes += (9 + dataSize); // NACK + DATA
                }
                
                // Hybrid Cumulative ACK at end of burst
                if (isEndOfBurst) {
                    packets += (1 + extraTcpAck); // ACK up
                    bytes += ackSize;
                    // Server routes ACK to sender
                    senderPkts += (1 + extraTcpAck); // ACK down
                    senderBytes += ackSize;
                }
                
                if (time > maxLatency) maxLatency = time;
                
            } else if (protocol === 'baseline') {
                // Server -> Peer
                packets += 1; bytes += dataSize;
                let s2pLoss = Math.random() < loss;
                
                // Peer -> Server ACK
                packets += 1; bytes += ackSize;
                let ackLoss = Math.random() < loss;
                
                if (!s2sLoss && !s2pLoss && !ackLoss) {
                    time = LATENCY * 2;
                } else {
                    // Timeout (150ms) and retry
                    time = 150 + (LATENCY * 2);
                    packets += 3; // Resend data, ack back
                    bytes += (dataSize + dataSize + ackSize);
                }
                
                if (time > maxLatency) maxLatency = time;
            }
        }
        
        packets += senderPkts;
        bytes += senderBytes;
        latencies.push(maxLatency);
    }
    
    latencies.sort((a,b) => a - b);
    let avg = latencies.reduce((a,b)=>a+b, 0) / latencies.length;
    let p50 = latencies[Math.floor(latencies.length * 0.50)];
    let p95 = latencies[Math.floor(latencies.length * 0.95)];
    
    return { packets, bytes, avg, p50, p95 };
}

console.log("=== Hybrid Dart Measurement Pass (10,000 msgs, Burst=10) ===\n");
console.log("Measurements for 1:1 and 1:3 (Group of 4) topologies.\n");

for (let p of [1, 3]) {
    console.log(`=== Topology: 1 Sender to ${p} Receivers ===`);
    console.log(`Loss % | Protocol   | Packets | Bytes   | Avg Latency | p50 | p95`);
    console.log(`-------|------------|---------|---------|-------------|-----|-----`);
    for (let loss of PKT_LOSS_RATES) {
        let dUdp = runSim('dart-udp', p, loss);
        let dWs = runSim('dart-ws', p, loss);
        let b = runSim('baseline', p, loss);
        
        console.log(`${(loss*100).toString().padStart(6)} | Dart (UDP) | ${dUdp.packets.toString().padStart(7)} | ${dUdp.bytes.toString().padStart(7)} | ${dUdp.avg.toFixed(1).padStart(11)} | ${dUdp.p50.toString().padStart(3)} | ${dUdp.p95.toString().padStart(3)}`);
        console.log(`${(loss*100).toString().padStart(6)} | Dart (WS)  | ${dWs.packets.toString().padStart(7)} | ${dWs.bytes.toString().padStart(7)} | ${dWs.avg.toFixed(1).padStart(11)} | ${dWs.p50.toString().padStart(3)} | ${dWs.p95.toString().padStart(3)}`);
        console.log(`${(loss*100).toString().padStart(6)} | Baseline   | ${b.packets.toString().padStart(7)} | ${b.bytes.toString().padStart(7)} | ${b.avg.toFixed(1).padStart(11)} | ${b.p50.toString().padStart(3)} | ${b.p95.toString().padStart(3)}`);
        console.log(`-------|------------|---------|---------|-------------|-----|-----`);
    }
    console.log();
}
