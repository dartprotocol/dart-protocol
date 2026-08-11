import * as fs from 'fs';

// Deterministic parameters for reproducible runs. Override via env, e.g.
//   MSGS=5000 LATENCY=25 SEED=7 npx ts-node src/benchmark.ts
const PKT_LOSS_RATES = [0.0, 0.1, 0.3];
const MSGS_TO_SEND = parseInt(process.env.MSGS || '10000', 10);
const LATENCY = parseInt(process.env.LATENCY || '50', 10); // ms one-way
const SEED = parseInt(process.env.SEED || '12345', 10);

// Small seeded PRNG (mulberry32) so the simulation is fully reproducible.
function makeRng(seed: number) {
  let a = seed >>> 0;
  return function () {
    a |= 0;
    a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function runSim(protocol: 'dart' | 'baseline', peers: number, loss: number, rng: () => number) {
    let packets = 0;
    let bytes = 0;
    let latencies: number[] = [];

    for (let i = 0; i < MSGS_TO_SEND; i++) {
        let maxLatency = 0;
        
        // Sender -> Server
        let senderPkts = 1;
        let senderBytes = 43;
        let s2sLoss = rng() < loss;
        
        for (let p = 0; p < peers; p++) {
            let time = 0;
            
            if (protocol === 'dart') {
                // Server -> Peer
                packets++; bytes += 43; // Fan-out
                let s2pLoss = rng() < loss;
                
                if (!s2sLoss && !s2pLoss) {
                    time = LATENCY * 2; 
                } else {
                    // Packet was dropped. Dart relies on the NEXT message's seq number 
                    // or a sparse Sync probe to detect loss.
                    // For simulation: assume the loss is detected by the next packet arriving (delay + 50ms)
                    // or by a Sync probe (400ms). We'll assume average 100ms detection delay during active bursts.
                    time = 100 + (LATENCY * 2); 
                    
                    // Nack up, Data down
                    packets += 2; bytes += (9 + 43);
                }
                
                if (time > maxLatency) maxLatency = time;
                
            } else if (protocol === 'baseline') {
                // Server -> Peer
                packets++; bytes += 43;
                let s2pLoss = rng() < loss;
                
                // Peer -> Server ACK
                packets++; bytes += 7;
                let ackLoss = rng() < loss;
                
                if (!s2sLoss && !s2pLoss && !ackLoss) {
                    time = LATENCY * 2;
                } else {
                    // Timeout (150ms) and retry
                    time = 150 + (LATENCY * 2);
                    packets += 3; // Resend data, ack back
                    bytes += (43 + 43 + 7);
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

console.log(`Discrete-event simulation. Messages=${MSGS_TO_SEND}, one-way latency=${LATENCY}ms, seed=${SEED}.`);
console.log("This is a synthetic model, not a live network measurement: each \"packet\" is an");
console.log("assumed fixed 43-byte payload and the model does not simulate real loss bursts.");
console.log("Measurements for 1:1 and 1:3 (Group of 4) topologies.");
for (let p of [1, 3]) {
    console.log(`\n=== Topology: 1 Sender to ${p} Receivers ===`);
    console.log(`Loss % | Protocol | Packets | Bytes   | Avg Latency | p50 | p95`);
    console.log(`-------|----------|---------|---------|-------------|-----|-----`);
    for (let loss of PKT_LOSS_RATES) {
        let d = runSim('dart', p, loss, makeRng(SEED));
        let b = runSim('baseline', p, loss, makeRng(SEED));
        
        console.log(`${(loss*100).toString().padStart(6)} | Dart     | ${d.packets.toString().padStart(7)} | ${d.bytes.toString().padStart(7)} | ${d.avg.toFixed(1).padStart(11)} | ${d.p50.toString().padStart(3)} | ${d.p95.toString().padStart(3)}`);
        console.log(`${(loss*100).toString().padStart(6)} | Baseline | ${b.packets.toString().padStart(7)} | ${b.bytes.toString().padStart(7)} | ${b.avg.toFixed(1).padStart(11)} | ${b.p50.toString().padStart(3)} | ${b.p95.toString().padStart(3)}`);
    }
}
