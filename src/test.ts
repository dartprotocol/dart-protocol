import { DartClient } from './client';
import { DartGroupServer } from './server';
import { Codec } from './core';

async function delay(ms: number) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function runTests() {
  console.log("Starting Dart Protocol Group Server Tests...\n");

  const server = new DartGroupServer(9000);

  const clientA = new DartClient(8001);
  const clientB = new DartClient(8002);
  const clientC = new DartClient(8003);
  const clientD = new DartClient(8004);

  // All clients only talk to the server
  clientA.addPeer('127.0.0.1', 9000);
  clientB.addPeer('127.0.0.1', 9000);
  clientC.addPeer('127.0.0.1', 9000);
  clientD.addPeer('127.0.0.1', 9000);

  // Pin the server's fingerprint so key exchange is authenticated (MITM check)
  const serverFp = Codec.serverFingerprint(server.getServerFingerprint());
  [clientA, clientB, clientC, clientD].forEach(c => c.setServerFingerprint(serverFp));

  // Server registers them to Conv 1
  server.joinGroup(1, { id: 'udp:127.0.0.1:8001', type: 'udp', address: '127.0.0.1', port: 8001 });
  server.joinGroup(1, { id: 'udp:127.0.0.1:8002', type: 'udp', address: '127.0.0.1', port: 8002 });
  server.joinGroup(1, { id: 'udp:127.0.0.1:8003', type: 'udp', address: '127.0.0.1', port: 8003 });
  server.joinGroup(1, { id: 'udp:127.0.0.1:8004', type: 'udp', address: '127.0.0.1', port: 8004 });

  // Key exchange so the server learns each peer's senderId and the conversation
  // key is established (Data darts refuse to send without a key).
  clientA.joinConversation(1);
  clientB.joinConversation(1);
  clientC.joinConversation(1);
  clientD.joinConversation(1);
  await delay(200);

  // --- Test 1: Happy Path Group Fan-out ---
  console.log("--- Test 1: Group Fan-out (4 members, 0% loss) ---");
  clientA.sendData(1, "Hello group!");
  await delay(200);

  console.log("Client A (Sender) packets received:", clientA.stats.packetsReceived);
  console.log("Client B packets received:", clientB.stats.packetsReceived);
  console.log("Client C packets received:", clientC.stats.packetsReceived);
  console.log("Client D packets received:", clientD.stats.packetsReceived);
  console.log("Server packets fanned out:", server.stats.packetsSent);
  console.log("Expected: B,C,D receive 1 packet. Server sends 3 packets.\n");

  // Reset stats
  [clientA, clientB, clientC, clientD].forEach(c => c.stats = { packetsSent: 0, packetsReceived: 0, bytesSent: 0, bytesReceived: 0, nacksSent: 0, nacksReceived: 0, retransmits: 0, syncsSent: 0 });
  server.stats = { packetsReceived: 0, packetsSent: 0, nacksReceived: 0, nacksSent: 0, repairsSent: 0 };

  // --- Test 2: Client Packet Drop -> Server Repair ---
  console.log("--- Test 2: Client drops packet, Server repairs from cache ---");
  clientC.simulateLossPercent = 1.0; // C drops the next packet
  clientA.sendData(1, "Msg 2");

  // Restore C's network before the Sync/repair logic
  setTimeout(() => { clientC.simulateLossPercent = 0.0; }, 10);
  
  // A sends Msg 3 to trigger C's NACK for Msg 2
  await delay(50);
  clientA.sendData(1, "Msg 3");
  await delay(300);

  console.log("Client C Nacks Sent:", clientC.stats.nacksSent);
  console.log("Server Nacks Received:", server.stats.nacksReceived);
  console.log("Server Repairs Sent:", server.stats.repairsSent);
  console.log("Client A Retransmits (should be 0, server handled it!):", clientA.stats.retransmits);
  console.log("Expected: C missed Msg 2, got Msg 3, NACKed server for 2. Server repaired from cache without waking up A.\n");

  // --- Test 3: TCP Fallback ---
  console.log("--- Test 3: TCP Fallback Activation ---");
  clientB.enableFallback('127.0.0.1', 9001); // 9001 is the TCP port
  await delay(100); // let TCP connect
  
  clientA.sendData(1, "TCP Fallback test message");
  await delay(200);
  
  console.log("Client B packets received:", clientB.stats.packetsReceived);
  console.log("Expected: B received the message via TCP without losing state.");
  
  clientA.close();
  clientB.close();
  clientC.close();
  clientD.close();
  server.close();
  console.log("Tests Complete.");
}

runTests().catch(console.error);
