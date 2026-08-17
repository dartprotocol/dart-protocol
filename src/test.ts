import { DartClient } from './client';
import { DartGroupServer } from './server';
import { Codec, SEQ_MOD, TYPE_NACK, pairwiseKey, signControlFrame, advanceChain, chainMessageKey, chainNextKey } from './core';

async function delay(ms: number) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function runTests() {
  console.log("Starting Dart Protocol Group Server Tests...\n");
  let failed = 0;
  const check = (ok: boolean) => { if (!ok) failed++; };

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
  
  // --- Test 4: 24-bit sequence-number wrap (0xFFFFFF -> 0 -> 1 ...) ---
  console.log("--- Test 4: Sequence-number wrap across the 24-bit boundary ---");
  const clientE = new DartClient(8005);
  const clientF = new DartClient(8006);
  clientE.addPeer('127.0.0.1', 9000);
  clientF.addPeer('127.0.0.1', 9000);
  clientE.setServerFingerprint(serverFp);
  clientF.setServerFingerprint(serverFp);
  server.joinGroup(2, { id: 'udp:127.0.0.1:8005', type: 'udp', address: '127.0.0.1', port: 8005 });
  server.joinGroup(2, { id: 'udp:127.0.0.1:8006', type: 'udp', address: '127.0.0.1', port: 8006 });
  clientE.joinConversation(2);
  clientF.joinConversation(2);
  await delay(200);

  // Wind E's counter to just before the wrap so its first message is the 24-bit
  // maximum and the following ones wrap through 0.
  (clientE as any).nextSeq = SEQ_MOD - 1;

  const wrapPayloads = ["wrap-FFFFFE?no-max", "wrap-0", "wrap-1", "wrap-2", "wrap-3", "wrap-4", "wrap-5"];
  for (let i = 0; i < wrapPayloads.length; i++) {
    clientE.sendData(2, wrapPayloads[i]);
    await delay(60);
  }
  await delay(600);

  const received = (clientF as any).receivedMessages.get(clientE.senderId) || new Map();
  const expected = [SEQ_MOD - 1, 0, 1, 2, 3, 4, 5];
  let wrapOk = true;
  for (let i = 0; i < expected.length; i++) {
    const dart = received.get(expected[i]);
    const ok = dart && dart.payload === wrapPayloads[i];
    if (!ok) wrapOk = false;
    console.log(`  seq 0x${expected[i].toString(16)} payload=${dart ? JSON.stringify(dart.payload) : 'MISSING'} ${ok ? 'OK' : 'FAIL'}`);
  }
  check(wrapOk);
  console.log(wrapOk ? "Wrap test PASS" : "Wrap test FAIL");

  // --- Test 5: Per-sender control-frame auth (forgery resistance) ---
  console.log("--- Test 5: Control-frame forgery resistance ---");
  clientA.sendData(1, "forge-me");
  await delay(150);
  (clientA as any).stats.retransmits = 0;

  const aPub = (clientB as any).roster.get(1).get(clientA.senderId);
  const aPort = clientA.port;
  const sendUdp = (buf: Buffer) => (clientB as any).socket.send(buf, aPort, '127.0.0.1', () => {});

  // B forges a NACK claiming to be C, targeting A, for a message A sent.
  // B signs it with B's own key; A verifies against C's key -> must reject.
  const groupKey = clientB.getCurrentKey(1);
  if (!groupKey) throw new Error('client B has no group key');
  const forgedNack = { type: TYPE_NACK, convId: 1, senderId: clientC.senderId, targetId: clientA.senderId, missingSeq: [1] };
  const forgedBuf = Codec.encodeNack(forgedNack, groupKey);
  const forgedSigned = signControlFrame(forgedBuf, pairwiseKey((clientB as any).clientECDH, aPub));
  sendUdp(forgedSigned);
  await delay(200);
  const forgedRetrans = (clientA as any).stats.retransmits;
  check(forgedRetrans === 0);
  console.log(`  A retransmits after FORGED NACK (expect 0): ${forgedRetrans} ${forgedRetrans === 0 ? 'OK' : 'FAIL'}`);

  // Positive control: B sends a genuine NACK (senderId=B) -> A must retransmit.
  const realNack = { type: TYPE_NACK, convId: 1, senderId: clientB.senderId, targetId: clientA.senderId, missingSeq: [1] };
  const realBuf = Codec.encodeNack(realNack, groupKey);
  const realSigned = signControlFrame(realBuf, pairwiseKey((clientB as any).clientECDH, aPub));
  sendUdp(realSigned);
  await delay(200);
  const realRetrans = (clientA as any).stats.retransmits;
  check(realRetrans >= 1);
  console.log(`  A retransmits after GENUINE NACK (expect >= 1): ${realRetrans} ${realRetrans >= 1 ? 'OK' : 'FAIL'}`);

  // B forges a DictReset claiming to be C, targeting A (server-verified path).
  // The server must reject it, so A's history survives.
  const forgedReset = { type: 0x06, convId: 1, senderId: clientC.senderId, targetId: clientA.senderId };
  const forgedResetBuf = Codec.encodeDictReset(forgedReset, groupKey);
  const sPub = (clientB as any).serverPubKeys.get(1);
  const forgedResetSigned = signControlFrame(forgedResetBuf, pairwiseKey((clientB as any).clientECDH, sPub));
  (clientB as any).broadcast(forgedResetSigned);
  await delay(200);
  const historyIntact = (clientA as any).sentMessages.has(1);
  check(historyIntact);
  console.log(`  A history intact after FORGED DictReset (expect true): ${historyIntact} ${historyIntact ? 'OK' : 'FAIL'}`);

  // --- Test 7: Per-message ratchet properties ---
  console.log("--- Test 7: Per-message ratchet (unique keys, forward secrecy) ---");
  const seed = Buffer.alloc(32, 0x42);
  const m0 = advanceChain({ key: seed, index: 0 }, 0);
  const m1 = advanceChain(m0.state, 1);
  const m2 = advanceChain(m1.state, 2);
  const keysDistinct = !m0.messageKey.equals(m1.messageKey) && !m1.messageKey.equals(m2.messageKey) && !m0.messageKey.equals(m2.messageKey);
  // The chain is one-way: after ratcheting to index 2 the chain key is not the
  // seed, so a compromised chain state can't recover past message keys.
  const ratcheted = !m2.state.key.equals(seed);
  // A receiver that skipped a gap derives the SAME key as one that processed
  // every message (loss tolerance).
  const skipped = advanceChain({ key: m0.state.key, index: 1 }, 3);
  const sequential = advanceChain(m1.state, 3);
  const gapConsistent = skipped.messageKey.equals(sequential.messageKey);
  const labeled = chainMessageKey(chainNextKey(seed), 1).equals(m1.messageKey);
  // Golden cross-language vectors (must match the Go / Rust codec tests).
  const gSeed = Buffer.alloc(32, 0x44);
  const gMatch =
    chainMessageKey(gSeed, 0).equals(Buffer.from('e4b4d1bdd01191ce786b8f5efe2202757d94378135ad772bb9e01ed22d8ce688', 'hex')) &&
    chainNextKey(gSeed).equals(Buffer.from('4f174eacd84d526c6e0ebd801d14be1a17b4b87d740f1d9518349204546d5e38', 'hex')) &&
    advanceChain({ key: gSeed, index: 0 }, 2).messageKey.equals(Buffer.from('1ded480040e14f6fba5be12a1666a3542dec36f01629c21411b9d5f80bce05a0', 'hex'));
  check(keysDistinct && ratcheted && gapConsistent && labeled && gMatch);
  console.log(`  keys distinct: ${keysDistinct} ${keysDistinct ? 'OK' : 'FAIL'}`);
  console.log(`  chain ratcheted (one-way): ${ratcheted} ${ratcheted ? 'OK' : 'FAIL'}`);
  console.log(`  gap-consistent (loss tolerance): ${gapConsistent} ${gapConsistent ? 'OK' : 'FAIL'}`);
  console.log(`  index-labeled keys: ${labeled} ${labeled ? 'OK' : 'FAIL'}`);
  console.log(`  golden vectors match (Go/Rust): ${gMatch} ${gMatch ? 'OK' : 'FAIL'}`);

  // --- Test 6: Creator departure -> successor election + immediate rekey ---
  console.log("--- Test 6: Creator departure (successor takes over rotation) ---");
  const epochBefore = clientB.currentEpoch(1);
  // Simulate the creator (A=8001) leaving: the server elects the smallest
  // remaining senderId (B=8002) as the new creator and notifies everyone.
  (server as any).removePeer('udp:127.0.0.1:8001');
  await delay(500);
  const bIsCreator = (clientB as any).isCreator.get(1) === true;
  const cIsCreator = (clientC as any).isCreator.get(1) === true;
  const epochAfter = clientB.currentEpoch(1);
  const successorElected = bIsCreator && !cIsCreator;
  const rekeyed = epochAfter > epochBefore;
  check(successorElected && rekeyed);
  console.log(`  B isCreator=${bIsCreator} C isCreator=${cIsCreator} (expect true/false) ${successorElected ? 'OK' : 'FAIL'}`);
  console.log(`  epoch ${epochBefore} -> ${epochAfter} (expect bumped) ${rekeyed ? 'OK' : 'FAIL'}`);

  clientA.close();
  clientB.close();
  clientC.close();
  clientD.close();
  clientE.close();
  clientF.close();
  server.close();
  if (failed > 0) {
    console.log(`\nTests Complete: ${failed} FAILED`);
    process.exit(1);
  }
  console.log("\nTests Complete: all checks passed.");
}

runTests().catch(console.error);
