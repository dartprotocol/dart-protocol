// Comprehensive end-to-end Dart benchmark: real clients + real servers at scale,
// measured packet/byte counts and delivery, compared to a positive-ACK baseline.
// Baseline model: each message costs 1 (sender->server) + (K-1) (fan-out) +
// (K-1) (ACKs) = (2K-1) packets, inflated by 1/(1-L) for link loss L.
const { DartGroupServer } = require('/var/www/html/dart/src/server.js');
const { DartClient } = require('/var/www/html/dart/src/client.js');
const { Codec } = require('/var/www/html/dart/src/core.js');
const { execFile } = require('child_process');
const delay = (ms) => new Promise((r) => setTimeout(r, ms));

const ZERO = { packetsSent: 0, packetsReceived: 0, bytesSent: 0, bytesReceived: 0, nacksSent: 0, nacksReceived: 0, retransmits: 0, syncsSent: 0 };
const ACK_BYTES = 64; // assumed positive-ACK packet size (incl. IP/UDP headers)

async function startServer(kind) {
  if (kind === 'ts') {
    const s = new DartGroupServer(9000);
    return { kind, close: () => s.close(), fp: Codec.serverFingerprint(s.getServerFingerprint()), server: s };
  }
  const bin = kind === 'go' ? '/var/www/html/dart/go/server/server' : '/var/www/html/dart/rust/target/release/server';
  const p = execFile(bin, [], { cwd: '/var/www/html/dart' });
  let out = ''; p.stdout.on('data', (d) => (out += d)); p.stderr.on('data', (d) => (out += d));
  let fp;
  for (let i = 0; i < 60 && !fp; i++) {
    await delay(100);
    const m = out.match(/fingerprint: (\w+)/);
    if (m) fp = m[1];
  }
  return { kind, close: () => p.kill(), fp, proc: p };
}

async function makeClients(server, N) {
  const clients = [];
  for (let i = 0; i < N; i++) {
    const c = new DartClient(9100 + i);
    c.addPeer('127.0.0.1', 9000);
    c.setServerFingerprint(server.fp);
    clients.push(c);
  }
  return clients;
}

async function joinAll(clients) {
  const t0 = Date.now();
  for (const c of clients) c.joinConversation(1);
  for (let i = 0; i < 300; i++) {
    await delay(25);
    if (clients.every((c) => c.hasJoined(1))) break;
  }
  const joinMs = Date.now() - t0;
  const joinPkts = clients.reduce((a, c) => a + c.stats.packetsSent + c.stats.packetsReceived, 0);
  return { joinMs, joinPkts };
}

function resetStats(clients) {
  for (const c of clients) c.stats = { ...ZERO };
}

function sumStats(clients) {
  const s = { ...ZERO };
  for (const c of clients) {
    for (const k of Object.keys(s)) s[k] += c.stats[k];
  }
  return s;
}

async function fanout(clients, senderIdx, M, spacing, loss) {
  const sender = clients[senderIdx];
  for (let i = 1; i <= M; i++) {
    sender.sendData(1, `bench ${i} message payload ${i}`);
    await delay(spacing);
  }
  await delay(1200 + M * 2);
  // delivery: how many of the M 'bench' messages each receiver decoded
  const senderId = sender.senderId;
  const perReceiver = [];
  for (let i = 0; i < clients.length; i++) {
    if (i === senderIdx) continue;
    const map = clients[i].receivedMessages.get(senderId);
    let got = 0;
    if (map) for (const d of map.values()) if (d.payload.startsWith('bench')) got++;
    perReceiver.push(got);
  }
  const delivered = perReceiver.reduce((a, b) => a + b, 0);
  const expected = M * (clients.length - 1);
  return { delivered, expected, perReceiver };
}

async function allToAll(clients, m, spacing, staggered) {
  const N = clients.length;
  const tasks = clients.map((c, idx) => (async () => {
    const offset = staggered ? idx * 15 : 0;
    await delay(offset);
    for (let i = 1; i <= m; i++) {
      c.sendData(1, `bench ${c.senderId}-${i} payload`);
      await delay(spacing + (staggered ? Math.floor(Math.random() * 30) : 0));
    }
  })());
  await Promise.all(tasks);
  await delay(3000 + N * m * 0.5);
  // delivery: every client should receive (N-1)*m bench messages
  let delivered = 0, expected = 0;
  for (let i = 0; i < N; i++) {
    const self = clients[i].senderId;
    let got = 0;
    for (const [sid, map] of clients[i].receivedMessages) {
      if (sid === self) continue;
      for (const d of map.values()) if (d.payload.startsWith('bench')) got++;
    }
    delivered += got;
    expected += (N - 1) * m;
  }
  return { delivered, expected };
}

function baseline(N, M, L) {
  const packets = (M * (2 * N - 1)) / (1 - L);
  const ackPackets = (M * (N - 1)) / (1 - L);
  const ackBytes = ackPackets * ACK_BYTES;
  return { packets, ackBytes, dataPackets: (M * N) / (1 - L) };
}

async function scenario(label, kind, N, mode, M, m, spacing, loss) {
  const server = await startServer(kind);
  await delay(300);
  const clients = await makeClients(server, N);
  const { joinMs, joinPkts } = await joinAll(clients);
  const ok = clients.every((c) => c.hasJoined(1));

  if (loss > 0) {
    for (let i = 0; i < N; i++) clients[i].simulateLossPercent = loss;
  }

  resetStats(clients);
  const t0 = Date.now();
  let res;
  if (mode === 'fanout') res = await fanout(clients, 0, M, spacing, loss);
  else res = await allToAll(clients, m, spacing, mode === 'alltoall-staggered');
  const elapsedMs = Date.now() - t0;

  const s = sumStats(clients);
  const wirePackets = s.packetsSent + s.packetsReceived;
  const wireBytes = s.bytesSent + s.bytesReceived;
  const totalMessages = mode === 'fanout' ? M : N * m;
  const K = N;
  const bl = baseline(K, totalMessages, loss);
  const gainPkts = ((bl.packets - wirePackets) / bl.packets) * 100;
  const deliveryRate = res.delivered / res.expected;

  console.log(`\n=== ${label} | server=${kind} users=${N} mode=${mode} msgs=${totalMessages} loss=${loss*100}% ===`);
  console.log(`  join: ${joinMs}ms, ${joinPkts} packets (${(joinPkts/N).toFixed(0)}/user) | all-joined=${ok}`);
  if (server.server) {
    const ss = server.server.stats;
    console.log(`  server: recv=${ss.packetsReceived} sent=${ss.packetsSent} repairs=${ss.repairsSent}`);
  }
  console.log(`  wire: ${wirePackets} packets, ${(wireBytes/1024).toFixed(1)} KB | ${(wirePackets/totalMessages).toFixed(2)} packets/message`);
  console.log(`  ctrl: nacks=${s.nacksSent} retransmits=${s.retransmits} syncs=${s.syncsSent}`);
  console.log(`  delivery: ${(deliveryRate*100).toFixed(2)}% (${res.delivered}/${res.expected}) | elapsed ${elapsedMs}ms`);
  console.log(`  baseline (+ACK): ${bl.packets.toFixed(0)} packets | gain = ${gainPkts.toFixed(1)}% fewer packets`);
  console.log(`  baseline ACK bytes to remove: ${(bl.ackBytes/1024).toFixed(1)} KB`);

  clients.forEach((c) => c.close());
  server.close();
  await delay(400);
  return { wirePackets, wireBytes, gainPkts, deliveryRate, totalMessages, K, joinPkts };
}

// Cross-language: real Go + Rust native clients join and receive.
async function crossLanguage(M, spacing) {
  const server = await startServer('ts');
  await delay(300);
  const fp = server.fp;
  const sims = [];
  for (let i = 0; i < 2; i++) {
    const c = new DartClient(9100 + i);
    c.addPeer('127.0.0.1', 9000);
    c.setServerFingerprint(fp);
    sims.push(c);
  }
  const go = execFile('/var/www/html/dart/go/dart-cli', [], { env: { ...process.env, DART_SERVER_FINGERPRINT: fp } });
  const rust = execFile('/var/www/html/dart/rust/target/release/client', [], { env: { ...process.env, DART_SERVER_FINGERPRINT: fp } });
  let goOut = ''; go.stdout.on('data', (d) => (goOut += d));
  let rustOut = ''; rust.stdout.on('data', (d) => (rustOut += d));
  go.stdin.write('1\n');
  rust.stdin.write('1\n');

  for (const c of sims) c.joinConversation(1);
  for (let i = 0; i < 200 && !(goOut.includes('group key established') && rustOut.includes('group key established')); i++) await delay(50);

  const sender = sims[0];
  for (let i = 1; i <= M; i++) { sender.sendData(1, `bench ${i} message payload ${i}`); await delay(spacing); }
  await delay(3000);

  const goGot = (goOut.match(/bench \d+ message payload/g) || []).length;
  const rustGot = (rustOut.match(/bench \d+ message payload/g) || []).length;
  console.log(`\n=== Cross-language (TS server, TS sim + Go + Rust clients) | msgs=${M} ===`);
  console.log(`  Go   client delivery: ${goGot}/${M} (${((goGot / M) * 100).toFixed(1)}%)`);
  console.log(`  Rust client delivery: ${rustGot}/${M} (${((rustGot / M) * 100).toFixed(1)}%)`);

  go.kill(); rust.kill(); sims.forEach((c) => c.close()); server.close();
  await delay(400);
  return { goGot, rustGot, M };
}

async function main() {
  const results = [];
  // 1) Scale: fan-out, TS server
  for (const N of [2, 10, 50, 100]) {
    results.push(await scenario(`Scale fanout N=${N}`, 'ts', N, 'fanout', 100, 0, 20, 0));
  }
  // 2) All-to-all chat (synchronized burst = worst case)
  for (const N of [10]) {
    results.push(await scenario(`All-to-all burst N=${N}`, 'ts', N, 'alltoall', 0, 20, 20, 0));
  }
  results.push(await scenario('All-to-all burst N=50 (worst case)', 'ts', 50, 'alltoall', 0, 20, 20, 0));
  // 2b) Realistic staggered chat (random inter-arrival)
  results.push(await scenario('All-to-all staggered N=50', 'ts', 50, 'alltoall-staggered', 0, 20, 20, 0));
  // 3) Loss resilience
  results.push(await scenario('Loss 10% fanout N=10', 'ts', 10, 'fanout', 100, 0, 20, 0.10));
  results.push(await scenario('Loss 30% fanout N=10', 'ts', 10, 'fanout', 100, 0, 20, 0.30));
  // 4) Go / Rust servers
  results.push(await scenario('Go server, TS clients N=20', 'go', 20, 'fanout', 100, 0, 20, 0));
  results.push(await scenario('Rust server, TS clients N=20', 'rust', 20, 'fanout', 100, 0, 20, 0));
  // 5) Cross-language: real Go + Rust native clients
  await crossLanguage(50, 20);
  console.log('\n\n========== SUMMARY ==========');
  for (const r of results) {
    console.log(`users=${String(r.K).padStart(4)} msgs=${String(r.totalMessages).padStart(5)} packets=${String(r.wirePackets).padStart(7)} gain=${r.gainPkts.toFixed(1).padStart(5)}% delivery=${(r.deliveryRate*100).toFixed(1)}%`);
  }
  process.exit(0);
}

main().catch((e) => { console.error(e); process.exit(1); });
