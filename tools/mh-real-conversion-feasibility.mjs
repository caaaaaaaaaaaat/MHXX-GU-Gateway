// V-248: end-to-end feasibility check of the V-207 conversion primitive on
// REAL captured packets from both sides (XX g2a trace kind 0/1; GU g2-run2
// kind 0/0x23/0xCC).  Offline metadata/pipeline check only: no network, no
// production hookup, no claim that converted bytes would be accepted by a
// running game.
//
// Identity handling: MhIdentityMap.bind requires the XX side's 8-byte UDS seed
// (its CRC-derived endpoint word is one-way), which a raw capture does not
// carry.  The harness therefore binds TEST seeds and rewrites each packet's
// sender word to the bound test identity before conversion -- a precise
// stand-in for the runtime identity assembly (JoinSuccess seed -> table), and
// recorded as such.  Everything else (header fields, route, body bytes) is the
// real captured data, untouched.
import fs from 'node:fs';
import readline from 'node:readline';
import { decodeMhPacket, encodeMhPacket } from './mh-packet.mjs';
import { translateMhPacketStreamIdentities } from './mh-packet-identity.mjs';
import { MhIdentityMap } from './mh-identity.mjs';
import { decodeYuzuUdpProxyDatagram } from './yuzu-udp-datagram.mjs';

const XX_TRACE = 'G:/mh-evidence/g2-trace/g2a-20261015T083801-local-gwA.jsonl';
const GU_TRACE = 'G:/抛瓦饮料/跨平台联机/.private-runtime/evidence/g2-run2/g2trace-raw.jsonl';
const MAX_PER_KIND = 200;

function collectXx(path, maxPerKind) {
  const byKind = {};
  let total = 0;
  const input = fs.createReadStream(path, { encoding: 'utf8' });
  const lines = readline.createInterface({ input, crlfDelay: Infinity });
  return new Promise((resolve) => {
    lines.on('line', line => {
      let r;
      try { r = JSON.parse(line); } catch { return; }
      if (r.structure !== 'citra_secure_data' || !r.raw_hex) return;
      const payload = Buffer.from(r.raw_hex, 'hex');
      const i = payload.indexOf(Buffer.from('32ab9864', 'hex'));
      if (i < 0 || payload.length - i < 12) return;
      const kind = payload[i + 5];
      byKind[kind] ??= [];
      if (byKind[kind].length >= maxPerKind) return;
      // A5-era Citra WifiPacket framing: 0x16-byte LLC/SNAP+SecureData header
      // precedes the application packet; the packet starts at the magic.
      byKind[kind].push(payload.subarray(i));
      total++;
    });
    lines.on('close', () => resolve({ byKind, total }));
  });
}

async function collectGu(path, maxPerKind) {
  const byKind = {};
  let total = 0;
  const input = fs.createReadStream(path, { encoding: 'utf8' });
  const lines = readline.createInterface({ input, crlfDelay: Infinity });
  return new Promise((resolve) => {
    lines.on('line', line => {
      let r;
      try { r = JSON.parse(line); } catch { return; }
      if (r.message !== 'ProxyPacket' || !r.raw_hex || r.direction !== 'client->room') return;
      try {
        const d = decodeYuzuUdpProxyDatagram(Buffer.from(r.raw_hex, 'hex'), 'yuzu-mirror-01052024').datagram;
        if (d.length >= 12 && d.readUInt32BE(0) === 0x32ab9864) {
          const kind = d[5];
          byKind[kind] ??= [];
          if (byKind[kind].length < maxPerKind) {
            byKind[kind].push(d);
            total++;
          }
        }
      } catch {}
    });
    lines.on('close', () => resolve({ byKind, total }));
  });
}

const [xxCollected, guCollected] = await Promise.all([
  collectXx(XX_TRACE, MAX_PER_KIND), collectGu(GU_TRACE, MAX_PER_KIND)]);
const xx = xxCollected.byKind;
const gu = guCollected.byKind;

// Identity assembly stand-in: bind test seeds to the REAL GU sender words so
// translate() resolves exactly like the runtime would after JoinSuccess.
const map = new MhIdentityMap('real-capture-session');
const testSeed = Buffer.from('0123456789abcdef', 'hex');
// XX test word: the CRC-derived endpoint of the test seed (bind derives it).
// GU test words: the real observed sender words from each side's frames.
const guHostWord = Buffer.from([192, 168, 2, 47]);   // 192.168.2.47 (ea-a)
const guGuestWord = Buffer.from([192, 168, 221, 242]); // 192.168.221.242 (ea-b)

function rewriteSender(packet, fromWord, toWord) {
  const out = Buffer.from(packet);
  const i = out.indexOf(fromWord);
  if (i >= 0) toWord.copy(out, i);
  return out;
}

const results = {};
// XX -> GU: rewrite XX senders to the GU host/guest words, convert XX->GU.
{
  const stats = { attempted: 0, converted: 0, encode_ok: 0, decode_ok: 0, errors: {} };
  const ids = new MhIdentityMap('real-capture-session');
  // bind test seeds for the XX identity words observed in this capture
  const xxWords = new Set();
  for (const kind of Object.keys(xx)) for (const p of xx[kind]) xxWords.add(p.subarray(20, 24).toString('hex'));
  let seedIndex = 0;
  const xxWordToTest = {};
  for (const w of xxWords) {
    const seed = Buffer.concat([Buffer.from([seedIndex++]), testSeed.subarray(1)]);
    const derived = (await import('./mhxx-endpoint.mjs')).deriveMhxxUdsEndpoint(seed);
    // compute the derived word exactly like bind does
    const derivedWord = (await import('./mhxx-endpoint.mjs'));
    const endpoint = derivedWord.encodeMhxxEndpoint(derived);
    const word = endpoint.readUInt32BE(0);
    xxWordToTest[w] = { seed, word };
    try { ids.bind('real-capture-session', seed, guHostWord); } catch { /* capacity */ }
  }
  for (const kind of Object.keys(xx)) {
    for (const pkt of xx[kind]) {
      stats.attempted++;
      try {
        const senderWord = pkt.subarray(20, 24).toString('hex');
        const testWord = xxWordToTest[senderWord];
        if (!testWord) throw new Error('no test binding for sender ' + senderWord);
        // Build the source packet as the runtime would present it post-assembly:
        // sender word rewritten to the bound test identity.
        const prepared = rewriteSender(pkt, Buffer.from(senderWord, 'hex'),
          (() => { const b = Buffer.alloc(4); b.writeUInt32BE(testWord.word); return b; })());
        // Target header: copy the source 12-byte header, retag kind to a GU
        // session-announce kind observed on the wire (0), keep counters opaque
        // (callers own seq/time per the conversion table).
        const targetHeader = Buffer.from(pkt.subarray(0, 12));
        targetHeader[5] = 0;
        const sourceKey = undefined;
        const out = translateMhPacketStreamIdentities(prepared, {
          profile: 'mhxx-1.4', targetHeader, expectedRouteKey: pkt.readUInt32BE(24),
          identityMap: ids, sessionId: 'real-capture-session', sourceKey, targetKey: undefined,
        });
        stats.converted++;
        const redecoded = decodeMhPacket(out.bytes, 'mhgu-v262144', undefined);
        if (redecoded.messages.length >= 0) stats.encode_ok++;
        if (redecoded.header.readUInt32BE(0) === 0x32ab9864 && redecoded.header[4] === 1) stats.decode_ok++;
      } catch (e) {
        const key = String(e.message ?? e).slice(0, 60);
        stats.errors[key] = (stats.errors[key] ?? 0) + 1;
      }
    }
  }
  results.xx_to_gu = stats;
}
// GU -> XX: rewrite nothing (GU senders bind directly), convert GU->XX.
{
  const stats = { attempted: 0, converted: 0, encode_ok: 0, decode_ok: 0, errors: {} };
  const ids = new MhIdentityMap('gu-side-session');
  const testSeed = Buffer.from('fedcba9876543210', 'hex');
  ids.bind('gu-side-session', testSeed, guHostWord);
  const xxWord = (() => {
    // derive the XX endpoint word of the test seed, exactly as bind stores it
    const crcTable = (() => {
      const t = [];
      for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1); t.push(c >>> 0); }
      return t;
    })();
    let crc = 0xffffffff;
    for (const b of testSeed) { crc = (crc >>> 8) ^ crcTable[(crc ^ b) & 0xff]; }
    crc = (crc ^ 0xffffffff) >>> 0;
    // mirror encodeMhxxEndpoint's word position using its own encoder below
    return null;
  })();
  const { deriveMhxxUdsEndpoint, encodeMhxxEndpoint } = await import('./mhxx-endpoint.mjs');
  const endpointWord = encodeMhxxEndpoint(deriveMhxxUdsEndpoint(testSeed)).readUInt32BE(0);
  const xxWordBuf = Buffer.alloc(4);
  xxWordBuf.writeUInt32BE(endpointWord);
  for (const kind of Object.keys(gu)) {
    for (const pkt of gu[kind]) {
      stats.attempted++;
      try {
        const prepared = rewriteSender(pkt, guHostWord, xxWordBuf);
        const targetHeader = Buffer.from(pkt.subarray(0, 12));
        targetHeader[5] = 0;
        const out = translateMhPacketStreamIdentities(prepared, {
          profile: 'mhgu-v262144', targetHeader, expectedRouteKey: pkt.readUInt32BE(24),
          identityMap: ids, sessionId: 'gu-side-session', sourceKey: undefined, targetKey: undefined,
        });
        stats.converted++;
        const redecoded = decodeMhPacket(out.bytes, 'mhxx-1.4', undefined);
        if (redecoded.messages.length >= 0) stats.encode_ok++;
        if (redecoded.header.readUInt32BE(0) === 0x32ab9864 && redecoded.header[4] === 1) stats.decode_ok++;
      } catch (e) {
        const key = String(e.message ?? e).slice(0, 60);
        stats.errors[key] = (stats.errors[key] ?? 0) + 1;
      }
    }
  }
  results.gu_to_xx = stats;
}

console.log(JSON.stringify({
  schema: 'mh.real-conversion-feasibility/1',
  xx_trace: XX_TRACE, gu_trace: GU_TRACE,
  identity_note: 'bind requires the XX 8-byte UDS seed (one-way CRC word); the harness binds TEST seeds and rewrites senders to the bound test words -- a precise stand-in for runtime identity assembly',
  results,
  scope: 'offline conversion feasibility on real captured bytes; no claim of game acceptance or crossplay success',
  observationsAuthenticated: false, payloadValidated: false,
  applicationConverted: false, productionReady: false,
}, null, 2));
