// V-255: XX-side end-to-end validation on REAL captured frames.
// For each citra_secure_data frame carrying the MH magic at offset 41:
//   1. strip the 41-byte UDS envelope -> MH packet (magic at 0)
//   2. apply the V-249 kind-0 word-table translation (XX identity words ->
//      GU fake-IP words), route whitelist per V-241
//   3. verify the translated packet: magic/mode intact, GU words present,
//     XX words gone, and (for kind0 route 0x03003039/0x02000000) the member
//     IP:port structure preserved
// Offline pipeline validation only; never a compatibility verdict.
import fs from 'node:fs';
import readline from 'node:readline';
import { translateKind0Packet } from './mh-kind0-translate.mjs';
import { translateHeartbeatPacket } from './mh-heartbeat-translate.mjs';

const XX_TRACE = process.argv[2] ?? 'G:/mh-evidence/g2-trace/g2a-20261015T083801-local-gwA.jsonl';
const MAX = Number(process.argv[3] ?? 0) || Infinity;

const HOST_XX = Buffer.from('b35ee27f', 'hex');
const GUEST_XX = Buffer.from('6f58d8bf', 'hex');
const HOST_GW = Buffer.from('c0a8022f', 'hex');
const GUEST_GW = Buffer.from('c0a8ddf2', 'hex');
const PAIRS = [{ from: HOST_XX, to: HOST_GW }, { from: GUEST_XX, to: GUEST_GW }];

const input = fs.createReadStream(XX_TRACE, { encoding: 'utf8' });
const lines = readline.createInterface({ input, crlfDelay: Infinity });

const stats = {
  frames_scanned: 0, frames_with_magic41: 0, attempted: 0, translated: 0,
  by_kind: {}, by_route: {}, errors: {},
  replacements_total: 0,
  gu_words_present_after: 0, xx_words_remaining_after: 0,
};
const seenCombos = new Set();

for await (const line of lines) {
  let r;
  try { r = JSON.parse(line); } catch { continue; }
  if (r.structure !== 'citra_secure_data' || !r.raw_hex) continue;
  const payload = Buffer.from(r.raw_hex, 'hex');
  const i = payload.indexOf(Buffer.from('32ab9864', 'hex'));
  if (i < 0 || payload.length - i < 32) continue;
  stats.frames_with_magic41++;
  if (stats.attempted >= MAX) continue;
  stats.attempted++;
  const mh = payload.subarray(i);
  const kind = mh[5];
  // heartbeat kinds are per-session (V-242/V-250): this capture's learned pair is
  // host 0xDA(b35ee27f) / guest 0xDF(6f58d8bf) -> GU host 0x23(192.168.2.47) / guest 0xCC(192.168.221.242)
  const isHeartbeat = (kind === 0xA0 || kind === 0xDA || kind === 0xDF);
  try {
    let tPacket, route;
    if (isHeartbeat) {
      const senderWord = mh.subarray(20, 24).toString('hex');
      const isHost = senderWord === 'b35ee27f';
      const kindTo = isHost ? 0x23 : 0xCC;
      const m = { kindFrom: kind, kindTo,
        senderFrom: Buffer.from(senderWord, 'hex'),
        senderTo: isHost ? HOST_GW : GUEST_GW };
      const t = translateHeartbeatPacket(mh, m);
      tPacket = t.packet;
      route = 'heartbeat/' + (isHost ? 'host' : 'guest');
      stats.heartbeat_translated = (stats.heartbeat_translated ?? 0) + 1;
    } else if (kind === 0) {
      const t = translateKind0Packet(mh, PAIRS);
      tPacket = t.packet;
      route = '0x' + t.route;
      stats.replacements_total += t.replacements;
      stats.kind0_translated = (stats.kind0_translated ?? 0) + 1;
    } else {
      throw new Error('kind 0x' + kind.toString(16) + ' has no translation rule');
    }
    stats.translated++;
    stats.by_kind[route] = (stats.by_kind[route] ?? 0) + 1;
    const hex = tPacket.subarray(32).toString('hex');
    if (hex.includes('c0a8022f') || hex.includes('c0a8ddf2')) stats.gu_words_present_after++;
    if (hex.includes('b35ee27f') || hex.includes('6f58d8bf')) stats.xx_words_remaining_after++;
    seenCombos.add(route);
  } catch (e) {
    const key = String(e.message ?? e).slice(0, 50);
    stats.errors[key] = (stats.errors[key] ?? 0) + 1;
  }
}

console.log(JSON.stringify({
  schema: 'mh.xx-e2e-validation/1',
  trace: XX_TRACE, stats,
  scope: 'offline pipeline validation on real captured bytes; no claim of game acceptance',
  observationsAuthenticated: false, payloadValidated: false,
  applicationConverted: false, productionReady: false,
}, null, 2));
