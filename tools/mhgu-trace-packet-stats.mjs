// V-238 G2 analysis: parse real MHGU ProxyPacket payloads against the offline
// MH packet contracts. Read-only; outputs aggregate metadata only, never payload bytes.
// Usage: node mhgu-trace-packet-stats.mjs <trace.jsonl> [maxRecords]
import fs from 'node:fs';
import readline from 'node:readline';
import { decodeYuzuUdpProxyDatagram } from './yuzu-udp-datagram.mjs';
import { mhPacketHeader, mhMessages } from './app-profile.mjs';

const tracePath = process.argv[2];
if (!tracePath) { console.error('usage: node mhgu-trace-packet-stats.mjs <trace.jsonl> [maxRecords]'); process.exit(2); }
const maxRecords = Number(process.argv[3] ?? 10000);

const input = fs.createReadStream(tracePath, { encoding: 'utf8' });
const lines = readline.createInterface({ input, crlfDelay: Infinity });

let checked = 0, decode_fail = 0, raw_total = 0;
const headers = {}, statuses = {}, kinds = {}, lens = {}, msg_ctrl = {};
let total_messages = 0;
// Per-kind stream-subheader aggregates (first stream chunk of each first message).
// Sequence/cumulative-ACK are transport metadata (V-185: +12 is cumulative ACK,
// never an address identity); aggregated modulo-free as uint32 min/max/distinct.
const per_kind = {};
function kindBucket(kind) {
  const key = String(kind);
  if (!per_kind[key]) per_kind[key] = {
    packets: 0, senders: {}, routes: {}, seq_min: null, seq_max: null, seq_distinct: new Set(),
    ack_min: null, ack_max: null, flags: {}, data_chunks: 0, terminal_chunks: 0,
    sender_seq_min: {}, sender_seq_max: {},
  };
  return per_kind[key];
}

for await (const line of lines) {
  let r;
  try { r = JSON.parse(line); } catch { continue; }
  if (r.message !== 'ProxyPacket' || !r.raw_hex) continue;
  raw_total++;
  if (checked >= maxRecords) continue;
  checked++;
  try {
    const packet = Buffer.from(r.raw_hex, 'hex');
    const { datagram } = decodeYuzuUdpProxyDatagram(packet, 'yuzu-mirror-01052024');
    const h = mhPacketHeader(datagram);
    if (!h) { headers['unrecognized'] = (headers['unrecognized'] ?? 0) + 1; continue; }
    const key = h.truncated ? 'truncated' : `mode${h.mode}`;
    headers[key] = (headers[key] ?? 0) + 1;
    if (!h.truncated) kinds[String(h.kind)] = (kinds[String(h.kind)] ?? 0) + 1;
    if (!h.truncated && h.mode === 1) {
      const m = mhMessages(datagram);
      statuses[m.status] = (statuses[m.status] ?? 0) + 1;
      if (m.reason) statuses['reason:' + m.reason] = (statuses['reason:' + m.reason] ?? 0) + 1;
      if (m.status === 'parsed') {
        total_messages += m.messages.length;
        for (const msg of m.messages) {
          const ck = String(msg.control_bits);
          msg_ctrl[ck] = (msg_ctrl[ck] ?? 0) + 1;
          // Stream subheader lives at the message body start (outer header 20B).
          // Per V-192/V-191: flags@0..2, len@2, seq@8, cumACK@12, bitmap@16.
          const bodyOff = 12 + 20 + msg.offset;
          if (datagram.length >= bodyOff + 24) {
            const sender = datagram.subarray(bodyOff - 12, bodyOff - 8).toString('hex');
            const route = datagram.readUInt32BE(bodyOff - 8);
            const seq = datagram.readUInt32BE(bodyOff + 8);
            const ack = datagram.readUInt32BE(bodyOff + 12);
            const flags = datagram.readUInt16BE(bodyOff);
            const b = kindBucket(h.kind);
            b.packets++;
            b.senders[sender] = (b.senders[sender] ?? 0) + 1;
            const rk = '0x' + route.toString(16).padStart(8, '0');
            b.routes[rk] = (b.routes[rk] ?? 0) + 1;
            b.seq_distinct.add(seq);
            b.seq_min = b.seq_min === null ? seq : Math.min(b.seq_min, seq);
            b.seq_max = b.seq_max === null ? seq : Math.max(b.seq_max, seq);
            b.ack_min = b.ack_min === null ? ack : Math.min(b.ack_min, ack);
            b.ack_max = b.ack_max === null ? ack : Math.max(b.ack_max, ack);
            const fk = '0x' + flags.toString(16).padStart(4, '0');
            b.flags[fk] = (b.flags[fk] ?? 0) + 1;
            if (flags & 1) b.data_chunks++;
            if (flags & 2) b.terminal_chunks++;
            b.sender_seq_min[sender] = Math.min(b.sender_seq_min[sender] ?? seq, seq);
            b.sender_seq_max[sender] = Math.max(b.sender_seq_max[sender] ?? seq, seq);
          }
        }
      }
      const L = datagram.length;
      lens[L] = (lens[L] ?? 0) + 1;
    }
  } catch (e) {
    decode_fail++;
    const name = String(e.message ?? e).slice(0, 70);
    statuses['ERR:' + name] = (statuses['ERR:' + name] ?? 0) + 1;
  }
}
const result = {
  schema: 'crossplay.mhgu-trace-packet-stats/2',
  trace: tracePath, proxy_records_total: raw_total, checked, decode_fail,
  packet_headers: headers, kind_field: kinds,
  mode1_parse: statuses, mode1_message_control_bits: msg_ctrl, total_messages,
  datagram_lengths_top: Object.entries(lens).sort((a, b) => b[1] - a[1]).slice(0, 15),
  per_kind_stream_subheaders: Object.fromEntries(Object.entries(per_kind).map(([k, b]) => [k, {
    packets: b.packets,
    senders: b.senders,
    routes: b.routes,
    sequence: { min: b.seq_min, max: b.seq_max, distinct: b.seq_distinct.size },
    cumulative_ack: { min: b.ack_min, max: b.ack_max },
    flags: b.flags, data_chunks: b.data_chunks, terminal_chunks: b.terminal_chunks,
    per_sender_sequence: Object.fromEntries(Object.keys(b.senders).map(s =>
      [s, { min: b.sender_seq_min[s], max: b.sender_seq_max[s] }])),
  }])),
  field_notes: 'subheader offsets per V-191/V-192 (flags@0, seq@8, cumACK@12, bitmap@16); sender/route from 20B message header; cumACK is transport metadata, never an address identity (V-185)',
  scope: 'metadata aggregates only; no payload bytes emitted; recognition is not a compatibility verdict',
};
console.log(JSON.stringify(result, null, 2));
