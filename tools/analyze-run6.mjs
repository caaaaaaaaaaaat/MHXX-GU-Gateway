import fs from 'node:fs';
import readline from 'node:readline';
import { decodeYuzuUdpProxyDatagram } from './yuzu-udp-datagram.mjs';
import { learnHeartbeatPair } from './mh-heartbeat-pair-learn.mjs';
const input = fs.createReadStream('G:/抛瓦饮料/跨平台联机/.private-runtime/evidence/g2-run6/crossgame-trace.jsonl', { encoding: 'utf8' });
const lines = readline.createInterface({ input, crlfDelay: Infinity });
let n = 0, hb = 0, kind0n = 0;
const kinds = {}; const ldn = {}; const gu = [];
for await (const line of lines) {
  const r = JSON.parse(line);
  n++;
  if (r.message === 'LdnPacket') { const t = r.ldn_type; ldn[t] = (ldn[t] ?? 0) + 1; }
  if (r.message !== 'ProxyPacket' || !r.raw_hex || r.direction !== 'client->room') continue;
  try {
    const d = decodeYuzuUdpProxyDatagram(Buffer.from(r.raw_hex, 'hex'), 'yuzu-mirror-01052024').datagram;
    if (d.length >= 12 && d.readUInt32BE(0) === 0x32ab9864) {
      const k = d[5]; kinds[k] = (kinds[k] ?? 0) + 1;
      if (k === 0x60 || k === 0x73) { hb++; gu.push({ kind: k, sender: (r.local_ip || ''), seq: d.subarray(6, 8).toString('hex'), rel_time: d.subarray(8, 10).toString('hex'), time_echo: d.subarray(10, 12).toString('hex') }); }
      if (k === 0) kind0n++;
    }
  } catch {}
}
console.log('lines:', n, 'LDN types:', JSON.stringify(ldn));
console.log('kinds:', kinds, 'heartbeats(0x60/0x73):', hb, 'kind0:', kind0n);
if (gu.length > 20) {
  const r2 = learnHeartbeatPair(gu, {});
  console.log('learner:', JSON.stringify({ learned: r2.learned, candidates: r2.candidates.map(c => ({ kind: '0x' + c.kind.toString(16), sender: c.sender, frames: c.frames })) }));
}
