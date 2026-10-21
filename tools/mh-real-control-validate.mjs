import fs from 'node:fs';
import readline from 'node:readline';
import { decodeYuzuUdpProxyDatagram } from './yuzu-udp-datagram.mjs';
import { translateControlFrame } from './mh-control-frame-translate.mjs';
const input = fs.createReadStream('G:/抛瓦饮料/跨平台联机/.private-runtime/evidence/g2-run2/g2trace-raw.jsonl', { encoding: 'utf8' });
const lines = readline.createInterface({ input, crlfDelay: Infinity });
const GU_HOST = Buffer.from('c0a8022f', 'hex');
const GU_GUEST = Buffer.from('c0a8ddf2', 'hex');
const XX_HOST = Buffer.from('b35ee27f', 'hex');
const XX_GUEST = Buffer.from('6f58d8bf', 'hex');
let attempted = 0, ok = 0; const errs = {}; const routes = {};
for await (const line of lines) {
  const r = JSON.parse(line);
  if (r.message !== 'ProxyPacket' || !r.raw_hex || r.direction !== 'client->room') continue;
  const d = decodeYuzuUdpProxyDatagram(Buffer.from(r.raw_hex, 'hex'), 'yuzu-mirror-01052024').datagram;
  if (d.length < 32 || d.readUInt32BE(0) !== 0x32ab9864) continue;
  const route = d.readUInt32BE(24);
  if (route !== 0x06000000 && route !== 0x02100000) continue;
  attempted++;
  try {
    const senderGU = d.subarray(20, 24);
    const senderXX = senderGU.equals(GU_HOST) ? XX_HOST : senderGU.equals(GU_GUEST) ? XX_GUEST : null;
    if (!senderXX) throw new Error('unmapped sender');
    const out = translateControlFrame(d, { senderFrom: senderGU, senderTo: senderXX });
    ok++;
    routes['0x' + route.toString(16).padStart(8, '0')] = (routes['0x' + route.toString(16).padStart(8, '0')] ?? 0) + 1;
  } catch (e) { errs[String(e.message).slice(0, 40)] = (errs[String(e.message).slice(0, 40)] ?? 0) + 1; }
}
console.log('GU->XX control frames: attempted=' + attempted + ' translated=' + ok);
console.log('routes:', routes);
console.log('errors:', errs);
