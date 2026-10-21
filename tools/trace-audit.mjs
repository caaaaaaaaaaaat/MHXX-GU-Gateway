// SPDX-License-Identifier: GPL-3.0-or-later
// Read-only G2 trace audit. Outputs aggregate metadata, never payload bytes.
import fs from 'node:fs';
import readline from 'node:readline';
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import { pathToFileURL } from 'node:url';

const required = ['manifest_id', 'run_id', 'channel', 'platform', 'build_id', 'role',
  'event_label', 'stage', 'direction', 'utc', 'monotonic_ms', 'length', 'sha256', 'structure', 'decoded'];
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const bump = (map, key) => {
  Object.defineProperty(map, key, { value: (Object.hasOwn(map, key) ? map[key] : 0) + 1,
    enumerable: true, configurable: true, writable: true });
};

export async function auditTrace(path) {
  const result = { schema: 'crossplay.trace-audit/1', lines: 0, raw_records: 0,
    raw_verified: 0, errors: 0, error_reasons: {}, error_examples: [], identities: [],
    events: {}, structures: {}, stages: {}, decoded: {}, wifi_types: {},
    secure_data_channels: {}, payload_lengths: {}, room_proxy_records: 0,
    proxy_plain_verified: 0, room_ldn_records: 0, peers: {} };
  const identities = new Set();
  let lastTime = -1;
  const error = message => {
    result.errors++;
    bump(result.error_reasons, message);
    if (result.error_examples.length < 20) result.error_examples.push({ line: result.lines, reason: message });
  };
  const input = fs.createReadStream(path, { encoding: 'utf8' });
  const lines = readline.createInterface({ input, crlfDelay: Infinity });
  try {
    for await (const line of lines) {
      result.lines++;
      if (line.length > 2 * 1024 * 1024) { error('line exceeds 2 MiB'); continue; }
      let r;
      try { r = JSON.parse(line); } catch { error('invalid JSON'); continue; }
      if (!r || typeof r !== 'object' || Array.isArray(r)) { error('record is not an object'); continue; }
      const missing = required.filter(key => !Object.hasOwn(r, key));
      if (missing.length) { error(`missing fields: ${missing.join(',')}`); continue; }
      if (!Number.isSafeInteger(r.length) || r.length < 0 || r.length > 65536) error('invalid length');
      if (typeof r.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(r.sha256)) error('invalid SHA256');
      if (!Number.isSafeInteger(r.monotonic_ms) || r.monotonic_ms < lastTime) error('invalid or decreasing monotonic time');
      else lastTime = r.monotonic_ms;
      if (!['A', 'B', 'C'].includes(r.channel)) error('invalid channel');
      if (typeof r.decoded !== 'boolean') error('decoded is not boolean');
      if (!r.decoded && !r.undecoded_reason) error('undecoded record lacks reason');
      if (typeof r.utc !== 'string' || !r.utc.endsWith('Z') || !Number.isFinite(Date.parse(r.utc))) error('invalid UTC timestamp');
      const identity = JSON.stringify([r.manifest_id, r.run_id, r.channel, r.platform, r.build_id, r.role]);
      identities.add(identity);
      bump(result.events, r.event_label);
      bump(result.structures, r.structure);
      bump(result.decoded, String(r.decoded));
      const stage = JSON.stringify([r.stage, r.event_label, r.direction]);
      bump(result.stages, stage);
      if (Object.hasOwn(r, 'raw_hex')) {
        result.raw_records++;
        if (typeof r.raw_hex !== 'string' || r.raw_hex.length > 131072 || !/^(?:[a-fA-F0-9]{2})*$/.test(r.raw_hex)) {
          error('invalid raw hex'); continue;
        }
        const raw = Buffer.from(r.raw_hex, 'hex');
        if (raw.length !== r.length || sha(raw) !== r.sha256) { error('raw length or SHA256 mismatch'); continue; }
        result.raw_verified++;
        if (r.event_label === 'room.c2s' || r.event_label === 'room.s2c') {
          if (!Number.isSafeInteger(r.peer_id) || r.peer_id < 1) error('room frame lacks peer identity');
          else bump(result.peers, String(r.peer_id));
          if (r.structure === 'yuzu_room_proxy') {
            result.room_proxy_records++;
            if (raw.length < 21 || raw[0] !== 5 || raw.readUInt32BE(17) !== raw.length - 21) {
              error('invalid ProxyPacket envelope length'); continue;
            }
            if (r.local_ip !== [...raw.subarray(2,6)].join('.') || r.remote_ip !== [...raw.subarray(9,13)].join('.') ||
              r.local_port !== raw.readUInt16BE(6) || r.remote_port !== raw.readUInt16BE(13) ||
              r.local_family !== raw[1] || r.remote_family !== raw[8] || r.protocol !== raw[15] ||
              r.compressed_length !== raw.length - 21 || r.broadcast !== (raw[16] !== 0)) {
              error('ProxyPacket metadata disagrees with wire header'); continue;
            }
            if (r.zstd_verified === true) {
              try {
                const plain = zlib.zstdDecompressSync(raw.subarray(21), { maxOutputLength: 60000 });
                if (plain.length !== r.plain_length || sha(plain) !== r.plain_sha256) error('Proxy plaintext length or SHA256 mismatch');
                else result.proxy_plain_verified++;
              } catch { error('claimed verified Zstd frame cannot be decompressed within limit'); }
            }
          } else if (r.structure === 'yuzu_room_ldn') {
            result.room_ldn_records++;
            if (raw.length < 15 || raw[0] !== 6 || raw.readUInt32BE(11) !== raw.length - 15) {
              error('invalid LdnPacket envelope length'); continue;
            }
            const expected = [0, 0x480, 0x40, 0x480, 0x40, 0][raw[1]];
            // Invalid wire data must fail even when its metadata accurately says
            // it was not decoded. Metadata agreement alone is not validity.
            if (expected === undefined || expected !== raw.length - 15 || raw[10] > 1) {
              error('invalid LdnPacket type, body size or broadcast'); continue;
            }
            if (r.local_ip !== [...raw.subarray(2,6)].join('.') || r.remote_ip !== [...raw.subarray(6,10)].join('.') ||
              r.broadcast !== (raw[10] !== 0) || r.ldn_type !== raw[1] || r.body_length !== raw.length - 15 ||
              r.expected_body_length !== expected || r.ldn_size_verified !== (expected === raw.length - 15)) {
              error('LdnPacket metadata disagrees with exact size table');
            }
            if (r.ldn_body_decoded===true && (raw[1]===1 || raw[1]===3) && raw.length===15+0x480) {
              const body=raw.subarray(15);
              const hex64=offset=>'0x'+body.readBigUInt64LE(offset).toString(16).padStart(16,'0');
              const count=body[0x67], advertise=body.readUInt16LE(0x26a);
              if (r.local_communication_id_hex!==hex64(0) || r.scene_id!==body.readUInt16LE(10) ||
                r.session_id_high_hex!==hex64(16) || r.session_id_low_hex!==hex64(24) ||
                r.network_bssid!==body.subarray(0x20,0x26).toString('hex') || r.network_type!==body[0x4b] ||
                r.wifi_channel!==body.readInt16LE(0x48) || r.node_count!==count || r.node_count_max!==body[0x66] ||
                count>8 || advertise>0x180 || r.advertise_length!==advertise ||
                r.advertise_sha256!==sha(body.subarray(0x26c,0x26c+advertise))) error('NetworkInfo metadata disagrees with wire body');
              if (Object.hasOwn(r,'node_slots') && r.node_slots!==8) error('invalid NetworkInfo node slot coverage');
              for(let i=0;i<(r.node_slots===8?8:Math.min(count,8));i++) {
                const offset=0x68+i*0x40, prefix=`node_${i}_`;
                if(r[prefix+'ipv4_raw']!==[...body.subarray(offset,offset+4)].join('.') ||
                  r[prefix+'mac']!==body.subarray(offset+4,offset+10).toString('hex') ||
                  r[prefix+'id']!==String(body.readInt8(offset+10)) ||
                  r[prefix+'connected']!==(body[offset+11]!==0) ||
                  r[prefix+'communication_version']!==String(body.readInt16LE(offset+46))) error('NetworkInfo node metadata disagrees with wire body');
              }
            }
            if (r.ldn_body_decoded===true && (raw[1]===2 || raw[1]===4) && raw.length===15+0x40) {
              const body=raw.subarray(15);
              if(r.node_ipv4_raw!==[...body.subarray(0,4)].join('.') || r.node_mac!==body.subarray(4,10).toString('hex') ||
                r.node_id!==String(body.readInt8(10)) || r.node_connected!==(body[11]!==0) ||
                r.node_communication_version!==String(body.readInt16LE(46))) error('NodeInfo metadata disagrees with wire body');
            }
          }
        }
        // Citra WifiPacket: id + type + channel + MACs + BE u32 size.
        if ((r.event_label === 'citra.in' || r.event_label === 'citra.out') && raw[0] === 5) {
          if (raw.length < 19 || raw.readUInt32BE(15) !== raw.length - 19) { error('invalid WifiPacket length'); continue; }
          bump(result.wifi_types, JSON.stringify([r.event_label, raw[1]]));
          bump(result.payload_lengths, JSON.stringify([r.stage, r.event_label, raw[1], raw.length - 19]));
          // Decode only the documented LLC/SNAP SecureData format.
          const body = raw.subarray(19);
          if (raw[1] === 1 && body.length >= 22 && body.subarray(0, 8).equals(Buffer.from('aaaa03000000876d', 'hex'))) {
            bump(result.secure_data_channels, JSON.stringify([r.stage, r.event_label, body[15]]));
          }
        }
      }
    }
  } finally { lines.close(); input.destroy(); }
  result.identities = [...identities].map(value => JSON.parse(value));
  if (result.lines === 0) error('empty trace');
  if (identities.size !== 1) error('trace must contain one stable run identity');
  if (result.events['run.begin'] !== 1) error('trace must contain exactly one run.begin');
  result.passed = result.errors === 0;
  result.scope = 'schema, monotonicity and available raw integrity; no gameplay or compatibility verdict';
  return result;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    if (process.argv.length !== 3) throw new Error('usage: node trace-audit.mjs <trace.jsonl>');
    const report = await auditTrace(process.argv[2]);
    console.log(JSON.stringify(report, null, 2));
    process.exitCode = report.passed ? 0 : 1;
  } catch (error) {
    // IO/parse exceptions do not include an input line or payload.
    console.error(`trace audit failed: ${error.code ?? error.message}`);
    process.exitCode = 2;
  }
}
