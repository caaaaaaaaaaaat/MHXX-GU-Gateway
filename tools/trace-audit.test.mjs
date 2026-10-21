// SPDX-License-Identifier: GPL-3.0-or-later
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import { auditTrace } from './trace-audit.mjs';

const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const marker = () => ({ manifest_id: 'synthetic', run_id: 'test', channel: 'A',
  platform: 'citra', build_id: 'synthetic', role: 'host', event_label: 'run.begin',
  stage: 'hall', direction: 'n/a', utc: '2026-10-15T00:00:00Z', monotonic_ms: 1,
  length: 0, sha256: hash(Buffer.alloc(0)), structure: 'marker', decoded: true });
async function audit(records) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'crossplay-trace-test-'));
  try {
    const file = path.join(dir, 'synthetic.jsonl');
    await fs.writeFile(file, records.map(r => typeof r === 'string' ? r : JSON.stringify(r)).join('\n'));
    return await auditTrace(file);
  } finally { await fs.rm(dir, { recursive: true, force: true }); }
}
test('valid marker and synthetic WifiPacket produce metadata without raw bytes', async () => {
  const raw = Buffer.alloc(41);
  raw[0] = 5; raw[1] = 1; raw[2] = 11; raw.writeUInt32BE(22, 15);
  Buffer.from('aaaa03000000876d', 'hex').copy(raw, 19); raw[34] = 243;
  const r = { ...marker(), event_label: 'citra.in', direction: 'citra->gateway',
    structure: 'citra_secure_data', length: raw.length, sha256: hash(raw), raw_hex: raw.toString('hex') };
  const result = await audit([marker(), r]);
  assert.equal(result.passed, true);
  assert.equal(result.raw_verified, 1);
  assert.equal(result.secure_data_channels['["hall","citra.in",243]'], 1);
  assert.equal(JSON.stringify(result).includes(raw.toString('hex')), false);
});
test('malformed, missing and corrupted records fail visibly', async () => {
  for (const records of [[], ['{'], [{}], [marker(), { ...marker(), raw_hex: 'ff' }],
    [{ ...marker(), decoded: false }], [marker(), { ...marker(), monotonic_ms: 0 }],
    [marker(), { ...marker(), run_id: 'other' }], [{ ...marker(), utc: 'yesterday' }]]) {
    assert.equal((await audit(records)).passed, false);
  }
});
test('raw WifiPacket length is checked independently of trace hash', async () => {
  const raw = Buffer.alloc(19); raw[0] = 5; raw.writeUInt32BE(2, 15);
  const r = { ...marker(), event_label: 'citra.in', raw_hex: raw.toString('hex'), length: raw.length, sha256: hash(raw) };
  const result = await audit([marker(), r]);
  assert.equal(result.passed, false);
  assert.match(result.error_examples[0].reason, /WifiPacket/);
  assert.equal(result.error_reasons['invalid WifiPacket length'],1);
});
test('unknown event names cannot corrupt histograms', async () => {
  const result = await audit([marker(), { ...marker(), event_label: '__proto__' }]);
  assert.equal(result.passed, true);
  assert.equal(result.events.__proto__, 1);
});
test('complete room Proxy envelope independently verifies ports and plaintext hash', async () => {
  const plain = Buffer.from('synthetic capture payload');
  const compressed = zlib.zstdCompressSync(plain);
  const raw = Buffer.alloc(21 + compressed.length);
  raw[0] = 5; raw[1] = 1; raw.writeUInt16BE(19001, 6); raw[8] = 1;
  raw.writeUInt16BE(19002, 13); raw[15] = 3; raw.writeUInt32BE(compressed.length, 17); compressed.copy(raw, 21);
  const record = { ...marker(), event_label: 'room.c2s', structure: 'yuzu_room_proxy', peer_id: 1,
    raw_hex: raw.toString('hex'), length: raw.length, sha256: hash(raw), local_family: 1,
    remote_family: 1, local_port: 19001, remote_port: 19002, protocol: 3, broadcast: false,
    local_ip: '0.0.0.0', remote_ip: '0.0.0.0',
    compressed_length: compressed.length, zstd_verified: true, plain_length: plain.length, plain_sha256: hash(plain) };
  const result = await audit([marker(), record]);
  assert.equal(result.passed, true);
  assert.equal(result.proxy_plain_verified, 1);
  assert.equal((await audit([marker(), { ...record, remote_port: 1 }])).passed, false);
  assert.equal((await audit([marker(), { ...record, local_ip: '10.0.0.1' }])).passed, false);
  assert.equal((await audit([marker(), { ...record, remote_ip: '10.0.0.2' }])).passed, false);
  assert.equal((await audit([marker(), { ...record, plain_sha256: '0'.repeat(64) }])).passed, false);
});
test('LDN capture metadata is checked against the independent exact size table', async () => {
  const raw = Buffer.alloc(15); raw[0] = 6;
  const record = { ...marker(), event_label: 'room.s2c', structure: 'yuzu_room_ldn', peer_id: 2,
    raw_hex: raw.toString('hex'), length: raw.length, sha256: hash(raw), ldn_type: 0,
    local_ip: '0.0.0.0', remote_ip: '0.0.0.0', broadcast: false,
    body_length: 0, expected_body_length: 0, ldn_size_verified: true };
  assert.equal((await audit([marker(), record])).passed, true);
  assert.equal((await audit([marker(), { ...record, expected_body_length: 64 }])).passed, false);
  assert.equal((await audit([marker(), { ...record, remote_ip: '10.0.0.1' }])).passed, false);
  assert.equal((await audit([marker(), { ...record, broadcast: true }])).passed, false);
});

test('NetworkInfo 64-bit identities and advertisement hash are checked against wire offsets',async()=>{
  const raw=Buffer.alloc(15+0x480);raw[0]=6;raw[1]=1;raw.writeUInt32BE(0x480,11);
  const body=raw.subarray(15);body.writeBigUInt64LE(0x1122334455667788n,0);body.writeBigUInt64LE(0x80000000000000fen,16);
  const record={...marker(),event_label:'room.s2c',structure:'yuzu_room_ldn',peer_id:1,
    raw_hex:raw.toString('hex'),length:raw.length,sha256:hash(raw),ldn_type:1,
    local_ip:'0.0.0.0',remote_ip:'0.0.0.0',broadcast:false,body_length:0x480,expected_body_length:0x480,ldn_size_verified:true,ldn_body_decoded:true,
    local_communication_id_hex:'0x1122334455667788',scene_id:0,session_id_high_hex:'0x80000000000000fe',session_id_low_hex:'0x0000000000000000',
    network_bssid:'000000000000',network_type:0,wifi_channel:0,node_count:0,node_count_max:0,advertise_length:0,advertise_sha256:hash(Buffer.alloc(0))};
  assert.equal((await audit([marker(),record])).passed,true);
  for(const patch of [{local_communication_id_hex:'0x1122334455667800'},{session_id_high_hex:'0x8000000000000000'},
    {advertise_sha256:'0'.repeat(64)},{node_count:1},{wifi_channel:11}]) assert.equal((await audit([marker(),{...record,...patch}])).passed,false);
  // Explicit slot coverage audits the entire fixed array, including slots
  // above the connected count. Legacy captures lack this coverage marker.
  const full={...record,node_slots:8};
  for(let i=0;i<8;i++)Object.assign(full,{[`node_${i}_ipv4_raw`]:'0.0.0.0',
    [`node_${i}_mac`]:'000000000000',[`node_${i}_id`]:'0',
    [`node_${i}_connected`]:false,[`node_${i}_communication_version`]:'0'});
  assert.equal((await audit([marker(),full])).passed,true);
  assert.equal((await audit([marker(),{...full,node_7_connected:true}])).passed,false);
  assert.equal((await audit([marker(),{...full,node_slots:7}])).passed,false);
});

test('invalid LDN wire fails even when metadata faithfully describes the invalid packet',async()=>{
  for(const [type,size,broadcast] of [[6,0,0],[255,0,0],[0,1,0],[1,0,0],[2,63,0],[3,0x481,0],[4,65,0],[5,1,0],[0,0,2]]) {
    const raw=Buffer.alloc(15+size);raw[0]=6;raw[1]=type;raw[10]=broadcast;raw.writeUInt32BE(size,11);
    const expected=[0,0x480,0x40,0x480,0x40,0][type];
    const record={...marker(),event_label:'room.s2c',structure:'yuzu_room_ldn',peer_id:1,
      raw_hex:raw.toString('hex'),length:raw.length,sha256:hash(raw),ldn_type:type,
      local_ip:'0.0.0.0',remote_ip:'0.0.0.0',broadcast:broadcast!==0,
      body_length:size,expected_body_length:expected,ldn_size_verified:expected===size};
    const result=await audit([marker(),record]);
    assert.equal(result.passed,false,`type=${type} size=${size} broadcast=${broadcast}`);
    assert.equal(result.error_reasons['invalid LdnPacket type, body size or broadcast'],1);
  }
});
