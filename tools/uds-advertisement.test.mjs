// SPDX-License-Identifier: GPL-3.0-or-later
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {udsAdvertisement} from './uds-advertisement.mjs';
const hash=(name,b)=>crypto.createHash(name).update(b).digest('hex');
function fixture(change=()=>{}) {
  const tag=Buffer.alloc(57);tag[0]=221;tag[1]=55;
  Buffer.from('001f321511223344770012345566778802040000','hex').copy(tag,2);
  tag[53]=3;Buffer.from('aabbcc','hex').copy(tag,54);change(tag);
  Buffer.from(hash('sha1',tag.subarray(2)),'hex').copy(tag,33);
  const body=Buffer.concat([Buffer.alloc(12),Buffer.from('00080000000000000000','hex'),tag]);
  const raw=Buffer.alloc(19+body.length);raw[0]=5;raw[2]=11;
  raw.writeUInt32BE(body.length,15);body.copy(raw,19);return raw;
}
function record(raw) {return {event_label:'citra.in',length:raw.length,sha256:hash('sha256',raw),raw_hex:raw.toString('hex')};}
test('public UDS IE extracts independent wire offsets without claiming encrypted node validation',()=>{
  const result=udsAdvertisement(record(fixture()));
  assert.equal(result.wlan_comm_id_hex,'0x11223344');assert.equal(result.network_id_hex,'0x55667788');
  assert.equal(result.id,119);assert.equal(result.attributes,0x1234);
  assert.equal(result.total_nodes,2);assert.equal(result.max_nodes,4);
  assert.equal(result.advertise_length,3);assert.equal(result.advertise_sha256,hash('sha256',Buffer.from('aabbcc','hex')));
  assert.equal(result.encrypted_nodes_verified,false);assert.equal(result.game_verified,false);
  assert.equal(JSON.stringify(result).includes('aabbcc'),false);
});
test('raw integrity and IE SHA1 are independently required',()=>{
  const raw=fixture();raw[raw.length-1]^=1;
  assert.throws(()=>udsAdvertisement(record(raw)),/sha1/);
  const r=record(fixture());r.sha256='0'.repeat(64);
  assert.throws(()=>udsAdvertisement(r),/integrity/);
});
test('truncation and malformed public IE reject even if outer hash and SHA1 agree',()=>{
  for(const raw of [fixture(t=>t[53]=4),fixture(t=>t[18]=5),fixture(t=>t[19]=17)])
    assert.throws(()=>udsAdvertisement(record(raw)));
  const raw=fixture();raw[32]=255;
  assert.throws(()=>udsAdvertisement(record(raw)),/truncated/);
  const original=fixture(),tag=original.subarray(41);
  const duplicate=Buffer.concat([original,tag]);duplicate.writeUInt32BE(duplicate.length-19,15);
  assert.throws(()=>udsAdvertisement(record(duplicate)),/duplicate/);
});
test('non-beacons are excluded and malformed raw is never silently accepted',()=>{
  const raw=fixture();raw[1]=1;assert.equal(udsAdvertisement(record(raw)),null);
  assert.throws(()=>udsAdvertisement({event_label:'citra.in'}),/raw/);
  assert.equal(udsAdvertisement({event_label:'room.c2s'}),null);
});
