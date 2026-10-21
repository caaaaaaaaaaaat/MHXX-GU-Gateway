import assert from 'node:assert/strict';
import test from 'node:test';
import { translateHeartbeatPacket } from './mh-heartbeat-translate.mjs';

function makeHeartbeat(kind, sender, seq = 0x1234, relTime = 0xbeef, timeEcho = 0xcafe) {
  const p = Buffer.alloc(32);
  p.writeUInt32BE(0x32ab9864, 0);
  p[4] = 1; p[5] = kind;
  p.writeUInt16BE(seq, 6);
  p.writeUInt16BE(relTime, 8);
  p.writeUInt16BE(timeEcho, 10);
  // message header: ctrl/byte1/len@12..16, sender@20..24
  p.writeUInt16BE(24, 14);            // message length 24 (stream header only)
  p.writeUInt32BE(0x06000000, 16 + 4); // route @ packet 20? place route at 20..24 region
  sender.copy(p, 20);
  return p;
}
const SXX_HOST = Buffer.from('b35ee27f', 'hex');
const SGU_HOST = Buffer.from('c0a8022f', 'hex');
const SXX_GUEST = Buffer.from('6f58d8bf', 'hex');

test('translates kind and sender, preserves all other bytes', () => {
  const pkt = makeHeartbeat(0xDA, SXX_HOST);
  const r = translateHeartbeatPacket(pkt, { kindFrom: 0xDA, kindTo: 0x60, senderFrom: SXX_HOST, senderTo: SGU_HOST });
  assert.equal(r.applicationConverted, false);
  assert.equal(r.packet[5], 0x60);
  assert.equal(r.packet.subarray(20, 24).toString('hex'), SGU_HOST.toString('hex'));
  // time words verbatim
  assert.equal(r.packet.readUInt16BE(8), 0xbeef);
  assert.equal(r.packet.readUInt16BE(10), 0xcafe);
  assert.equal(r.packet.readUInt16BE(6), 0x1234);
  assert.equal(r.packet.readUInt32BE(0), 0x32ab9864);
  assert.equal(r.packet[4], 1);
  assert.equal(r.packet.length, pkt.length);
});

test('input is not mutated; kind mismatch rejects', () => {
  const pkt = makeHeartbeat(0x60, SGU_HOST);
  const snapshot = Buffer.from(pkt);
  assert.throws(() => translateHeartbeatPacket(pkt, { kindFrom: 0xDA, kindTo: 0x73, senderFrom: SGU_HOST, senderTo: SXX_HOST }), /mh_hb_kind_mismatch/);
  assert.deepEqual(pkt, snapshot);
  const r = translateHeartbeatPacket(pkt, { kindFrom: 0x60, kindTo: 0x73, senderFrom: SGU_HOST, senderTo: SXX_HOST });
  assert.equal(r.packet[5], 0x73);
});

test('validation matrix', () => {
  const pkt = makeHeartbeat(0x60, SGU_HOST);
  const badMagic = Buffer.from(pkt); badMagic.writeUInt32BE(0xdeadbeef, 0);
  assert.throws(() => translateHeartbeatPacket(badMagic, { kindFrom: 0x60, kindTo: 0x73, senderFrom: SGU_HOST, senderTo: SXX_HOST }), /mh_hb_magic/);
  const badMode = Buffer.from(pkt); badMode[4] = 2;
  assert.throws(() => translateHeartbeatPacket(badMode, { kindFrom: 0x60, kindTo: 0x73, senderFrom: SGU_HOST, senderTo: SXX_HOST }), /mh_hb_mode/);
  assert.throws(() => translateHeartbeatPacket(pkt.subarray(0, 20), { kindFrom: 0x60, kindTo: 0x73, senderFrom: SGU_HOST, senderTo: SXX_HOST }), /mh_hb_packet/);
  assert.throws(() => translateHeartbeatPacket(pkt, {}), /mh_hb_kind_options/);
  assert.throws(() => translateHeartbeatPacket(pkt, { kindFrom: 0x60, kindTo: 0x10000, senderFrom: SGU_HOST, senderTo: SXX_HOST }), /mh_hb_kind_options/);
  assert.throws(() => translateHeartbeatPacket(pkt, { kindFrom: 0x60, kindTo: 0x73, senderFrom: 'no', senderTo: SXX_HOST }), /mh_hb_sender_options/);
  assert.throws(() => translateHeartbeatPacket(pkt, { kindFrom: 0x60, kindTo: 0x73, senderFrom: SGU_HOST, senderTo: SGU_HOST }), /mh_hb_sender_identity/);
  // sender word not present in the packet (and a distinct target, so the
  // identity guard does not fire first)
  assert.throws(() => translateHeartbeatPacket(pkt, { kindFrom: 0x60, kindTo: 0x73, senderFrom: SXX_HOST, senderTo: SXX_GUEST }), /mh_hb_sender_not_found/);
});

test('deterministic and reverse direction works', () => {
  const pkt = makeHeartbeat(0x73, SGU_HOST);
  const r1 = translateHeartbeatPacket(pkt, { kindFrom: 0x73, kindTo: 0xDA, senderFrom: SGU_HOST, senderTo: SXX_GUEST });
  const r2 = translateHeartbeatPacket(pkt, { kindFrom: 0x73, kindTo: 0xDA, senderFrom: SGU_HOST, senderTo: SXX_GUEST });
  assert.deepEqual(r1.packet, r2.packet);
  assert.equal(r1.packet[5], 0xDA);
  const back = translateHeartbeatPacket(r1.packet, { kindFrom: 0xDA, kindTo: 0x73, senderFrom: SXX_GUEST, senderTo: SGU_HOST });
  assert.equal(back.packet[5], 0x73);
});
