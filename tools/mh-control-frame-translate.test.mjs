import assert from 'node:assert/strict';
import test from 'node:test';
import { translateControlFrame } from './mh-control-frame-translate.mjs';

const XX_HOST = Buffer.from('b35ee27f', 'hex');
const GU_HOST = Buffer.from('c0a8022f', 'hex');
const XX_GUEST = Buffer.from('6f58d8bf', 'hex');
const GU_GUEST = Buffer.from('c0a8ddf2', 'hex');

function makeFrame(route, sender, tailHex = 'f1d98ea3c9') {
  const pkt = Buffer.alloc(52);
  pkt.writeUInt32BE(0x32ab9864, 0);
  pkt[4] = 1; pkt[5] = 0;
  pkt.writeUInt16BE(0x10, 12 + 0);            // ctrl=0, len=0x10
  sender.copy(pkt, 12 + 8);
  pkt.writeUInt32BE(route, 12 + 12);
  // trailing timestamp words live at the very end of the frame
  Buffer.from(tailHex, 'hex').copy(pkt, 52 - 5);
  return pkt;
}

test('keepalive frame: sender replaced, body verbatim, GU words verified', () => {
  const pkt = makeFrame(0x06000000, XX_HOST, '1bdeca5cb6');
  const r = translateControlFrame(pkt, { senderFrom: XX_HOST, senderTo: GU_HOST });
  assert.equal(r.route, '0x06000000');
  assert.equal(r.applicationConverted, false);
  const hex = r.packet.toString('hex');
  assert.ok(hex.includes('c0a8022f'), 'GU host word present');
  assert.ok(!hex.includes('b35ee27f'), 'XX word gone');
  // trailing timestamp preserved
  assert.ok(hex.endsWith('1bdeca5cb6'), 'tail preserved');
});

test('reverse direction: GU host word -> XX host word', () => {
  const pkt = makeFrame(0x06000000, GU_HOST, 'f1d98ea3c9');
  const r = translateControlFrame(pkt, { senderFrom: GU_HOST, senderTo: XX_HOST });
  const hex = r.packet.toString('hex');
  assert.ok(hex.includes('b35ee27f'), 'XX word present after reverse');
});

test('0x02100000 frames translate the same way', () => {
  const pkt = makeFrame(0x02100000, XX_GUEST, '1bccdd6513');
  const r = translateControlFrame(pkt, { senderFrom: XX_GUEST, senderTo: GU_GUEST });
  assert.equal(r.route, '0x02100000');
  assert.ok(r.packet.toString('hex').includes('c0a8ddf2'));
});

test('unsupported routes reject', () => {
  assert.throws(() => translateControlFrame(makeFrame(0x20000000, XX_HOST), { senderFrom: XX_HOST, senderTo: GU_HOST }), /mh_ctl_route/);
  assert.throws(() => translateControlFrame(makeFrame(0x03003039, XX_HOST), { senderFrom: XX_HOST, senderTo: GU_HOST }), /mh_ctl_route/);
});

test('validation matrix', () => {
  assert.throws(() => translateControlFrame(Buffer.alloc(20), { senderFrom: XX_HOST, senderTo: GU_HOST }), /mh_ctl_packet/);
  const bad = makeFrame(0x06000000, XX_HOST); bad.writeUInt32BE(0xdeadbeef, 0);
  assert.throws(() => translateControlFrame(bad, { senderFrom: XX_HOST, senderTo: GU_HOST }), /mh_ctl_magic/);
  const mode2 = makeFrame(0x06000000, XX_HOST); mode2[4] = 2;
  assert.throws(() => translateControlFrame(mode2, { senderFrom: XX_HOST, senderTo: GU_HOST }), /mh_ctl_mode/);
  assert.throws(() => translateControlFrame(makeFrame(0x06000000, XX_HOST), { senderFrom: 'no', senderTo: GU_HOST }), /mh_ctl_sender_shape/);
  assert.throws(() => translateControlFrame(makeFrame(0x06000000, XX_HOST), { senderFrom: XX_HOST, senderTo: XX_HOST }), /mh_ctl_sender_identity/);
  // sender not in packet -> not found
  assert.throws(() => translateControlFrame(makeFrame(0x06000000, XX_HOST), { senderFrom: GU_GUEST, senderTo: GU_HOST }), /mh_ctl_sender_not_found/);
});

test('deterministic and non-mutating', () => {
  const pkt = makeFrame(0x06000000, XX_HOST, '1bdeca5cb6');
  const snap = Buffer.from(pkt);
  const r1 = translateControlFrame(pkt, { senderFrom: XX_HOST, senderTo: GU_HOST });
  assert.deepEqual(pkt, snap);
  const r2 = translateControlFrame(pkt, { senderFrom: XX_HOST, senderTo: GU_HOST });
  assert.deepEqual(r1.packet, r2.packet);
});
