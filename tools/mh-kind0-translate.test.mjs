import assert from 'node:assert/strict';
import test from 'node:test';
import { translateKind0Body, translateKind0Packet } from './mh-kind0-translate.mjs';

const HOST_GW = Buffer.from('c0a8022f', 'hex');   // GU host fake IP (measured)
const GUEST_GW = Buffer.from('c0a8ddf2', 'hex');  // GU guest fake IP (measured)
const HOST_XX = Buffer.from('b35ee27f', 'hex');   // XX host identity word (measured)
const GUEST_XX = Buffer.from('6f58d8bf', 'hex');  // XX guest identity word (measured)
const PAIRS = [{ from: HOST_GW, to: HOST_XX }, { from: GUEST_GW, to: GUEST_XX }];

// Real GU route 0x03003039 body captured in g2-run2 (member announce).
const REAL_0300_BODY = Buffer.from(
  '01114900000000000000000002000000e6147194d33f87880100000000000000'
  + 'c0a8022f3039000000c0a8ddf2303900000100000000000000'
  + '00ff0000000000000000ff0000000000000000ff0000000000000000ff0000000000000000ff0000000000000000ff00000000', 'hex');
const REAL_0200_BODY = Buffer.from(
  '02020001010002000400040000000000c0a8022f3039c0a8022f30393fd388873fd3'
  + 'c0a8022f00000000000000000000000000000000000000000000000000000000000000'
  + '0000000000000000000000000000000000000000000000000000000000000000000000'
  + '0000000000c0a8ddf23039c0a8ddf230396840d9406840c0a8ddf20000000000000000'
  + '0000000000000000000000000000000000000000000000000000000000000000000000'
  + '0000000100d9598a4e', 'hex');

function makeKind0Packet(route, body) {
  const header = Buffer.alloc(12);
  header.writeUInt32BE(0x32ab9864, 0);
  header[4] = 1; header[5] = 0;
  const msg = Buffer.alloc(20);
  msg.writeUInt32BE(route, 12);
  msg.writeUInt32BE(0xc0a8022f, 20 - 20 + 8); // sender @8 in message header
  const packet = Buffer.concat([header, msg, body]);
  return packet;
}

test('translateKind0Body rewrites fake-IP words and preserves everything else', () => {
  const r = translateKind0Body(REAL_0300_BODY, PAIRS);
  assert.equal(r.applicationConverted, false);
  assert.ok(r.replacements >= 2, 'at least the two member IP words are replaced');
  assert.ok(!r.body.includes(HOST_GW), 'no GU host IP remains');
  assert.ok(!r.body.includes(GUEST_GW), 'no GU guest IP remains');
  // port words (3039) survive
  assert.ok(r.body.indexOf(Buffer.from('3039', 'hex')) > 0, 'port word survives');
  // byte count unchanged
  assert.equal(r.body.length, REAL_0300_BODY.length);
});

test('round trip: translating back with reversed pairs restores the original body', () => {
  const forward = translateKind0Body(REAL_0300_BODY, PAIRS);
  const reverse = translateKind0Body(forward.body,
    [{ from: HOST_XX, to: HOST_GW }, { from: GUEST_XX, to: GUEST_GW }]);
  assert.deepEqual(reverse.body, REAL_0300_BODY);
});

test('route 0x02000000 member address pairs are translated the same way', () => {
  const r = translateKind0Body(REAL_0200_BODY, PAIRS);
  assert.ok(r.replacements >= 4, 'multiple member address pairs in the 0x0200 body');
  assert.ok(!r.body.includes(HOST_GW) && !r.body.includes(GUEST_GW));
});

test('translateKind0Packet validates magic/mode/kind/route', () => {
  const pkt = makeKind0Packet(0x03003039, REAL_0300_BODY);
  assert.doesNotThrow(() => translateKind0Packet(pkt, PAIRS));
  const badMagic = Buffer.from(pkt); badMagic.writeUInt32BE(0xdeadbeef, 0);
  assert.throws(() => translateKind0Packet(badMagic, PAIRS), /mh_kind0_magic/);
  const badMode = Buffer.from(pkt); badMode[4] = 2;
  assert.throws(() => translateKind0Packet(badMode, PAIRS), /mh_kind0_mode/);
  const badKind = Buffer.from(pkt); badKind[5] = 0x23;
  assert.throws(() => translateKind0Packet(badKind, PAIRS), /mh_kind0_kind/);
  const badRoute = Buffer.from(pkt); badRoute.writeUInt32BE(0xdeadbeef, 24);
  assert.throws(() => translateKind0Packet(badRoute, PAIRS), /mh_kind0_route/);
});

test('input validation: shapes, ranges, duplicates', () => {
  assert.throws(() => translateKind0Body('no', PAIRS), /mh_kind0_body/);
  assert.throws(() => translateKind0Body(REAL_0300_BODY, 'no'), /mh_kind0_pairs/);
  assert.throws(() => translateKind0Body(REAL_0300_BODY, []), /mh_kind0_pairs_range/);
  assert.throws(() => translateKind0Body(REAL_0300_BODY, PAIRS.concat(PAIRS)), /mh_kind0_pair_duplicate/);
  assert.throws(() => translateKind0Body(REAL_0300_BODY, [{ from: HOST_GW, to: 'no' }]), /mh_kind0_pair_shape/);
  assert.throws(() => translateKind0Body(REAL_0300_BODY, [{ from: HOST_GW, to: HOST_GW }]), /mh_kind0_pair_identity/);
  assert.throws(() => translateKind0Body(REAL_0300_BODY,
    [{ from: HOST_GW, to: HOST_XX }, { from: HOST_GW, to: GUEST_XX }]), /mh_kind0_pair_duplicate/);
});

test('translation is deterministic and does not mutate inputs', () => {
  const original = Buffer.from(REAL_0300_BODY);
  const snapshot = Buffer.from(REAL_0300_BODY);
  const r1 = translateKind0Body(original, PAIRS);
  const r2 = translateKind0Body(original, PAIRS);
  assert.deepEqual(original, snapshot);
  assert.deepEqual(r1.body, r2.body);
  assert.equal(r1.replacements, r2.replacements);
});
