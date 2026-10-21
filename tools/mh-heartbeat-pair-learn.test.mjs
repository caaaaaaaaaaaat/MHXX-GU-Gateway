import assert from 'node:assert/strict';
import test from 'node:test';
import { learnHeartbeatPair } from './mh-heartbeat-pair-learn.mjs';

// synthetic packet factory: heartbeat kinds have one sender each and high-entropy
// time fields; data kinds share senders and have low-entropy time fields.
function makePackets({ hbA, hbB, senderA, senderB, dataKinds, hbFrames = 40, dataFrames = 30 }) {
  const out = [];
  let t = 0, u = 0;
  for (let i = 0; i < hbFrames; i++) {
    t = (t * 31 + 17 + i * 7919) >>> 16;
    u = (u * 47 + 11 + i * 6553) >>> 16;
    const rt = ('0000' + (((t + i * 101) % 65536))).slice(-4);
    const te = ('0000' + (((t * 7 + i * 13) % 65536))).slice(-4);
    out.push({ kind: hbA, sender: senderA, seq: ('0000' + ((t + i) % 65536)).slice(-4), rel_time: rt, time_echo: te });
    const rt2 = ('0000' + (((u + i * 57) % 65536))).slice(-4);
    const te2 = ('0000' + (((u * 7 + i * 29) % 65536))).slice(-4);
    out.push({ kind: hbB, sender: senderB, seq: ('0000' + ((u + i) % 65536)).slice(-4), rel_time: rt2, time_echo: te2 });
  }
  for (let i = 0; i < dataFrames; i++) {
    out.push({ kind: dataKinds[i % dataKinds.length], sender: i % 2 ? senderA : senderB, seq: '0000', rel_time: '0000', time_echo: '0000' });
  }
  return out;
}

test('learns the mirrored heartbeat pair from a synthetic session', () => {
  const packets = makePackets({ hbA: 0xA0, hbB: 0xDA, senderA: 'b35ee27f', senderB: '6f58d8bf', dataKinds: [0, 1] });
  const r = learnHeartbeatPair(packets, { minFrames: 10 });
  assert.equal(r.learned, true);
  assert.equal(r.heartbeat_pair.length, 2);
  const kinds = r.heartbeat_pair.map(c => c.kind).sort((a, b) => a - b);
  assert.deepEqual(kinds, [0xA0, 0xDA]);
  assert.equal(r.heartbeat_pair[0].sender, 'b35ee27f');
  assert.equal(r.heartbeat_pair[1].sender, '6f58d8bf');
  assert.equal(r.total_packets, packets.length);
  for (const flag of ['observationsAuthenticated', 'payloadValidated', 'applicationConverted', 'productionReady']) {
    assert.equal(r[flag], false);
  }
});

test('second session with different heartbeat kinds still learns (per-session values)', () => {
  const packets = makePackets({ hbA: 0x1A, hbB: 0xEF, senderA: '11223344', senderB: '55667788', dataKinds: [0] });
  const r = learnHeartbeatPair(packets, { minFrames: 10 });
  assert.equal(r.learned, true);
  assert.deepEqual(r.heartbeat_pair.map(c => c.kind).sort((a, b) => a - b), [0x1A, 0xEF]);
});

test('GU-style pair (0x23/0xCC) is learned the same way', () => {
  const packets = makePackets({ hbA: 0x23, hbB: 0xCC, senderA: 'c0a8022f', senderB: 'c0a8ddf2', dataKinds: [0] });
  const r = learnHeartbeatPair(packets, { minFrames: 10 });
  assert.equal(r.learned, true);
  assert.deepEqual(r.heartbeat_pair.map(c => c.kind).sort((a, b) => a - b), [0x23, 0xCC]);
});

test('single-candidate sessions do not form a pair', () => {
  const packets = makePackets({ hbA: 0xA0, hbB: 0xDA, senderA: 'aaaa', senderB: 'aaaa', dataKinds: [0] });
  const r = learnHeartbeatPair(packets, { minFrames: 10 });
  // Both kinds stay candidates (single sender each), but they share the same
  // sender, so the mirrored-pair condition refuses to pair them.
  assert.equal(r.learned, false);
  assert.equal(r.candidates.length, 2);
  assert.equal(r.heartbeat_pair, null);
});

test('low-entropy time fields fail the entropy gate', () => {
  const packets = makePackets({ hbA: 0xA0, hbB: 0xDA, senderA: 'aaaa', senderB: 'bbbb', dataKinds: [0] });
  for (const p of packets) { p.rel_time = '0000'; p.time_echo = '0000'; }
  const r = learnHeartbeatPair(packets, { minFrames: 10 });
  assert.equal(r.learned, false);
});

test('invalid shapes are rejected without partial results', () => {
  assert.throws(() => learnHeartbeatPair('no'), /mh_heartbeat_pair_packets/);
  assert.throws(() => learnHeartbeatPair([], { minFrames: 1 }), /mh_heartbeat_pair_packets/);
  assert.throws(() => learnHeartbeatPair([null]), /mh_heartbeat_pair_packet_shape/);
  assert.throws(() => learnHeartbeatPair([{ kind: 1 }]), /mh_heartbeat_pair_packet_shape/);
  assert.throws(() => learnHeartbeatPair([{ kind: 256, sender: 'a', seq: '00', rel_time: '00', time_echo: '00' }], { minFrames: 1 }), /mh_heartbeat_pair_packet_shape/);
  // a shape-valid single packet is accepted and simply yields no pair (asserted in the single-candidate case above).
  assert.throws(() => learnHeartbeatPair(makePackets({ hbA: 1, hbB: 2, senderA: 'a', senderB: 'b', dataKinds: [0] }), { minFrames: 10, minShare: 0 }), /mh_heartbeat_pair_options/);
  assert.throws(() => learnHeartbeatPair(makePackets({ hbA: 1, hbB: 2, senderA: 'a', senderB: 'b', dataKinds: [0] }), { minFrames: 10, minTimeEntropy: 1 }), /mh_heartbeat_pair_options/);
});

test('inputs are not mutated and results are deterministic', () => {
  const packets = makePackets({ hbA: 0xA0, hbB: 0xDA, senderA: 'b35ee27f', senderB: '6f58d8bf', dataKinds: [0, 1] });
  const snapshot = JSON.stringify(packets);
  const r1 = learnHeartbeatPair(packets, { minFrames: 10 });
  const r2 = learnHeartbeatPair(packets, { minFrames: 10 });
  assert.equal(JSON.stringify(packets), snapshot);
  assert.deepEqual(r1, r2);
});
