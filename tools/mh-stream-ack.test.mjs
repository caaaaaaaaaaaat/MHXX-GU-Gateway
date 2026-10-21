import assert from 'node:assert/strict';
import test from 'node:test';
import { applyMhStreamAck, isMhStreamScheduleDue, MH_STREAM_MAX_TIME as MAX } from './mh-stream-ack.mjs';
import { encodeMhStreamChunk } from './mh-stream-chunk.mjs';
const profiles = ['mhxx-1.4', 'mhgu-v262144'];
function ack(base, bitmap, profile) {
  const header = Buffer.alloc(24); header.writeUInt32BE(base, 12); header.writeBigUInt64BE(bitmap, 16);
  return encodeMhStreamChunk({ header, payload: Buffer.alloc(0) }, profile);
}
test('cumulative ACK releases a prefix then bitmap targets new head plus one', () => {
  for (const profile of profiles) {
    const state = {base: 100, schedules: [1n, 2n, 3n, 4n, 5n]};
    const bytes = ack(102, 1n, profile), before = Buffer.from(bytes);
    assert.deepEqual(applyMhStreamAck(state, bytes, profile),
      {base: 102, schedules: [3n, MAX, 5n], released: 2, stale: false});
    assert.deepEqual(state.schedules, [1n, 2n, 3n, 4n, 5n]);
    assert.deepEqual(bytes, before);
  }
});
test('selective bits cross the low/high word boundary without releasing window slots', () => {
  for (const profile of profiles) {
    const schedules = Array(64).fill(0n);
    const result = applyMhStreamAck({base: 0, schedules}, ack(0, (1n << 31n) | (1n << 32n) | (1n << 63n), profile), profile);
    assert.equal(result.schedules[32], MAX); assert.equal(result.schedules[33], MAX);
    assert.equal(result.schedules[0], 0n); assert.equal(result.schedules[63], 0n);
    assert.equal(result.released, 0); assert.equal(result.schedules.length, 64);
  }
});
test('stale ACK leaves independent state and ignores bitmap', () => {
  const state = {base: 10, schedules: [1n, 2n]};
  const result = applyMhStreamAck(state, ack(9, MAX, profiles[0]), profiles[0]);
  assert.equal(result.stale, true); assert.deepEqual(result.schedules, [1n, 2n]);
  result.schedules[0] = 9n; assert.equal(state.schedules[0], 1n);
});
test('ACK beyond outstanding fails and complete cumulative ACK empties window', () => {
  for (const profile of profiles) {
    const state = {base: 10, schedules: [0n, 0n]};
    assert.throws(() => applyMhStreamAck(state, ack(13, 0n, profile), profile), /beyond/);
    assert.deepEqual(applyMhStreamAck(state, ack(12, MAX, profile), profile).schedules, []);
  }
});
test('window model rejects unsupported state, wrap and malformed profile/input', () => {
  const bytes = ack(0, 0n, profiles[0]);
  for (const state of [null, {base: -1, schedules: []}, {base: 0xffffffff, schedules: [0n]},
    {base: 0, schedules: Array(65).fill(0n)}, {base: 0, schedules: Array(2)},
    {base: 0, schedules: [0]}, {base: 0, schedules: [-1n]}]) {
    assert.throws(() => applyMhStreamAck(state, bytes, profiles[0]), /window/);
  }
  assert.throws(() => applyMhStreamAck({base: 0, schedules: []}, bytes, 'unknown'), /profile/);
  assert.throws(() => applyMhStreamAck({base: 0, schedules: []}, Buffer.alloc(23), profiles[0]));
});
test('uint64 scheduling uses unsigned comparison including maximum equality', () => {
  assert.equal(isMhStreamScheduleDue(MAX - 1n, MAX), false);
  assert.equal(isMhStreamScheduleDue(MAX, MAX), true);
  assert.equal(isMhStreamScheduleDue(1n << 63n, 1n), true);
  assert.equal(isMhStreamScheduleDue(5n, 5n), true);
  for (const value of [-1n, MAX + 1n, 0, undefined]) assert.throws(() => isMhStreamScheduleDue(value, 0n), /time/);
});
