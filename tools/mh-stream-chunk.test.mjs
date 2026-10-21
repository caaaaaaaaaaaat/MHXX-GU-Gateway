import assert from 'node:assert/strict';
import test from 'node:test';
import { decodeMhStreamChunk, encodeMhStreamChunk, assembleMhStreamChunks } from './mh-stream-chunk.mjs';
const profiles = ['mhxx-1.4', 'mhgu-v262144'];
function value(sequence, size, terminal) {
  const header = Buffer.alloc(24, 0xa5);
  header.writeUInt16BE(terminal ? 3 : 1, 0);
  header.writeUInt32BE(sequence, 8);
  return { header, payload: Buffer.alloc(size, sequence & 255) };
}
test('both fixed profiles roundtrip opaque header bytes and independent payload', () => {
  for (const profile of profiles) {
    const input = value(123, 17, true);
    const before = Buffer.from(input.header);
    const encoded = encodeMhStreamChunk(input, profile);
    const decoded = decodeMhStreamChunk(encoded, profile);
    assert.equal(decoded.sequence, 123);
    assert.deepEqual(encodeMhStreamChunk(decoded, profile), encoded);
    assert.deepEqual(input.header, before);
    decoded.payload.fill(0); encoded.fill(0);
    assert.equal(input.payload[0], 123);
  }
});
test('GU enforces proven 1416 payload boundary in encode decode and assembly', () => {
  const gu = 'mhgu-v262144';
  const valid = encodeMhStreamChunk(value(0, 1416, true), gu);
  assert.equal(assembleMhStreamChunks([valid], gu, 0).payload.length, 1416);
  const tooLarge = encodeMhStreamChunk(value(0, 1417, true), 'mhxx-1.4');
  assert.throws(() => encodeMhStreamChunk(value(0, 1417, true), gu), /payload_limit/);
  assert.throws(() => decodeMhStreamChunk(tooLarge, gu), /payload_limit/);
  assert.throws(() => assembleMhStreamChunks([tooLarge], gu, 0), /payload_limit/);
});
test('both profiles restore shuffled chunks and preserve complete ordered headers', () => {
  for (const profile of profiles) {
    const a = encodeMhStreamChunk(value(40, 2, false), profile);
    const b = encodeMhStreamChunk(value(41, 3, true), profile);
    const output = assembleMhStreamChunks([b, a, a], profile, 40);
    assert.deepEqual(output.payload, Buffer.from([40, 40, 41, 41, 41]));
    assert.equal(output.headers[0].readUInt32BE(8), 40);
    output.headers[0].fill(0);
    assert.equal(a.readUInt32BE(8), 40);
  }
});
test('shared assembly keeps gap, terminal and session-start requirements', () => {
  for (const profile of profiles) {
    const a = encodeMhStreamChunk(value(0, 1, false), profile);
    const c = encodeMhStreamChunk(value(2, 1, true), profile);
    assert.throws(() => assembleMhStreamChunks([a, c], profile, 0), /gap/);
    assert.throws(() => assembleMhStreamChunks([a], profile, 0), /terminal/);
    assert.throws(() => assembleMhStreamChunks([c], profile, undefined), /start_sequence/);
  }
});
test('shared interfaces reject unsupported profiles and malformed input', () => {
  for (const profile of [undefined, null, 'mhgu', 'mhxx', {}]) {
    assert.throws(() => decodeMhStreamChunk(Buffer.alloc(24), profile), /profile/);
    assert.throws(() => encodeMhStreamChunk(value(0, 0, true), profile), /profile/);
    assert.throws(() => assembleMhStreamChunks([], profile, 0), /profile/);
  }
  for (const profile of profiles) {
    for (const input of [null, {}, {header: Buffer.alloc(23), payload: Buffer.alloc(0)},
      {header: Buffer.alloc(24), payload: []}, value(0, 65536, true)]) {
      assert.throws(() => encodeMhStreamChunk(input, profile));
    }
    assert.throws(() => decodeMhStreamChunk(Buffer.alloc(25), profile), /length/);
    assert.throws(() => assembleMhStreamChunks(Array(65).fill(null), profile, 0), /count/);
  }
});
test('encoding changes only payload length and preserves unknown flag bits', () => {
  for (const profile of profiles) {
    const input = value(0xffffffff, 0, true);
    input.header.writeUInt16BE(0x8003, 0);
    const output = encodeMhStreamChunk(input, profile);
    const expected = Buffer.from(input.header); expected.writeUInt16BE(0, 2);
    assert.deepEqual(output, expected);
    assert.equal(decodeMhStreamChunk(output, profile).flags, 0x8003);
  }
});
