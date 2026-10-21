import assert from 'node:assert/strict';
import test from 'node:test';
import { decodeMhxxStreamChunk, assembleMhxxStreamChunks } from './mhxx-stream-chunk.mjs';
const profile = 'mhxx-1.4';
function chunk(sequence, payload, terminal = false) {
  const bytes = Buffer.alloc(24 + payload.length, 0xa5);
  bytes.writeUInt16BE(terminal ? 3 : 1, 0);
  bytes.writeUInt16BE(payload.length, 2);
  bytes.writeUInt32BE(sequence, 8);
  Buffer.from(payload).copy(bytes, 24);
  return bytes;
}
test('nested decoder preserves opaque header and isolates input', () => {
  const bytes = chunk(0x10203040, [7, 8], true);
  const result = decodeMhxxStreamChunk(bytes, profile);
  assert.equal(result.sequence, 0x10203040);
  assert.equal(result.flags, 3);
  assert.equal(result.data, true);
  assert.equal(result.terminal, true);
  assert.deepEqual(result.payload, Buffer.from([7, 8]));
  result.header.fill(0); result.payload.fill(0);
  assert.equal(bytes[24], 7); assert.equal(bytes[4], 0xa5);
});
test('out-of-order blocks assemble by sequence and exact duplicates are idempotent', () => {
  const a = chunk(10, [1, 2]), b = chunk(11, [3]), c = chunk(12, [4, 5], true);
  const out = assembleMhxxStreamChunks([c, a, b, a], profile, 10);
  assert.deepEqual(out.payload, Buffer.from([1, 2, 3, 4, 5]));
  assert.equal(out.headers.length, 3);
  out.headers[0].fill(0); out.payload.fill(0);
  assert.equal(a[24], 1); assert.equal(a[4], 0xa5);
});
test('missing or premature terminal and sequence gaps cannot produce a message', () => {
  for (const blocks of [[chunk(1, [1])], [chunk(1, [], true), chunk(2, [], true)],
    [chunk(2, [], true)], [chunk(1, []), chunk(3, [], true)]]) {
    assert.throws(() => assembleMhxxStreamChunks(blocks, profile, 1), /gap|terminal/);
  }
});
test('conflicting duplicate, ack-only block and wrapped sequence are rejected', () => {
  assert.throws(() => assembleMhxxStreamChunks([chunk(1, [1], true), chunk(1, [2], true)], profile, 1), /duplicate/);
  const ack = chunk(1, [], true); ack.writeUInt16BE(2, 0);
  assert.throws(() => assembleMhxxStreamChunks([ack], profile, 1), /not_data/);
  assert.throws(() => assembleMhxxStreamChunks([chunk(0, [], true)], profile, 0xffffffff), /wrapped/);
});
test('strict profile, input length and caller batch limits are enforced', () => {
  for (const bytes of [null, [], Buffer.alloc(23), Buffer.alloc(25)]) {
    assert.throws(() => decodeMhxxStreamChunk(bytes, profile));
  }
  assert.throws(() => decodeMhxxStreamChunk(chunk(0, [], true), 'mhgu-v262144'), /profile/);
  for (const start of [-1, 0x100000000, NaN, undefined]) {
    assert.throws(() => assembleMhxxStreamChunks([chunk(0, [], true)], profile, start), /start_sequence/);
  }
  assert.throws(() => assembleMhxxStreamChunks([], profile, 0), /count/);
  assert.throws(() => assembleMhxxStreamChunks(Array(65).fill(chunk(0, [], true)), profile, 0), /count/);
  assert.throws(() => assembleMhxxStreamChunks(Array.from({length: 17}, (_, i) => chunk(i, Buffer.alloc(65535), i === 16)), profile, 0), /byte_limit/);
});
test('empty terminal message and maximum sequence are representable without wrap', () => {
  const out = assembleMhxxStreamChunks([chunk(0xffffffff, [], true)], profile, 0xffffffff);
  assert.equal(out.payload.length, 0);
  assert.equal(out.headers.length, 1);
});
