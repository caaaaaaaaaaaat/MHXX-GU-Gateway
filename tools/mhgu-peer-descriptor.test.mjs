import assert from 'node:assert/strict';
import test from 'node:test';
import { decodeMhguPeerDescriptor, encodeMhguPeerDescriptor } from './mhgu-peer-descriptor.mjs';
import { decodeMhPeerDescriptor, encodeMhPeerDescriptor } from './mh-peer-descriptor.mjs';

// Independent literal layout: 6 + 23 + 6, repeated. No game data.
const golden = Buffer.from(
  '010203043039' + '000102030405060708090a0b0c0d0e0f10111213141516' + 'c0a801020102' +
  '000000000000' + 'ffeeddccbbaa99887766554433221100a1b2c3d4e5f607' + 'ffffffffffff', 'hex');

test('explicit MHXX/GU profiles share framing and preserve all four endpoints and opaque bytes', () => {
  for (const source of ['mhxx-1.4', 'mhgu-v262144']) {
    for (const target of ['mhxx-1.4', 'mhgu-v262144']) {
      const decoded = decodeMhPeerDescriptor(golden, source);
      assert.deepEqual(encodeMhPeerDescriptor(decoded, target), golden);
    }
  }
  const xx = decodeMhPeerDescriptor(golden, 'mhxx-1.4');
  const gu = decodeMhPeerDescriptor(golden, 'mhgu-v262144');
  xx[0].opaqueFields.fill(0);
  assert.equal(gu[0].opaqueFields[1], 1);
});

test('shared descriptor interface rejects unspecified or unsupported game profiles', () => {
  for (const profile of [undefined, null, '', 'mhxx', 'mhgu', 'mhxx-1.3']) {
    assert.throws(() => decodeMhPeerDescriptor(golden, profile), /unsupported/);
    assert.throws(() => encodeMhPeerDescriptor([], profile), /unsupported/);
  }
  assert.throws(() => decodeMhPeerDescriptor(Buffer.alloc(71), 'mhxx-1.4'), /70_bytes/);
});

test('GU descriptor decodes four distinct endpoint slots and preserves opaque fields exactly', () => {
  const records = decodeMhguPeerDescriptor(golden);
  assert.equal(golden.length, 70);
  assert.deepEqual(records.map(r => [r.endpointA, r.endpointB]), [
    [{ address: '1.2.3.4', port: 12345 }, { address: '192.168.1.2', port: 258 }],
    [{ address: '0.0.0.0', port: 0 }, { address: '255.255.255.255', port: 65535 }],
  ]);
  assert.equal(records[0].opaqueFields.toString('hex'), '000102030405060708090a0b0c0d0e0f10111213141516');
  assert.equal(records[1].opaqueFields.toString('hex'), 'ffeeddccbbaa99887766554433221100a1b2c3d4e5f607');
  assert.deepEqual(encodeMhguPeerDescriptor(records), golden);
});

test('descriptor rejects truncated, trailing and malformed structures without changing caller data', () => {
  for (const value of [Buffer.alloc(69), Buffer.alloc(71), Buffer.alloc(0), new Uint8Array(70), null]) {
    assert.throws(() => decodeMhguPeerDescriptor(value), /70_bytes/);
  }
  for (const value of [[], Array(1), Array(2), Array(3), null]) {
    assert.throws(() => encodeMhguPeerDescriptor(value));
  }
  const records = decodeMhguPeerDescriptor(golden);
  records[1].endpointB.port = 65536;
  assert.throws(() => encodeMhguPeerDescriptor(records), /invalid_mhxx_endpoint/);
  assert.equal(records[0].opaqueFields.length, 23);
  records[1].opaqueFields = Buffer.alloc(22);
  assert.throws(() => encodeMhguPeerDescriptor(records), /23_opaque/);
});

test('descriptor buffers are isolated and endpoint edits preserve every unrelated byte', () => {
  const input = Buffer.from(golden);
  const records = decodeMhguPeerDescriptor(input);
  input.fill(0);
  assert.deepEqual(encodeMhguPeerDescriptor(records), golden);
  records[1].endpointA = { address: '10.20.30.40', port: 5678 };
  const output = encodeMhguPeerDescriptor(records);
  const expected = Buffer.from(golden);
  Buffer.from('0a141e28162e', 'hex').copy(expected, 35);
  assert.deepEqual(output, expected);
  output.fill(0);
  assert.equal(records[0].opaqueFields[1], 1);
  records[0].opaqueFields.fill(255);
  assert.equal(golden[7], 1);
});
