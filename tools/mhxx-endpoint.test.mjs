import assert from 'node:assert/strict';
import test from 'node:test';
import {decodeMhxxEndpoint, encodeMhxxEndpoint, deriveMhxxUdsEndpoint} from './mhxx-endpoint.mjs';

test('local UDS endpoint matches independent Python zlib CRC-32 golden values', () => {
  for (const [seed, endpointHex] of [
    ['0000000000000000', '6522df693039'],
    ['0102030405060708', '3fca88c53039'],
    ['3132333435363738', '9ae0daaf3039'],
    ['ffffffffffffffff', '2144df1c3039'],
  ]) {
    const bytes = Buffer.from(seed, 'hex');
    assert.equal(encodeMhxxEndpoint(deriveMhxxUdsEndpoint(bytes)).toString('hex'), endpointHex);
    assert.equal(bytes.toString('hex'), seed);
  }
});

test('local seed derivation requires exactly the eight original memory-order bytes', () => {
  for (const value of [null, 1n, '0102030405060708', new Uint8Array(8), Buffer.alloc(7), Buffer.alloc(9)]) {
    assert.throws(() => deriveMhxxUdsEndpoint(value), /requires_eight_bytes/);
  }
  assert.notDeepEqual(deriveMhxxUdsEndpoint(Buffer.from('0102030405060708', 'hex')),
                     deriveMhxxUdsEndpoint(Buffer.from('0807060504030201', 'hex')));
});

test('endpoint uses independent IPv4 octets and a big-endian port', () => {
  const golden = Buffer.from('c0a801021234', 'hex');
  const endpoint = {address: '192.168.1.2', port: 4660};
  assert.deepEqual(decodeMhxxEndpoint(golden), endpoint);
  assert.deepEqual(encodeMhxxEndpoint(endpoint), golden);
  assert.equal(golden.toString('hex'), 'c0a801021234');
});

test('representation preserves zero and all-ones without imposing routing policy', () => {
  for (const [hex, endpoint] of [
    ['000000000000', {address: '0.0.0.0', port: 0}],
    ['ffffffffffff', {address: '255.255.255.255', port: 65535}],
    ['7f00000100ff', {address: '127.0.0.1', port: 255}],
  ]) {
    const bytes = Buffer.from(hex, 'hex');
    assert.deepEqual(decodeMhxxEndpoint(bytes), endpoint);
    assert.deepEqual(encodeMhxxEndpoint(endpoint), bytes);
  }
});

test('endpoint rejects short or trailing data rather than consuming a guessed prefix', () => {
  for (const value of [null, '010203040506', new Uint8Array(6), Buffer.alloc(5), Buffer.alloc(7)]) {
    assert.throws(() => decodeMhxxEndpoint(value), /requires_six_bytes/);
  }
});

test('encoder rejects ambiguous addresses and out-of-range ports without coercion', () => {
  for (const address of ['01.2.3.4', '256.0.0.1', '1.2.3', '1.2.3.4.5',
    '1.2.3.-1', '1.2.3.4 ', '1e1.2.3.4', '::1', '', '1.2.3.4\n']) {
    assert.throws(() => encodeMhxxEndpoint({address, port: 1}), /invalid_mhxx_endpoint/);
  }
  for (const port of [-1, 65536, 1.5, NaN, Infinity, '80', null]) {
    assert.throws(() => encodeMhxxEndpoint({address: '1.2.3.4', port}), /invalid_mhxx_endpoint/);
  }
  for (const value of [null, {}, {address: 123, port: 1}]) {
    assert.throws(() => encodeMhxxEndpoint(value), /invalid_mhxx_endpoint/);
  }
});
