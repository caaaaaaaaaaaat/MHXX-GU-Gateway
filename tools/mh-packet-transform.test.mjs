import assert from 'node:assert/strict';
import test from 'node:test';
import { encryptMhPacketBody, decryptMhPacketBody } from './mh-packet-transform.mjs';
import { encryptMhguPacketBody, decryptMhguPacketBody } from './mhgu-packet-transform.mjs';

const profiles = ['mhxx-1.4', 'mhgu-v262144'];
const key = Buffer.from('2b7e151628aed2a6abf7158809cf4f3c', 'hex');
const plain = Buffer.from('6bc1bee22e409f96e93d7e117393172a', 'hex');
const encrypted = Buffer.from('3ad77bb40d7a3660a89ecaf32466ef97', 'hex');

test('both fixed profiles match known-answer AES block and preserve GU API behavior', () => {
  for (const profile of profiles) {
    assert.deepEqual(encryptMhPacketBody(plain, key, profile), encrypted);
    assert.deepEqual(decryptMhPacketBody(encrypted, key, profile), plain);
  }
  assert.deepEqual(encryptMhguPacketBody(plain, key, profiles[1]), encrypted);
  assert.deepEqual(decryptMhguPacketBody(encrypted, key, profiles[1]), plain);
  assert.throws(() => encryptMhguPacketBody(plain, key, profiles[0]), /profile/);
});

test('cross-profile body transform retains FF padding and supports explicit distinct keys', () => {
  const body = Buffer.alloc(1455, 0x17), targetKey = Buffer.alloc(16, 0x55);
  const before = Buffer.from(body);
  const wireA = encryptMhPacketBody(body, key, profiles[0]);
  const decoded = decryptMhPacketBody(wireA, key, profiles[0]);
  const wireB = encryptMhPacketBody(decoded, targetKey, profiles[1]);
  const recovered = decryptMhPacketBody(wireB, targetKey, profiles[1]);
  assert.deepEqual(recovered.subarray(0, body.length), body);
  assert.equal(recovered.length, 1456); assert.equal(recovered[1455], 255);
  assert.notDeepEqual(wireA, wireB);
  recovered.fill(0); decoded.fill(0); assert.deepEqual(body, before);
});

test('shared transform validates both profiles and exact key/alignment/capacity constraints', () => {
  for (const profile of profiles) {
    for (const operation of [encryptMhPacketBody, decryptMhPacketBody]) {
      assert.throws(() => operation(plain, Buffer.alloc(17), profile), /key16/);
      assert.throws(() => operation(new Uint8Array(16), key, profile), /body/);
      assert.throws(() => operation(Buffer.alloc(1457), key, profile), /limit/);
    }
    assert.throws(() => decryptMhPacketBody(Buffer.alloc(17), key, profile), /alignment/);
    assert.equal(encryptMhPacketBody(Buffer.alloc(1456), key, profile).length, 1456);
  }
  assert.throws(() => encryptMhPacketBody(plain, key, 'unknown'), /profile/);
  assert.throws(() => decryptMhPacketBody(encrypted, key), /profile/);
});
