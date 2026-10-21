import assert from 'node:assert/strict';
import test from 'node:test';
import { encryptMhguPacketBody, decryptMhguPacketBody } from './mhgu-packet-transform.mjs';

const profile = 'mhgu-v262144';
// Public AES-128 ECB known-answer block (NIST SP800-38A F.1.1).
const key = Buffer.from('2b7e151628aed2a6abf7158809cf4f3c', 'hex');
const plaintext = Buffer.from('6bc1bee22e409f96e93d7e117393172a', 'hex');
const ciphertext = Buffer.from('3ad77bb40d7a3660a89ecaf32466ef97', 'hex');

test('GU body AES encrypt/decrypt matches independent known-answer block', () => {
  assert.deepEqual(encryptMhguPacketBody(plaintext, key, profile), ciphertext);
  assert.deepEqual(decryptMhguPacketBody(ciphertext, key, profile), plaintext);
});

test('GU uses independent blocks without implicit extra padding on aligned input', () => {
  const input = Buffer.concat([plaintext, plaintext]);
  assert.deepEqual(encryptMhguPacketBody(input, key, profile), Buffer.concat([ciphertext, ciphertext]));
  assert.equal(encryptMhguPacketBody(Buffer.alloc(0), key, profile).length, 0);
  assert.equal(decryptMhguPacketBody(Buffer.alloc(0), key, profile).length, 0);
});

test('partial bodies get FF fill and decryption retains sentinel and payload FF bytes', () => {
  for (const size of [1, 15, 17, 31, 1455]) {
    const body = Buffer.alloc(size, 0x41); body[size - 1] = 255;
    const encrypted = encryptMhguPacketBody(body, key, profile);
    const decrypted = decryptMhguPacketBody(encrypted, key, profile);
    assert.equal(encrypted.length, Math.ceil(size / 16) * 16);
    assert.deepEqual(decrypted.subarray(0, size), body);
    assert.ok(decrypted.subarray(size).every(value => value === 255));
    assert.equal(decrypted.length, encrypted.length);
  }
});

test('GU transform rejects incompatible profile, key, body and capacity boundaries', () => {
  for (const operation of [encryptMhguPacketBody, decryptMhguPacketBody]) {
    assert.throws(() => operation(plaintext, key, 'mhxx-1.4'), /profile/);
    assert.throws(() => operation(plaintext, Buffer.alloc(15), profile), /key16/);
    assert.throws(() => operation(plaintext, new Uint8Array(16), profile), /key16/);
    assert.throws(() => operation(new Uint8Array(16), key, profile), /body/);
    assert.throws(() => operation(Buffer.alloc(1457), key, profile), /body_limit/);
  }
  assert.throws(() => decryptMhguPacketBody(Buffer.alloc(15), key, profile), /alignment/);
  assert.equal(encryptMhguPacketBody(Buffer.alloc(1456), key, profile).length, 1456);
  assert.equal(decryptMhguPacketBody(Buffer.alloc(1456), key, profile).length, 1456);
});

test('GU transform keeps caller key and source independent from output', () => {
  const input = Buffer.from(plaintext), localKey = Buffer.from(key);
  const encrypted = encryptMhguPacketBody(input, localKey, profile);
  const decrypted = decryptMhguPacketBody(encrypted, localKey, profile);
  encrypted.fill(0); decrypted.fill(0);
  assert.deepEqual(input, plaintext); assert.deepEqual(localKey, key);
});
