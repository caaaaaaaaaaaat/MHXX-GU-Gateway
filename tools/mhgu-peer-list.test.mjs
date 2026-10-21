import assert from 'node:assert/strict';
import test from 'node:test';
import { decodeMhguPeerListBody, encodeMhguPeerListBody } from './mhgu-peer-list.mjs';
import { decodeMhPeerListBody, encodeMhPeerListBody } from './mh-peer-list.mjs';

test('shared exact-body list codec preserves every byte across both explicit profiles', () => {
  for (const count of [0, 1, 4, 255]) {
    const bytes = golden(count);
    bytes[0] = 0x20;
    for (const from of ['mhxx-1.4', 'mhgu-v262144']) {
      for (const to of ['mhxx-1.4', 'mhgu-v262144']) {
        const decoded = decodeMhPeerListBody(bytes, from);
        const encoded = encodeMhPeerListBody(decoded, to);
        assert.deepEqual(encoded, bytes);
        encoded.fill(0);
        assert.deepEqual(encodeMhPeerListBody(decoded, to), bytes);
      }
    }
  }
});

test('shared list codec requires an exact known profile and retains strict body bounds', () => {
  for (const profile of [undefined, null, '', 'mhxx', 'mhgu', {}, 'mhxx-1.5']) {
    assert.throws(() => decodeMhPeerListBody(golden(1), profile), /unsupported_mh_peer_list_profile/);
    assert.throws(() => encodeMhPeerListBody({}, profile), /unsupported_mh_peer_list_profile/);
  }
  for (const profile of ['mhxx-1.4', 'mhgu-v262144']) {
    assert.throws(() => decodeMhPeerListBody(golden(1).subarray(0, -1), profile), /length_mismatch/);
    assert.throws(() => decodeMhPeerListBody(Buffer.concat([golden(1), Buffer.alloc(1)]), profile), /length_mismatch/);
    const fragmented = golden(1);
    fragmented[8] = 2;
    assert.throws(() => decodeMhPeerListBody(fragmented, profile), /unsupported/);
  }
});

function golden(count) {
  const body = Buffer.alloc(12 + count * 72);
  Buffer.from('a5007e001234567801998877', 'hex').copy(body);
  body[1] = count;
  for (let i = 0; i < count; i++) {
    const offset = 12 + 72 * i;
    for (let j = 0; j < 70; j++) body[offset + j] = (i * 13 + j) & 255;
    body[offset + 70] = i;
    body[offset + 71] = 255 - i;
  }
  return body;
}

test('GU full list respects 12-byte header, 72-byte stride and separate number/trailing byte', () => {
  for (const count of [0, 1, 4, 255]) {
    const body = golden(count);
    const decoded = decodeMhguPeerListBody(body);
    assert.equal(decoded.entries.length, count);
    for (let i = 0; i < count; i++) {
      assert.equal(decoded.entries[i].number, i);
      assert.equal(decoded.entries[i].trailingByte, 255 - i);
      assert.equal(decoded.entries[i].descriptor[0].opaqueFields[0], (i * 13 + 6) & 255);
    }
    assert.deepEqual(encodeMhguPeerListBody(decoded), body);
  }
});

test('GU full list rejects fragments, inconsistent lengths/counts and invalid entries', () => {
  for (const variant of [0, 2, 255]) {
    const body = golden(1); body[8] = variant;
    assert.throws(() => decodeMhguPeerListBody(body), /variant/);
  }
  for (const body of [Buffer.alloc(11), null, new Uint8Array(12)]) {
    assert.throws(() => decodeMhguPeerListBody(body));
  }
  for (const body of [golden(1).subarray(0, 83), Buffer.concat([golden(1), Buffer.alloc(1)])]) {
    assert.throws(() => decodeMhguPeerListBody(body), /length_mismatch/);
  }
  const decoded = decodeMhguPeerListBody(golden(1));
  decoded.header[1] = 2;
  assert.throws(() => encodeMhguPeerListBody(decoded), /count/);
  decoded.header[1] = 1;
  for (const value of [-1, 256, 1.5, '1']) {
    decoded.entries[0].number = value;
    assert.throws(() => encodeMhguPeerListBody(decoded), /entry/);
  }
});

test('GU full list preserves unknown bytes and isolates input and output storage', () => {
  const body = golden(1), expected = Buffer.from(body);
  const decoded = decodeMhguPeerListBody(body);
  body.fill(0);
  assert.deepEqual(encodeMhguPeerListBody(decoded), expected);
  const output = encodeMhguPeerListBody(decoded);
  output.fill(0);
  assert.deepEqual(encodeMhguPeerListBody(decoded), expected);
  decoded.entries[0].number = 253;
  expected[82] = 253;
  assert.deepEqual(encodeMhguPeerListBody(decoded), expected);
});
