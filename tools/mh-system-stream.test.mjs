import assert from 'node:assert/strict';
import test from 'node:test';
import { recoverMhPeerListFromStream, recoverMhPeerListFromMessages, encodeMhStreamMessage, translateMhStreamMessageIdentity } from './mh-system-stream.mjs';
import { MhIdentityMap } from './mh-identity.mjs';
import { deriveMhxxUdsEndpoint, encodeMhxxEndpoint } from './mhxx-endpoint.mjs';
import { encodeMhStreamChunk } from './mh-stream-chunk.mjs';
import { encodeMhPeerListBody } from './mh-peer-list.mjs';
import { decodeMhPeerDescriptor } from './mh-peer-descriptor.mjs';
import { encodeMhPeerListFragment } from './mh-peer-list-fragment.mjs';
const profiles = ['mhxx-1.4', 'mhgu-v262144'];

test('identity translation maps original sender and preserves route, ACK, body and padding', () => {
  const map = new MhIdentityMap('room-a');
  const seed = Buffer.from('0102030405060708', 'hex'), gu = Buffer.from('0a010203', 'hex');
  map.bind('room-a', seed, gu);
  const xx = encodeMhxxEndpoint(deriveMhxxUdsEndpoint(seed)).subarray(0, 4);
  for (const profile of profiles) {
    const source = messages(profile);
    const identity = profile === profiles[0] ? xx : gu;
    const expected = profile === profiles[0] ? gu : xx;
    const translated = source.map(message => {
      identity.copy(message, 8);
      const before = Buffer.from(message);
      const output = translateMhStreamMessageIdentity(message, profile, 0x12340001, map, 'room-a');
      assert.equal(output.profile, profile === profiles[0] ? profiles[1] : profiles[0]);
      assert.deepEqual(output.bytes.subarray(8, 12), expected);
      assert.deepEqual(output.bytes.subarray(0, 8), before.subarray(0, 8));
      assert.deepEqual(output.bytes.subarray(12), before.subarray(12));
      output.bytes[0] ^= 1; assert.deepEqual(message, before); output.bytes[0] ^= 1;
      return output.bytes;
    });
    const recovered = recoverMhPeerListFromMessages(translated, profile === profiles[0] ? profiles[1] : profiles[0], 40, 0x12340001);
    assert.deepEqual(recovered.body, full(profile));
  }
});

test('identity translation rejects stale sessions, unknown senders and incorrect routes', () => {
  const map = new MhIdentityMap('new-room'), message = messages(profiles[0])[0];
  assert.throws(() => translateMhStreamMessageIdentity(message, profiles[0], 0x12340001, map, 'old-room'), /session_mismatch/);
  assert.throws(() => translateMhStreamMessageIdentity(message, profiles[0], 0x12340001, map, 'new-room'), /unmapped/);
  assert.throws(() => translateMhStreamMessageIdentity(message, profiles[0], 2, map, 'new-room'), /route_mismatch/);
  assert.throws(() => translateMhStreamMessageIdentity(message, 'unknown', 0x12340001, map, 'new-room'), /profile/);
  assert.throws(() => translateMhStreamMessageIdentity(message, profiles[0], 0x12340001, {}, 'new-room'), /identity_map/);
  message.fill(0, 8, 12);
  assert.equal(translateMhStreamMessageIdentity(message, profiles[0], 0x12340001, map, 'new-room').bytes.readUInt32BE(8), 0);
  assert.throws(() => translateMhStreamMessageIdentity(message, profiles[0], 0x12340001, map), /session_mismatch/);
});

test('identity translation refuses blocks exceeding target capacity and malformed framing', () => {
  const map = new MhIdentityMap('room');
  const outerHeader = Buffer.alloc(20), streamHeader = Buffer.alloc(24);
  const tooLarge = encodeMhStreamMessage({outerHeader, streamHeader, payload: Buffer.alloc(1417)}, profiles[0], 0);
  assert.throws(() => translateMhStreamMessageIdentity(tooLarge, profiles[0], 0, map, 'room'));
  const message = messages(profiles[0])[0];
  assert.throws(() => translateMhStreamMessageIdentity(message.subarray(0, message.length - 1), profiles[0], 0x12340001, map, 'room'), /outer_length/);
  message[0] = 255;
  assert.throws(() => translateMhStreamMessageIdentity(message, profiles[0], 0x12340001, map, 'room'), /outer_message/);
});
function full(profile) {
  const header = Buffer.alloc(12); header[0] = 0x20; header[1] = 1; header[8] = 1;
  return encodeMhPeerListBody({ header, entries: [{ descriptor: decodeMhPeerDescriptor(Buffer.alloc(70, 7), profile),
    number: 3, trailingByte: 0xa5 }] }, profile);
}
function blocks(body, profile) {
  const cut = 17;
  return [body.subarray(0, cut), body.subarray(cut)].map((payload, i) => {
    const header = Buffer.alloc(24, 0x55); header.writeUInt16BE(i === 1 ? 3 : 1, 0);
    header.writeUInt32BE(40 + i, 8);
    return encodeMhStreamChunk({header, payload}, profile);
  });
}
test('both profiles recover shuffled stream blocks before full-list decoding', () => {
  for (const profile of profiles) {
    const body = full(profile), chunks = blocks(body, profile);
    const result = recoverMhPeerListFromStream(chunks.toReversed(), profile, 40);
    assert.equal(result.kind, 'peer-list');
    assert.deepEqual(result.body, body);
    assert.equal(result.list.entries[0].number, 3);
    assert.equal(result.list.entries[0].trailingByte, 0xa5);
    result.body.fill(0); result.streamHeaders[0].fill(0);
    assert.equal(result.list.header[0], 0x20);
    assert.equal(chunks[0].readUInt32BE(8), 40);
  }
});
test('list variant2 remains a separate fragment after transport assembly', () => {
  for (const profile of profiles) {
    const header = Buffer.alloc(12); header[0] = 0x20; header[1] = 1; header[8] = 2; header[10] = 1;
    const entries = [{ descriptor: decodeMhPeerDescriptor(Buffer.alloc(70), profile), number: 2, trailingByte: 0 }];
    const body = encodeMhPeerListFragment({header, entries}, profile);
    const result = recoverMhPeerListFromStream(blocks(body, profile), profile, 40);
    assert.equal(result.kind, 'peer-list-fragment');
    assert.equal(result.fragment.header[8], 2);
    assert.equal(result.fragment.entries.length, 1);
    assert.equal(result.list, undefined);
  }
});
test('incomplete transport and malformed system body never reach successful list output', () => {
  for (const profile of profiles) {
    const body = full(profile), chunks = blocks(body, profile);
    assert.throws(() => recoverMhPeerListFromStream([chunks[0]], profile, 40), /terminal/);
    for (const malformed of [body.subarray(0, 11), body.subarray(0, 83)]) {
      assert.throws(() => recoverMhPeerListFromStream(blocks(malformed, profile), profile, 40));
    }
    const wrong = Buffer.from(body); wrong[0] = 0x21;
    assert.throws(() => recoverMhPeerListFromStream(blocks(wrong, profile), profile, 40), /unsupported_type/);
    wrong[0] = 0x20; wrong[8] = 3;
    assert.throws(() => recoverMhPeerListFromStream(blocks(wrong, profile), profile, 40), /variant/);
  }
});
test('pipeline retains strict profile and explicit starting sequence', () => {
  const chunks = blocks(full(profiles[0]), profiles[0]);
  assert.throws(() => recoverMhPeerListFromStream(chunks, 'unknown', 40), /profile/);
  assert.throws(() => recoverMhPeerListFromStream(chunks, profiles[0]), /start_sequence/);
});

function messages(profile) {
  return blocks(full(profile), profile).map(body => {
    const message = Buffer.alloc(Math.ceil((20 + body.length) / 4) * 4, 0xa5);
    message[0] = 1; message.writeUInt16BE(body.length, 2); message.writeUInt32BE(0x12340001, 12);
    body.copy(message, 20);
    return message;
  });
}

test('rebuilt messages preserve identities, route and ACK fields through list recovery', () => {
  for (const profile of profiles) {
    const originals = messages(profile);
    const rebuilt = originals.map(original => {
      const outerHeader = Buffer.from(original.subarray(0, 20));
      const streamHeader = Buffer.from(original.subarray(20, 44));
      const payload = Buffer.from(original.subarray(44, 20 + original.readUInt16BE(2)));
      const before = [outerHeader, streamHeader, payload].map(value => Buffer.from(value));
      outerHeader.writeUInt16BE(0, 2);
      const output = encodeMhStreamMessage({outerHeader, streamHeader, payload}, profile, 0x12340001);
      assert.equal(output.readUInt16BE(2), 24 + payload.length);
      assert.deepEqual(output.subarray(4, 20), before[0].subarray(4));
      assert.deepEqual(output.subarray(24, 44), before[1].subarray(4));
      assert.ok(output.subarray(44 + payload.length).every(value => value === 0));
      output[8] ^= 1;
      assert.deepEqual(streamHeader, before[1]); assert.deepEqual(payload, before[2]);
      assert.equal(outerHeader[8], before[0][8]);
      output[8] ^= 1;
      return output;
    });
    assert.deepEqual(recoverMhPeerListFromMessages(rebuilt, profile, 40, 0x12340001).body, full(profile));
  }
});

test('output rejects missing route, sentinel, profile limits and outer length overflow', () => {
  const outerHeader = Buffer.alloc(20); outerHeader.writeUInt32BE(1, 12);
  const streamHeader = Buffer.alloc(24), payload = Buffer.alloc(0);
  const input = {outerHeader, streamHeader, payload};
  assert.throws(() => encodeMhStreamMessage(input, profiles[0]), /expected_route/);
  assert.throws(() => encodeMhStreamMessage(input, profiles[0], 2), /route_mismatch/);
  assert.throws(() => encodeMhStreamMessage(input, 'unknown', 1), /profile/);
  assert.throws(() => encodeMhStreamMessage({...input, outerHeader: Buffer.alloc(19)}, profiles[0], 1), /outer_message/);
  const sentinel = Buffer.from(outerHeader); sentinel[0] = 255;
  assert.throws(() => encodeMhStreamMessage({...input, outerHeader: sentinel}, profiles[0], 1), /outer_message/);
  assert.throws(() => encodeMhStreamMessage({...input, payload: Buffer.alloc(1417)}, profiles[1], 1));
  assert.throws(() => encodeMhStreamMessage({...input, payload: Buffer.alloc(65512)}, profiles[0], 1), /outer_length/);
  const maximum = encodeMhStreamMessage({...input, payload: Buffer.alloc(65511)}, profiles[0], 1);
  assert.equal(maximum.readUInt16BE(2), 65535);
  assert.equal(maximum.length, 65556);
});
test('aligned outer messages filter route before nested recovery and preserve identity/header', () => {
  for (const profile of profiles) {
    const input = messages(profile), before = input.map(value => Buffer.from(value));
    const output = recoverMhPeerListFromMessages(input, profile, 40, 0x12340001);
    assert.equal(output.list.entries[0].number, 3);
    assert.equal(output.outerHeaders[0].readUInt32BE(8), 0xa5a5a5a5);
    output.outerHeaders[0].fill(0); output.body.fill(0);
    assert.deepEqual(input, before);
  }
});
test('outer boundary rejects mixed routes, missing route, sentinel and alignment truncation', () => {
  const profile = profiles[0], input = messages(profile);
  const changed = input.map(value => Buffer.from(value)); changed[1].writeUInt32BE(1, 12);
  assert.throws(() => recoverMhPeerListFromMessages(changed, profile, 40, 0x12340001), /route_mismatch/);
  assert.throws(() => recoverMhPeerListFromMessages(input, profile, 40), /expected_route/);
  const sentinel = Buffer.from(input[0]); sentinel[0] = 255;
  assert.throws(() => recoverMhPeerListFromMessages([sentinel], profile, 40, 0x12340001), /outer_message/);
  assert.throws(() => recoverMhPeerListFromMessages([input[0].subarray(0, input[0].length - 1)], profile, 40, 0x12340001), /outer_length/);
});
