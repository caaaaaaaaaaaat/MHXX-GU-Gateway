import assert from 'node:assert/strict';
import test from 'node:test';
import { translateMhBasePeerDescriptorEndpoint, translateMhBasePeerListEndpoints } from './mh-base-peer-list-endpoints.mjs';
import { MhIdentityMap } from './mh-identity.mjs';
import { deriveMhxxUdsEndpoint, encodeMhxxEndpoint } from './mhxx-endpoint.mjs';
import { encodeMhStreamMessage, recoverMhPeerListFromMessages } from './mh-system-stream.mjs';

const profiles = ['mhxx-1.4', 'mhgu-v262144'];
function setup(profile = profiles[0]) {
  const identityMap = new MhIdentityMap('room');
  const peers = Array.from({length: 4}, (_, index) => {
    const seed = Buffer.alloc(8, index + 1), gu = Buffer.from([10, 2, 3, index + 1]);
    identityMap.bind('room', seed, gu);
    const xx = encodeMhxxEndpoint(deriveMhxxUdsEndpoint(seed)).subarray(0, 4);
    return { from: profile === profiles[0] ? xx : gu, to: profile === profiles[0] ? gu : xx };
  });
  return { options: { profile, endpointBranch: 'base-first-endpoint-a', identityMap, sessionId: 'room' }, peers };
}
// Hand-laid wire fixture: not built using the list or descriptor encoders.
function body(peers, variant = 1, { slot = 0, start = 0, total = peers.length } = {}) {
  const bytes = Buffer.alloc(12 + peers.length * 72);
  Buffer.from('20007ec91234567801998877', 'hex').copy(bytes);
  bytes[1] = total; bytes[8] = variant;
  if (variant === 2) { bytes[9] = slot; bytes[10] = peers.length; bytes[11] = start; }
  peers.forEach((peer, index) => {
    const offset = 12 + index * 72;
    for (let j = 0; j < 72; j++) bytes[offset + j] = (j * 17 + index * 37) & 255;
    peer.from.copy(bytes, offset); bytes.writeUInt16BE(12345, offset + 4);
    // Embed the SAME source address at opaque words and other endpoints too;
    // their provenance is unknown, so matching bytes must not cause replacement.
    for (const word of [18, 29, 35, 53, 64]) peer.from.copy(bytes, offset + word);
  });
  return bytes;
}
function expectedBody(input, peers) {
  const expected = Buffer.from(input);
  peers.forEach((peer, index) => peer.to.copy(expected, 12 + index * 72));
  return expected;
}

test('descriptor conversion changes only selected base endpoint, in both directions', () => {
  for (const profile of profiles) {
    const {options, peers} = setup(profile);
    const descriptor = body(peers.slice(0, 1)).subarray(12, 82), before = Buffer.from(descriptor);
    const result = translateMhBasePeerDescriptorEndpoint(descriptor, options);
    const expected = Buffer.from(before); peers[0].to.copy(expected);
    assert.deepEqual(result.bytes, expected);
    assert.equal(result.profile, profiles.find(value => value !== profile));
    assert.equal(result.applicationConverted, false);
    assert.deepEqual(result.bytes.subarray(4), before.subarray(4));
    result.bytes.fill(0); assert.deepEqual(descriptor, before);
  }
});

test('full list maps all four selected endpoints but preserves every other byte and roundtrips', () => {
  for (const profile of profiles) {
    const {options, peers} = setup(profile), input = body(peers), before = Buffer.from(input);
    const result = translateMhBasePeerListEndpoints(input, options);
    assert.deepEqual(result.bytes, expectedBody(input, peers));
    assert.equal(result.applicationConverted, false);
    const reverse = translateMhBasePeerListEndpoints(result.bytes, {...options, profile: result.profile});
    assert.deepEqual(reverse.bytes, before);
    result.bytes.fill(0); assert.deepEqual(input, before);
    assert.equal(options.identityMap.size, 4);
  }
});

test('variant2 converts only local entries, retaining both fragment slots/count/start/header', () => {
  for (const profile of profiles) {
    const {options, peers} = setup(profile);
    for (const slot of [0, 1]) {
      const local = peers.slice(slot * 2, slot * 2 + 2);
      const input = body(local, 2, {slot, start: slot * 2, total: 4});
      const result = translateMhBasePeerListEndpoints(input, options);
      assert.deepEqual(result.bytes, expectedBody(input, local));
      assert.deepEqual(result.bytes.subarray(0, 12), input.subarray(0, 12));
      assert.equal(result.applicationConverted, false);
    }
  }
});

test('empty lists and empty fragments still reject missing branch, bad map, profile or stale session', () => {
  const {options} = setup();
  for (const input of [body([]), body([], 2), body([], 2, {slot: 1, start: 2, total: 2})]) {
    assert.deepEqual(translateMhBasePeerListEndpoints(input, options).bytes, input);
    for (const endpointBranch of [undefined, 'derived', true]) {
      assert.throws(() => translateMhBasePeerListEndpoints(input, {...options, endpointBranch}), /explicit_branch/);
    }
    assert.throws(() => translateMhBasePeerListEndpoints(input, {...options, identityMap: {}}), /identity_map/);
    assert.throws(() => translateMhBasePeerListEndpoints(input, {...options, sessionId: 'stale'}), /session_mismatch/);
    assert.throws(() => translateMhBasePeerListEndpoints(input, {...options, profile: 'mhxx'}), /profile/);
  }
});

test('late unknown identity, zero address or invalid port rejects whole list without side effects', () => {
  for (const profile of profiles) {
    const {options, peers} = setup(profile), valid = body(peers);
    for (const mutate of [
      bytes => bytes.writeUInt32BE(0x11223344, 12 + 3 * 72),
      bytes => bytes.writeUInt32BE(0, 12 + 3 * 72),
      bytes => bytes.writeUInt16BE(12344, 12 + 3 * 72 + 4),
    ]) {
      const input = Buffer.from(valid); mutate(input); const before = Buffer.from(input);
      assert.throws(() => translateMhBasePeerListEndpoints(input, options), /unmapped|port12345/);
      assert.deepEqual(input, before);
      assert.equal(options.identityMap.size, 4);
      assert.deepEqual(translateMhBasePeerListEndpoints(valid, options).bytes, expectedBody(valid, peers));
    }
    options.identityMap.reset('next');
    assert.throws(() => translateMhBasePeerListEndpoints(valid, options), /session_mismatch/);
    assert.throws(() => translateMhBasePeerListEndpoints(valid, {...options, sessionId: 'next'}), /unmapped/);
  }
});

test('strict body, descriptor and fragment bounds reject rather than guess or truncate', () => {
  const {options, peers} = setup(), full = body(peers.slice(0, 1));
  for (const input of [null, [], new Uint8Array(full), Buffer.alloc(11), full.subarray(0, -1), Buffer.concat([full, Buffer.alloc(1)])]) {
    assert.throws(() => translateMhBasePeerListEndpoints(input, options));
  }
  for (const [offset, value] of [[0, 0x21], [8, 0], [8, 3], [1, 2]]) {
    const input = Buffer.from(full); input[offset] = value;
    assert.throws(() => translateMhBasePeerListEndpoints(input, options));
  }
  for (const [offset, value] of [[9, 2], [10, 2], [11, 1]]) {
    const input = body(peers.slice(0, 1), 2); input[offset] = value;
    assert.throws(() => translateMhBasePeerListEndpoints(input, options));
  }
  for (const descriptor of [null, Buffer.alloc(69), Buffer.alloc(71)]) {
    assert.throws(() => translateMhBasePeerDescriptorEndpoint(descriptor, options));
  }
});

test('recovered source body can be partially mapped and reframed using explicit target stream headers', () => {
  for (const profile of profiles) {
    const {options, peers} = setup(profile), input = body(peers);
    const outerHeader = Buffer.alloc(20, 0x31), streamHeader = Buffer.alloc(24, 0x52);
    outerHeader.writeUInt32BE(0x12340001, 12);
    streamHeader.writeUInt16BE(3, 0); streamHeader.writeUInt32BE(40, 8);
    const source = encodeMhStreamMessage({outerHeader, streamHeader, payload: input}, profile, 0x12340001);
    const sourceBefore = Buffer.from(source);
    const recovered = recoverMhPeerListFromMessages([source], profile, 40, 0x12340001);
    const mapped = translateMhBasePeerListEndpoints(recovered.body, options);
    // Target headers are independent caller-owned state, NOT copied source state.
    const targetOuter = Buffer.alloc(20, 0x73), targetStream = Buffer.alloc(24, 0x94);
    targetOuter.writeUInt32BE(0x12340001, 12);
    targetStream.writeUInt16BE(3, 0); targetStream.writeUInt32BE(99, 8);
    const outerBefore = Buffer.from(targetOuter), streamBefore = Buffer.from(targetStream);
    const framed = encodeMhStreamMessage({outerHeader: targetOuter, streamHeader: targetStream, payload: mapped.bytes}, mapped.profile, 0x12340001);
    const target = recoverMhPeerListFromMessages([framed], mapped.profile, 99, 0x12340001);
    const expectedOuter = Buffer.from(targetOuter), expectedStream = Buffer.from(targetStream);
    expectedOuter.writeUInt16BE(24 + mapped.bytes.length, 2);
    expectedStream.writeUInt16BE(mapped.bytes.length, 2);
    assert.deepEqual(target.body, expectedBody(input, peers));
    assert.deepEqual(target.outerHeaders, [expectedOuter]);
    assert.deepEqual(target.streamHeaders, [expectedStream]);
    assert.notDeepEqual(target.outerHeaders, recovered.outerHeaders);
    assert.notDeepEqual(target.streamHeaders, recovered.streamHeaders);
    assert.deepEqual(source, sourceBefore);
    assert.deepEqual(targetOuter, outerBefore); assert.deepEqual(targetStream, streamBefore);
    assert.equal(mapped.applicationConverted, false);
  }
});
