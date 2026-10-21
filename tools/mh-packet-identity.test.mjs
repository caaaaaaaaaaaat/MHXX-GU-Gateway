import assert from 'node:assert/strict';
import test from 'node:test';
import { translateMhPacketStreamIdentities } from './mh-packet-identity.mjs';
import { decodeMhPacket, encodeMhPacket } from './mh-packet.mjs';
import { encodeMhStreamMessage } from './mh-system-stream.mjs';
import { MhIdentityMap } from './mh-identity.mjs';
import { deriveMhxxUdsEndpoint, encodeMhxxEndpoint } from './mhxx-endpoint.mjs';

const xx = 'mhxx-1.4', gu = 'mhgu-v262144', route = 0x10001;
const sourceKey = Buffer.alloc(16, 0x31), targetKey = Buffer.alloc(16, 0x42);
const seed = Buffer.from('0123456789abcdef', 'hex');
const xxId = encodeMhxxEndpoint(deriveMhxxUdsEndpoint(seed)).subarray(0, 4);
const guId = Buffer.from([192, 0, 2, 7]);
function header(mode = 1, tag = 0xa5) {
  const h = Buffer.alloc(12, tag); h.writeUInt32BE(0x32ab9864); h[4] = mode; return h;
}
function setup(profile = xx, mode = 1) {
  const identityMap = new MhIdentityMap('session'); identityMap.bind('session', seed, guId);
  return { profile, targetHeader: header(mode, 0xb6), expectedRouteKey: route, identityMap,
    sessionId: 'session', sourceKey, targetKey };
}
function message(profile, identity = profile === xx ? xxId : guId, payload = Buffer.from([0xde,0xad,0xbe,0xef,0x17])) {
  const outerHeader = Buffer.alloc(20, 0x73), streamHeader = Buffer.alloc(24, 0x51);
  identity.copy(outerHeader, 8); outerHeader.writeUInt32BE(route, 12);
  streamHeader.writeUInt16BE(3, 0);
  return encodeMhStreamMessage({outerHeader, streamHeader, payload}, profile, route);
}

test('identity-only packets map both directions and all mode combinations with distinct explicit keys', () => {
  for (const profile of [xx, gu]) for (const inMode of [1,2]) for (const outMode of [1,2]) {
    const options = setup(profile, outMode), input = message(profile);
    const source = encodeMhPacket({header: header(inMode), messages: [input]}, profile, sourceKey);
    const before = Buffer.from(source), headerBefore = Buffer.from(options.targetHeader);
    const result = translateMhPacketStreamIdentities(source, options);
    const target = profile === xx ? gu : xx;
    assert.equal(result.profile, target); assert.equal(result.applicationConverted, false);
    const parsed = decodeMhPacket(result.bytes, target, targetKey);
    assert.deepEqual(parsed.header, options.targetHeader);
    const expected = Buffer.from(input); (profile === xx ? guId : xxId).copy(expected, 8);
    assert.deepEqual(parsed.messages, [expected]);
    assert.deepEqual(source, before); assert.deepEqual(options.targetHeader, headerBefore);
    const restored = translateMhPacketStreamIdentities(result.bytes, {
      ...options, profile: target, targetHeader: header(inMode), sourceKey: targetKey, targetKey: sourceKey,
    });
    assert.deepEqual(decodeMhPacket(restored.bytes, profile, sourceKey).messages, [input]);
    // AES padding is not stripped when converting mode2 to mode1.
    if (inMode === 2 && outMode === 1) assert.ok(parsed.trailer.length > 0);
  }
});

test('multiple stream messages, zero identity and opaque trailer remain byte-preserved except mapped identity', () => {
  const options = setup();
  const messages = [message(xx), message(xx, Buffer.alloc(4))];
  const trailer = Buffer.from([255, 1, 0, 77]);
  const source = encodeMhPacket({header: header(), messages, trailer}, xx);
  const parsed = decodeMhPacket(translateMhPacketStreamIdentities(source, options).bytes, gu);
  assert.deepEqual(parsed.trailer, trailer); assert.deepEqual(parsed.messages[1], messages[1]);
  const expected = Buffer.from(messages[0]); guId.copy(expected, 8);
  assert.deepEqual(parsed.messages[0], expected); assert.equal(options.identityMap.size, 1);
});

test('empty and sentinel-only packets still require valid session, map, route and target header', () => {
  for (const trailer of [Buffer.alloc(0), Buffer.from([255, 0])]) {
    const source = encodeMhPacket({header: header(), messages: [], trailer}, xx);
    const options = setup();
    assert.deepEqual(decodeMhPacket(translateMhPacketStreamIdentities(source, options).bytes, gu).trailer, trailer);
    assert.throws(() => translateMhPacketStreamIdentities(source, {...options, sessionId: 'old'}), /session_mismatch/);
    assert.throws(() => translateMhPacketStreamIdentities(source, {...options, identityMap: {}}), /identity_map/);
    assert.throws(() => translateMhPacketStreamIdentities(source, {...options, expectedRouteKey: undefined}), /identity_route/);
    assert.throws(() => translateMhPacketStreamIdentities(source, {...options, targetHeader: undefined}), /header12/);
    assert.throws(() => translateMhPacketStreamIdentities(source, {...options, profile: 'unknown'}), /identity_profile/);
  }
});

test('mixed routes, unmapped identities and non-stream messages fail without input or map mutation', () => {
  const options = setup();
  const badRoute = message(xx); badRoute.writeUInt32BE(route+1, 12);
  const badIdentity = message(xx, Buffer.from([1,2,3,4]));
  const nonStream = Buffer.alloc(20); nonStream.writeUInt32BE(route,12);
  for (const bad of [badRoute, badIdentity, nonStream]) {
    const source = encodeMhPacket({header: header(), messages: [message(xx), bad]}, xx);
    const before = Buffer.from(source);
    assert.throws(() => translateMhPacketStreamIdentities(source, options));
    assert.deepEqual(source, before); assert.equal(options.identityMap.size, 1);
    assert.deepEqual(options.identityMap.translate('session','mhxx-to-mhgu',xxId),guId);
  }
  options.identityMap.reset('new');
  const source = encodeMhPacket({header: header(), messages: [message(xx)]},xx);
  assert.throws(() => translateMhPacketStreamIdentities(source, options), /session_mismatch/);
  assert.throws(() => translateMhPacketStreamIdentities(source, {...options,sessionId:'new'}), /unmapped/);
});

test('mode2 key/alignment and target block capacity are enforced without fallback', () => {
  const options = setup(xx,2);
  const source = encodeMhPacket({header: header(2),messages:[message(xx)]},xx,sourceKey);
  assert.throws(() => translateMhPacketStreamIdentities(source,{...options,sourceKey:undefined}),/key16/);
  assert.throws(() => translateMhPacketStreamIdentities(source,{...options,targetKey:undefined}),/key16/);
  assert.throws(() => translateMhPacketStreamIdentities(source.subarray(0,source.length-1),options),/alignment/);
  // A single valid GU-sized stream payload fills a mode1 packet's 1460 body;
  // rounding it to AES blocks exceeds the target's 1456 aligned capacity.
  const full = encodeMhPacket({header:header(),messages:[message(xx,xxId,Buffer.alloc(1416))]},xx);
  assert.equal(full.length,1472);
  assert.throws(() => translateMhPacketStreamIdentities(full,options),/body_limit/);
  assert.equal(translateMhPacketStreamIdentities(full,{...options,targetHeader:header()}).bytes.length,1472);
});
