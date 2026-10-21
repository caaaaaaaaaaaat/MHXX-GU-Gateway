import assert from 'node:assert/strict';
import test from 'node:test';
import { decodeMhPacket, encodeMhPacket } from './mh-packet.mjs';
import { encodeMhStreamMessage, recoverMhPeerListFromMessages } from './mh-system-stream.mjs';

const profiles = ['mhxx-1.4', 'mhgu-v262144'];
const key = Buffer.alloc(16, 0x73);

test('hand-authored packet fixture decodes independently of encoder', () => {
  const wire = Buffer.from('32ab986401a5123456789abc' +
    '01020003112233445566778800010001aabbccdddeadbe7e' + 'ff000977', 'hex');
  for (const profile of profiles) {
    const parsed = decodeMhPacket(wire, profile);
    assert.deepEqual(parsed.messages, [Buffer.from('01020003112233445566778800010001aabbccdddeadbe7e','hex')]);
    assert.deepEqual(parsed.trailer, Buffer.from('ff000977','hex'));
    assert.deepEqual(encodeMhPacket(parsed, profile), wire);
    const body = Buffer.from(parsed.body); parsed.messages[0].fill(0); parsed.trailer.fill(0);
    assert.deepEqual(parsed.body, body);
  }
});

test('empty mode2, exact AES alignment and 73-message boundary are explicit', () => {
  for (const profile of profiles) {
    const empty = encodeMhPacket({header:header(2),messages:[]},profile,key);
    assert.equal(empty.length,12);
    assert.equal(decodeMhPacket(empty,profile,key).termination,'exact_end');
    const aligned = encodeMhPacket({header:header(2),messages:[message(12)]},profile,key);
    assert.equal(aligned.length,44);
    assert.equal(decodeMhPacket(aligned,profile,key).trailer.length,0);
    const messages = Array.from({length:73},()=>message(0));
    const full = encodeMhPacket({header:header(),messages},profile);
    assert.equal(decodeMhPacket(full,profile).messages.length,73);
    assert.throws(()=>encodeMhPacket({header:header(),messages:[...messages,message(0)]},profile),/messages/);
  }
});
function header(mode = 1) {
  const value = Buffer.from('32ab986401a5123456789abc', 'hex'); value[4] = mode; return value;
}
function message(length = 1) {
  const value = Buffer.alloc(Math.ceil((20 + length) / 4) * 4, 0xa7);
  value[0] = 1; value.writeUInt16BE(length, 2); return value;
}

test('mode1 packet preserves unknown header, inner alignment and opaque sentinel trailer', () => {
  for (const profile of profiles) {
    const input = {header: header(), messages: [message(), message(4)], trailer: Buffer.from([255, 0, 7])};
    const wire = encodeMhPacket(input, profile), before = Buffer.from(wire);
    const parsed = decodeMhPacket(wire, profile);
    assert.equal(parsed.termination, 'sentinel'); assert.deepEqual(parsed.messages, input.messages);
    assert.deepEqual(parsed.header, input.header); assert.deepEqual(parsed.trailer, input.trailer);
    assert.deepEqual(encodeMhPacket(parsed, profile), wire);
    parsed.header.fill(0); parsed.messages[0].fill(0); parsed.trailer.fill(0); parsed.body.fill(0);
    assert.deepEqual(wire, before);
  }
});

test('mode2 decrypts before framing and preserves FF padding for exact reencoding', () => {
  for (const profile of profiles) {
    const wire = encodeMhPacket({header: header(2), messages: [message()]}, profile, key);
    const parsed = decodeMhPacket(wire, profile, key);
    assert.equal(parsed.header[4], 2); assert.equal(parsed.body.length, 32);
    assert.deepEqual(parsed.messages, [message()]); assert.equal(parsed.trailer.length, 8);
    assert.ok(parsed.trailer.every(value => value === 255));
    assert.deepEqual(encodeMhPacket(parsed, profile, key), wire);
    assert.throws(() => decodeMhPacket(wire, profile), /key16/);
    assert.throws(() => decodeMhPacket(wire.subarray(0, wire.length-1), profile, key), /alignment/);
  }
});

test('empty and exact-end packets remain valid without fabricated trailer', () => {
  for (const profile of profiles) {
    const empty = decodeMhPacket(header(), profile);
    assert.equal(empty.messages.length, 0); assert.equal(empty.termination, 'exact_end');
    const wire = encodeMhPacket({header: header(), messages: [message(0)]}, profile);
    assert.equal(decodeMhPacket(wire, profile).termination, 'exact_end');
    assert.deepEqual(encodeMhPacket(empty, profile), header());
  }
});

test('packet decoder rejects unknown profile, magic, mode, capacity and partial messages', () => {
  assert.throws(() => decodeMhPacket(header(), 'unknown'), /profile/);
  assert.throws(() => decodeMhPacket(Buffer.alloc(11), profiles[0]), /short_header/);
  const badMagic = header(); badMagic[0] = 0;
  assert.throws(() => decodeMhPacket(badMagic, profiles[0]), /magic/);
  assert.throws(() => decodeMhPacket(header(3), profiles[0]), /mode/);
  for (const body of [Buffer.alloc(19), message().subarray(0, 23), Buffer.alloc(1461)]) {
    assert.throws(() => decodeMhPacket(Buffer.concat([header(),body]), profiles[0]));
  }
});

test('packet encoder rejects malformed/sparse input and honors mode-specific capacity', () => {
  const profile = profiles[0];
  assert.throws(() => encodeMhPacket({header: header(), messages: new Array(1)}, profile), /message/);
  assert.throws(() => encodeMhPacket({header: header(), messages: [message().subarray(0,23)]}, profile), /alignment/);
  assert.throws(() => encodeMhPacket({header: header(), messages: [], trailer: Buffer.from([0])}, profile), /trailer/);
  assert.throws(() => encodeMhPacket({header: header(), messages: [message(1441)]}, profile), /body_limit/);
  assert.equal(encodeMhPacket({header: header(), messages: [message(1440)]}, profile).length, 1472);
  assert.throws(() => encodeMhPacket({header: header(2), messages: [message(1440)]}, profile,key), /body_limit/);
  assert.equal(encodeMhPacket({header: header(2), messages: [message(1436)]}, profile,key).length, 1468);
});

test('both packet modes feed separated stream messages into system-list recovery', () => {
  for (const profile of profiles) for (const mode of [1,2]) {
    const body = Buffer.alloc(12); body[0] = 0x20; body[8] = 1;
    const outerHeader = Buffer.alloc(20), streamHeader = Buffer.alloc(24);
    outerHeader.writeUInt32BE(0x10001,12); streamHeader.writeUInt16BE(3,0); streamHeader.writeUInt32BE(40,8);
    const inner = encodeMhStreamMessage({outerHeader,streamHeader,payload: body},profile,0x10001);
    const wire = encodeMhPacket({header: header(mode), messages: [inner]},profile,key);
    const parsed = decodeMhPacket(wire,profile,key);
    const recovered = recoverMhPeerListFromMessages(parsed.messages,profile,40,0x10001);
    assert.equal(recovered.kind,'peer-list'); assert.deepEqual(recovered.body,body);
    assert.equal(recovered.list.entries.length,0);
  }
});
