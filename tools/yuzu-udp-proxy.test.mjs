// SPDX-License-Identifier: GPL-3.0-or-later
import test from 'node:test';
import assert from 'node:assert/strict';
import { translateYuzuUdpProxyProfile as translate, decodeYuzuUdpProxyPacket as decode,
  encodeYuzuUdpProxyPacket as encode } from './yuzu-udp-proxy.mjs';
const old = 'yuzu-2022-7edc31be2';
// Codec tests use literal wire bytes rather than generating expected bytes with the encoder.
const mirror = 'yuzu-mirror-01052024';
// Independent wire fixtures: ID, family/IP/port twice, protocol, bool, BE32 length, opaque bytes.
const oldHex = '0500c0a801023039000a141e28abcd020100000005deadbeef00';
const mirrorHex = '0501c0a801023039010a141e28abcd030100000005deadbeef00';
function frame(profile = old, length = 5) {
  const bytes = Buffer.alloc(21 + length, 0xa5);
  Buffer.from(profile === old ? oldHex : mirrorHex, 'hex').copy(bytes, 0, 0, 21);
  bytes.writeUInt32BE(length, 17);
  return bytes;
}
function flags(result, profile) {
  assert.equal(result.profile, profile);
  for (const key of ['payloadValidated', 'applicationConverted', 'productionReady']) assert.equal(result[key], false);
}

test('codec literal fixtures roundtrip on both profiles with fresh buffers', () => {
  for (const [profile, hex] of [[old, oldHex], [mirror, mirrorHex]]) {
    const input = Buffer.from(hex, 'hex'), snapshot = Buffer.from(input);
    const decoded = decode(input, profile); flags(decoded, profile);
    assert.equal(decoded.header.toString('hex'), hex.slice(0, 42));
    assert.equal(decoded.data.toString('hex'), 'deadbeef00');
    const encoded = encode(decoded.header, decoded.data, profile); flags(encoded, profile);
    assert.deepEqual(encoded.bytes, snapshot);
    input.fill(0); assert.deepEqual(encoded.bytes, snapshot);
    decoded.header.fill(0); decoded.data.fill(0); assert.deepEqual(encoded.bytes, snapshot);
  }
});

test('encoder uses independent target header, overwrites only length, never guesses enums', () => {
  const header = Buffer.from('0501ac100102beef017f0000020001037fdeadbeef', 'hex');
  assert.equal(header.length, 21);
  const snapshot = Buffer.from(header), data = Buffer.from('112233', 'hex');
  const result = encode(header, data, mirror);
  assert.equal(result.bytes.toString('hex'), '0501ac100102beef017f0000020001037f00000003112233');
  assert.deepEqual(header, snapshot); assert.equal(data.toString('hex'), '112233');
  assert.throws(() => encode(header, data, old), /source_enums/);
});

test('codec rejects wrong header/data/profile and invalid packets without mutation', () => {
  const header = frame().subarray(0, 21), snapshot = Buffer.from(header);
  for (const bad of [undefined, null, {}, new Uint8Array(21), Buffer.alloc(20), Buffer.alloc(22)])
    assert.throws(() => encode(bad, Buffer.alloc(0), old), /header/);
  for (const bad of [undefined, null, [], new Uint8Array(0), Buffer.alloc(65537)])
    assert.throws(() => encode(header, bad, old), /data/);
  for (const bad of [undefined, null, 'yuzu-ea']) {
    assert.throws(() => encode(header, Buffer.alloc(0), bad), /profile/);
    assert.throws(() => decode(frame(), bad), /profile/);
  }
  for (const offset of [0, 1, 8, 15]) {
    const bad = Buffer.from(header); bad[offset] = 255;
    assert.throws(() => encode(bad, Buffer.alloc(0), old), /envelope|source_enums/);
  }
  const badLength = frame(); badLength.writeUInt32BE(100, 17);
  assert.throws(() => decode(badLength, old), /envelope/);
  for (const bad of [null, {}, new Uint8Array(21), Buffer.alloc(20), Buffer.alloc(65558)])
    assert.throws(() => decode(bad, old), /size/);
  assert.deepEqual(header, snapshot);
});

test('codec empty and maximum opaque data, exact boundaries, subarray isolation', () => {
  for (const profile of [old, mirror]) for (const size of [0, 1, 65536]) {
    const backing = Buffer.concat([Buffer.from([7]), frame(profile, size), Buffer.from([9])]);
    const input = backing.subarray(1, -1), snapshot = Buffer.from(backing);
    const decoded = decode(input, profile);
    const result = encode(decoded.header, decoded.data, profile);
    assert.deepEqual(result.bytes, input); assert.deepEqual(backing, snapshot);
    decoded.header[2] ^= 255; assert.deepEqual(backing, snapshot);
    if (size) decoded.data[0] ^= 255;
    assert.deepEqual(backing, snapshot); assert.deepEqual(result.bytes, input);
  }
});

test('decode/explicit target rebuild agrees with enum-only translation for all profile pairs', () => {
  for (const source of [old, mirror]) for (const target of [old, mirror]) {
    const input = frame(source, 300); const decoded = decode(input, source);
    const targetHeader = frame(target, 0).subarray(0, 21);
    const rebuilt = encode(targetHeader, decoded.data, target);
    assert.deepEqual(rebuilt.bytes, translate(input, source, target).bytes);
    flags(rebuilt, target);
    assert.equal(decoded.header.readUInt32BE(17), 300);
    assert.equal(targetHeader.readUInt32BE(17), 0);
  }
});

test('independent hex fixtures translate both ways, changing exactly three bytes', () => {
  for (const [source, target, a, b] of [[old, mirror, oldHex, mirrorHex], [mirror, old, mirrorHex, oldHex]]) {
    const input = Buffer.from(a, 'hex');
    const snapshot = Buffer.from(input);
    const result = translate(input, source, target);
    flags(result, target);
    assert.equal(result.bytes.toString('hex'), b);
    assert.deepEqual(input, snapshot);
    assert.deepEqual([...input.keys()].filter(i => input[i] !== result.bytes[i]), [1, 8, 15]);
    assert.deepEqual(translate(result.bytes, target, source).bytes, input);
  }
});

test('explicit profiles required on both sides; no EA/default/date guess', () => {
  for (const bad of [undefined, null, '', 'yuzu-ea', 'yuzu-2024', 'mhgu-v262144', {}, new String(old)]) {
    assert.throws(() => translate(frame(), bad, mirror), /yuzu_udp_proxy_profile/);
    assert.throws(() => translate(frame(), old, bad), /yuzu_udp_proxy_profile/);
  }
});

test('both families and explicit UDP must match the declared source', () => {
  for (const profile of [old, mirror]) {
    const input = frame(profile), snapshot = Buffer.from(input);
    for (const offset of [1, 8, 15]) for (let value = 0; value < 256; value++) {
      if (value === input[offset]) continue;
      const bad = Buffer.from(input); bad[offset] = value;
      assert.throws(() => translate(bad, profile, old), /yuzu_udp_proxy_source_enums/);
    }
    assert.throws(() => translate(input, profile === old ? mirror : old, old), /yuzu_udp_proxy_source_enums/);
    assert.deepEqual(input, snapshot);
  }
});

test('reject non-Buffers, incomplete framing, wrong ID, length mismatch and trailing data', () => {
  for (const bad of [null, {}, [], new Uint8Array(26), 'packet', ...Array.from({ length: 21 }, (_, n) => Buffer.alloc(n))]) {
    assert.throws(() => translate(bad, old, mirror), /yuzu_udp_proxy_size/);
  }
  const input = frame();
  for (const [offset, value] of [[0, 6], [0, 0], [0, 255]]) {
    const bad = Buffer.from(input); bad[offset] = value;
    assert.throws(() => translate(bad, old, mirror), /yuzu_udp_proxy_envelope/);
  }
  for (const length of [0, 4, 6, 0xffffffff]) {
    const bad = Buffer.from(input); bad.writeUInt32BE(length, 17);
    assert.throws(() => translate(bad, old, mirror), /yuzu_udp_proxy_envelope/);
  }
  for (const bad of [input.subarray(0, -1), Buffer.concat([input, Buffer.of(0)])]) {
    assert.throws(() => translate(bad, old, mirror), /yuzu_udp_proxy_envelope/);
  }
});

test('tooling capacity includes empty and exactly 64 KiB opaque data, not 65537', () => {
  for (const profile of [old, mirror]) for (const length of [0, 1, 65536]) {
    const result = translate(frame(profile, length), profile, profile);
    assert.equal(result.bytes.length, 21 + length);
    assert.equal(result.bytes.readUInt32BE(17), length);
    flags(result, profile);
  }
  assert.throws(() => translate(frame(old, 65537), old, mirror), /yuzu_udp_proxy_size/);
});

test('same-profile translation returns independent buffers even for subarray input', () => {
  const backing = Buffer.concat([Buffer.of(9), frame(), Buffer.of(8)]);
  const input = backing.subarray(1, -1), snapshot = Buffer.from(backing);
  const a = translate(input, old, old), b = translate(input, old, old);
  assert.deepEqual(a.bytes, input);
  a.bytes.fill(0); assert.deepEqual(backing, snapshot); assert.deepEqual(b.bytes, input);
  input.fill(7); assert.deepEqual(b.bytes, snapshot.subarray(1, -1));
});

test('all broadcast byte values preserved without normalization or payload validation', () => {
  for (let value = 0; value < 256; value++) {
    const input = Buffer.from(oldHex, 'hex'); input[16] = value;
    const result = translate(input, old, mirror);
    assert.equal(result.bytes[16], value);
    assert.deepEqual(result.bytes.subarray(17), input.subarray(17));
    flags(result, mirror);
  }
});

test('deterministic arbitrary endpoints/payload stay opaque for all profile pairs', () => {
  let state = 12345;
  const next = () => { state = (Math.imul(state, 1664525) + 1013904223) >>> 0; return state; };
  for (const source of [old, mirror]) for (const target of [old, mirror]) for (let n = 0; n < 80; n++) {
    const input = frame(source, next() % 300);
    for (const i of [2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 14, 16]) input[i] = next() & 255;
    for (let i = 21; i < input.length; i++) input[i] = next() & 255;
    const snapshot = Buffer.from(input), expected = Buffer.from(input);
    expected[1] = expected[8] = target === old ? 0 : 1; expected[15] = target === old ? 2 : 3;
    const result = translate(input, source, target);
    assert.deepEqual(result.bytes, expected); assert.deepEqual(input, snapshot); flags(result, target);
  }
});
