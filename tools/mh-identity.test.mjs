import assert from 'node:assert/strict';
import test from 'node:test';
import { MhIdentityMap, mhguLdnIdentityFromFakeIp } from './mh-identity.mjs';

const bytes = hex => Buffer.from(hex, 'hex');
const seeds = ['0000000000000000', '0102030405060708', '3132333435363738', 'ffffffffffffffff'];
// Independent Python zlib CRC32 golden values, never emulator or game bytes.
const xx = ['6522df69', '3fca88c5', '9ae0daaf', '2144df1c'];
const gu = ['0a000001', '0a000002', '0a000003', '0a000004'];

test('2022 fake IP identity agrees with independent IPC/SDK/main byte-order simulation', () => {
  for (const hex of ['01020304', 'c0a80102', 'ffffffff', '00000000']) {
    const ip = bytes(hex);
    const ipc = Buffer.from(ip).reverse();
    const expected = Buffer.alloc(4);
    expected.writeUInt32BE(ipc.readUInt32LE());
    assert.deepEqual(mhguLdnIdentityFromFakeIp(ip, 'yuzu-2022-7edc31be2'), expected);
    assert.equal(ip.toString('hex'), hex);
  }
});

test('fake IP helper requires explicit supported profile and isolated four-byte Buffer', () => {
  for (const profile of [undefined, null, '', 'yuzu-2024', 'yuzu-2022']) {
    assert.throws(() => mhguLdnIdentityFromFakeIp(bytes('01020304'), profile), /unsupported/);
  }
  for (const input of ['1.2.3.4', new Uint8Array(4), Buffer.alloc(3), Buffer.alloc(5), null]) {
    assert.throws(() => mhguLdnIdentityFromFakeIp(input, 'yuzu-2022-7edc31be2'), /four_bytes/);
  }
  const input = bytes('01020304');
  const output = mhguLdnIdentityFromFakeIp(input, 'yuzu-2022-7edc31be2');
  output.fill(0);
  assert.equal(input.toString('hex'), '01020304');
});

test('profile-derived identity integrates bidirectionally but zero cannot bind a peer', () => {
  const map = new MhIdentityMap('profile');
  const identity = mhguLdnIdentityFromFakeIp(bytes('c0a80102'), 'yuzu-2022-7edc31be2');
  map.bind('profile', bytes(seeds[0]), identity);
  identity.fill(0);
  assert.equal(map.translate('profile', 'mhxx-to-mhgu', bytes(xx[0])).toString('hex'), 'c0a80102');
  assert.equal(map.translate('profile', 'mhgu-to-mhxx', bytes('c0a80102')).toString('hex'), xx[0]);
  assert.throws(() => map.bind('profile', bytes(seeds[1]), mhguLdnIdentityFromFakeIp(Buffer.alloc(4), 'yuzu-2022-7edc31be2')), /zero_binding/);
  assert.equal(map.size, 1);
});

test('identity mapping is bijective for all four players and preserves original forwarded identity', () => {
  const map = new MhIdentityMap('quest-A');
  seeds.forEach((seed, i) => map.bind('quest-A', bytes(seed), bytes(gu[i])));
  assert.equal(map.size, 4);
  // No outer-sender input: a forwarded message carrying player 2 stays player 2.
  for (let i = 0; i < 4; i++) {
    assert.equal(map.translate('quest-A', 'mhxx-to-mhgu', bytes(xx[i])).toString('hex'), gu[i]);
    assert.equal(map.translate('quest-A', 'mhgu-to-mhxx', bytes(gu[i])).toString('hex'), xx[i]);
  }
  map.bind('quest-A', bytes(seeds[0]), bytes(gu[0]));
  assert.equal(map.size, 4);
  assert.throws(() => map.bind('quest-A', bytes('0200000000000000'), bytes('0a000005')), /game_capacity/);
  assert.equal(map.size, 4);
});

test('zero default identity is preserved while unknown identities fail without mutating input', () => {
  const map = new MhIdentityMap('room');
  const zero = Buffer.alloc(4);
  for (const direction of ['mhxx-to-mhgu', 'mhgu-to-mhxx']) {
    assert.deepEqual(map.translate('room', direction, zero), zero);
    assert.notEqual(map.translate('room', direction, zero), zero);
    const unknown = bytes('12345678');
    assert.throws(() => map.translate('room', direction, unknown), /unmapped/);
    assert.equal(unknown.toString('hex'), '12345678');
  }
  assert.throws(() => map.bind('room', bytes(seeds[0]), zero), /zero_binding/);
  assert.equal(map.size, 0);
});

test('seed CRC collisions, GU identity collisions and peer rebinds are rejected atomically', () => {
  const map = new MhIdentityMap('room');
  map.bind('room', bytes(seeds[0]), bytes(gu[0]));
  // zlib confirms both seeds give 0x6522df69: CRC is not unique or authentication.
  assert.throws(() => map.bind('room', bytes('010000006567bcb8'), bytes(gu[0])), /seed_crc_collision/);
  assert.throws(() => map.bind('room', bytes(seeds[1]), bytes(gu[0])), /gu_collision/);
  assert.throws(() => map.bind('room', bytes(seeds[0]), bytes(gu[1])), /peer_rebind/);
  assert.equal(map.size, 1);
  assert.equal(map.translate('room', 'mhgu-to-mhxx', bytes(gu[0])).toString('hex'), xx[0]);
});

test('reset drops both directions and stale session calls are rejected, including zero identity', () => {
  const map = new MhIdentityMap('old');
  map.bind('old', bytes(seeds[0]), bytes(gu[0]));
  map.reset('new');
  assert.equal(map.size, 0);
  assert.throws(() => map.translate('old', 'mhxx-to-mhgu', Buffer.alloc(4)), /session_mismatch/);
  assert.throws(() => map.bind('old', bytes(seeds[0]), bytes(gu[0])), /session_mismatch/);
  for (const [direction, value] of [['mhxx-to-mhgu', xx[0]], ['mhgu-to-mhxx', gu[0]]]) {
    assert.throws(() => map.translate('new', direction, bytes(value)), /unmapped/);
  }
  map.bind('new', bytes(seeds[0]), bytes(gu[1]));
  assert.equal(map.translate('new', 'mhxx-to-mhgu', bytes(xx[0])).toString('hex'), gu[1]);
  assert.throws(() => map.reset(''), /invalid_mh_identity_session/);
  assert.equal(map.size, 1);
  map.reset('new');
  assert.equal(map.size, 0);
});

test('bindings and translated results do not alias caller buffers', () => {
  const map = new MhIdentityMap('room');
  const seed = bytes(seeds[0]), identity = bytes(gu[0]);
  map.bind('room', seed, identity);
  seed.fill(255); identity.fill(255);
  map.bind('room', bytes(seeds[0]), bytes(gu[0]));
  const output = map.translate('room', 'mhxx-to-mhgu', bytes(xx[0]));
  output.fill(255);
  assert.equal(map.translate('room', 'mhxx-to-mhgu', bytes(xx[0])).toString('hex'), gu[0]);
});

test('peer departure removes both directions while other peers remain and address reuse is explicit', () => {
  const map = new MhIdentityMap('room');
  map.bind('room', bytes(seeds[0]), bytes(gu[0]));
  map.bind('room', bytes(seeds[1]), bytes(gu[1]));
  assert.throws(() => map.unbind('room', bytes('010000006567bcb8')), /seed_crc_collision/);
  assert.throws(() => map.unbind('old-room', bytes(seeds[0])), /session_mismatch/);
  assert.equal(map.size, 2);
  assert.equal(map.unbind('room', bytes(seeds[0])), true);
  assert.equal(map.unbind('room', bytes(seeds[0])), false);
  assert.throws(() => map.translate('room', 'mhxx-to-mhgu', bytes(xx[0])), /unmapped/);
  assert.throws(() => map.translate('room', 'mhgu-to-mhxx', bytes(gu[0])), /unmapped/);
  assert.equal(map.translate('room', 'mhxx-to-mhgu', bytes(xx[1])).toString('hex'), gu[1]);
  map.bind('room', bytes(seeds[2]), bytes(gu[0]));
  assert.equal(map.translate('room', 'mhgu-to-mhxx', bytes(gu[0])).toString('hex'), xx[2]);
  assert.equal(map.size, 2);
});

test('session labels, direction and exact-width inputs are enforced', () => {
  for (const id of ['', null, 4, 'x'.repeat(129)]) assert.throws(() => new MhIdentityMap(id), /invalid_mh_identity_session/);
  const map = new MhIdentityMap('room');
  for (const seed of [null, [], Buffer.alloc(7), Buffer.alloc(9)]) {
    assert.throws(() => map.bind('room', seed, bytes(gu[0])), /eight_bytes/);
  }
  for (const value of [null, [], Buffer.alloc(3), Buffer.alloc(5)]) {
    assert.throws(() => map.bind('room', bytes(seeds[0]), value), /four_bytes/);
    assert.throws(() => map.translate('room', 'mhxx-to-mhgu', value), /four_bytes/);
  }
  assert.throws(() => map.translate('room', 'other', Buffer.alloc(4)), /invalid_mh_identity_direction/);
  assert.equal(map.size, 0);
});
