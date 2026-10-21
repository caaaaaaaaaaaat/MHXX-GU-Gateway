import assert from 'node:assert/strict';
import test from 'node:test';
import { selectMhBasePeerEndpoint, translateMhBasePeerEndpoint } from './mh-base-peer-endpoint.mjs';
import { MhIdentityMap } from './mh-identity.mjs';
import { deriveMhxxUdsEndpoint, encodeMhxxEndpoint } from './mhxx-endpoint.mjs';

const seed = Buffer.from('0102030405060708', 'hex');
function setup() {
  const identities = new MhIdentityMap('session');
  identities.bind('session', seed, Buffer.from([10, 0, 0, 7]));
  const descriptor = Buffer.alloc(70, 0xa5);
  encodeMhxxEndpoint(deriveMhxxUdsEndpoint(seed)).copy(descriptor);
  return { identities, descriptor };
}

test('base branch selects first endpointA regardless of derived flags and other endpoints', () => {
  for (const profile of ['mhxx-1.4', 'mhgu-v262144']) {
    const descriptor = Buffer.alloc(70, 0xee);
    Buffer.from([10, 0, 0, 7, 0x30, 0x39]).copy(descriptor);
    for (const flag of [0, 1, 2, 3, 255]) {
      descriptor[27] = flag;
      assert.deepEqual(selectMhBasePeerEndpoint(descriptor, profile), { address: '10.0.0.7', port: 12345 });
    }
  }
});

test('mapped selected endpoint roundtrips across fixed profiles without mutating descriptor', () => {
  const { identities, descriptor } = setup();
  const before = Buffer.from(descriptor);
  const gu = translateMhBasePeerEndpoint(descriptor, 'mhxx-1.4', identities, 'session');
  assert.equal(gu.profile, 'mhgu-v262144');
  assert.deepEqual(gu.endpoint, { address: '10.0.0.7', port: 12345 });
  const reverse = Buffer.from(descriptor);
  gu.bytes.copy(reverse);
  const xx = translateMhBasePeerEndpoint(reverse, gu.profile, identities, 'session');
  assert.equal(xx.profile, 'mhxx-1.4');
  assert.deepEqual(xx.bytes, before.subarray(0, 6));
  gu.bytes.fill(0);
  assert.deepEqual(descriptor, before);
});

test('mapping rejects stale session, unbound identity and invalid mapper', () => {
  const { identities, descriptor } = setup();
  assert.throws(() => translateMhBasePeerEndpoint(descriptor, 'mhxx-1.4', identities, 'stale'), /session_mismatch/);
  identities.unbind('session', seed);
  assert.throws(() => translateMhBasePeerEndpoint(descriptor, 'mhxx-1.4', identities, 'session'), /unmapped/);
  assert.throws(() => translateMhBasePeerEndpoint(descriptor, 'mhxx-1.4', {}, 'session'), /identity_map/);
});

test('mapping rejects default endpoints and unsupported ports rather than guessing', () => {
  const { identities, descriptor } = setup();
  for (const port of [0, 1, 12344, 65535]) {
    descriptor.writeUInt16BE(port, 4);
    assert.throws(() => translateMhBasePeerEndpoint(descriptor, 'mhxx-1.4', identities, 'session'), /port12345/);
  }
  descriptor.writeUInt16BE(12345, 4);
  descriptor.writeUInt32BE(0, 0);
  assert.throws(() => translateMhBasePeerEndpoint(descriptor, 'mhxx-1.4', identities, 'session'), /port12345/);
});

test('base branch requires exact descriptor size and fixed build profile', () => {
  for (const bytes of [null, [], Buffer.alloc(69), Buffer.alloc(71)]) {
    assert.throws(() => selectMhBasePeerEndpoint(bytes, 'mhxx-1.4'));
  }
  for (const profile of [undefined, null, 'mhxx', 'mhgu', {}]) {
    assert.throws(() => selectMhBasePeerEndpoint(Buffer.alloc(70), profile), /profile/);
  }
});
