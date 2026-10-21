import assert from 'node:assert/strict';
import test from 'node:test';
import { decodeMhPeerListFragment, encodeMhPeerListFragment } from './mh-peer-list-fragment.mjs';

function fixture(total, slot, start, count) {
  const bytes = Buffer.alloc(12 + count * 72);
  Buffer.from('20047e001234567802000200', 'hex').copy(bytes);
  bytes[1] = total; bytes[9] = slot; bytes[10] = count; bytes[11] = start;
  for (let i = 12; i < bytes.length; i++) bytes[i] = (i * 19) & 255;
  return bytes;
}

test('fragment codec uses local count and preserves total, slot, range and opaque bytes', () => {
  for (const args of [[4,0,0,2],[4,1,2,2],[255,1,254,1],[0,0,0,0],[255,0,0,255]]) {
    const bytes = fixture(...args);
    for (const from of ['mhxx-1.4','mhgu-v262144']) {
      const decoded = decodeMhPeerListFragment(bytes, from);
      assert.equal(decoded.entries.length, args[3]);
      for (const to of ['mhxx-1.4','mhgu-v262144']) {
        const output = encodeMhPeerListFragment(decoded, to);
        assert.deepEqual(output, bytes);
        output.fill(0);
        assert.deepEqual(encodeMhPeerListFragment(decoded, to), bytes);
      }
      decoded.header.fill(0);
      if (decoded.entries.length) decoded.entries[0].descriptor[0].opaqueFields.fill(0);
      assert.deepEqual(bytes, fixture(...args));
    }
  }
});

test('fragment codec rejects invalid ranges, slots, lengths, counts and profiles', () => {
  for (const profile of ['mhxx-1.4','mhgu-v262144']) {
    for (const args of [[4,2,0,2],[4,255,0,2],[4,0,3,2],[255,0,255,1]]) {
      const bytes = fixture(...args);
      assert.throws(() => decodeMhPeerListFragment(bytes, profile), /out_of_range/);
      assert.throws(() => encodeMhPeerListFragment({header:bytes.subarray(0,12),entries:[]},profile), /out_of_range/);
    }
    const bytes = fixture(4,0,0,2);
    for (const bad of [bytes.subarray(0,-1),Buffer.concat([bytes,Buffer.alloc(1)])]) {
      assert.throws(() => decodeMhPeerListFragment(bad,profile), /length_mismatch/);
    }
    assert.throws(() => encodeMhPeerListFragment({header:bytes.subarray(0,12),entries:[]},profile), /count_mismatch/);
    bytes[8]=1;
    assert.throws(() => decodeMhPeerListFragment(bytes,profile), /variant/);
  }
  assert.throws(() => decodeMhPeerListFragment(fixture(4,0,0,2),'unknown'), /profile/);
  assert.throws(() => encodeMhPeerListFragment({header:fixture(0,0,0,0),entries:[]},'unknown'), /profile/);
  for (const bad of [null, [], Buffer.alloc(11)]) assert.throws(() => decodeMhPeerListFragment(bad,'mhxx-1.4'));
});
