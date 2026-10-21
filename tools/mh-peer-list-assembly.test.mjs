import assert from 'node:assert/strict';
import test from 'node:test';
import { assembleMhPeerListFragments } from './mh-peer-list-assembly.mjs';

function fragment(total, slot, start, count) {
  const bytes = Buffer.alloc(12 + count * 72);
  Buffer.from('20047e001234567802000200','hex').copy(bytes);
  bytes[1]=total; bytes[9]=slot; bytes[10]=count; bytes[11]=start;
  for (let i=0;i<count;i++) {
    bytes.fill((start+i)*7 & 255,12+i*72,12+(i+1)*72);
    bytes[12+i*72+70]=start+i;
  }
  return bytes;
}

test('offline assembly accepts both arrival orders and every four-entry split', () => {
  for (const profile of ['mhxx-1.4','mhgu-v262144']) {
    for (let split=0;split<=4;split++) {
      const parts=[fragment(4,0,0,split),fragment(4,1,split,4-split)];
      for (const order of [parts,[...parts].reverse()]) {
        const merged=assembleMhPeerListFragments(order,profile);
        assert.deepEqual(merged.entries.map(entry=>entry.number),[0,1,2,3]);
        assert.deepEqual(merged.fragmentHeaders,parts.map(part=>part.subarray(0,12)));
        assert.equal(Object.hasOwn(merged,'header'),false);
        merged.fragmentHeaders[0].fill(0);
        merged.entries[0].descriptor[0].opaqueFields.fill(255);
        assert.deepEqual(parts[0],fragment(4,0,0,split));
        assert.deepEqual(parts[1],fragment(4,1,split,4-split));
      }
    }
    assert.equal(assembleMhPeerListFragments([fragment(0,0,0,0),fragment(0,1,0,0)],profile).entries.length,0);
    assert.equal(assembleMhPeerListFragments([fragment(255,0,0,128),fragment(255,1,128,127)],profile).entries.length,255);
  }
});

test('offline assembly rejects missing/duplicate slots, header conflicts, overlaps and gaps', () => {
  const profile='mhxx-1.4';
  for (const bad of [null,[],[fragment(4,0,0,2)]]) assert.throws(()=>assembleMhPeerListFragments(bad,profile),/two_fragments/);
  assert.throws(()=>assembleMhPeerListFragments([fragment(4,0,0,2),fragment(4,0,2,2)],profile),/duplicate_slot/);
  assert.throws(()=>assembleMhPeerListFragments([fragment(4,0,0,3),fragment(4,1,2,2)],profile),/overlap/);
  assert.throws(()=>assembleMhPeerListFragments([fragment(4,0,0,1),fragment(4,1,2,2)],profile),/gap/);
  for (const offset of [0,1,2,3,4,5,6,7]) {
    const pair=[fragment(4,0,0,2),fragment(4,1,2,2)];
    pair[1][offset]^=1;
    assert.throws(()=>assembleMhPeerListFragments(pair,profile),/header_conflict|out_of_range/);
  }
  assert.throws(()=>assembleMhPeerListFragments([fragment(4,0,0,2),fragment(4,1,2,2)],'unknown'),/profile/);
});
