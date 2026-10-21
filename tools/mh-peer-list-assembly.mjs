// Offline pair validation. The caller supplies fragments from one authenticated peer/session.
import { decodeMhPeerListFragment } from './mh-peer-list-fragment.mjs';

export function assembleMhPeerListFragments(fragments, profile) {
  if (!Array.isArray(fragments) || fragments.length !== 2) {
    throw new TypeError('peer_list_assembly_requires_two_fragments');
  }
  const decoded = fragments.map(bytes => decodeMhPeerListFragment(bytes, profile));
  decoded.sort((a, b) => a.header[9] - b.header[9]);
  const [first, second] = decoded;
  if (first.header[9] !== 0 || second.header[9] !== 1) throw new Error('peer_list_assembly_duplicate_slot');
  // Preserve unknown fields; reject differences rather than assigning speculative semantics.
  if (!first.header.subarray(0, 9).equals(second.header.subarray(0, 9))) {
    throw new Error('peer_list_assembly_header_conflict');
  }
  const entries = Array(first.header[1]);
  const covered = new Uint8Array(entries.length);
  for (const fragment of decoded) {
    for (let local = 0; local < fragment.entries.length; local++) {
      const index = fragment.header[11] + local;
      if (covered[index]) throw new Error('peer_list_assembly_overlap');
      covered[index] = 1;
      entries[index] = fragment.entries[local];
    }
  }
  if (covered.some(value => value !== 1)) throw new Error('peer_list_assembly_gap');
  // Keep both original headers. A synthesized variant1 header would invent unverified fields.
  return { fragmentHeaders: decoded.map(fragment => fragment.header), entries };
}
