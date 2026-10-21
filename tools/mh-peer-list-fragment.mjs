// Strict offline fragment container; does not reconstruct or authenticate a session.
import { decodeMhPeerListBody, encodeMhPeerListBody } from './mh-peer-list.mjs';

function checkHeader(header) {
  if (!Buffer.isBuffer(header) || header.length !== 12) throw new TypeError('fragment_header_requires_12_bytes');
  if (header[8] !== 2) throw new Error('unsupported_peer_list_fragment_variant');
  if (header[9] > 1) throw new Error('peer_list_fragment_slot_out_of_range');
  if (header[11] + header[10] > header[1]) throw new Error('peer_list_fragment_entries_out_of_range');
}

export function decodeMhPeerListFragment(bytes, profile) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 12) throw new TypeError('invalid_peer_list_fragment');
  checkHeader(bytes.subarray(0, 12));
  const container = Buffer.from(bytes);
  container[1] = bytes[10];
  container[8] = 1;
  const { entries } = decodeMhPeerListBody(container, profile);
  return { header: Buffer.from(bytes.subarray(0, 12)), entries };
}

export function encodeMhPeerListFragment(value, profile) {
  checkHeader(value?.header);
  const header = Buffer.from(value.header);
  header[1] = value.header[10];
  header[8] = 1;
  const output = encodeMhPeerListBody({ header, entries: value.entries }, profile);
  value.header.copy(output);
  return output;
}
