// Fixed MHGU update parser 13A665C: two 35-byte subrecords, offline only.
// Each has two six-byte BE endpoints around 23 opaque bytes (13A7EE0).
import { decodeMhxxEndpoint, encodeMhxxEndpoint } from './mhxx-endpoint.mjs';

export function decodeMhguPeerDescriptor(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length !== 70) {
    throw new TypeError('mhgu_peer_descriptor_requires_70_bytes');
  }
  return [0, 35].map(offset => ({
    endpointA: decodeMhxxEndpoint(bytes.subarray(offset, offset + 6)),
    opaqueFields: Buffer.from(bytes.subarray(offset + 6, offset + 29)),
    endpointB: decodeMhxxEndpoint(bytes.subarray(offset + 29, offset + 35)),
  }));
}

export function encodeMhguPeerDescriptor(records) {
  if (!Array.isArray(records) || records.length !== 2) {
    throw new TypeError('mhgu_peer_descriptor_requires_two_records');
  }
  const output = Buffer.alloc(70);
  for (let index = 0; index < 2; index++) {
    const record = records[index];
    if (!record || !Buffer.isBuffer(record.opaqueFields) || record.opaqueFields.length !== 23) {
      throw new TypeError('mhgu_peer_descriptor_requires_23_opaque_bytes');
    }
    const offset = index * 35;
    encodeMhxxEndpoint(record.endpointA).copy(output, offset);
    record.opaqueFields.copy(output, offset + 6);
    encodeMhxxEndpoint(record.endpointB).copy(output, offset + 29);
  }
  return output;
}
