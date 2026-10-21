// Offline parser for an explicitly identified GU full list body (variant 1).
import { decodeMhPeerDescriptor, encodeMhPeerDescriptor } from './mh-peer-descriptor.mjs';

function checkHeader(header) {
  if (!Buffer.isBuffer(header) || header.length !== 12) {
    throw new TypeError('mhgu_peer_list_requires_12_byte_header');
  }
  if (header[8] !== 1) throw new Error('unsupported_mhgu_peer_list_variant');
}

export function decodeMhguPeerListBody(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 12) {
    throw new TypeError('invalid_mhgu_peer_list_body');
  }
  checkHeader(bytes.subarray(0, 12));
  const count = bytes[1];
  if (bytes.length !== 12 + count * 72) throw new Error('mhgu_peer_list_length_mismatch');
  return {
    header: Buffer.from(bytes.subarray(0, 12)),
    entries: Array.from({ length: count }, (_, index) => {
      const offset = 12 + index * 72;
      return {
        descriptor: decodeMhPeerDescriptor(bytes.subarray(offset, offset + 70), 'mhgu-v262144'),
        number: bytes[offset + 70], trailingByte: bytes[offset + 71],
      };
    }),
  };
}

export function encodeMhguPeerListBody(value) {
  checkHeader(value?.header);
  if (!Array.isArray(value.entries) || value.entries.length !== value.header[1]) {
    throw new TypeError('mhgu_peer_list_count_mismatch');
  }
  const output = Buffer.alloc(12 + value.entries.length * 72);
  value.header.copy(output);
  for (let index = 0; index < value.entries.length; index++) {
    const entry = value.entries[index];
    if (!entry || !Number.isInteger(entry.number) || entry.number < 0 || entry.number > 255 ||
        !Number.isInteger(entry.trailingByte) || entry.trailingByte < 0 || entry.trailingByte > 255) {
      throw new TypeError('invalid_mhgu_peer_list_entry');
    }
    const offset = 12 + index * 72;
    encodeMhPeerDescriptor(entry.descriptor, 'mhgu-v262144').copy(output, offset);
    output[offset + 70] = entry.number;
    output[offset + 71] = entry.trailingByte;
  }
  return output;
}
