// Only the copy/order/fallback stage at 0x796A90..0x796AFC, not full initialization.
import { decodeMhPeerDescriptor } from './mh-peer-descriptor.mjs';

export function prepareMhxxDerivedWorkingDescriptor(bytes, profile) {
  if (profile !== 'mhxx-1.4') throw new TypeError('unsupported_mhxx_working_descriptor_profile');
  decodeMhPeerDescriptor(bytes, profile); // Exact size/type validation before reading offsets.
  const output = (bytes[27] & 2) !== 0
    ? Buffer.from(bytes)
    : Buffer.concat([bytes.subarray(35, 70), bytes.subarray(0, 35)]);
  for (const offset of [26, 25, 27]) {
    if (output[offset] === 0) output[offset] = output[offset + 35];
  }
  return output;
}
