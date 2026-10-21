// Shared framing only, independently inspected in both fixed game images.
import { decodeMhguPeerDescriptor, encodeMhguPeerDescriptor } from './mhgu-peer-descriptor.mjs';

function checkProfile(profile) {
  if (profile !== 'mhxx-1.4' && profile !== 'mhgu-v262144') {
    throw new TypeError('unsupported_mh_peer_descriptor_profile');
  }
}

export function decodeMhPeerDescriptor(bytes, profile) {
  checkProfile(profile);
  return decodeMhguPeerDescriptor(bytes);
}

export function encodeMhPeerDescriptor(records, profile) {
  checkProfile(profile);
  return encodeMhguPeerDescriptor(records);
}
