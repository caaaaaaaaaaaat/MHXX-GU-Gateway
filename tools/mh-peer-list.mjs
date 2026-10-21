// Offline exact-body representation. Callers must already know the body boundary.
import { decodeMhguPeerListBody, encodeMhguPeerListBody } from './mhgu-peer-list.mjs';

function checkProfile(profile) {
  if (profile !== 'mhxx-1.4' && profile !== 'mhgu-v262144') {
    throw new TypeError('unsupported_mh_peer_list_profile');
  }
}

export function decodeMhPeerListBody(bytes, profile) {
  checkProfile(profile);
  return decodeMhguPeerListBody(bytes);
}

export function encodeMhPeerListBody(value, profile) {
  checkProfile(profile);
  return encodeMhguPeerListBody(value);
}
