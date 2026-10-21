// GU v262144 body transform only (V203). Does not derive keys, authenticate a
// session, process the 12-byte packet header or enable production forwarding.
import { encryptMhPacketBody, decryptMhPacketBody } from './mh-packet-transform.mjs';

function validateProfile(profile) {
  if (profile !== 'mhgu-v262144') throw new TypeError('unsupported_mhgu_transform_profile');
}

export function encryptMhguPacketBody(body, key, profile) {
  validateProfile(profile);
  return encryptMhPacketBody(body, key, profile);
}

export function decryptMhguPacketBody(body, key, profile) {
  validateProfile(profile);
  return decryptMhPacketBody(body, key, profile);
}
