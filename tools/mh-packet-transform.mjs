// Fixed XX1.4/GU-v262144 packet-body transform (V203/V204). Explicit key only.
// Does not handle packet headers, derive keys, or authenticate peer/session.
import { createCipheriv, createDecipheriv } from 'node:crypto';

function validate(body, key, profile) {
  if (profile !== 'mhxx-1.4' && profile !== 'mhgu-v262144') {
    throw new TypeError('unsupported_mh_packet_transform_profile');
  }
  if (!Buffer.isBuffer(body)) throw new TypeError('mhgu_transform_body');
  if (!Buffer.isBuffer(key) || key.length !== 16) throw new TypeError('mhgu_transform_key16');
  // Both images allow raw body <=1460 and rounded body <=1460; aligned max1456.
  if (body.length > 1456) throw new Error('mhgu_transform_body_limit');
}

export function encryptMhPacketBody(body, key, profile) {
  validate(body, key, profile);
  const padded = Buffer.alloc(Math.ceil(body.length / 16) * 16, 0xff);
  body.copy(padded);
  const cipher = createCipheriv('aes-128-ecb', key, null);
  cipher.setAutoPadding(false);
  return Buffer.concat([cipher.update(padded), cipher.final()]);
}

export function decryptMhPacketBody(body, key, profile) {
  validate(body, key, profile);
  if (body.length % 16 !== 0) throw new Error('mhgu_transform_block_alignment');
  const cipher = createDecipheriv('aes-128-ecb', key, null);
  cipher.setAutoPadding(false);
  // Decrypted FF padding remains available to the inner sentinel parser.
  return Buffer.concat([cipher.update(body), cipher.final()]);
}
