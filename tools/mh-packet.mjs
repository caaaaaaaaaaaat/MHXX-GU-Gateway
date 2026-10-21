// Offline packet framing for fixed images. Successful framing is not successful
// application conversion or authentication; callers own peer/session binding.
import { encryptMhPacketBody, decryptMhPacketBody } from './mh-packet-transform.mjs';

function checkProfile(profile) {
  if (profile !== 'mhxx-1.4' && profile !== 'mhgu-v262144') throw new TypeError('mh_packet_profile');
}

function checkHeader(header) {
  if (!Buffer.isBuffer(header) || header.length !== 12) throw new TypeError('mh_packet_header12');
  if (header.readUInt32BE(0) !== 0x32ab9864) throw new Error('mh_packet_magic');
  if (header[4] !== 1 && header[4] !== 2) throw new Error('mh_packet_mode');
}

function splitBody(body) {
  if (body.length > 1460) throw new Error('mh_packet_body_limit');
  const messages = [];
  for (let offset = 0; offset < body.length;) {
    if (body[offset] === 255) {
      return { messages, trailer: Buffer.from(body.subarray(offset)), termination: 'sentinel' };
    }
    if (offset + 20 > body.length) throw new Error('mh_packet_short_message_header');
    const stride = Math.ceil((20 + body.readUInt16BE(offset + 2)) / 4) * 4;
    if (offset + stride > body.length) throw new Error('mh_packet_message_length_or_alignment');
    messages.push(Buffer.from(body.subarray(offset, offset + stride)));
    offset += stride;
  }
  return { messages, trailer: Buffer.alloc(0), termination: 'exact_end' };
}

export function decodeMhPacket(packet, profile, key) {
  checkProfile(profile);
  if (!Buffer.isBuffer(packet) || packet.length < 12) throw new TypeError('mh_packet_short_header');
  const header = Buffer.from(packet.subarray(0, 12));
  checkHeader(header);
  if (packet.length > 1472) throw new Error('mh_packet_body_limit');
  const body = header[4] === 2 ? decryptMhPacketBody(packet.subarray(12), key, profile)
    : Buffer.from(packet.subarray(12));
  return { header, body, ...splitBody(body) };
}

export function encodeMhPacket({header, messages, trailer = Buffer.alloc(0)}, profile, key) {
  checkProfile(profile);
  checkHeader(header);
  if (!Array.isArray(messages) || messages.length > 73) throw new TypeError('mh_packet_messages');
  if (!Buffer.isBuffer(trailer) || (trailer.length && trailer[0] !== 255)) throw new TypeError('mh_packet_trailer');
  let total = trailer.length;
  for (const message of messages) {
    if (!Buffer.isBuffer(message) || message.length < 20 || message[0] === 255) throw new TypeError('mh_packet_message');
    if (message.length !== Math.ceil((20 + message.readUInt16BE(2)) / 4) * 4) throw new Error('mh_packet_message_length_or_alignment');
    total += message.length;
    if (total > 1460) throw new Error('mh_packet_body_limit');
  }
  if (total > 1460) throw new Error('mh_packet_body_limit');
  const body = Buffer.concat([...messages, trailer]);
  const wireBody = header[4] === 2 ? encryptMhPacketBody(body, key, profile) : body;
  return Buffer.concat([header, wireBody]);
}
