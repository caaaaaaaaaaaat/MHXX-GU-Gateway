// Offline stream -> complete system body -> typed list pipeline (V183).
import { assembleMhStreamChunks, encodeMhStreamChunk, decodeMhStreamChunk } from './mh-stream-chunk.mjs';
import { MhIdentityMap } from './mh-identity.mjs';
import { decodeMhPeerListBody } from './mh-peer-list.mjs';
import { decodeMhPeerListFragment } from './mh-peer-list-fragment.mjs';

// Maps only the original identity in the outer message header, never the relay
// sender or identities embedded in its body. Caller associates peer/session.
export function translateMhStreamMessageIdentity(message, profile, expectedRouteKey, identityMap, sessionId) {
  if (!Number.isInteger(expectedRouteKey) || expectedRouteKey < 0 || expectedRouteKey > 0xffffffff) {
    throw new TypeError('mh_system_expected_route');
  }
  if (!Buffer.isBuffer(message) || message.length < 20 || message[0] === 0xff) {
    throw new TypeError('mh_system_invalid_outer_message');
  }
  const length = message.readUInt16BE(2);
  if (message.length !== Math.ceil((20 + length) / 4) * 4) throw new Error('mh_system_outer_length');
  if (message.readUInt32BE(12) !== expectedRouteKey) throw new Error('mh_system_route_mismatch');
  const body = message.subarray(20, 20 + length);
  decodeMhStreamChunk(body, profile);
  const targetProfile = profile === 'mhxx-1.4' ? 'mhgu-v262144' : 'mhxx-1.4';
  // This primitive cannot split a block or invent new reliability state.
  decodeMhStreamChunk(body, targetProfile);
  if (!(identityMap instanceof MhIdentityMap)) throw new TypeError('mh_system_identity_map');
  const direction = profile === 'mhxx-1.4' ? 'mhxx-to-mhgu' : 'mhgu-to-mhxx';
  const identity = identityMap.translate(sessionId, direction, message.subarray(8, 12));
  const bytes = Buffer.from(message);
  identity.copy(bytes, 8);
  return { profile: targetProfile, bytes };
}

// Rebuild one already-associated stream message. Caller owns sequence/ACK state;
// this does not allocate a channel, translate identities or frame a datagram.
export function encodeMhStreamMessage({ outerHeader, streamHeader, payload }, profile, expectedRouteKey) {
  if (!Number.isInteger(expectedRouteKey) || expectedRouteKey < 0 || expectedRouteKey > 0xffffffff) {
    throw new TypeError('mh_system_expected_route');
  }
  if (!Buffer.isBuffer(outerHeader) || outerHeader.length !== 20 || outerHeader[0] === 0xff) {
    throw new TypeError('mh_system_invalid_outer_message');
  }
  if (outerHeader.readUInt32BE(12) !== expectedRouteKey) throw new Error('mh_system_route_mismatch');
  const body = encodeMhStreamChunk({ header: streamHeader, payload }, profile);
  if (body.length > 0xffff) throw new Error('mh_system_outer_length');
  const message = Buffer.alloc(Math.ceil((20 + body.length) / 4) * 4);
  outerHeader.copy(message);
  message.writeUInt16BE(body.length, 2);
  body.copy(message, 20);
  return message;
}

export function recoverMhPeerListFromStream(chunks, profile, startSequence) {
  const { headers, payload } = assembleMhStreamChunks(chunks, profile, startSequence);
  if (payload.length < 12) throw new Error('mh_system_short_list');
  if (payload[0] !== 0x20) throw new Error('mh_system_unsupported_type');
  if (payload[8] === 1) {
    return { kind: 'peer-list', streamHeaders: headers, body: payload,
      list: decodeMhPeerListBody(payload, profile) };
  }
  if (payload[8] === 2) {
    return { kind: 'peer-list-fragment', streamHeaders: headers, body: payload,
      fragment: decodeMhPeerListFragment(payload, profile) };
  }
  throw new Error('mh_system_unsupported_list_variant');
}

// Inputs are already separated, aligned 20-byte-header messages, not datagrams.
// Caller provides one verified route and associates the same peer/session.
export function recoverMhPeerListFromMessages(messages, profile, startSequence, expectedRouteKey) {
  if (!Number.isInteger(expectedRouteKey) || expectedRouteKey < 0 || expectedRouteKey > 0xffffffff) {
    throw new TypeError('mh_system_expected_route');
  }
  if (!Array.isArray(messages) || messages.length < 1 || messages.length > 64) {
    throw new TypeError('mh_system_message_count');
  }
  const outerHeaders = [];
  const chunks = messages.map(message => {
    if (!Buffer.isBuffer(message) || message.length < 20 || message[0] === 0xff) {
      throw new TypeError('mh_system_invalid_outer_message');
    }
    const length = message.readUInt16BE(2);
    if (message.length !== Math.ceil((20 + length) / 4) * 4) throw new Error('mh_system_outer_length');
    if (message.readUInt32BE(12) !== expectedRouteKey) throw new Error('mh_system_route_mismatch');
    outerHeaders.push(Buffer.from(message.subarray(0, 20)));
    return message.subarray(20, 20 + length);
  });
  return { ...recoverMhPeerListFromStream(chunks, profile, startSequence), outerHeaders };
}
