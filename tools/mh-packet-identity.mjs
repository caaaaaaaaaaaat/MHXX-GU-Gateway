// Offline identity-only composition, NOT complete application conversion.
// Caller supplies the target packet header and owns authenticated peer/session,
// route association, packet counters and reliable-stream state.
import { decodeMhPacket, encodeMhPacket } from './mh-packet.mjs';
import { translateMhStreamMessageIdentity } from './mh-system-stream.mjs';
import { MhIdentityMap } from './mh-identity.mjs';

export function translateMhPacketStreamIdentities(packet, {
  profile, targetHeader, expectedRouteKey, identityMap, sessionId, sourceKey, targetKey,
}) {
  if (profile !== 'mhxx-1.4' && profile !== 'mhgu-v262144') throw new TypeError('mh_packet_identity_profile');
  if (!(identityMap instanceof MhIdentityMap)) throw new TypeError('mh_packet_identity_map');
  if (!Number.isInteger(expectedRouteKey) || expectedRouteKey < 0 || expectedRouteKey > 0xffffffff) {
    throw new TypeError('mh_packet_identity_route');
  }
  // Check the session even for an empty/sentinel-only packet. Zero does not bind
  // a peer, but the map still rejects a stale session before returning it.
  const direction = profile === 'mhxx-1.4' ? 'mhxx-to-mhgu' : 'mhgu-to-mhxx';
  identityMap.translate(sessionId, direction, Buffer.alloc(4));
  const targetProfile = profile === 'mhxx-1.4' ? 'mhgu-v262144' : 'mhxx-1.4';
  // Validate explicit target header/mode/key without copying source counters.
  encodeMhPacket({ header: targetHeader, messages: [] }, targetProfile, targetKey);
  const decoded = decodeMhPacket(packet, profile, sourceKey);
  const messages = decoded.messages.map(message =>
    translateMhStreamMessageIdentity(message, profile, expectedRouteKey, identityMap, sessionId).bytes);
  const bytes = encodeMhPacket({ header: targetHeader, messages, trailer: decoded.trailer }, targetProfile, targetKey);
  return { profile: targetProfile, bytes, applicationConverted: false };
}
