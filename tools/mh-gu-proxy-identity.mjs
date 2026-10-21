// Offline identity-only layer composition. No network, authentication or lifecycle inference.
import { decodeYuzuUdpProxyDatagram, encodeYuzuUdpProxyDatagram } from './yuzu-udp-datagram.mjs';
import { encodeYuzuUdpProxyPacket } from './yuzu-udp-proxy.mjs';
import { translateMhPacketStreamIdentities } from './mh-packet-identity.mjs';

// GU source is a complete Room IdProxyPacket event, NOT an ENet/UDP wire packet.
// Output is a raw MHXX packet, NOT a Citra/UDS transport frame.
export function translateMhguProxyToMhxx(packet, {
  proxyProfile, targetHeader, expectedRouteKey, identityMap, sessionId, sourceKey, targetKey,
}) {
  const decoded = decodeYuzuUdpProxyDatagram(packet, proxyProfile);
  const translated = translateMhPacketStreamIdentities(decoded.datagram, {
    profile: 'mhgu-v262144', targetHeader, expectedRouteKey, identityMap, sessionId, sourceKey, targetKey,
  });
  return {
    ...translated, sourceProxyProfile: proxyProfile, outputLayer: 'mh-packet',
    compressionValidated: true, payloadValidated: false, productionReady: false,
  };
}

// Input is a raw MHXX packet extracted by the caller from a verified transport.
// Both the target MH header and the target Room header are independent caller inputs.
export function translateMhxxToMhguProxy(packet, {
  proxyProfile, targetProxyHeader, targetHeader, expectedRouteKey, identityMap, sessionId, sourceKey, targetKey,
}) {
  // Validate the explicit target envelope even for empty MH packets; never copy a source header.
  encodeYuzuUdpProxyPacket(targetProxyHeader, Buffer.alloc(0), proxyProfile);
  const translated = translateMhPacketStreamIdentities(packet, {
    profile: 'mhxx-1.4', targetHeader, expectedRouteKey, identityMap, sessionId, sourceKey, targetKey,
  });
  const encoded = encodeYuzuUdpProxyDatagram(targetProxyHeader, translated.bytes, proxyProfile);
  return {
    ...encoded, profile: translated.profile, targetProxyProfile: proxyProfile,
    outputLayer: 'yuzu-room-udp-proxy',
  };
}
