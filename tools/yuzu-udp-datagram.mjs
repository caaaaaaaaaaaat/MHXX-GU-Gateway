// SPDX-License-Identifier: GPL-3.0-or-later
// Offline bounded compression composition only. Never sends or authenticates traffic.
import { decodeYuzuUdpProxyPacket, encodeYuzuUdpProxyPacket } from './yuzu-udp-proxy.mjs';
import { decodeBoundedZstdFrame, encodeBoundedZstdFrame } from './zstd-frame.mjs';

export function decodeYuzuUdpProxyDatagram(packet, profile) {
  const decoded = decodeYuzuUdpProxyPacket(packet, profile);
  const datagram = decodeBoundedZstdFrame(decoded.data);
  return {
    profile, header: decoded.header, datagram, compressionValidated: true,
    payloadValidated: false, applicationConverted: false, productionReady: false,
  };
}

export function encodeYuzuUdpProxyDatagram(header, datagram, profile) {
  // Validate explicit target template/profile before attempting compression.
  encodeYuzuUdpProxyPacket(header, Buffer.alloc(0), profile);
  const frame = encodeBoundedZstdFrame(datagram);
  return {
    ...encodeYuzuUdpProxyPacket(header, frame, profile), compressionValidated: true,
  };
}
