// SPDX-License-Identifier: GPL-3.0-or-later
// Offline opaque envelope codec and reference-profile enum translation only.
// Not a game/room protocol bridge; data is not decoded or authenticated.
function profileValues(profile) {
  if (profile === 'yuzu-2022-7edc31be2') return { family: 0, udp: 2 };
  if (profile === 'yuzu-mirror-01052024') return { family: 1, udp: 3 };
  throw new Error('yuzu_udp_proxy_profile');
}

function validatePacket(packet, profile) {
  const source = profileValues(profile);
  // 64 KiB is a conservative tooling bound, not an emulator/game capacity claim.
  if (!Buffer.isBuffer(packet) || packet.length < 21 || packet.length > 21 + 65536) {
    throw new Error('yuzu_udp_proxy_size');
  }
  if (packet[0] !== 5 || packet.readUInt32BE(17) !== packet.length - 21) {
    throw new Error('yuzu_udp_proxy_envelope');
  }
  if (packet[1] !== source.family || packet[8] !== source.family || packet[15] !== source.udp) {
    throw new Error('yuzu_udp_proxy_source_enums');
  }
}

// header includes the wire length field, useful for exact decode/encode roundtrips.
// Encoder treats it as a template and ALWAYS recomputes that field from data.
export function decodeYuzuUdpProxyPacket(packet, profile) {
  validatePacket(packet, profile);
  return {
    profile, header: Buffer.from(packet.subarray(0, 21)), data: Buffer.from(packet.subarray(21)),
    payloadValidated: false, applicationConverted: false, productionReady: false,
  };
}

export function encodeYuzuUdpProxyPacket(header, data, profile) {
  profileValues(profile);
  if (!Buffer.isBuffer(header) || header.length !== 21) throw new Error('yuzu_udp_proxy_header');
  if (!Buffer.isBuffer(data) || data.length > 65536) throw new Error('yuzu_udp_proxy_data');
  const bytes = Buffer.concat([header, data]);
  bytes.writeUInt32BE(data.length, 17);
  validatePacket(bytes, profile);
  return {
    profile, bytes,
    payloadValidated: false, applicationConverted: false, productionReady: false,
  };
}

export function translateYuzuUdpProxyProfile(packet, sourceProfile, targetProfile) {
  profileValues(sourceProfile);
  const target = profileValues(targetProfile);
  validatePacket(packet, sourceProfile);
  const bytes = Buffer.from(packet);
  bytes[1] = target.family;
  bytes[8] = target.family;
  bytes[15] = target.udp;
  return {
    profile: targetProfile, bytes,
    payloadValidated: false, applicationConverted: false, productionReady: false,
  };
}
