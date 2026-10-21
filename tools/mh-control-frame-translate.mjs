// V-257: control-frame translation between XX and GU sessions for the routes
// measured isomorphic on real captures (V-241/V-250/V-254): 0x06000000
// keepalive, 0x02100000, 0x01000000 counter frames.  Structure:
//   12B MH header (magic/mode1/kind) + 20B message header (sender@8..12,
//   route@12..16) + body.
// Translation = sender word substitution (identity table) + kind passthrough
// (identical on both sides for these routes) + body verbatim (the only
// per-side bytes are the trailing local timestamp words, which are host-local
// values and pass through unchanged).  Offline translation only.
import assert from 'node:assert/strict';

const SUPPORTED_ROUTES = new Set([0x06000000, 0x02100000, 0x01000000]);

export function translateControlFrame(packet, { senderFrom, senderTo }) {
  if (!Buffer.isBuffer(packet) || packet.length < 32) throw new TypeError('mh_ctl_packet');
  if (packet.readUInt32BE(0) !== 0x32ab9864) throw new TypeError('mh_ctl_magic');
  if (packet[4] !== 1) throw new TypeError('mh_ctl_mode');
  if (!Buffer.isBuffer(senderFrom) || senderFrom.length !== 4
      || !Buffer.isBuffer(senderTo) || senderTo.length !== 4) {
    throw new TypeError('mh_ctl_sender_shape');
  }
  if (senderFrom.equals(senderTo)) throw new TypeError('mh_ctl_sender_identity');
  const sender = packet.subarray(12 + 8, 12 + 12);
  if (!sender.equals(senderFrom)) throw new TypeError('mh_ctl_sender_not_found');
  const route = packet.readUInt32BE(12 + 12);
  if (!SUPPORTED_ROUTES.has(route)) throw new TypeError('mh_ctl_route');
  const out = Buffer.from(packet);
  senderTo.copy(out, 12 + 8);
  return { packet: out, route: '0x' + route.toString(16).padStart(8, '0'), applicationConverted: false };
}

export function assertSupportedRoute(route) {
  assert(SUPPORTED_ROUTES.has(route), 'mh_ctl_route');
}
