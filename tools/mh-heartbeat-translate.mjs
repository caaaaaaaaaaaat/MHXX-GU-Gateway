// V-251: heartbeat frame translation between XX and GU sessions.
// Measured basis (V-242/V-243/V-250): heartbeat kinds are PER-SESSION random
// values on both wires (XX: 0xA0/0xDA, 0x1A/0xEF, 0xDA/0xDF; GU: 0x23/0xCC,
// 0x60/0x73 across five observed sessions), each kind bound to exactly one
// sender, +8/+10 are high-entropy time words with UNPROVEN semantics --
// they are passed through verbatim, never regenerated.
// The kind mapping (kindFrom -> kindTo) and the sender mapping come from the
// session-scoped learner + identity table; this primitive does NO learning.
// Offline metadata translation only; never a compatibility verdict.

export function translateHeartbeatPacket(packet, options) {
  const opts = options ?? {};
  if (!Buffer.isBuffer(packet) || packet.length < 32) {
    throw new TypeError('mh_hb_packet');
  }
  if (packet.readUInt32BE(0) !== 0x32ab9864) throw new TypeError('mh_hb_magic');
  if (packet[4] !== 1) throw new TypeError('mh_hb_mode');
  const kindFrom = opts.kindFrom;
  const kindTo = opts.kindTo;
  if (!Number.isInteger(kindFrom) || kindFrom < 0 || kindFrom > 0xff
      || !Number.isInteger(kindTo) || kindTo < 0 || kindTo > 0xff) {
    throw new TypeError('mh_hb_kind_options');
  }
  if (packet[5] !== kindFrom) throw new TypeError('mh_hb_kind_mismatch');
  if (!Buffer.isBuffer(opts.senderFrom) || opts.senderFrom.length !== 4
      || !Buffer.isBuffer(opts.senderTo) || opts.senderTo.length !== 4) {
    throw new TypeError('mh_hb_sender_options');
  }
  if (opts.senderFrom.equals(opts.senderTo)) throw new TypeError('mh_hb_sender_identity');
  const out = Buffer.from(packet);
  out[5] = kindTo;
  // sender lives in the first message header at packet offset 20..24
  const senderIndex = out.indexOf(opts.senderFrom, 20);
  if (senderIndex < 0) throw new TypeError('mh_hb_sender_not_found');
  opts.senderTo.copy(out, senderIndex);
  // +8/+10 time words pass through verbatim (semantics unproven, V-242).
  return { packet: out, applicationConverted: false };
}
