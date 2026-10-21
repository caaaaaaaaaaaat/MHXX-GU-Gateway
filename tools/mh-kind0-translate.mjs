// V-249: field-level translation for kind-0 session-announce packets between
// MHXX (UDS) and MHGU (LDN) on the MEASURED routes (V-241/V-242 real captures):
//   route 0x03003039  member/port announce (contains plain fake-IP:port pairs)
//   route 0x02000000  member address pairs (same structure, terminal flag)
//   route 0x01000000  counter + word (kept verbatim)
//   route 0x06000000  keepalive (kept verbatim)
// Identity substitution: every 4-byte fake-IP word found in the body that
// matches a table entry is rewritten to the counterpart word (V-241: identity
// is fake-IP derived on both sides).  Everything else is byte-preserved.
// Offline metadata/structure translation only; never a compatibility verdict.
const KIND0 = 0;

export function translateKind0Body(body, identityPairs) {
  if (!Buffer.isBuffer(body)) throw new TypeError('mh_kind0_body');
  if (!Array.isArray(identityPairs)) throw new TypeError('mh_kind0_pairs');
  if (identityPairs.length === 0 || identityPairs.length > 4) {
    throw new TypeError('mh_kind0_pairs_range');
  }
  const table = [];
  for (const pair of identityPairs) {
    if (!pair || typeof pair !== 'object' || !Buffer.isBuffer(pair.from) || !Buffer.isBuffer(pair.to)
        || pair.from.length !== 4 || pair.to.length !== 4) {
      throw new TypeError('mh_kind0_pair_shape');
    }
    if (pair.from.equals(pair.to)) throw new TypeError('mh_kind0_pair_identity');
    table.push({ from: pair.from, to: Buffer.from(pair.to) });
  }
  // ambiguity guard: two "from" words must differ
  for (let i = 0; i < table.length; i++) {
    for (let j = i + 1; j < table.length; j++) {
      if (table[i].from.equals(table[j].from)) throw new TypeError('mh_kind0_pair_duplicate');
    }
  }
  const out = Buffer.from(body);
  let replacements = 0;
  const hits = [];
  for (let i = 0; i + 4 <= out.length; i++) {
    for (const pair of table) {
      if (out.subarray(i, i + 4).equals(pair.from)) {
        pair.to.copy(out, i);
        ++replacements;
        hits.push({ offset: i, from: pair.from.toString('hex'), to: pair.to.toString('hex') });
        break;
      }
    }
  }
  return { body: out, replacements, hits, applicationConverted: false };
}

export function translateKind0Packet(packet, identityPairs, expectedKind = KIND0) {
  if (!Buffer.isBuffer(packet) || packet.length < 32) throw new TypeError('mh_kind0_packet');
  if (packet.readUInt32BE(0) !== 0x32ab9864) throw new TypeError('mh_kind0_magic');
  if (packet[4] !== 1) throw new TypeError('mh_kind0_mode');
  if (packet[5] !== expectedKind) throw new TypeError('mh_kind0_kind');
  // The kind-0 announce is a single message: header 20B at offset 12.
  const route = packet.readUInt32BE(12 + 12);
  const supported = new Set([0x03003039, 0x02000000, 0x01000000, 0x06000000]);
  if (!supported.has(route)) throw new TypeError('mh_kind0_route');
  const bodyStart = 12 + 20;
  const body = packet.subarray(bodyStart);
  const translated = translateKind0Body(body, identityPairs);
  const out = Buffer.from(packet);
  translated.body.copy(out, bodyStart);
  return { route: '0x' + route.toString(16).padStart(8, '0'),
    replacements: translated.replacements, hits: translated.hits,
    packet: out, applicationConverted: false };
}
