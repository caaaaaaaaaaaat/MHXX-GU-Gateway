// Offline heartbeat-pair learner for XX/GU MH packet streams (V-242).
// Input: packets already reduced to {kind, sender, seq, rel_time, time_echo}.
// Learns the per-session mirrored heartbeat pair by the measured signature:
//   high frame share + single sender per kind + high-entropy time fields,
//   the two kinds bound to different senders.  Metadata aggregates only.
const prefix = 'mh_heartbeat_pair';

function entropyScore(values) {
  if (values.length === 0) return 0;
  return new Set(values).size / values.length;
}

// packets: array of plain {kind:number, sender:string, seq:string, rel_time:string, time_echo:string}
// options: {minShare (default 0.10), maxSenderKinds? unused, minFrames (default 20), minTimeEntropy (default 0.5)}
export function learnHeartbeatPair(packets, options) {
  if (!Array.isArray(packets) || Object.getPrototypeOf(packets) !== Array.prototype
      || packets.length < 1 || packets.length > 200000) {
    throw new TypeError(prefix + '_packets');
  }
  const opt = { minShare: 0.10, minFrames: 20, minTimeEntropy: 0.3, ...(options ?? {}) };
  if (typeof opt.minShare !== 'number' || opt.minShare <= 0 || opt.minShare >= 1
      || !Number.isInteger(opt.minFrames) || opt.minFrames < 1
      || typeof opt.minTimeEntropy !== 'number' || opt.minTimeEntropy <= 0 || opt.minTimeEntropy >= 1) {
    throw new TypeError(prefix + '_options');
  }
  const total = packets.length;
  const byKind = new Map();
  for (const p of packets) {
    if (!p || typeof p !== 'object' || !Number.isInteger(p.kind) || p.kind < 0 || p.kind > 0xff
        || typeof p.sender !== 'string' || typeof p.seq !== 'string'
        || typeof p.rel_time !== 'string' || typeof p.time_echo !== 'string') {
      throw new TypeError(prefix + '_packet_shape');
    }
    if (!byKind.has(p.kind)) byKind.set(p.kind, []);
    byKind.get(p.kind).push(p);
  }
  // candidate kinds: high frame share AND single sender AND high-entropy time fields.
  const candidates = [];
  for (const [kind, frames] of byKind) {
    const share = frames.length / total;
    if (share < opt.minShare || frames.length < opt.minFrames) continue;
    const senders = new Set(frames.map(f => f.sender));
    if (senders.size !== 1) continue;
    const rt = entropyScore(frames.map(f => f.rel_time));
    const te = entropyScore(frames.map(f => f.time_echo));
    if (Math.min(rt, te) < opt.minTimeEntropy) continue;
    const sender = frames[0].sender;
    candidates.push({ kind, sender, frames: frames.length, share: Number(share.toFixed(4)),
      rel_time_entropy: Number(rt.toFixed(4)), time_echo_entropy: Number(te.toFixed(4)) });
  }
  // pair: exactly two candidates on different senders, or none.
  let pair = null;
  if (candidates.length === 2 && candidates[0].sender !== candidates[1].sender) {
    pair = [candidates[0], candidates[1]];
  }
  return {
    total_packets: total, distinct_kinds: byKind.size, candidates, heartbeat_pair: pair,
    learned: pair !== null,
    scope: 'offline metadata aggregates; heartbeat kinds are per-session values, never static; not a compatibility verdict',
    observationsAuthenticated: false, payloadValidated: false,
    applicationConverted: false, productionReady: false,
  };
}
