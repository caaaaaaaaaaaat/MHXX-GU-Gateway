// Offline body codec for MHXX 1.4 receive entry 7F4734, not a UDP codec.
// Input begins after the outer 20-byte message header. Other header words stay opaque.
export function decodeMhxxStreamChunk(bytes, profile) {
  if (profile !== 'mhxx-1.4') throw new TypeError('unsupported_mhxx_stream_profile');
  if (!Buffer.isBuffer(bytes) || bytes.length < 24) throw new TypeError('mhxx_stream_short_header');
  const length = bytes.readUInt16BE(2);
  if (bytes.length !== 24 + length) throw new Error('mhxx_stream_length');
  const flags = bytes.readUInt16BE(0);
  return { header: Buffer.from(bytes.subarray(0, 24)), payload: Buffer.from(bytes.subarray(24)),
    flags, data: (flags & 1) !== 0, terminal: (flags & 2) !== 0,
    sequence: bytes.readUInt32BE(8) };
}

// Caller associates one peer/session and supplies its known starting sequence.
// Conservative batch policy: <=64 chunks, <=1MiB, no wrap, gaps or conflicting
// duplicates. These limits are library policy, not inferred game capacities.
export function assembleMhxxStreamChunks(chunks, profile, startSequence) {
  if (!Number.isInteger(startSequence) || startSequence < 0 || startSequence > 0xffffffff) {
    throw new TypeError('mhxx_stream_start_sequence');
  }
  if (!Array.isArray(chunks) || chunks.length < 1 || chunks.length > 64) {
    throw new TypeError('mhxx_stream_chunk_count');
  }
  const bySequence = new Map();
  let total = 0;
  for (const bytes of chunks) {
    const chunk = decodeMhxxStreamChunk(bytes, profile);
    if (!chunk.data) throw new Error('mhxx_stream_not_data');
    if (chunk.sequence < startSequence) throw new Error('mhxx_stream_old_or_wrapped');
    const prior = bySequence.get(chunk.sequence);
    if (prior) {
      if (!prior.header.equals(chunk.header) || !prior.payload.equals(chunk.payload)) {
        throw new Error('mhxx_stream_conflicting_duplicate');
      }
      continue;
    }
    total += chunk.payload.length;
    if (total > 1024 * 1024) throw new Error('mhxx_stream_byte_limit');
    bySequence.set(chunk.sequence, chunk);
  }
  const ordered = [...bySequence.values()].sort((a, b) => a.sequence - b.sequence);
  for (let index = 0; index < ordered.length; index++) {
    const chunk = ordered[index];
    if (chunk.sequence !== startSequence + index) throw new Error('mhxx_stream_gap');
    if (chunk.terminal !== (index === ordered.length - 1)) throw new Error('mhxx_stream_terminal_boundary');
  }
  return { headers: ordered.map(chunk => chunk.header), payload: Buffer.concat(ordered.map(chunk => chunk.payload)) };
}
