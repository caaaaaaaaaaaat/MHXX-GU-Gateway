// Shared nested framing independently inspected in the two fixed game images.
import { decodeMhxxStreamChunk, assembleMhxxStreamChunks } from './mhxx-stream-chunk.mjs';

function checkProfile(profile) {
  if (profile !== 'mhxx-1.4' && profile !== 'mhgu-v262144') {
    throw new TypeError('unsupported_mh_stream_profile');
  }
}

export function decodeMhStreamChunk(bytes, profile) {
  checkProfile(profile);
  if (profile === 'mhgu-v262144' && Buffer.isBuffer(bytes) && bytes.length >= 24
      && bytes.readUInt16BE(2) > 1416) throw new Error('mhgu_stream_payload_limit');
  return decodeMhxxStreamChunk(bytes, 'mhxx-1.4');
}

// Header is authoritative for flags/sequence/unknown words. Only length changes.
export function encodeMhStreamChunk(value, profile) {
  checkProfile(profile);
  if (!value || !Buffer.isBuffer(value.header) || value.header.length !== 24
      || !Buffer.isBuffer(value.payload) || value.payload.length > 65535) {
    throw new TypeError('mh_stream_header_or_payload');
  }
  if (profile === 'mhgu-v262144' && value.payload.length > 1416) {
    throw new Error('mhgu_stream_payload_limit');
  }
  const output = Buffer.concat([value.header, value.payload]);
  output.writeUInt16BE(value.payload.length, 2);
  return output;
}

export function assembleMhStreamChunks(chunks, profile, startSequence) {
  checkProfile(profile);
  if (!Array.isArray(chunks) || chunks.length < 1 || chunks.length > 64) {
    throw new TypeError('mh_stream_chunk_count');
  }
  // Apply the source build's receive bound before using the shared batch model.
  for (const bytes of chunks) decodeMhStreamChunk(bytes, profile);
  return assembleMhxxStreamChunks(chunks, 'mhxx-1.4', startSequence);
}
