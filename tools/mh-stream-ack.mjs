// Offline ACK phase only, based on V185..V187; no timers, sends or session state.
import { decodeMhStreamChunk } from './mh-stream-chunk.mjs';
export const MH_STREAM_MAX_TIME = 0xffffffffffffffffn;

export function applyMhStreamAck(state, bytes, profile) {
  const chunk = decodeMhStreamChunk(bytes, profile);
  if (!state || !Number.isInteger(state.base) || state.base < 0 || state.base > 0xffffffff
      || !Array.isArray(state.schedules) || state.schedules.length > 64
      || state.base + state.schedules.length > 0xffffffff
      || Array.from(state.schedules).some(value => typeof value !== 'bigint' || value < 0n || value > MH_STREAM_MAX_TIME)) {
    throw new TypeError('mh_ack_invalid_window');
  }
  const acknowledgement = chunk.header.readUInt32BE(12);
  const bitmap = chunk.header.readBigUInt64BE(16);
  const delta = (acknowledgement - state.base) | 0;
  // ARM signed subtraction result: stale ACK skips both ACK phases.
  if (delta < 0) return { base: state.base, schedules: [...state.schedules], released: 0, stale: true };
  if (delta > state.schedules.length) throw new Error('mh_ack_beyond_outstanding');
  const schedules = state.schedules.slice(delta);
  for (let index = 1; index < schedules.length; index++) {
    if ((bitmap & (1n << BigInt(index - 1))) !== 0n) schedules[index] = MH_STREAM_MAX_TIME;
  }
  return { base: acknowledgement, schedules, released: delta, stale: false };
}

export function isMhStreamScheduleDue(now, due) {
  for (const value of [now, due]) {
    if (typeof value !== 'bigint' || value < 0n || value > MH_STREAM_MAX_TIME) {
      throw new TypeError('mh_stream_invalid_time');
    }
  }
  return now >= due;
}
