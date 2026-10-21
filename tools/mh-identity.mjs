// Offline, session-scoped identity mapping. GU values must come from verified
// wire evidence or the explicit, statically checked build profile below.
// This module does not emit packets.
import { deriveMhxxUdsEndpoint, encodeMhxxEndpoint } from './mhxx-endpoint.mjs';

// Normal-order RoomMember fake IP, NOT reversed LDN NodeInfo/IPC raw bytes.
// V-140: fixed 2022 service reverses IPC bytes; SDK copies them unchanged;
// main reads LE32 and serializes BE32, restoring normal-order fake IP bytes.
export function mhguLdnIdentityFromFakeIp(fakeIpBytes, emulatorProfile) {
  if (emulatorProfile !== 'yuzu-2022-7edc31be2') {
    throw new TypeError('unsupported_mhgu_identity_profile');
  }
  if (!Buffer.isBuffer(fakeIpBytes) || fakeIpBytes.length !== 4) {
    throw new TypeError('mhgu_fake_ip_requires_four_bytes');
  }
  return Buffer.from(fakeIpBytes);
}

function checkSessionId(value) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 128) {
    throw new TypeError('invalid_mh_identity_session');
  }
}

export class MhIdentityMap {
  #sessionId;
  #forward = new Map();
  #reverse = new Map();

  constructor(sessionId) {
    checkSessionId(sessionId);
    this.#sessionId = sessionId;
  }

  #checkSession(sessionId) {
    if (sessionId !== this.#sessionId) throw new Error('mh_identity_session_mismatch');
  }

  // A reset invalidates all previous bindings, even if the label is reused.
  reset(sessionId) {
    checkSessionId(sessionId);
    this.#sessionId = sessionId;
    this.#forward.clear();
    this.#reverse.clear();
  }

  get size() { return this.#forward.size; }

  unbind(sessionId, seedBytes) {
    this.#checkSession(sessionId);
    const xx = encodeMhxxEndpoint(deriveMhxxUdsEndpoint(seedBytes)).readUInt32BE(0);
    const old = this.#forward.get(xx);
    if (!old) return false;
    if (!old.seed.equals(seedBytes)) throw new Error('mh_identity_seed_crc_collision');
    this.#forward.delete(xx);
    this.#reverse.delete(old.gu);
    return true;
  }

  bind(sessionId, seedBytes, guIdentityBytes) {
    this.#checkSession(sessionId);
    // deriveMhxxUdsEndpoint enforces exactly eight original LE64 seed bytes.
    const xx = encodeMhxxEndpoint(deriveMhxxUdsEndpoint(seedBytes)).readUInt32BE(0);
    if (!Buffer.isBuffer(guIdentityBytes) || guIdentityBytes.length !== 4) {
      throw new TypeError('mhgu_wire_identity_requires_four_bytes');
    }
    const gu = guIdentityBytes.readUInt32BE(0);
    // Zero is a valid unbound/default message identity, so cannot also name a
    // peer in this table. Reject ambiguous evidence rather than overriding it.
    if (xx === 0 || gu === 0) throw new Error('mh_identity_zero_binding');
    const old = this.#forward.get(xx);
    if (old && !old.seed.equals(seedBytes)) throw new Error('mh_identity_seed_crc_collision');
    if (old && old.gu !== gu) throw new Error('mh_identity_peer_rebind');
    if (this.#reverse.has(gu) && this.#reverse.get(gu) !== xx) {
      throw new Error('mh_identity_gu_collision');
    }
    if (!old && this.#forward.size >= 4) throw new Error('mh_identity_game_capacity');
    if (!old) {
      this.#forward.set(xx, { gu, seed: Buffer.from(seedBytes) });
      this.#reverse.set(gu, xx);
    }
  }

  translate(sessionId, direction, identityBytes) {
    this.#checkSession(sessionId);
    if (direction !== 'mhxx-to-mhgu' && direction !== 'mhgu-to-mhxx') {
      throw new TypeError('invalid_mh_identity_direction');
    }
    if (!Buffer.isBuffer(identityBytes) || identityBytes.length !== 4) {
      throw new TypeError('mh_wire_identity_requires_four_bytes');
    }
    const input = identityBytes.readUInt32BE(0);
    if (input === 0) return Buffer.alloc(4);
    const mapped = direction === 'mhxx-to-mhgu'
      ? this.#forward.get(input)?.gu : this.#reverse.get(input);
    if (mapped === undefined) throw new Error('mh_identity_unmapped');
    const output = Buffer.alloc(4);
    output.writeUInt32BE(mapped);
    return output;
  }
}
