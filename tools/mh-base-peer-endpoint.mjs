// Offline base-state branch only (XX 7EC0D8, GU 139A598).
// Caller must establish that its session uses this factory; no mode detection.
import { decodeMhPeerDescriptor } from './mh-peer-descriptor.mjs';
import { MhIdentityMap } from './mh-identity.mjs';
import { decodeMhxxEndpoint } from './mhxx-endpoint.mjs';

export function selectMhBasePeerEndpoint(descriptor, profile) {
  return decodeMhPeerDescriptor(descriptor, profile)[0].endpointA;
}

// Translate only the selected endpoint, never the complete descriptor or its
// opaque words. Evidence-backed bindings must already exist in the identity map.
export function translateMhBasePeerEndpoint(descriptor, profile, identities, sessionId) {
  selectMhBasePeerEndpoint(descriptor, profile);
  if (!(identities instanceof MhIdentityMap)) throw new TypeError('mh_endpoint_requires_identity_map');
  if (descriptor.readUInt32BE(0) === 0 || descriptor.readUInt16BE(4) !== 12345) {
    throw new Error('mh_endpoint_requires_bound_port12345');
  }
  const direction = profile === 'mhxx-1.4' ? 'mhxx-to-mhgu' : 'mhgu-to-mhxx';
  const output = Buffer.from(descriptor.subarray(0, 6));
  identities.translate(sessionId, direction, output.subarray(0, 4)).copy(output);
  return { profile: profile === 'mhxx-1.4' ? 'mhgu-v262144' : 'mhxx-1.4',
    endpoint: decodeMhxxEndpoint(output), bytes: output };
}
