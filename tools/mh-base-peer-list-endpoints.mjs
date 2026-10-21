// Offline partial conversion only. The caller must have established the base-state
// factory for EVERY descriptor (XX 7EC0D8 / GU 139A598), body boundary and session.
// The explicit branch label is an assertion by the caller, not runtime detection.
import { translateMhBasePeerEndpoint } from './mh-base-peer-endpoint.mjs';
import { decodeMhPeerListBody } from './mh-peer-list.mjs';
import { decodeMhPeerListFragment } from './mh-peer-list-fragment.mjs';
import { MhIdentityMap } from './mh-identity.mjs';

function checkContext({ profile, endpointBranch, identityMap, sessionId }) {
  if (profile !== 'mhxx-1.4' && profile !== 'mhgu-v262144') {
    throw new TypeError('mh_base_list_profile');
  }
  if (endpointBranch !== 'base-first-endpoint-a') throw new Error('mh_base_list_requires_explicit_branch');
  if (!(identityMap instanceof MhIdentityMap)) throw new TypeError('mh_base_list_identity_map');
  const direction = profile === 'mhxx-1.4' ? 'mhxx-to-mhgu' : 'mhgu-to-mhxx';
  // Do not bypass session validation on an empty list/fragment.
  identityMap.translate(sessionId, direction, Buffer.alloc(4));
  return profile === 'mhxx-1.4' ? 'mhgu-v262144' : 'mhxx-1.4';
}

export function translateMhBasePeerDescriptorEndpoint(descriptor, options) {
  const profile = checkContext(options);
  const mapped = translateMhBasePeerEndpoint(descriptor, options.profile, options.identityMap, options.sessionId);
  const bytes = Buffer.from(descriptor);
  mapped.bytes.copy(bytes, 0);
  // Unknown words (including wire18/wire53) and other endpoints are NOT converted.
  return { profile, bytes, applicationConverted: false };
}

export function translateMhBasePeerListEndpoints(body, options) {
  const profile = checkContext(options);
  if (!Buffer.isBuffer(body) || body.length < 12) throw new TypeError('mh_base_list_body');
  if (body[0] !== 0x20) throw new Error('mh_base_list_type');
  const decode = body[8] === 1 ? decodeMhPeerListBody
    : body[8] === 2 ? decodeMhPeerListFragment : null;
  if (!decode) throw new Error('mh_base_list_variant');
  const { entries } = decode(body, options.profile);
  const bytes = Buffer.from(body);
  for (let index = 0; index < entries.length; index++) {
    const offset = 12 + index * 72;
    const mapped = translateMhBasePeerDescriptorEndpoint(body.subarray(offset, offset + 70), options);
    mapped.bytes.copy(bytes, offset);
  }
  // Return no partial body on failure; no identity binding or reliability state writes.
  // A fragment remains a fragment with its original slot/count/start and unknown header.
  return { profile, bytes, applicationConverted: false };
}
