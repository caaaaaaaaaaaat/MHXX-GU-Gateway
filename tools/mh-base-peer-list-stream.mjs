// Offline conditional base-endpoint mapping of ONE complete typed system body.
// Checked-sender variant verifies byte correspondence, NOT session authentication.
// No stream state allocation, transport framing, authentication or branch detection.
import { recoverMhPeerListFromMessages, encodeMhStreamMessage } from './mh-system-stream.mjs';
import { translateMhBasePeerListEndpoints } from './mh-base-peer-list-endpoints.mjs';
import { MhIdentityMap } from './mh-identity.mjs';

export function translateMhBasePeerListStream(messages, {
  profile, sourceStartSequence, sourceRouteKey, endpointBranch, identityMap, sessionId,
  targetStartSequence, targetRouteKey, targetPlan,
}) {
  if (!Number.isInteger(targetStartSequence) || targetStartSequence < 0 || targetStartSequence > 0xffffffff) {
    throw new TypeError('mh_base_stream_target_start');
  }
  if (!Array.isArray(targetPlan) || targetPlan.length < 1 || targetPlan.length > 64) {
    throw new TypeError('mh_base_stream_target_plan');
  }
  const recovered = recoverMhPeerListFromMessages(messages, profile, sourceStartSequence, sourceRouteKey);
  const mapped = translateMhBasePeerListEndpoints(recovered.body, {profile, endpointBranch, identityMap, sessionId});
  let offset = 0;
  const output = [];
  for (let index = 0; index < targetPlan.length; index++) {
    const item = targetPlan[index];
    if (!Object.hasOwn(targetPlan, index) || !item || !Number.isInteger(item.payloadLength)
        || item.payloadLength < 0 || item.payloadLength > mapped.bytes.length - offset) {
      throw new TypeError('mh_base_stream_target_length');
    }
    if (!Buffer.isBuffer(item.streamHeader) || item.streamHeader.length !== 24
        || item.streamHeader.readUInt32BE(8) !== targetStartSequence + index) {
      throw new Error('mh_base_stream_target_sequence');
    }
    output.push(encodeMhStreamMessage({
      outerHeader: item.outerHeader, streamHeader: item.streamHeader,
      payload: mapped.bytes.subarray(offset, offset + item.payloadLength),
    }, mapped.profile, targetRouteKey));
    offset += item.payloadLength;
  }
  if (offset !== mapped.bytes.length) throw new Error('mh_base_stream_target_total');
  // Validate flags, terminal boundary, target profile and full typed body again.
  const target = recoverMhPeerListFromMessages(output, mapped.profile, targetStartSequence, targetRouteKey);
  if (!target.body.equals(mapped.bytes)) throw new Error('mh_base_stream_target_body');
  return {
    profile: mapped.profile, kind: recovered.kind, body: Buffer.from(mapped.bytes), messages: output,
    payloadValidated: false, applicationConverted: false, productionReady: false,
  };
}

export function translateMhBasePeerListStreamCheckedSender(messages, { sourceSenderIdentity, ...options }) {
  if (options.profile !== 'mhxx-1.4' && options.profile !== 'mhgu-v262144') {
    throw new TypeError('mh_base_stream_sender_profile');
  }
  if (!(options.identityMap instanceof MhIdentityMap)) throw new TypeError('mh_base_stream_sender_map');
  if (!Buffer.isBuffer(sourceSenderIdentity) || sourceSenderIdentity.length !== 4) {
    throw new TypeError('mh_base_stream_sender_identity');
  }
  const direction = options.profile === 'mhxx-1.4' ? 'mhxx-to-mhgu' : 'mhgu-to-mhxx';
  const expectedTarget = options.identityMap.translate(options.sessionId, direction, sourceSenderIdentity);
  if (!Array.isArray(messages) || messages.length < 1 || messages.length > 64) {
    throw new TypeError('mh_base_stream_sender_messages');
  }
  // Check ORIGINAL batch, before stream de-duplication can discard outer headers.
  for (let index = 0; index < messages.length; index++) {
    const message = messages[index];
    if (!Object.hasOwn(messages, index) || !Buffer.isBuffer(message) || message.length < 20) {
      throw new TypeError('mh_base_stream_sender_message');
    }
    if (!message.subarray(8, 12).equals(sourceSenderIdentity)) throw new Error('mh_base_stream_source_sender_mismatch');
  }
  // Do not use single-message identity translation here: a valid XX source chunk
  // can exceed GU's 1416-byte limit and must be resegmented by the explicit plan.
  const result = translateMhBasePeerListStream(messages, options);
  for (const message of result.messages) {
    if (!message.subarray(8, 12).equals(expectedTarget)) throw new Error('mh_base_stream_target_sender_mismatch');
  }
  return {...result, senderCorrespondenceValidated: true, observationsAuthenticated: false};
}
