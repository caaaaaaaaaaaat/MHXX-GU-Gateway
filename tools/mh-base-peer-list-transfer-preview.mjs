// Offline first typed-body -> explicit target candidate association. No delivery.
import { previewMhStreamReceiveWindow } from './mh-stream-receive-preview.mjs';
import { readMhStreamDataFields, readMhStreamContext, checkMhStreamMessageContext } from './mh-stream-context.mjs';
import { translateMhBasePeerListStreamCheckedSender } from './mh-base-peer-list-stream.mjs';
import { encodeMhStreamMessage } from './mh-system-stream.mjs';
import { decodeMhStreamChunk } from './mh-stream-chunk.mjs';
import { MhIdentityMap } from './mh-identity.mjs';
const prefix = 'mh_base_transfer_preview';
function targetPlanRows(value, context, start) {
  if (!Number.isInteger(start) || start < 0 || start > 0xffffffff) throw new TypeError(prefix + '_target_start');
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype || value.length < 1 || value.length > 64
      || Reflect.ownKeys(value).length !== value.length + 1) throw new TypeError(prefix + '_target_plan');
  return Array.from({length: value.length}, (_, index) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) throw new TypeError(prefix + '_target_plan');
    const item = readMhStreamDataFields(descriptor.value, ['outerHeader', 'streamHeader', 'payloadLength'], prefix + '_target_item');
    const limit = context.profile === 'mhgu-v262144' ? 1416 : 65511;
    if (!Number.isInteger(item.payloadLength) || item.payloadLength < 0 || item.payloadLength > limit) throw new TypeError(prefix + '_target_payload_length');
    // The probe checks explicit target header bytes, not a send/ACK window.
    // Template length fields are rewritten by the existing encoder, as before.
    const probe = encodeMhStreamMessage({...item, payload: Buffer.alloc(0)}, context.profile, context.routeKey);
    const checked = checkMhStreamMessageContext(probe, context, context, prefix);
    const chunk = decodeMhStreamChunk(checked.body, context.profile);
    if (start + index > 0xffffffff || chunk.sequence !== start + index) throw new Error(prefix + '_target_sequence');
    if (!chunk.data || chunk.terminal !== (index === value.length - 1)) throw new Error(prefix + '_target_flags');
    return {outerHeader: Buffer.from(item.outerHeader), streamHeader: Buffer.from(item.streamHeader), payloadLength: item.payloadLength};
  });
}
export function previewMhBasePeerListTransfer(snapshot, messages, observedContext, options) {
  const input = readMhStreamDataFields(options, ['endpointBranch', 'identityMap', 'targetContext', 'targetStartSequence', 'targetPlan'], prefix + '_options');
  // Recompute from raw source observations; never accept an external preview/proof.
  const source = previewMhStreamReceiveWindow(snapshot, messages, observedContext);
  const from = source.window.context, to = readMhStreamContext(input.targetContext, prefix);
  const targetProfile = from.profile === 'mhxx-1.4' ? 'mhgu-v262144' : 'mhxx-1.4';
  if (to.profile !== targetProfile || to.sessionId !== from.sessionId) throw new Error(prefix + '_target_context');
  if (input.endpointBranch !== 'base-first-endpoint-a') throw new Error(prefix + '_endpoint_branch');
  if (!(input.identityMap instanceof MhIdentityMap)) throw new TypeError(prefix + '_identity_map');
  const direction = from.profile === 'mhxx-1.4' ? 'mhxx-to-mhgu' : 'mhgu-to-mhxx';
  const targetSender = input.identityMap.translate(from.sessionId, direction, from.senderIdentity);
  if (!targetSender.equals(to.senderIdentity)) throw new Error(prefix + '_target_sender');
  const plan = targetPlanRows(input.targetPlan, to, input.targetStartSequence);
  let candidate = null;
  if (source.preview !== null) {
    candidate = translateMhBasePeerListStreamCheckedSender(source.window.messages.slice(0, source.preview.chunkCount), {
      profile: from.profile, sourceSenderIdentity: from.senderIdentity,
      sourceStartSequence: source.window.startSequence, sourceRouteKey: from.routeKey,
      endpointBranch: input.endpointBranch, identityMap: input.identityMap, sessionId: from.sessionId,
      targetStartSequence: input.targetStartSequence, targetRouteKey: to.routeKey, targetPlan: plan,
    });
  }
  return {source, target: {context: {...to, senderIdentity: Buffer.from(to.senderIdentity)}, startSequence: input.targetStartSequence},
    candidate, candidateAvailable: candidate !== null, sourceConsumptionPerformed: false, targetEnqueuePerformed: false,
    ackGenerationPerformed: false, deliveryStatus: 'unverified', observationsAuthenticated: false,
    payloadValidated: false, applicationConverted: false, productionReady: false};
}
