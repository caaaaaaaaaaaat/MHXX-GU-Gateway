// Offline same-side ACK snapshot update. Labels are assertions, NOT authentication.
import { applyMhStreamAck } from './mh-stream-ack.mjs';

import { readMhStreamDataFields as dataFields, checkMhStreamMessageContext } from './mh-stream-context.mjs';

export function applyMhStreamAckForContext(window, message, observedContext) {
  const input = dataFields(window, ['context', 'base', 'schedules'], 'mh_context_ack_window');
  const {context: expected, body} = checkMhStreamMessageContext(message, input.context, observedContext, 'mh_context_ack');
  // The nested ACK acknowledges THIS window's send sequences. It is not the
  // incoming message's data sequence (+8) and is never endpoint-identity mapped.
  const result = applyMhStreamAck({base: input.base, schedules: input.schedules}, body, expected.profile);
  return {
    window: {context: {...expected, senderIdentity: Buffer.from(expected.senderIdentity)}, base: result.base, schedules: result.schedules},
    released: result.released, stale: result.stale, contextMatched: true,
    observationsAuthenticated: false, payloadValidated: false, applicationConverted: false, productionReady: false,
  };
}
