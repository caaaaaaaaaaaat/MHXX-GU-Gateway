// Offline consecutive terminal-body sequence preview: no consumption, ACK or delivery.
import { previewMhStreamReceiveWindow } from './mh-stream-receive-preview.mjs';
import { readMhStreamDataFields, readMhStreamContext, checkMhStreamMessageContext } from './mh-stream-context.mjs';
import { decodeMhStreamChunk } from './mh-stream-chunk.mjs';
const prefix = 'mh_receive_sequence';
function messagesArray(value) {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype || value.length > 64
      || Reflect.ownKeys(value).length !== value.length + 1) throw new TypeError(prefix + '_messages');
  return Array.from({length: value.length}, (_, index) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) throw new TypeError(prefix + '_messages');
    return descriptor.value;
  });
}
export function previewMhStreamBodySequence(snapshot, messages, observedContext, options) {
  const input = readMhStreamDataFields(snapshot, ['context', 'startSequence', 'messages'], prefix + '_snapshot');
  const context = readMhStreamContext(input.context, prefix), start = input.startSequence;
  if (!Number.isInteger(start) || start < 0 || start > 0xffffffff) throw new TypeError(prefix + '_start_sequence');
  const opt = readMhStreamDataFields(options, ['bodyLimit'], prefix + '_options');
  if (!Number.isInteger(opt.bodyLimit) || opt.bodyLimit < 1 || opt.bodyLimit > 64) throw new TypeError(prefix + '_body_limit');
  // Pre-pass applies the same strict per-message checks as one preview call, only to
  // bucket unique messages by sequence for per-round filtering. It adds no trust:
  // every round below re-runs the existing receive preview over its own subset.
  const supplied = [...messagesArray(input.messages), ...messagesArray(messages)];
  if (supplied.length < 1 || supplied.length > 64) throw new TypeError(prefix + '_supplied_count');
  const unique = new Map();
  let duplicateCount = 0;
  for (const message of supplied) {
    const {body} = checkMhStreamMessageContext(message, context, observedContext, prefix);
    const chunk = decodeMhStreamChunk(body, context.profile);
    if (!chunk.data) throw new Error(prefix + '_not_data');
    if (chunk.sequence < start) throw new Error(prefix + '_sequence_range');
    const prior = unique.get(chunk.sequence);
    if (prior) {
      if (!prior.chunk.header.equals(chunk.header) || !prior.chunk.payload.equals(chunk.payload)) {
        throw new Error(prefix + '_conflicting_duplicate');
      }
      duplicateCount++;
      continue;
    }
    unique.set(chunk.sequence, {chunk, message});
  }
  const ordered = [...unique.values()].sort((a, b) => a.chunk.sequence - b.chunk.sequence);
  // Body boundary model: one terminal chunk ends a body; the next starts at +1.
  // Tool policy only; later rounds never widen what one preview call would accept.
  const bodies = [];
  let roundStart = start, stoppedReason = 'limit';
  while (bodies.length < opt.bodyLimit) {
    const roundMessages = ordered.filter(entry => entry.chunk.sequence >= roundStart).map(entry => entry.message);
    if (roundMessages.length === 0) { stoppedReason = 'no_more_messages'; break; }
    const round = previewMhStreamReceiveWindow(
      {context: input.context, startSequence: roundStart, messages: []}, roundMessages, observedContext);
    if (round.preview === null) { stoppedReason = 'no_complete_body'; break; }
    bodies.push({startSequence: roundStart, terminalSequence: round.preview.terminalSequence,
      chunkCount: round.preview.chunkCount, body: round.preview.body, streamHeaders: round.preview.streamHeaders});
    if (round.preview.terminalSequence === 0xffffffff) { stoppedReason = 'sequence_wrap'; break; }
    roundStart = round.preview.terminalSequence + 1;
  }
  return {window: {context: {...context, senderIdentity: Buffer.from(context.senderIdentity)},
      startSequence: start, messages: ordered.map(entry => Buffer.from(entry.message))},
    bodies, bodyCount: bodies.length, requestedBodyLimit: opt.bodyLimit,
    complete: bodies.length === opt.bodyLimit, stoppedReason,
    duplicateCount, uniqueCount: unique.size, previewOnly: true,
    observationsAuthenticated: false, payloadValidated: false, applicationConverted: false, productionReady: false};
}
