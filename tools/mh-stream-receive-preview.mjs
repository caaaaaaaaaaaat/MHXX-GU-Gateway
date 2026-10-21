// Offline finite receive snapshot preview: no consumption, ACK or delivery.
import { readMhStreamDataFields, readMhStreamContext, checkMhStreamMessageContext } from './mh-stream-context.mjs';
import { decodeMhStreamChunk, assembleMhStreamChunks } from './mh-stream-chunk.mjs';
const prefix = 'mh_receive_preview';
function messagesArray(value) {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype || value.length > 64
      || Reflect.ownKeys(value).length !== value.length + 1) throw new TypeError(prefix + '_messages');
  return Array.from({length: value.length}, (_, index) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) throw new TypeError(prefix + '_messages');
    return descriptor.value;
  });
}
export function previewMhStreamReceiveWindow(snapshot, messages, observedContext) {
  const input = readMhStreamDataFields(snapshot, ['context', 'startSequence', 'messages'], prefix + '_snapshot');
  const context = readMhStreamContext(input.context, prefix), start = input.startSequence;
  if (!Number.isInteger(start) || start < 0 || start > 0xffffffff) throw new TypeError(prefix + '_start_sequence');
  const supplied = [...messagesArray(input.messages), ...messagesArray(messages)];
  if (supplied.length < 1 || supplied.length > 64) throw new TypeError(prefix + '_supplied_count');
  const bySequence = new Map();
  let payloadBytes = 0, duplicateCount = 0;
  for (const message of supplied) {
    const {body} = checkMhStreamMessageContext(message, context, observedContext, prefix);
    const chunk = decodeMhStreamChunk(body, context.profile);
    if (!chunk.data) throw new Error(prefix + '_not_data');
    if (chunk.sequence < start || chunk.sequence - start >= 64) throw new Error(prefix + '_sequence_range');
    const prior = bySequence.get(chunk.sequence);
    if (prior) {
      if (!prior.chunk.header.equals(chunk.header) || !prior.chunk.payload.equals(chunk.payload)) throw new Error(prefix + '_conflicting_duplicate');
      duplicateCount++;
      continue;
    }
    payloadBytes += chunk.payload.length;
    if (payloadBytes > 1024 * 1024) throw new Error(prefix + '_byte_limit');
    bySequence.set(chunk.sequence, {chunk, body, message: Buffer.from(message)});
  }
  const ordered = [...bySequence.values()].sort((a,b) => a.chunk.sequence - b.chunk.sequence);
  const contiguous = [];
  let preview = null;
  for (const entry of ordered) {
    if (entry.chunk.sequence !== start + contiguous.length) break;
    contiguous.push(entry.body);
    if (entry.chunk.terminal) {
      const assembled = assembleMhStreamChunks(contiguous, context.profile, start);
      preview = {body: assembled.payload, streamHeaders: assembled.headers, terminalSequence: entry.chunk.sequence, chunkCount: contiguous.length};
      break;
    }
  }
  return {window: {context: {...context, senderIdentity: Buffer.from(context.senderIdentity)}, startSequence: start,
    messages: ordered.map(entry => entry.message)}, preview, contiguousPrefixCount: contiguous.length,
    pendingPayloadBytes: payloadBytes, duplicateCount, contextMatched: true, previewOnly: true,
    observationsAuthenticated: false, payloadValidated: false, applicationConverted: false, productionReady: false};
}
