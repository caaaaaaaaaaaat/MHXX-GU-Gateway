// Offline same-side ACK replay and unsigned schedule comparison; NEVER sends.
import { applyMhStreamAckForContext } from './mh-stream-context-ack.mjs';
import { isMhStreamScheduleDue } from './mh-stream-ack.mjs';

function readObservation(value) {
  const fields = ['message', 'context', 'now'];
  if (!value || typeof value !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) {
    throw new TypeError('mh_send_replay_observation');
  }
  const keys = Reflect.ownKeys(value), descriptors = Object.getOwnPropertyDescriptors(value);
  if (keys.length !== fields.length || keys.some(key => !fields.includes(key))
      || fields.some(key => !Object.hasOwn(descriptors[key], 'value'))) {
    throw new TypeError('mh_send_replay_observation');
  }
  return Object.fromEntries(fields.map(key => [key, descriptors[key].value]));
}
function readBatch(observations) {
  if (!Array.isArray(observations) || Object.getPrototypeOf(observations) !== Array.prototype
      || observations.length < 1 || observations.length > 64
      || Reflect.ownKeys(observations).length !== observations.length + 1) {
    throw new TypeError('mh_send_replay_batch');
  }
  return Array.from({length: observations.length}, (_, index) => {
    const field = Object.getOwnPropertyDescriptor(observations, String(index));
    if (!field || !Object.hasOwn(field, 'value')) throw new TypeError('mh_send_replay_batch');
    return readObservation(field.value);
  });
}

export function replayMhStreamSendWindow(window, observations) {
  const batch = readBatch(observations);
  let current = window, previousTime = null, releasedTotal = 0, staleCount = 0;
  const steps = [];
  for (const {message, context, now} of batch) {
    // Validate the declared unsigned64 time even when no records remain.
    isMhStreamScheduleDue(now, 0n);
    if (previousTime !== null && now < previousTime) throw new Error('mh_send_replay_clock_regression');
    const result = applyMhStreamAckForContext(current, message, context);
    current = result.window;
    const scheduleEligibleIndices = [];
    for (let index = 0; index < current.schedules.length; index++) {
      if (isMhStreamScheduleDue(now, current.schedules[index])) scheduleEligibleIndices.push(index);
    }
    steps.push({base: current.base, schedules: [...current.schedules], released: result.released,
      stale: result.stale, sampleTime: now, scheduleEligibleIndices});
    releasedTotal += result.released;
    if (result.stale) staleCount++;
    previousTime = now;
  }
  return {window: current, steps, releasedTotal, staleCount, contextMatched: true,
    scheduleComparisonOnly: true, observationsAuthenticated: false, payloadValidated: false,
    applicationConverted: false, productionReady: false};
}
