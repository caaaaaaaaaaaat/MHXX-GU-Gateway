// Offline JSON metadata consistency checker, not a runtime observer or authorization gate.
// Tokens/generations are recorder assertions; no addresses, keys or payloads are needed.
const BASE = ['seq', 'type', 'sessionId', 'epoch'];
const PAIR = ['collectionId', 'generation'];
const FIELDS = {
  begin: [], publish: PAIR, clear: PAIR,
  'prepare-result': ['attemptId', 'status'],
  'pool-enter': [...PAIR, 'attemptId'],
  'pool-result': ['attemptId', 'status'],
  acquire: [...PAIR, 'attemptId'],
};
function fail(code) { throw new Error('mh_collection_evidence_' + code); }
function positive(n) { return Number.isSafeInteger(n) && n > 0; }
function token(s, prefix) { return typeof s === 'string' && new RegExp('^' + prefix + '[1-9][0-9]{0,7}$').test(s); }
function validate(event) {
  if (!event || typeof event !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(event))) fail('event');
  const keys = Reflect.ownKeys(event);
  // Accept data records only; do not evaluate accessors or unknown data properties.
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(event, key);
    if (typeof key !== 'string' || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) fail('fields');
  }
  if (typeof event.type !== 'string' || !Object.hasOwn(FIELDS, event.type)) fail('type');
  const expected = [...BASE, ...FIELDS[event.type]];
  if (keys.length !== expected.length || expected.some(key => !Object.hasOwn(event, key))) fail('fields');
  if (![event.seq, event.sessionId, event.epoch].every(positive)) fail('sequence_context');
  if (Object.hasOwn(event, 'collectionId') && (!token(event.collectionId, 'o') || !positive(event.generation))) fail('collection');
  if (Object.hasOwn(event, 'attemptId') && !token(event.attemptId, 'a')) fail('attempt');
  if (Object.hasOwn(event, 'status') && (!Number.isInteger(event.status) || event.status < 0 || event.status > 0xffffffff)) fail('status');
}

export function checkMhCollectionEvidence(events) {
  if (!Array.isArray(events) || events.length < 1 || events.length > 4096) fail('events');
  if (Reflect.ownKeys(events).length !== events.length + 1) fail('events');
  let sequence = 0, context = null, current = null, pending = null, readyAttempt = null;
  const generations = new Map(), attempts = new Map(), links = [], gaps = [];
  const gap = (seq, reason) => gaps.push({ seq, reason });
  const matches = event => current && current.collectionId === event.collectionId && current.generation === event.generation;
  const needCurrent = () => { if (!current) fail('no_publication'); };
  const abandon = seq => { if (pending) gap(seq, 'unfinished-attempt'); pending = null; };
  for (let index = 0; index < events.length; index++) {
    if (!Object.hasOwn(events, index)) fail('events');
    const descriptor = Object.getOwnPropertyDescriptor(events, String(index));
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) fail('events');
    const event = descriptor.value;
    validate(event);
    if (event.seq <= sequence) fail('sequence');
    sequence = event.seq;
    if (event.type === 'begin') {
      if (context && event.epoch <= context.epoch) fail('epoch_order');
      abandon(event.seq);
      context = { sessionId: event.sessionId, epoch: event.epoch };
      current = null;
      readyAttempt = null;
      continue;
    }
    if (!context || event.sessionId !== context.sessionId || event.epoch !== context.epoch) fail('stale_context');
    if (event.type === 'publish') {
      if (current) fail('replace_without_clear');
      if (event.generation <= (generations.get(event.collectionId) ?? 0)) fail('generation_reuse');
      readyAttempt = null;
      generations.set(event.collectionId, event.generation);
      current = { collectionId: event.collectionId, generation: event.generation };
      continue;
    }
    if (event.type === 'clear') {
      if (!matches(event)) fail('collection_mismatch');
      abandon(event.seq);
      current = null;
      readyAttempt = null;
      continue;
    }
    needCurrent();
    if (event.type === 'prepare-result') {
      if (pending || attempts.has(event.attemptId)) fail('attempt_order');
      readyAttempt = null;
      pending = { ...current, ...context, attemptId: event.attemptId, prepareStatus: event.status, entered: false };
      attempts.set(event.attemptId, pending);
    } else if (event.type === 'pool-enter') {
      if (!matches(event)) fail('collection_mismatch');
      if (!pending) {
        if (attempts.has(event.attemptId)) fail('attempt_reuse');
        readyAttempt = null;
        pending = { ...current, ...context, attemptId: event.attemptId, prepareStatus: null, entered: false };
        attempts.set(event.attemptId, pending);
      }
      if (pending.attemptId !== event.attemptId || pending.entered) fail('attempt_order');
      pending.entered = true;
    } else if (event.type === 'pool-result') {
      if (!pending || !pending.entered || pending.attemptId !== event.attemptId) fail('attempt_order');
      pending.poolStatus = event.status;
      if (pending.prepareStatus === null) gap(event.seq, 'missing-prepare-result');
      else if (pending.prepareStatus !== 0) gap(event.seq, 'prepare-failed');
      if (event.status !== 0) gap(event.seq, 'pool-failed');
      readyAttempt = pending.prepareStatus === 0 && event.status === 0 ? pending.attemptId : null;
      pending = null;
    } else if (event.type === 'acquire') {
      if (!matches(event)) fail('collection_mismatch');
      const attempt = attempts.get(event.attemptId);
      const linked = event.attemptId === readyAttempt && !!attempt && attempt.sessionId === context.sessionId && attempt.epoch === context.epoch
        && attempt.collectionId === current.collectionId && attempt.generation === current.generation
        && attempt.prepareStatus === 0 && attempt.poolStatus === 0 && !pending;
      if (!linked) gap(event.seq, 'acquire-without-successful-initialization');
      links.push({ seq: event.seq, attemptId: event.attemptId, ...context, ...current, linked });
    }
  }
  abandon(sequence);
  if (!links.length) gap(sequence, 'missing-acquire');
  return {
    metadataConsistent: true, localContractSatisfied: gaps.length === 0 && links.length > 0,
    links, gaps, observationsAuthenticated: false, applicationConverted: false, productionReady: false,
  };
}
