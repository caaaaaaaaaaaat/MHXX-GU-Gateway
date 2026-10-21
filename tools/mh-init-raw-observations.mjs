// Offline declarations only: raw output words are NOT normalized success or readiness.
const BASE = ['seq', 'type', 'sessionId', 'epoch'];
const FIELDS = {
  begin: [],
  'prepare-enter': ['attemptId'],
  'prepare-return': ['attemptId', 'rawStatus'],
  'pool-enter': ['attemptId', 'collectionId', 'generation'],
  'pool-return': ['attemptId', 'rawStatus'],
};
const positive = n => Number.isSafeInteger(n) && n > 0;
const token = (s, prefix) => typeof s === 'string' && new RegExp('^' + prefix + '[1-9][0-9]{0,7}').exec(s)?.[0] === s;
function fail(code) { throw new Error('mh_init_raw_observations_' + code); }
function validate(event) {
  if (!event || typeof event !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(event))) fail('event');
  const keys = Reflect.ownKeys(event);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(event, key);
    if (typeof key !== 'string' || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) fail('fields');
  }
  if (typeof event.type !== 'string' || !Object.hasOwn(FIELDS, event.type)) fail('type');
  const expected = [...BASE, ...FIELDS[event.type]];
  if (keys.length !== expected.length || expected.some(key => !Object.hasOwn(event, key))) fail('fields');
  if (![event.seq, event.sessionId, event.epoch].every(positive)) fail('context');
  if (Object.hasOwn(event, 'attemptId') && !token(event.attemptId, 'a')) fail('attempt');
  if (Object.hasOwn(event, 'collectionId') && (!token(event.collectionId, 'o') || !positive(event.generation))) fail('collection');
  if (Object.hasOwn(event, 'rawStatus') && (!Number.isInteger(event.rawStatus) || event.rawStatus < 0 || event.rawStatus > 0xffffffff)) fail('status');
}
function classify(stage, value) {
  if (value === 0) return 'raw-zero';
  if (stage === 'prepare' && value === 0x10c02) return 'raw-context-gate';
  if (stage === 'pool' && value === 0x10c07) return 'raw-provider-or-count-gate';
  if (stage === 'pool' && value === 0x10c01) return 'raw-allocation-null';
  return 'unclassified';
}

export function checkMhInitRawObservations(events, profile) {
  if (profile !== 'mhgu-v262144') fail('profile');
  if (!Array.isArray(events) || events.length < 1 || events.length > 4096 || Reflect.ownKeys(events).length !== events.length + 1) fail('events');
  let sequence = 0, context = null, pending = null;
  const used = new Set(), attempts = [], gaps = [];
  const gap = (seq, reason) => gaps.push({ seq, reason });
  const fresh = event => {
    if (pending || used.has(event.attemptId)) fail('attempt_order');
    used.add(event.attemptId);
    pending = { ...context, attemptId: event.attemptId, collectionId: null, generation: null, prepare: null, pool: null };
    attempts.push(pending);
  };
  for (let index = 0; index < events.length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(events, String(index));
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) fail('events');
    const event = descriptor.value;
    validate(event);
    if (event.seq <= sequence) fail('sequence');
    sequence = event.seq;
    if (event.type === 'begin') {
      if (context && event.epoch <= context.epoch) fail('epoch_order');
      if (pending) gap(event.seq, 'unfinished-attempt');
      pending = null;
      context = { sessionId: event.sessionId, epoch: event.epoch };
      continue;
    }
    if (!context || event.sessionId !== context.sessionId || event.epoch !== context.epoch) fail('stale_context');
    if (event.type === 'prepare-enter') {
      fresh(event);
      pending.prepare = { enterSeq: event.seq, returnSeq: null, rawStatus: null, classification: null };
    } else if (event.type === 'pool-enter') {
      if (!pending) {
        fresh(event);
        gap(event.seq, 'missing-prepare-call');
      } else if (pending.attemptId !== event.attemptId || pending.pool) fail('attempt_order');
      if (pending.prepare && pending.prepare.returnSeq === null) gap(event.seq, 'missing-prepare-return');
      pending.collectionId = event.collectionId;
      pending.generation = event.generation;
      pending.pool = { enterSeq: event.seq, returnSeq: null, rawStatus: null, classification: null };
    } else {
      const stage = event.type === 'prepare-return' ? 'prepare' : 'pool';
      if (!pending || pending.attemptId !== event.attemptId || !pending[stage] || pending[stage].returnSeq !== null || (stage === 'prepare' && pending.pool)) fail('return_order');
      const label = classify(stage, event.rawStatus);
      Object.assign(pending[stage], { returnSeq: event.seq, rawStatus: event.rawStatus, classification: label });
      if (label === 'unclassified') gap(event.seq, 'unclassified-' + stage + '-output');
      if (stage === 'pool') pending = null;
    }
  }
  if (pending) gap(sequence, 'unfinished-attempt');
  if (!attempts.length) gap(sequence, 'no-attempt');
  return { profile, metadataConsistent: true, attempts, gaps,
    unresolvedEvidence: ['observation-source', 'normalization-semantics', 'resource-readiness', 'lifetime-and-type-binding'],
    observationsAuthenticated: false, normalizationEstablished: false, resourceReadinessEstablished: false,
    applicationConverted: false, productionReady: false };
}
