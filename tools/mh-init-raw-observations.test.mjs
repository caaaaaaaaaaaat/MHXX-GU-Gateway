import test from 'node:test';
import assert from 'node:assert/strict';
import { checkMhInitRawObservations as check } from './mh-init-raw-observations.mjs';
import { checkMhCollectionEvidence } from './mh-collection-evidence.mjs';
const profile = 'mhgu-v262144';
const e = (seq, type, fields = {}) => ({ seq, type, sessionId: 1, epoch: 1, ...fields });
const trace = (prepare = 0, pool = 0) => [e(1, 'begin'), e(2, 'prepare-enter', { attemptId: 'a1' }),
  e(3, 'prepare-return', { attemptId: 'a1', rawStatus: prepare }),
  e(4, 'pool-enter', { attemptId: 'a1', collectionId: 'o1', generation: 1 }),
  e(5, 'pool-return', { attemptId: 'a1', rawStatus: pool })];
const rejects = events => assert.throws(() => check(events, profile), /mh_init_raw_observations_/);
function flags(result) {
  assert.deepEqual(result.unresolvedEvidence, ['observation-source', 'normalization-semantics', 'resource-readiness', 'lifetime-and-type-binding']);
  for (const field of ['observationsAuthenticated', 'normalizationEstablished', 'resourceReadinessEstablished', 'applicationConverted', 'productionReady']) assert.equal(result[field], false);
  assert.equal(Object.hasOwn(result, 'normalizedEvents'), false);
  assert.equal(Object.hasOwn(result, 'localContractSatisfied'), false);
}

test('both raw zero outputs stay distinct and never generate normalized success', () => {
  const input = trace(), saved = structuredClone(input), result = check(input, profile);
  assert.deepEqual(result.gaps, []);
  assert.equal(result.attempts.length, 1);
  assert.deepEqual(result.attempts[0], { sessionId: 1, epoch: 1, attemptId: 'a1', collectionId: 'o1', generation: 1,
    prepare: { enterSeq: 2, returnSeq: 3, rawStatus: 0, classification: 'raw-zero' },
    pool: { enterSeq: 4, returnSeq: 5, rawStatus: 0, classification: 'raw-zero' } });
  flags(result);
  assert.deepEqual(input, saved);
  assert.throws(() => checkMhCollectionEvidence(input), /mh_collection_evidence_/);
  result.attempts[0].prepare.rawStatus = 123;
  assert.deepEqual(input, saved);
});

test('known nonzero outputs are observation categories, not normalized statuses', () => {
  for (const pool of [0x10c01, 0x10c07]) {
    const result = check(trace(0x10c02, pool), profile);
    assert.deepEqual(result.gaps, []);
    assert.equal(result.attempts[0].prepare.classification, 'raw-context-gate');
    assert.equal(result.attempts[0].pool.classification, pool === 0x10c01 ? 'raw-allocation-null' : 'raw-provider-or-count-gate');
    flags(result);
  }
});

test('unknown or cross-stage raw values are preserved with gaps, never guessed', () => {
  for (const [prepare, pool] of [[0x10c01, 0x10c02], [0xffffffff, 1]]) {
    const result = check(trace(prepare, pool), profile);
    assert.equal(result.attempts[0].prepare.rawStatus, prepare);
    assert.equal(result.attempts[0].pool.rawStatus, pool);
    assert.deepEqual(result.gaps.map(x => x.reason), ['unclassified-prepare-output', 'unclassified-pool-output']);
    flags(result);
  }
});

test('pool-only declaration cannot supply a missing prepare output', () => {
  const input = trace(); input.splice(1, 2);
  const result = check(input, profile);
  assert.equal(result.attempts[0].prepare, null);
  assert.deepEqual(result.gaps, [{ seq: 4, reason: 'missing-prepare-call' }]);
  flags(result);
});

test('missing prepare return remains a gap despite later pool raw zero', () => {
  const input = trace(); input.splice(2, 1);
  const result = check(input, profile);
  assert.equal(result.attempts[0].prepare.returnSeq, null);
  assert.equal(result.attempts[0].pool.rawStatus, 0);
  assert.deepEqual(result.gaps, [{ seq: 4, reason: 'missing-prepare-return' }]);
  rejects([...input.slice(0, 3), e(5, 'prepare-return', { attemptId: 'a1', rawStatus: 0 })]);
});

test('unfinished records survive epoch reset and cannot reuse attempt labels', () => {
  const input = trace().slice(0, 3);
  input.push(e(6, 'begin', { sessionId: 2, epoch: 2 }));
  const result = check(input, profile);
  assert.deepEqual(result.gaps, [{ seq: 6, reason: 'unfinished-attempt' }]);
  assert.equal(result.attempts[0].pool, null);
  rejects([...input, e(7, 'prepare-enter', { sessionId: 2, epoch: 2, attemptId: 'a1' })]);
  rejects([...input, e(7, 'prepare-enter', { attemptId: 'a2' })]);
  rejects([e(1, 'begin'), e(2, 'begin')]);
});

test('serial call pairing rejects wrong, duplicate, late and overlapping returns', () => {
  const input = trace();
  rejects(input.slice(1));
  rejects([input[0], input[2]]);
  rejects([input[0], input[1], { ...input[2], attemptId: 'a2' }]);
  rejects([input[0], input[1], input[2], { ...input[2], seq: 4 }]);
  rejects([input[0], input[1], e(3, 'prepare-enter', { attemptId: 'a2' })]);
  rejects([...input, { ...input[4], seq: 6 }]);
  rejects([...input.slice(0, 4), { ...input[3], seq: 5 }]);
  rejects(input.map(x => ({ ...x, seq: 1 })));
});

test('closed JSON fields reject normalized success, raw addresses and unsupported profiles', () => {
  for (const extra of [{ status: 0 }, { address: '0x1234' }, { payload: 'secret' }, { normalized: true }]) {
    const input = trace(); Object.assign(input[2], extra); rejects(input);
  }
  for (const bad of [undefined, 'mhxx-1.4', 'mhgu', null]) assert.throws(() => check(trace(), bad), /_profile/);
  const input = trace(); input[2].type = 'prepare-result'; rejects(input);
  for (const bad of ['o0', '0x12', 'o123456789']) { const t = trace(); t[3].collectionId = bad; rejects(t); }
  for (const suffix of ['\n', '\r', '\u2028', '\u2029']) {
    const attempt = trace(); attempt[1].attemptId += suffix; rejects(attempt);
    const collection = trace(); collection[3].collectionId += suffix; rejects(collection);
  }
  const nullPrototype = trace().map(x => Object.assign(Object.create(null), x));
  assert.equal(check(nullPrototype, profile).metadataConsistent, true);
});

test('uint32 raw words, positive contexts and generation/token bounds fail closed', () => {
  for (const rawStatus of [-1, 0x100000000, 0.5, NaN, Infinity, '0', null]) rejects(trace(rawStatus));
  for (const value of [0, -1, 0.5, Number.MAX_SAFE_INTEGER + 1, '1']) {
    const input = trace(); input[0].epoch = value; rejects(input);
    const t = trace(); t[3].generation = value; rejects(t);
  }
  const input = trace(); input[1].attemptId = 'a0'; rejects(input);
});

test('accessors, extra array fields, holes and oversized arrays are not evaluated', () => {
  let hits = 0;
  const input = trace(); Object.defineProperty(input[2], 'rawStatus', { enumerable: true, get() { hits++; return 0; } }); rejects(input);
  const indexed = trace(); Object.defineProperty(indexed, '2', { enumerable: true, get() { hits++; return trace()[2]; } }); rejects(indexed);
  assert.equal(hits, 0);
  const extras = trace(); extras.note = 'x'; rejects(extras);
  const holes = trace(); delete holes[2]; rejects(holes);
  rejects([]); rejects(Array(4097).fill(e(1, 'begin')));
  const maximum = Array.from({ length: 4096 }, (_, i) => e(i + 1, 'begin', { epoch: i + 1 }));
  assert.deepEqual(check(maximum, profile).gaps, [{ seq: 4096, reason: 'no-attempt' }]);
  const nonenum = trace(); Object.defineProperty(nonenum[2], 'x', { value: 1 }); rejects(nonenum);
});

test('empty and partial observations retain explicit gaps without readiness', () => {
  assert.deepEqual(check([e(1, 'begin')], profile).gaps, [{ seq: 1, reason: 'no-attempt' }]);
  for (const end of [2, 3, 4]) {
    const result = check(trace().slice(0, end), profile);
    assert.equal(result.gaps.at(-1).reason, 'unfinished-attempt'); flags(result);
  }
  const input = trace(1); input.push(e(6, 'begin', { epoch: 2 }));
  assert.equal(check(input, profile).gaps[0].reason, 'unclassified-prepare-output');
});

test('repeated collection labels do not assert generation validity or authenticate resources', () => {
  const input = trace();
  const next = trace().slice(1).map(x => ({ ...x, seq: x.seq + 4, attemptId: 'a2' }));
  input.push(...next);
  const result = check(input, profile);
  assert.equal(result.attempts.length, 2);
  assert.deepEqual(result.gaps, []);
  flags(result);
  const saved = structuredClone(result);
  input[3].collectionId = 'o9';
  assert.deepEqual(result, saved);
});
