import test from 'node:test';
import assert from 'node:assert/strict';
import { checkMhCollectionEvidence as check } from './mh-collection-evidence.mjs';
function trace(...items) {
  return items.map((item, i) => ({ seq: i + 1, sessionId: 1, epoch: 1, ...item }));
}
const begin = { type: 'begin' };
const pair = { collectionId: 'o1', generation: 1 };
const publish = { type: 'publish', ...pair };
const prepare = { type: 'prepare-result', attemptId: 'a1', status: 0 };
const enter = { type: 'pool-enter', attemptId: 'a1', ...pair };
const result = { type: 'pool-result', attemptId: 'a1', status: 0 };
const acquire = { type: 'acquire', attemptId: 'a1', ...pair };
const valid = () => trace(begin, publish, prepare, enter, result, acquire);
const reasons = out => out.gaps.map(g => g.reason);

test('metadata-only successful local links, independent return and no input mutation', () => {
  const input = valid(), copy = structuredClone(input);
  for (const event of input) Object.freeze(event);
  Object.freeze(input);
  const out = check(input);
  assert.equal(out.localContractSatisfied, true);
  assert.deepEqual(out.links, [{ seq: 6, attemptId: 'a1', sessionId: 1, epoch: 1, ...pair, linked: true }]);
  assert.deepEqual(out.gaps, []);
  assert.equal(out.observationsAuthenticated, false);
  assert.equal(out.applicationConverted, false);
  assert.equal(out.productionReady, false);
  out.links[0].collectionId = 'o9';
  assert.deepEqual(input, copy);
  assert.equal(check(input).links[0].collectionId, 'o1');
});

test('two initialization results are separate; missing/failed prepare is not overwritten', () => {
  for (const status of [1, 0xffffffff]) {
    const t = valid(); t[2].status = status;
    const out = check(t);
    assert.equal(out.localContractSatisfied, false);
    assert.equal(out.links[0].linked, false);
    assert.ok(reasons(out).includes('prepare-failed'));
  }
  const t = trace(begin, publish, enter, result, acquire);
  assert.ok(reasons(check(t)).includes('missing-prepare-result'));
  const failedPool = valid(); failedPool[4].status = 5;
  assert.ok(reasons(check(failedPool)).includes('pool-failed'));
});

test('partial traces, active attempts and clear interruption remain incomplete', () => {
  assert.equal(check(trace(begin)).localContractSatisfied, false);
  assert.ok(reasons(check(trace(begin, publish, prepare, enter))).includes('unfinished-attempt'));
  assert.ok(reasons(check(trace(begin, publish, acquire))).includes('acquire-without-successful-initialization'));
  const t = trace(begin, publish, prepare, enter, { type: 'clear', ...pair });
  assert.ok(reasons(check(t)).includes('unfinished-attempt'));
  assert.throws(() => check([...t, { ...result, seq: 6, sessionId: 1, epoch: 1 }]), /no_publication/);
});

test('generation reuse after clear and across session reset is rejected', () => {
  const prefix = [begin, publish, prepare, enter, result, acquire, { type: 'clear', ...pair }];
  assert.throws(() => check(trace(...prefix, publish)), /generation_reuse/);
  assert.throws(() => check(trace(...prefix, { ...begin, epoch: 2, sessionId: 2 }, { ...publish, epoch: 2, sessionId: 2 })), /generation_reuse/);
  const t = trace(...prefix, { ...publish, generation: 2 }, { ...acquire, generation: 2 });
  assert.equal(check(t).links.at(-1).linked, false);
  const fresh = trace(...prefix, { ...publish, generation: 2 }, { ...prepare, attemptId: 'a2' },
    { ...enter, attemptId: 'a2', generation: 2 }, { ...result, attemptId: 'a2' }, { ...acquire, attemptId: 'a2', generation: 2 });
  assert.equal(check(fresh).localContractSatisfied, true);
});

test('stale session/epoch and mismatched sampled collection fail closed', () => {
  for (const field of ['sessionId', 'epoch']) {
    const t = valid(); t[5][field] = 2;
    assert.throws(() => check(t), /stale_context/);
  }
  for (const field of ['collectionId', 'generation']) {
    const t = valid(); t[5][field] = field === 'generation' ? 2 : 'o2';
    assert.throws(() => check(t), /collection_mismatch/);
  }
  assert.throws(() => check(trace(begin, { ...begin, sessionId: 2 })), /epoch_order/);
  const t = valid(); t.push({ ...acquire, seq: 7, sessionId: 1, epoch: 2 });
  assert.throws(() => check(t), /stale_context/);
});

test('strict order, unsupported concurrency and attempt replay are rejected', () => {
  const t = valid(); t[5].seq = 5;
  assert.throws(() => check(t), /sequence/);
  assert.throws(() => check(trace(begin, publish, result)), /attempt_order/);
  assert.throws(() => check(trace(begin, publish, prepare, { ...prepare, attemptId: 'a2' })), /attempt_order/);
  assert.throws(() => check(trace(begin, publish, prepare, enter, enter)), /attempt_order/);
  assert.throws(() => check(trace(begin, publish, prepare, enter, result, enter)), /attempt_reuse/);
  assert.throws(() => check(trace(begin, publish, publish)), /replace_without_clear/);
});

test('new attempt revokes earlier successful association even if newer attempt fails', () => {
  const items = [begin, publish, prepare, enter, result, acquire,
    { ...prepare, attemptId: 'a2', status: 4 }, { ...enter, attemptId: 'a2' }, { ...result, attemptId: 'a2' }, acquire];
  const out = check(trace(...items));
  assert.equal(out.links[0].linked, true);
  assert.equal(out.links[1].linked, false);
  assert.equal(out.localContractSatisfied, false);
});

test('all new-attempt branches revoke old success; attempt tokens stay unique across epochs', () => {
  for (const tail of [
    [{ ...prepare, attemptId: 'a2' }, { ...enter, attemptId: 'a2' }, { ...result, attemptId: 'a2', status: 1 }, acquire],
    [{ ...enter, attemptId: 'a2' }, { ...result, attemptId: 'a2' }, acquire],
    [{ ...prepare, attemptId: 'a2' }, acquire],
  ]) {
    const t = [...valid(), ...trace(...tail).map(e => ({ ...e, seq: e.seq + 6 }))];
    assert.equal(check(t).links.at(-1).linked, false);
    assert.equal(check(t).localContractSatisfied, false);
  }
  const reused = [...valid(), ...trace({ ...begin, epoch: 2 }, { ...publish, generation: 2 }, prepare).map(e => ({ ...e, seq: e.seq + 6, epoch: 2 }))];
  assert.throws(() => check(reused), /attempt_order/);
  assert.equal(check([...valid(), { ...begin, seq: 7, sessionId: 2, epoch: 2 }]).localContractSatisfied, true);
});

test('closed JSON metadata schema rejects payloads, unknowns, invalid counters and accessors', () => {
  for (const extra of ['key', 'payload', 'address', 'vptr', 'body']) {
    const t = valid(); t[1][extra] = 'not-allowed';
    assert.throws(() => check(t), /fields/);
  }
  for (const value of [-1, 1.5, 0x100000000, NaN, Infinity, '0']) {
    const t = valid(); t[2].status = value;
    assert.throws(() => check(t), /status/);
  }
  for (const value of [0, -1, 1.1, Number.MAX_SAFE_INTEGER + 1]) {
    const t = valid(); t[1].generation = value;
    assert.throws(() => check(t), /collection/);
  }
  const raw = valid(); raw[1].collectionId = '0x2145a64';
  assert.throws(() => check(raw), /collection/);
  const accessor = valid(); Object.defineProperty(accessor[1], 'payload', { get() { throw new Error('must not evaluate'); }, enumerable: true });
  assert.throws(() => check(accessor), /fields/);
  const arrayAccessor = valid(); Object.defineProperty(arrayAccessor, '1', { get() { throw new Error('must not evaluate'); }, enumerable: true });
  assert.throws(() => check(arrayAccessor), /events/);
  const sparse = new Array(2); sparse[0] = valid()[0];
  assert.throws(() => check(sparse), /events/);
  const extraArray = valid(); extraArray.payload = 'no';
  assert.throws(() => check(extraArray), /events/);
  assert.throws(() => check([]), /events/);
  assert.throws(() => check(new Array(4097)), /events/);
});

test('complete new epoch can link fresh generation; ending clear is historical, not liveness', () => {
  const next = trace({ ...begin, sessionId: 2, epoch: 2 }, { ...publish, generation: 2 },
    { ...prepare, attemptId: 'a2' }, { ...enter, generation: 2, attemptId: 'a2' },
    { ...result, attemptId: 'a2' }, { ...acquire, generation: 2, attemptId: 'a2' },
    { type: 'clear', ...pair, generation: 2 }).map(e => ({ ...e, seq: e.seq + 6, epoch: 2, sessionId: 2 }));
  const out = check([...valid(), ...next]);
  assert.equal(out.localContractSatisfied, true);
  assert.deepEqual(out.links.map(l => [l.sessionId, l.epoch, l.generation, l.linked]), [[1, 1, 1, true], [2, 2, 2, true]]);
  assert.equal(out.productionReady, false);
});

test('epoch reset cannot erase an unfinished initialization gap', () => {
  const early = trace(begin, publish, prepare, enter);
  const complete = valid().map(e => ({ ...e, seq: e.seq + 4, epoch: 2, generation: Object.hasOwn(e, 'generation') ? 2 : undefined }));
  for (const e of complete) { if (e.generation === undefined) delete e.generation; if (Object.hasOwn(e, 'attemptId')) e.attemptId = 'a2'; }
  const out = check([...early, ...complete]);
  assert.ok(reasons(out).includes('unfinished-attempt'));
  assert.equal(out.links[0].linked, true);
  assert.equal(out.localContractSatisfied, false);
});

test('fresh epochs invalidate old attempts while preserving historical audit results', () => {
  const t = valid();
  t.push(...trace({ ...begin, epoch: 2 }, { ...publish, epoch: 2, generation: 2 }, { ...acquire, epoch: 2, generation: 2 }).map(e => ({ ...e, seq: e.seq + 6 })));
  const out = check(t);
  assert.deepEqual(out.links.map(l => l.linked), [true, false]);
  assert.equal(out.localContractSatisfied, false);
});
