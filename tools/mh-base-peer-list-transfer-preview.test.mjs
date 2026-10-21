import assert from 'node:assert/strict';
import test from 'node:test';
import { previewMhBasePeerListTransfer as preview } from './mh-base-peer-list-transfer-preview.mjs';
import { MhIdentityMap } from './mh-identity.mjs';
import { deriveMhxxUdsEndpoint, encodeMhxxEndpoint } from './mhxx-endpoint.mjs';
import { encodeMhStreamMessage, recoverMhPeerListFromMessages } from './mh-system-stream.mjs';
const profiles = ['mhxx-1.4', 'mhgu-v262144'];
function plan(context, start, lengths, tag = 0x83) {
  return lengths.map((payloadLength, i) => {
    const outerHeader = Buffer.alloc(20, tag), streamHeader = Buffer.alloc(24, tag + 1);
    context.senderIdentity.copy(outerHeader, 8); outerHeader.writeUInt32BE(context.routeKey, 12);
    streamHeader.writeUInt16BE(i === lengths.length - 1 ? 0x8003 : 0x8001);
    streamHeader.writeUInt32BE((start + i) >>> 0, 8);
    streamHeader.writeUInt32BE(tag === 0x83 ? 0x24681357 : 0x13572468, 12);
    return {outerHeader, streamHeader, payloadLength};
  });
}
function fixture(profile = profiles[0], count = 2) {
  const map = new MhIdentityMap('s1'), pairs = Array.from({length: 4}, (_, i) => {
    const seed = Buffer.alloc(8, i + 21), gu = Buffer.from([198, 51, 100, i + 1]); map.bind('s1', seed, gu);
    const xx = encodeMhxxEndpoint(deriveMhxxUdsEndpoint(seed)).subarray(0, 4);
    return profile === profiles[0] ? {from: xx, to: gu} : {from: gu, to: xx};
  });
  const body = Buffer.alloc(12 + count * 72, 0x65); body[0] = 0x20; body[1] = count; body[8] = 1;
  for (let i = 0; i < count; i++) { const off = 12 + 72 * i, p = pairs[i % 4];
    p.from.copy(body, off); body.writeUInt16BE(12345, off + 4);
    for (const rel of [18, 29, 35, 53, 64]) p.from.copy(body, off + rel);
  }
  const context = {profile, sessionId: 's1', epoch: 3, windowId: 'w1', routeKey: 0x44550001, senderIdentity: Buffer.from(pairs[0].from)};
  const targetContext = {...context, profile: profiles.find(p => p !== profile), epoch: 11, windowId: 'w2', routeKey: 0x66770002, senderIdentity: Buffer.from(pairs[0].to)};
  const snapshot = {context, startSequence: 100, messages: []};
  return {body, pairs, map, context, snapshot, options: {endpointBranch: 'base-first-endpoint-a', identityMap: map,
    targetContext, targetStartSequence: 900, targetPlan: plan(targetContext, 900, [body.length])}};
}
function messages(f, lengths = [f.body.length], body = f.body, start = f.snapshot.startSequence) {
  let offset = 0;
  const result = plan(f.context, start, lengths, 0x23).map(p => {
    const payload = body.subarray(offset, offset + p.payloadLength); offset += p.payloadLength;
    return encodeMhStreamMessage({...p, payload}, f.context.profile, f.context.routeKey);
  });
  assert.equal(offset, body.length); return result;
}
function run(f, incoming = messages(f), snapshot = f.snapshot) { return preview(snapshot, incoming, f.context, f.options); }
function mapped(f) { const b = Buffer.from(f.body); for (let i = 0; i < (b[8] === 2 ? b[10] : b[1]); i++) f.pairs[i % 4].to.copy(b, 12 + 72 * i); return b; }
function conservative(result) {
  assert.equal(result.deliveryStatus, 'unverified');
  for (const k of ['sourceConsumptionPerformed', 'targetEnqueuePerformed', 'ackGenerationPerformed', 'observationsAuthenticated', 'payloadValidated', 'applicationConverted', 'productionReady']) assert.equal(result[k], false);
  if (result.candidate) { assert.equal(result.candidate.senderCorrespondenceValidated, true);
    for (const k of ['observationsAuthenticated', 'payloadValidated', 'applicationConverted', 'productionReady']) assert.equal(result.candidate[k], false); }
}
function reject(f, incoming, regex = /mh_/) {
  const before = {messages: incoming.map(m => Buffer.from(m)), body: Buffer.from(f.body), source: Buffer.from(f.context.senderIdentity),
    target: Buffer.from(f.options.targetContext.senderIdentity), plan: f.options.targetPlan.map(p => ({outerHeader: Buffer.from(p.outerHeader), streamHeader: Buffer.from(p.streamHeader), payloadLength: p.payloadLength}))};
  assert.throws(() => run(f, incoming), regex); assert.deepEqual(incoming, before.messages); assert.deepEqual(f.body, before.body);
  assert.deepEqual(f.context.senderIdentity, before.source); assert.deepEqual(f.options.targetContext.senderIdentity, before.target); assert.deepEqual(f.options.targetPlan, before.plan);
}
test('both profiles accumulate a gap then associate only the first typed body with an independent target plan', () => {
  for (const profile of profiles) { const f = fixture(profile), source = messages(f, [17, 83, 56]);
    f.options.targetPlan = plan(f.options.targetContext, 900, [60, 96]);
    const tail = messages(f, [7], Buffer.from('opaque!'), 103)[0];
    const a = run(f, [source[2], tail]); assert.equal(a.candidate, null); conservative(a);
    const b = run(f, [source[0]], a.source.window); assert.equal(b.candidateAvailable, false); assert.equal(b.source.contiguousPrefixCount, 1);
    const c = run(f, [source[1]], b.source.window); conservative(c); assert.equal(c.candidateAvailable, true);
    assert.equal(c.source.preview.chunkCount, 3); assert.equal(c.source.window.messages.length, 4); assert.equal(c.source.window.startSequence, 100);
    assert.deepEqual(c.source.preview.body, f.body); assert.deepEqual(c.candidate.body, mapped(f)); assert.equal(c.candidate.messages.length, 2);
    assert.deepEqual(recoverMhPeerListFromMessages(c.candidate.messages, c.target.context.profile, 900, c.target.context.routeKey).body, mapped(f));
    c.candidate.messages.forEach((m, i) => { assert.equal(m.readUInt32BE(28), 900 + i); assert.equal(m.readUInt32BE(32), 0x24681357); });
    assert.deepEqual(c.source.window.messages[3], tail); assert.equal(f.map.size, 4);
  }
});
test('variant2 and empty typed lists preserve scope; zero labels and replay never establish delivery', () => {
  for (const profile of profiles) { const f = fixture(profile); f.body[8] = 2; f.body[1] = 4; f.body[9] = 1; f.body[10] = 2; f.body[11] = 2;
    const r = run(f); assert.deepEqual(r.candidate.body, mapped(f)); assert.deepEqual(r.candidate.body.subarray(0, 12), f.body.subarray(0, 12)); conservative(r);
    assert.deepEqual(run(f).candidate.messages, r.candidate.messages);
    const z = fixture(profile, 0); z.context.senderIdentity = Buffer.alloc(4); z.options.targetContext.senderIdentity = Buffer.alloc(4);
    z.options.targetContext.epoch = z.context.epoch; z.options.targetContext.windowId = z.context.windowId;
    z.options.targetPlan = plan(z.options.targetContext, 900, [12]); z.map.reset('s1');
    assert.equal(z.map.size, 0); const a = run(z); assert.equal(a.candidateAvailable, true); conservative(a);
    z.context.routeKey = 0x11223344;
    const literal = Buffer.from('0100002400000000000000001122334400000000' + '0003000c0000000000000064123456780000000000000000' + '200000000000000001000000', 'hex');
    const hand = run(z, [literal]); assert.equal(hand.candidateAvailable, true);
    assert.equal(hand.candidate.body.toString('hex'), '200000000000000001000000');
    assert.equal(hand.candidate.messages[0].readUInt32BE(32), 0x24681357); conservative(hand);
  }
});
test('incomplete input still rejects bad independent target headers, ownership declarations and mapping', () => {
  const mutations = [
    f => f.options.endpointBranch = 'derived', f => f.options.identityMap = {},
    f => f.options.targetContext.profile = f.context.profile, f => f.options.targetContext.sessionId = 's2',
    f => f.options.targetContext.epoch = 0, f => f.options.targetContext.senderIdentity = Buffer.alloc(4),
    f => f.options.targetPlan[0].outerHeader[0] = 0xff, f => f.options.targetPlan[0].outerHeader[12] ^= 1,
    f => f.options.targetPlan[0].outerHeader[8] ^= 1, f => f.options.targetPlan[0].streamHeader.writeUInt32BE(901, 8),
    f => f.options.targetPlan[0].streamHeader.writeUInt16BE(1), f => f.options.targetPlan[0].streamHeader.writeUInt16BE(2),
    f => f.options.targetPlan[0].payloadLength = -1, f => f.map.reset('s1'), f => f.map.reset('s2'),
  ];
  for (const mutate of mutations) { const f = fixture(); const missingStart = messages(f, [20, 136])[1]; mutate(f); assert.throws(() => run(f, [missingStart])); }
  const f = fixture(); f.options.targetPlan[0].payloadLength = 1;
  assert.equal(run(f, [messages(f, [20, 136])[1]]).candidate, null); reject(f, messages(f), /target_total/);
});
test('all source observations are revalidated, including tail and duplicates, with no external preview shortcut', () => {
  const f = fixture(), source = messages(f), tail = messages(f, [1], Buffer.from([0]), 101)[0];
  for (const mutate of [b => b[8] ^= 1, b => b[12] ^= 1, b => b.writeUInt16BE(2, 20), b => b.writeUInt16BE(65535, 2)]) {
    const bad = Buffer.from(tail); mutate(bad); reject(f, [...source, bad]);
  }
  const duplicate = Buffer.from(source[0]); duplicate[36] ^= 1; reject(f, [...source, duplicate], /conflicting_duplicate/);
  const prior = run(f); assert.throws(() => preview({...f.snapshot, preview: prior.source.preview}, source, f.context, f.options));
  assert.throws(() => preview(f.snapshot, source, {...f.context, epoch: 4}, f.options), /context_mismatch/);
  const unknown = fixture(); unknown.body[0] = 0x99; reject(unknown, messages(unknown), /mh_system_unsupported_type/);
});
test('late embedded endpoint failures and target totals throw atomically without changing bindings', () => {
  for (const mutate of [f => f.body.fill(0xab, 84, 88), f => f.body.fill(0, 84, 88), f => f.body.writeUInt16BE(12346, 88), f => f.body[8] = 3]) {
    const f = fixture(); mutate(f); reject(f, messages(f)); assert.equal(f.map.size, 4);
    assert.deepEqual(f.map.translate('s1', 'mhxx-to-mhgu', f.pairs[0].from), f.pairs[0].to);
  }
  const f = fixture(); f.options.targetPlan = plan(f.options.targetContext, 900, [100, 55]); reject(f, messages(f), /target_total/);
});
test('closed options, context, target rows and dense arrays reject getters without executing them', () => {
  let calls = 0;
  for (const where of ['options', 'context', 'row', 'array']) { const f = fixture(); const source = messages(f, [20, 136])[1];
    if (where === 'options') Object.defineProperty(f.options, 'targetPlan', {get() { calls++; throw Error('getter'); }});
    if (where === 'context') Object.defineProperty(f.options.targetContext, 'epoch', {get() { calls++; throw Error('getter'); }});
    if (where === 'row') Object.defineProperty(f.options.targetPlan[0], 'payloadLength', {get() { calls++; throw Error('getter'); }});
    if (where === 'array') Object.defineProperty(f.options.targetPlan, '0', {get() { calls++; throw Error('getter'); }});
    assert.throws(() => run(f, [source]));
  }
  assert.equal(calls, 0);
  for (const mutate of [f => f.options.extra = 1, f => f.options.targetContext.extra = 1, f => f.options.targetPlan[0].extra = 1,
    f => f.options.targetPlan.extra = 1, f => f.options.targetPlan[Symbol()] = 1, f => delete f.options.targetPlan[0],
    f => Object.setPrototypeOf(f.options.targetPlan, class extends Array {}.prototype), f => f.options.targetPlan = []]) {
    const f = fixture(); mutate(f); assert.throws(() => run(f, [messages(f, [20, 136])[1]]));
  }
  const f = fixture(); f.options = Object.assign(Object.create(null), f.options); f.options.targetContext = Object.assign(Object.create(null), f.options.targetContext);
  f.options.targetPlan[0] = Object.assign(Object.create(null), f.options.targetPlan[0]); assert.equal(run(f).candidateAvailable, true);
});
test('target payload, 64-item and no-wrap boundaries are checked even while source is incomplete', () => {
  for (const profile of profiles) { const f = fixture(profile), incomplete = [messages(f, [20, 136])[1]], limit = f.options.targetContext.profile === profiles[1] ? 1416 : 65511;
    f.options.targetPlan[0].payloadLength = limit; assert.equal(run(f, incomplete).candidate, null);
    f.options.targetPlan[0].payloadLength = limit + 1; assert.throws(() => run(f, incomplete), /target_payload_length/);
    f.options.targetStartSequence = 0xffffffff; f.options.targetPlan = plan(f.options.targetContext, 0xffffffff, [f.body.length]); assert.equal(run(f).candidate.messages[0].readUInt32BE(28), 0xffffffff);
    f.options.targetPlan = plan(f.options.targetContext, 0xffffffff, [0, f.body.length]); assert.throws(() => run(f, incomplete), /target_sequence/);
    f.options.targetStartSequence = 900; f.options.targetPlan = plan(f.options.targetContext, 900, [...Array(63).fill(0), f.body.length]); assert.equal(run(f).candidate.messages.length, 64);
    f.options.targetPlan = plan(f.options.targetContext, 900, [...Array(64).fill(0), f.body.length]); assert.throws(() => run(f, incomplete), /target_plan/);
  }  for (const profile of profiles) {
    const g = fixture(profile, 20), sourceLengths = profile === profiles[0] ? [1452] : [1416, 36];
    g.options.targetPlan = plan(g.options.targetContext, 900, profile === profiles[0] ? [1416, 36] : [1452]);
    const candidate = run(g, messages(g, sourceLengths)); assert.deepEqual(candidate.candidate.body, mapped(g));
    assert.equal(candidate.candidate.messages.length, profile === profiles[0] ? 2 : 1); conservative(candidate);
  }
});
test('candidate and full source output have independent buffers, no implicit consume/enqueue or replay protection', () => {
  const f = fixture(), incoming = messages(f), reference = run(f, incoming), result = run(f, incoming);
  const originals = incoming.map(b => Buffer.from(b)), oldPlan = f.options.targetPlan.map(p => ({outerHeader: Buffer.from(p.outerHeader), streamHeader: Buffer.from(p.streamHeader), payloadLength: p.payloadLength}));
  assert.deepEqual(result, reference); conservative(result);
  result.source.window.messages[0].fill(0); result.source.preview.body.fill(0); result.source.preview.streamHeaders[0].fill(0);
  result.source.window.context.senderIdentity.fill(0); result.target.context.senderIdentity.fill(0); result.candidate.body.fill(0); result.candidate.messages[0].fill(0);
  assert.deepEqual(incoming, originals); assert.deepEqual(f.options.targetPlan, oldPlan); assert.deepEqual(run(f, incoming), reference);
  const held = run(f, incoming); incoming[0].fill(0); f.options.targetPlan[0].outerHeader.fill(0); f.options.targetPlan[0].streamHeader.fill(0);
  f.context.senderIdentity.fill(0); f.options.targetContext.senderIdentity.fill(0); assert.deepEqual(held, reference);
});
