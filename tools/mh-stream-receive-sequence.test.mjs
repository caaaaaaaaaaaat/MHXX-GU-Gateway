import assert from 'node:assert/strict';
import test from 'node:test';
import { previewMhStreamBodySequence as sequence } from './mh-stream-receive-sequence.mjs';
import { previewMhStreamReceiveWindow as preview } from './mh-stream-receive-preview.mjs';
import { encodeMhStreamMessage } from './mh-system-stream.mjs';
const profiles = ['mhxx-1.4', 'mhgu-v262144'];
function context(profile = profiles[0]) {
  return {profile, sessionId: 's1', epoch: 5, windowId: 'w9', routeKey: 0x12345678, senderIdentity: Buffer.from([9, 8, 7, 6])};
}
function message(ctx, seq, payload, terminal, tag = 0x41) {
  const outerHeader = Buffer.alloc(20, tag); ctx.senderIdentity.copy(outerHeader, 8); outerHeader.writeUInt32BE(ctx.routeKey, 12);
  const streamHeader = Buffer.alloc(24, tag + 1); streamHeader.writeUInt16BE(terminal ? 0x8003 : 0x8001);
  streamHeader.writeUInt32BE(seq, 8); streamHeader.writeUInt32BE(0xdeadbeef, 12);
  return encodeMhStreamMessage({outerHeader, streamHeader, payload}, ctx.profile, ctx.routeKey);
}
function payload(size, fill) { return Buffer.alloc(size, fill); }
function conservative(result) {
  assert.equal(result.previewOnly, true);
  for (const k of ['observationsAuthenticated', 'payloadValidated', 'applicationConverted', 'productionReady']) assert.equal(result[k], false);
  assert.equal(result.window.startSequence >= 0, true);
}
function run(ctx, incoming, start, bodyLimit, pending = []) {
  return sequence({context: ctx, startSequence: start, messages: pending}, incoming, ctx, {bodyLimit});
}
test('both profiles preview consecutive bodies including an empty one and keep the window unconsumed', () => {
  for (const profile of profiles) {
    const ctx = context(profile), b1a = payload(10, 0x21), b1b = payload(20, 0x22), b3 = payload(30, 0x23);
    const incoming = [message(ctx, 100, b1a, false), message(ctx, 101, b1b, true),
      message(ctx, 102, Buffer.alloc(0), true), message(ctx, 103, b3, true)];
    const result = run(ctx, incoming, 100, 3);
    assert.equal(result.complete, true); assert.equal(result.stoppedReason, 'limit'); assert.equal(result.bodyCount, 3);
    conservative(result);
    assert.deepEqual(result.bodies[0], {startSequence: 100, terminalSequence: 101, chunkCount: 2,
      body: Buffer.concat([b1a, b1b]), streamHeaders: result.bodies[0].streamHeaders});
    assert.deepEqual(result.bodies[1], {startSequence: 102, terminalSequence: 102, chunkCount: 1,
      body: Buffer.alloc(0), streamHeaders: result.bodies[1].streamHeaders});
    assert.deepEqual(result.bodies[2].body, b3); assert.equal(result.bodies[2].chunkCount, 1);
    assert.equal(result.window.startSequence, 100); assert.equal(result.window.messages.length, 4);
    assert.equal(result.uniqueCount, 4); assert.equal(result.duplicateCount, 0);
    for (let i = 1; i < 3; i++) assert.equal(result.bodies[i].startSequence, result.bodies[i - 1].terminalSequence + 1);
    const partial = run(ctx, incoming.slice(0, 2), 100, 3);
    assert.equal(partial.complete, false); assert.equal(partial.stoppedReason, 'no_more_messages');
  }
});
test('hand-assembled literal hex bodies preview without the encoder', () => {
  const ctx = context(), outer = Buffer.alloc(44, 0x37);
  outer.writeUInt16BE(24, 2); ctx.senderIdentity.copy(outer, 8); outer.writeUInt32BE(ctx.routeKey, 12);
  outer.writeUInt16BE(0x8003, 20); outer.writeUInt16BE(0, 22); outer.writeUInt32BE(100, 28); outer.writeUInt32BE(0xcafef00d, 32);
  const next = Buffer.from(outer); next.writeUInt32BE(101, 28);
  const result = run(ctx, [outer, next], 100, 2);
  assert.equal(result.complete, true); assert.equal(result.bodyCount, 2);
  assert.deepEqual(result.bodies[0].body, Buffer.alloc(0)); assert.deepEqual(result.bodies[1].body, Buffer.alloc(0));
  assert.equal(result.bodies[0].streamHeaders[0].readUInt32BE(12), 0xcafef00d);
  conservative(result);
});
test('bodyLimit 1 matches the existing single receive preview on the same observations', () => {
  for (const profile of profiles) {
    const ctx = context(profile), b1 = payload(12, 0x31), tail = message(ctx, 102, payload(5, 0x32), true);
    const incoming = [message(ctx, 100, b1, false), message(ctx, 101, payload(8, 0x33), true), tail];
    const one = run(ctx, incoming, 100, 1), single = preview({context: ctx, startSequence: 100, messages: []}, incoming, ctx);
    assert.equal(one.bodyCount, 1); assert.equal(one.stoppedReason, 'limit');
    assert.deepEqual(one.bodies[0].body, single.preview.body);
    assert.deepEqual(one.bodies[0].streamHeaders, single.preview.streamHeaders);
    assert.equal(one.bodies[0].terminalSequence, single.preview.terminalSequence);
    assert.equal(one.bodies[0].chunkCount, single.preview.chunkCount);
    assert.deepEqual(one.window.messages, single.window.messages);
    assert.equal(one.uniqueCount, single.window.messages.length);
  }
});
test('incomplete later bodies and inter-body gaps stop honestly without consuming tails', () => {
  for (const profile of profiles) {
    const ctx = context(profile);
    const incomplete = [message(ctx, 100, payload(9, 0x41), true), message(ctx, 101, payload(4, 0x42), false),
      message(ctx, 103, payload(6, 0x43), true)];
    const a = run(ctx, incomplete, 100, 2);
    assert.equal(a.bodyCount, 1); assert.equal(a.complete, false); assert.equal(a.stoppedReason, 'no_complete_body');
    assert.equal(a.window.messages.length, 3); assert.equal(a.window.startSequence, 100);
    const gapped = [message(ctx, 100, payload(9, 0x44), true), message(ctx, 102, payload(6, 0x45), true)];
    const b = run(ctx, gapped, 100, 2);
    assert.equal(b.bodyCount, 1); assert.equal(b.stoppedReason, 'no_complete_body');
    assert.equal(b.bodies[0].terminalSequence, 100); assert.equal(b.window.messages.length, 2);
  }
});
test('uint32 wrap boundaries stop with an explicit reason', () => {
  const ctx = context();
  const last = run(ctx, [message(ctx, 0xffffffff, payload(3, 0x51), true)], 0xffffffff, 2);
  assert.equal(last.bodyCount, 1); assert.equal(last.stoppedReason, 'sequence_wrap'); assert.equal(last.complete, false);
  assert.equal(last.bodies[0].startSequence, 0xffffffff); conservative(last);
  const pair = run(ctx, [message(ctx, 0xfffffffe, payload(1, 0x52), true),
    message(ctx, 0xffffffff, payload(2, 0x53), true)], 0xfffffffe, 2);
  assert.equal(pair.bodyCount, 2); assert.equal(pair.stoppedReason, 'sequence_wrap'); assert.equal(pair.complete, true);
  const before = run(ctx, [message(ctx, 0xfffffffe, payload(1, 0x54), true)], 0xfffffffe, 2);
  assert.equal(before.bodyCount, 1); assert.equal(before.stoppedReason, 'no_more_messages');
});
test('identical duplicates stay first-wins while conflicting duplicates reject atomically', () => {
  const ctx = context(), first = message(ctx, 100, payload(7, 0x61), true), second = message(ctx, 101, payload(3, 0x62), true);
  const dup = run(ctx, [first, Buffer.from(first), second], 100, 2);
  assert.equal(dup.duplicateCount, 1); assert.equal(dup.uniqueCount, 2); assert.equal(dup.bodyCount, 2);
  assert.deepEqual(dup.window.messages, [first, second]); conservative(dup);
  const conflict = Buffer.from(second); conflict[36] ^= 1;
  const keep = [Buffer.from(first), Buffer.from(second)];
  assert.throws(() => run(ctx, [first, second, conflict], 100, 2), /mh_receive_sequence_conflicting_duplicate/);
  assert.deepEqual([first, second], keep);
});
test('pre-pass mirrors the single preview strictness with sequence-prefixed errors', () => {
  const ctx = context(), good = message(ctx, 100, payload(4, 0x71), true);
  const old = message(ctx, 99, payload(4, 0x72), true);
  const notData = message(ctx, 101, payload(4, 0x73), true); notData.writeUInt16BE(0x8002, 20);
  const badRoute = message(ctx, 101, payload(4, 0x74), true); badRoute.writeUInt32BE(ctx.routeKey ^ 1, 12);
  const badSender = message(ctx, 101, payload(4, 0x75), true); badSender[8] ^= 1;
  const badLength = message(ctx, 101, payload(4, 0x76), true); badLength.writeUInt16BE(9, 2);
  for (const [bad, name] of [[old, 'range'], [notData, 'not_data'], [badRoute, 'route'], [badSender, 'sender'], [badLength, 'outer_length']]) {
    assert.throws(() => run(ctx, [good, bad], 100, 1), new RegExp(name === 'range' ? 'mh_receive_sequence_sequence_range' : 'mh_receive_sequence_' + name), name);
  }
  assert.throws(() => run(ctx, [good], 100, 1, Array.from({length: 64}, () => Buffer.from(good))), /supplied_count/);
  assert.throws(() => run(ctx, [message(ctx, 100, payload(4, 0x77), true), message(ctx, 164, payload(4, 0x78), true)], 100, 2),
    /sequence_range/);
});
test('closed shapes and bodyLimit bounds reject getters without executing them', () => {
  const ctx = context(), good = [message(ctx, 100, payload(4, 0x81), true)];
  let calls = 0;
  const getterOptions = {get bodyLimit() { calls++; return 1; }};
  assert.throws(() => sequence({context: ctx, startSequence: 100, messages: []}, good, ctx, getterOptions), /mh_receive_sequence_options/);
  assert.equal(calls, 0);
  for (const limit of [0, 65, 1.5, '2', NaN]) assert.throws(() => run(ctx, good, 100, limit), /mh_receive_sequence_body_limit/);
  assert.throws(() => sequence({context: ctx, startSequence: 100, messages: []}, good, ctx, {bodyLimit: 1, extra: 2}), /mh_receive_sequence_options/);
  assert.throws(() => sequence({context: ctx, startSequence: 100, messages: [], extra: 1}, good, ctx, {bodyLimit: 1}), /mh_receive_sequence_snapshot/);
  const holey = [good[0]]; delete holey[0];
  assert.throws(() => run(ctx, holey, 100, 1), /mh_receive_sequence_messages/);
  assert.throws(() => run(ctx, Object.setPrototypeOf([good[0]], class extends Array {}.prototype), 100, 1), /mh_receive_sequence_messages/);
  const nullProto = Object.assign(Object.create(null), {bodyLimit: 1});
  assert.equal(sequence({context: ctx, startSequence: 100, messages: []}, good, ctx, nullProto).bodyCount, 1);
});
test('results are deterministic and detached from inputs and outputs', () => {
  const ctx = context(), incoming = [message(ctx, 100, payload(8, 0x91), true), message(ctx, 101, payload(5, 0x92), true)];
  const reference = run(ctx, incoming, 100, 2), again = run(ctx, incoming, 100, 2);
  assert.deepEqual(again, reference); conservative(reference);
  const originals = incoming.map(b => Buffer.from(b));
  reference.bodies[0].body.fill(0); reference.bodies[1].streamHeaders[0].fill(0);
  reference.window.messages[0].fill(0); reference.window.context.senderIdentity.fill(0);
  assert.deepEqual(incoming, originals); assert.deepEqual(run(ctx, incoming, 100, 2), again);
  const held = run(ctx, incoming, 100, 2); incoming[0].fill(0);
  assert.deepEqual(held, again);
});
