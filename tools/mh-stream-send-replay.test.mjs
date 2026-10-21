import assert from 'node:assert/strict';
import test from 'node:test';
import { replayMhStreamSendWindow as replay } from './mh-stream-send-replay.mjs';
import { applyMhStreamAckForContext as apply } from './mh-stream-context-ack.mjs';
import { MH_STREAM_MAX_TIME as MAX } from './mh-stream-ack.mjs';
import { encodeMhStreamMessage } from './mh-system-stream.mjs';
const profiles=['mhxx-1.4','mhgu-v262144'];
function ctx(profile=profiles[0]){return {profile,sessionId:'s1',epoch:1,windowId:'w1',routeKey:0x12340001,senderIdentity:Buffer.from('0a141e28','hex')};}
function win(c=ctx(),base=100,schedules=[10n,20n,30n,40n]){return {context:{...c,senderIdentity:Buffer.from(c.senderIdentity)},base,schedules:[...schedules]};}
function event(c,ack=100,bitmap=0n,now=20n,payload=Buffer.alloc(0)){
 const outerHeader=Buffer.alloc(20,0x35),streamHeader=Buffer.alloc(24);outerHeader.writeUInt32BE(c.routeKey,12);c.senderIdentity.copy(outerHeader,8);
 streamHeader.writeUInt32BE(0xdeadbeef,8);streamHeader.writeUInt32BE(ack,12);streamHeader.writeBigUInt64BE(bitmap,16);
 return {message:encodeMhStreamMessage({outerHeader,streamHeader,payload},c.profile,c.routeKey),context:{...c,senderIdentity:Buffer.from(c.senderIdentity)},now};
}
function snapshot(w,events){return {w:structuredClone(w),events:structuredClone(events)};}
function unchanged(w,events,before){assert.deepEqual(structuredClone(w),before.w);assert.deepEqual(structuredClone(events),before.events);}

test('both profiles replay cumulative/selective ACKs then compare remaining schedules without DATA delivery',()=>{
 for(const profile of profiles){const c=ctx(profile),w=win(c),events=[event(c,101,1n,20n,Buffer.from([0x20,0,1])),event(c,101,0n,25n),event(c,102,0n,30n)];
 const before=snapshot(w,events),r=replay(w,events);unchanged(w,events,before);
 assert.equal(r.window.base,102);assert.deepEqual(r.window.schedules,[MAX,40n]);assert.equal(r.releasedTotal,2);assert.equal(r.staleCount,0);
 assert.deepEqual(r.steps.map(s=>s.scheduleEligibleIndices),[[0],[0],[]]);assert.deepEqual(r.steps.map(s=>s.schedules),[[20n,MAX,40n],[20n,MAX,40n],[MAX,40n]]);
 assert.equal(r.contextMatched,true);assert.equal(r.scheduleComparisonOnly,true);
 for(const flag of ['observationsAuthenticated','payloadValidated','applicationConverted','productionReady'])assert.equal(r[flag],false);
 assert.equal(events[0].message.readUInt32BE(28),0xdeadbeef);
 }
});

test('independent hand hex, stale bitmap skip and MAX equality are comparisons not actual sends',()=>{
 const c=ctx(),w=win(c,10,[1n,2n,3n,4n]);
 const first={context:c,now:2n,message:Buffer.from('01000018010203040a141e2812340001001122330000000001020304000000630000000b0000000000000002','hex')};
 const events=[first,event(c,10,0xffffffffffffffffn,4n),event(c,11,0n,MAX)];const r=replay(w,events);
 assert.deepEqual(r.steps[0].schedules,[2n,3n,MAX]);assert.deepEqual(r.steps[0].scheduleEligibleIndices,[0]);
 assert.equal(r.steps[1].stale,true);assert.deepEqual(r.steps[1].schedules,[2n,3n,MAX]);assert.deepEqual(r.steps[1].scheduleEligibleIndices,[0,1]);
 assert.deepEqual(r.steps[2].scheduleEligibleIndices,[0,1,2]);assert.equal(r.staleCount,1);assert.equal(r.releasedTotal,1);
 assert.equal(r.applicationConverted,false);
});

test('zero outstanding, signed half range, no-wrap and 64 observation limits remain explicit',()=>{
 const c=ctx(),w=win(c,0xffffffff,[]);const one=event(c,0xffffffff,0n,0n);
 const r=replay(w,Array.from({length:64},()=>one));assert.equal(r.steps.length,64);assert.deepEqual(r.window.schedules,[]);
 assert.ok(r.steps.every(s=>s.scheduleEligibleIndices.length===0));assert.throws(()=>replay(w,Array.from({length:65},()=>one)),/batch/);
 const half=replay(win(c,0,[]),[event(c,0x80000000,MAX,0n)]);assert.equal(half.steps[0].stale,true);assert.equal(half.window.base,0);
 assert.throws(()=>replay(win(c,0xffffffff,[1n]),[event(c,0xffffffff)]),/invalid_window/);
 assert.throws(()=>replay(win(c,100,[1n]),[event(c,102)]),/beyond_outstanding/);
 const full=replay(win(c,0,Array(64).fill(0n)),[event(c,0,MAX,MAX-1n),event(c,0,0n,MAX)]);
 assert.deepEqual(full.steps[0].scheduleEligibleIndices,[0]);assert.equal(full.steps[1].scheduleEligibleIndices.length,64);
 assert.equal(full.window.schedules[0],0n);assert.ok(full.window.schedules.slice(1).every(due=>due===MAX));
});

test('late errors never return partial snapshots or mutate input, contexts must stay same-side',()=>{
 for(const profile of profiles){const c=ctx(profile),w=win(c);const good=event(c,101);
 const errors=[event(c,999),event(c,101),event(c,101),event(c,101),event(c,101)];
 errors[1].context.epoch++;errors[2].message[8]^=1;errors[3].message[12]^=1;errors[4].message=errors[4].message.subarray(0,25);
 for(const bad of errors){const events=[good,bad],before=snapshot(w,events);assert.throws(()=>replay(w,events));unchanged(w,events,before);}
 for(const patch of [{profile:profiles.find(p=>p!==profile)},{sessionId:'s2'},{windowId:'w2'},{routeKey:3},{senderIdentity:Buffer.alloc(4)}]){
 const bad=event(c,101);Object.assign(bad.context,patch);const es=[good,bad],before=snapshot(w,es);assert.throws(()=>replay(w,es),/context_mismatch/);unchanged(w,es,before);}
 }
});

test('declared clocks require uint64 BigInt and nondecreasing batch samples, even after full release',()=>{
 const c=ctx(),w=win(c);for(const now of [-1n,MAX+1n,1,NaN,null,undefined,'20',Object(1n)]){
 const e=event(c,104);e.now=now;assert.throws(()=>replay(w,[e]),/invalid_time/);
 assert.throws(()=>replay(win(c,104,[]),[{...e,message:event(c,104).message}]),/invalid_time/);}
 assert.throws(()=>replay(w,[event(c,100,0n,MAX),event(c,100,0n,0n)]),/clock_regression/);
 assert.throws(()=>replay(w,[event(c,104,0n,20n),event(c,104,0n,19n)]),/clock_regression/);
 assert.deepEqual(replay(w,[event(c,104,0n,0n),event(c,104,0n,0n)]).window.schedules,[]);
});

test('dense closed own data fields reject holes, getters, extras and unsupported observation shapes',()=>{
 const c=ctx(),w=win(c),e=event(c);let touched=0;
 for(const bad of [null,{},[],new Array(1),[e,,],Object.assign([e],{extra:1}),Object.assign([e],{[Symbol('x')]:1})])assert.throws(()=>replay(w,bad),/batch/);
 const array=[e];Object.defineProperty(array,'0',{get(){touched++;return e;}});assert.throws(()=>replay(w,array),/batch/);
 for(const key of ['message','context','now']){const item={...e};Object.defineProperty(item,key,{get(){touched++;return e[key];}});assert.throws(()=>replay(w,[item]),/observation/);}
 const hidden=Object.defineProperty([e],'hidden',{value:1});assert.throws(()=>replay(w,hidden),/batch/);
 const hole=Array(1),inherited=Object.create(Array.prototype);inherited[0]=e;Object.setPrototypeOf(hole,inherited);hole.extra=e;assert.throws(()=>replay(w,hole),/batch/);
 const getter={...e};Object.defineProperty(getter,'message',{get(){touched++;return e.message;}});
 for(const bad of [null,[],{}, {...e,extra:1},{...e,[Symbol('x')]:1},getter,Object.create(e)])assert.throws(()=>replay(w,[bad]),/observation/);
 const contextGetter={...c};Object.defineProperty(contextGetter,'epoch',{get(){touched++;return 1;}});assert.throws(()=>replay(w,[{...e,context:contextGetter}]),/context/);
 assert.equal(touched,0);const closed=Object.freeze(Object.assign(Object.create(null),e));assert.equal(replay(w,Object.freeze([closed])).steps.length,1);
});

test('result snapshots, histories, repeated calls and input buffers are isolated, not persistence/authentication',()=>{
 const c=ctx(),w=win(c),events=[event(c,100),event(c,100)];const before=snapshot(w,events),a=replay(w,events),b=replay(w,events);
 assert.deepEqual(a,b);assert.notStrictEqual(a.window.schedules,a.steps.at(-1).schedules);assert.notStrictEqual(a.window.schedules,w.schedules);assert.notStrictEqual(a.window.context,w.context);assert.notStrictEqual(a.window.context.senderIdentity,w.context.senderIdentity);
 a.steps[0].schedules[0]=99n;a.steps[0].scheduleEligibleIndices.push(63);assert.deepEqual(a.steps[1].scheduleEligibleIndices,[0,1]);assert.deepEqual(b.steps[0].scheduleEligibleIndices,[0,1]);
 assert.deepEqual(a.steps[1].schedules,[10n,20n,30n,40n]);assert.deepEqual(a.window.schedules,b.window.schedules);
 a.window.schedules[0]=999n;a.window.context.senderIdentity.fill(0);unchanged(w,events,before);assert.equal(b.observationsAuthenticated,false);
 const forged=ctx();forged.sessionId='s999';assert.equal(replay(win(forged),[event(forged)]).productionReady,false);
});

test('deterministic multi-step replay matches manual guarded ACK composition for both profiles',()=>{
 for(const profile of profiles)for(let seed=1;seed<=24;seed++){
 const c=ctx(profile),w=win(c,1000,Array.from({length:16},(_,i)=>BigInt(i+seed))),events=[];let current=w;const expected=[];
 for(let i=0;i<12;i++){const delta=Math.min((seed+i)%3,current.schedules.length),ack=current.base+delta;
 const e=event(c,ack,BigInt((seed*17+i)%256),BigInt(seed+i)),r=apply(current,e.message,e.context);events.push(e);current=r.window;
 expected.push({base:current.base,schedules:[...current.schedules],released:r.released,stale:r.stale,sampleTime:e.now,scheduleEligibleIndices:current.schedules.flatMap((due,index)=>e.now>=due?[index]:[])});}
 const r=replay(w,events);assert.deepEqual(r.window,current);assert.deepEqual(r.steps,expected);assert.equal(r.releasedTotal,16-current.schedules.length);
 }
});
