import assert from 'node:assert/strict';
import test from 'node:test';
import { applyMhStreamAckForContext as apply } from './mh-stream-context-ack.mjs';
import { applyMhStreamAck, MH_STREAM_MAX_TIME as MAX } from './mh-stream-ack.mjs';
import { encodeMhStreamMessage } from './mh-system-stream.mjs';
const profiles=['mhxx-1.4','mhgu-v262144'];
function context(profile=profiles[0]) {return {profile,sessionId:'s1',epoch:1,windowId:'w1',routeKey:0x12340001,senderIdentity:Buffer.from([10,20,30,40])};}
function clone(c){return {...c,senderIdentity:Buffer.from(c.senderIdentity)};}
function window(c,base=100,count=4){return {context:clone(c),base,schedules:Array.from({length:count},(_,i)=>BigInt(i+10))};}
function message(c,ack=100,bitmap=0n,sequence=987654,payload=Buffer.alloc(0),flags=0){
  const outerHeader=Buffer.alloc(20,0x35),streamHeader=Buffer.alloc(24,0x67);outerHeader.writeUInt32BE(c.routeKey,12);c.senderIdentity.copy(outerHeader,8);
  streamHeader.writeUInt16BE(flags,0);streamHeader.writeUInt32BE(sequence,8);streamHeader.writeUInt32BE(ack,12);streamHeader.writeBigUInt64BE(bitmap,16);
  return encodeMhStreamMessage({outerHeader,streamHeader,payload},c.profile,c.routeKey);
}
function preserved(w,m,c,fn){const before=structuredClone({base:w.base,schedules:w.schedules}),wc=clone(w.context),mc=Buffer.from(m),cc=clone(c);
  const result=fn();assert.deepEqual({base:w.base,schedules:w.schedules},before);assert.deepEqual(w.context,wc);assert.deepEqual(m,mc);assert.deepEqual(c,cc);return result;}

test('both same-side profiles update ACK with independent data sequence and preserve all input snapshots',()=>{
  for(const profile of profiles){const c=context(profile),w=window(c),m=message(c,102,1n,0xfffffffe,Buffer.from([0x20,0,1]),3);
    const result=preserved(w,m,c,()=>apply(w,m,c));assert.equal(result.window.base,102);assert.deepEqual(result.window.schedules,[12n,MAX]);
    assert.equal(result.released,2);assert.equal(result.stale,false);assert.equal(result.contextMatched,true);
    for(const flag of ['observationsAuthenticated','payloadValidated','applicationConverted','productionReady'])assert.equal(result[flag],false);
    const raw=applyMhStreamAck(w,m.subarray(20,20+m.readUInt16BE(2)),profile);assert.equal(raw.base,result.window.base);assert.deepEqual(raw.schedules,result.window.schedules);
    assert.deepEqual(result.window.context,c);result.window.context.senderIdentity.fill(0);result.window.schedules[0]=55n;
    assert.deepEqual(w.context.senderIdentity,c.senderIdentity);assert.deepEqual(w.schedules,[10n,11n,12n,13n]);
  }
});

test('hand-authored ACK-only message exercises +12 ACK and low-bit-first bitmap rather than incoming +8 sequence',()=>{
  const c=context(),w=window(c,10,4);
  const m=Buffer.from('01000018010203040a141e2812340001001122330000000001020304000000630000000b0000000000000002','hex');
  const r=apply(w,m,c);assert.equal(r.window.base,11);assert.equal(r.released,1);assert.deepEqual(r.window.schedules,[11n,12n,MAX]);
  assert.equal(m.readUInt32BE(28),99);
});

test('each stale or opposite-side context mismatch is rejected before updating a valid numerical window',()=>{
  for(const profile of profiles){const c=context(profile),w=window(c),m=message(c,101);
    for(const patch of [{profile:profiles.find(p=>p!==profile)},{sessionId:'s2'},{epoch:2},{windowId:'w2'},{routeKey:0x12340002},{senderIdentity:Buffer.alloc(4)}])
      preserved(w,m,c,()=>assert.throws(()=>apply(w,m,{...clone(c),...patch}),/context_mismatch/));
    const out=apply(w,m,c);assert.equal(out.window.base,101);assert.equal(w.base,100);
  }
});

test('wire route and original sender are independently required even when labels are internally consistent',()=>{
  for(const profile of profiles){const c=context(profile),w=window(c),m=message(c,101);
    for(const offset of [8,9,10,11,12,13,14,15]){const bad=Buffer.from(m);bad[offset]^=1;
      preserved(w,bad,c,()=>assert.throws(()=>apply(w,bad,c),offset<12?/sender_mismatch/:/route_mismatch/));}
    const zero=clone(c);zero.senderIdentity.fill(0);const zw=window(zero),zm=message(zero,101);assert.equal(apply(zw,zm,zero).observationsAuthenticated,false);
  }
});

test('closed data context/snapshot fields reject extras, accessors, malformed IDs and invalid numeric bounds',()=>{
  const c=context(),w=window(c),m=message(c);let touched=0;
  const getter={...c};Object.defineProperty(getter,'epoch',{get(){touched++;return 1;},enumerable:true});
  const badContexts=[null,[],{},getter,{...c,extra:1},{...c,[Symbol('hidden')]:1}];
  for(const patch of [{profile:'unknown'},{sessionId:''},{sessionId:'s0'},{sessionId:'s100000000'},{sessionId:'s1'+String.fromCharCode(10)},
    {windowId:'w0'},{windowId:'w1'+String.fromCharCode(13)},{epoch:0},{epoch:1.5},{epoch:Number.MAX_SAFE_INTEGER+1},{routeKey:-1},{routeKey:2**32},
    {senderIdentity:Buffer.alloc(3)},{senderIdentity:new Uint8Array(4)}])badContexts.push({...c,...patch});
  for(const bad of badContexts){assert.throws(()=>apply(w,m,bad));assert.throws(()=>apply({...w,context:bad},m,c));}
  assert.equal(touched,0);
  for(const bad of [null,[],{}, {...w,extra:1}, {...w,[Symbol('hidden')]:1}])assert.throws(()=>apply(bad,m,c),/window/);
  const gw={...w};Object.defineProperty(gw,'base',{get(){touched++;return 100;}});assert.throws(()=>apply(gw,m,c),/window/);assert.equal(touched,0);
  const nullContext=Object.assign(Object.create(null),c);assert.equal(apply({...w,context:nullContext},m,nullContext).contextMatched,true);
});

test('malformed outer/nested messages, padding boundaries, invalid window state and GU payload bound fail atomically',()=>{
  for(const profile of profiles){const c=context(profile),w=window(c),m=message(c);
    for(const bad of [null,new Uint8Array(m),Buffer.alloc(19),Buffer.concat([m,Buffer.alloc(1)]),m.subarray(0,m.length-1)])assert.throws(()=>apply(w,bad,c));
    const sentinel=Buffer.from(m);sentinel[0]=0xff;assert.throws(()=>apply(w,sentinel,c),/message/);
    const short=Buffer.from(m);short.writeUInt16BE(23,2);assert.throws(()=>apply(w,short,c),/short_header/);
    const nested=Buffer.from(m);nested.writeUInt16BE(1,22);assert.throws(()=>apply(w,nested,c),/length/);
    for(const patch of [{base:-1},{base:2**32},{base:0xffffffff,schedules:[1n]},{schedules:[0]},{schedules:Array(1)},{schedules:Array(65).fill(1n)},
      {schedules:[-1n]},{schedules:[MAX+1n]}])assert.throws(()=>apply({...w,...patch},m,c));
    const padded=message(c,100,0n,1,Buffer.from([1]),1);padded[padded.length-1]=0xfe;const before=Buffer.from(padded);assert.equal(apply(w,padded,c).window.base,100);assert.deepEqual(padded,before);
  }
  const xx=context(),w=window(xx),large=message(xx,100,0n,1,Buffer.alloc(1417),1);assert.equal(apply(w,large,xx).contextMatched,true);
  const gu={...clone(xx),profile:profiles[1]};assert.throws(()=>apply(window(gu),large,gu),/mhgu_stream_payload_limit/);
  assert.equal(apply(window(gu),message(gu,100,0n,1,Buffer.alloc(1416),1),gu).contextMatched,true);
});

test('stale, beyond-outstanding, boundary signed delta and selective ACK do not infer opposite-side delivery',()=>{
  for(const profile of profiles){const c=context(profile),w=window(c),stale=apply(w,message(c,99,~0n&MAX),c);
    assert.equal(stale.stale,true);assert.deepEqual(stale.window.schedules,w.schedules);assert.equal(stale.released,0);
    preserved(w,message(c,105),c,()=>assert.throws(()=>apply(w,message(c,105),c),/beyond_outstanding/));
    const signed=apply(w,message(c,(100+0x80000000)>>>0,MAX),c);assert.equal(signed.stale,true);
    const selective=apply(w,message(c,100,MAX),c);assert.deepEqual(selective.window.schedules,[10n,MAX,MAX,MAX]);assert.equal(selective.released,0);
    const all=apply(w,message(c,104,MAX),c);assert.deepEqual(all.window.schedules,[]);assert.equal(all.released,4);
    const empty=window(c,0xffffffff,0);assert.equal(apply(empty,message(c,0xffffffff),c).released,0);
  }
});

test('independent source/target sequence spaces stay separate; coherent fabricated labels are not authenticated',()=>{
  const a=context(),b={...context(profiles[1]),windowId:'w2',routeKey:0x55660002,senderIdentity:Buffer.from([192,0,2,7])};
  const wa=window(a,55,2),wb=window(b,202,3),mb=message(b,204,0n,77);
  const r=apply(wb,mb,b);assert.equal(r.window.base,204);assert.equal(wa.base,55);assert.deepEqual(wa.schedules,[10n,11n]);
  assert.throws(()=>apply(wa,mb,b),/context_mismatch/);
  const invented={...clone(b),sessionId:'s99',epoch:999,windowId:'w99'};
  const forged={...wb,context:clone(invented)};const pass=apply(forged,mb,invented);
  assert.equal(pass.contextMatched,true);assert.equal(pass.observationsAuthenticated,false);
  // Applying the same pure snapshot twice is not anti-replay; no receiver state is owned here.
  assert.deepEqual(apply(wb,mb,b),apply(wb,mb,b));
});
