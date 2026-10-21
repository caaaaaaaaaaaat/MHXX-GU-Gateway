import assert from 'node:assert/strict';
import test from 'node:test';
import { previewMhStreamReceiveWindow as preview } from './mh-stream-receive-preview.mjs';
import { encodeMhStreamMessage, recoverMhPeerListFromMessages } from './mh-system-stream.mjs';
import { assembleMhStreamChunks } from './mh-stream-chunk.mjs';
import { applyMhStreamAckForContext as applyAck } from './mh-stream-context-ack.mjs';
const profiles=['mhxx-1.4','mhgu-v262144'];
function ctx(profile=profiles[0]){return {profile,sessionId:'s1',epoch:1,windowId:'w1',routeKey:0x12340001,senderIdentity:Buffer.from('0a141e28','hex')};}
function state(c=ctx(),startSequence=100,messages=[]){return {context:{...c,senderIdentity:Buffer.from(c.senderIdentity)},startSequence,messages};}
function msg(c,sequence=100,payload=Buffer.alloc(0),flags=3,encoderProfile=c.profile){
 const outerHeader=Buffer.alloc(20,0x35),streamHeader=Buffer.alloc(24,0x67);outerHeader.writeUInt32BE(c.routeKey,12);c.senderIdentity.copy(outerHeader,8);
 streamHeader.writeUInt16BE(flags,0);streamHeader.writeUInt32BE(sequence,8);
 return encodeMhStreamMessage({outerHeader,streamHeader,payload},encoderProfile,c.routeKey);
}
function safe(s,ms,c,fn){const before=structuredClone({s,ms,c});const r=fn();assert.deepEqual(structuredClone({s,ms,c}),before);return r;}

test('both profiles retain out-of-order gaps then preview only first complete body without consuming tails',()=>{
 for(const profile of profiles){const c=ctx(profile),s=state(c),a=msg(c,100,Buffer.from('A'),1),b=msg(c,101,Buffer.from('B'),1),z=msg(c,102,Buffer.from('C')),tail=msg(c,103,Buffer.from('D'));
 const r=safe(s,[z,a],c,()=>preview(s,[z,a],c));assert.equal(r.preview,null);assert.equal(r.contiguousPrefixCount,1);assert.equal(r.window.messages.length,2);
 const completed=preview(r.window,[tail,b],c);assert.equal(completed.preview.body.toString(),'ABC');assert.equal(completed.preview.terminalSequence,102);assert.equal(completed.preview.chunkCount,3);assert.equal(completed.window.messages.length,4);assert.equal(completed.window.startSequence,100);assert.equal(completed.pendingPayloadBytes,4);
 const again=preview(completed.window,[],c);assert.deepEqual(again.preview,completed.preview);assert.deepEqual(again.window,completed.window);
 for(const key of ['observationsAuthenticated','payloadValidated','applicationConverted','productionReady'])assert.equal(again[key],false);assert.equal(again.previewOnly,true);
 assert.equal(preview(state(c),[z],c).contiguousPrefixCount,0);assert.equal(preview(state(c),[a,b],c).preview,null);
 }
});

test('independent hand hex and zero-length DATA terminal assemble an empty body, never process ACK',()=>{
 const wire=Buffer.from('01000018010203040a141e28123400010011223300030000010203040000000a0000000b0000000000000002','hex');
 for(const profile of profiles){const c=ctx(profile),r=preview(state(c,10),[wire],c);assert.equal(r.preview.body.length,0);assert.equal(r.preview.chunkCount,1);assert.equal(r.preview.terminalSequence,10);assert.equal(r.window.startSequence,10);assert.deepEqual(r.window.messages,[wire]);assert.equal(r.pendingPayloadBytes,0);}
});

test('1..64 total supplied items, local delta63/64 policy and uint32 non-wrapping boundaries',()=>{
 const c=ctx(),single=msg(c);assert.throws(()=>preview(state(c),[],c),/supplied_count/);
 const duplicate=preview(state(c),Array(64).fill(single),c);assert.equal(duplicate.duplicateCount,63);assert.equal(duplicate.window.messages.length,1);
 assert.throws(()=>preview(state(c,100,[single]),Array(64).fill(single),c),/supplied_count/);
 const full=preview(state(c,0),Array.from({length:64},(_,i)=>msg(c,i,Buffer.alloc(0),i===63?3:1)),c);assert.equal(full.preview.chunkCount,64);assert.equal(preview(full.window,[],c).window.messages.length,64);assert.throws(()=>preview(full.window,[full.window.messages[0]],c),/supplied_count/);
 assert.equal(preview(state(c),[msg(c,163)],c).preview,null);assert.throws(()=>preview(state(c),[msg(c,164)],c),/sequence_range/);
 assert.equal(preview(state(c,0xffffffff),[msg(c,0xffffffff)],c).preview.terminalSequence,0xffffffff);
 assert.equal(preview(state(c,0xfffffffe),[msg(c,0xffffffff),msg(c,0xfffffffe,Buffer.alloc(0),1)],c).preview.chunkCount,2);
 assert.throws(()=>preview(state(c,0xffffffff),[msg(c,0)],c),/sequence_range/);assert.throws(()=>preview(state(c),[msg(c,99)],c),/sequence_range/);
});

test('all supplied tail rows are checked; conflicting payload, terminal, opaque header and ACK duplicates reject',()=>{
 for(const profile of profiles){const c=ctx(profile),s=state(c),first=msg(c,100,Buffer.from('ready')),tail=msg(c,101,Buffer.from('x'));
 for(const offset of [20,24,32,44]){const conflict=Buffer.from(tail);conflict[offset]^=1;const ms=[first,tail,conflict];safe(s,ms,c,()=>assert.throws(()=>preview(s,ms,c),/conflicting_duplicate/));}
 const changedOuter=Buffer.from(tail);changedOuter[4]^=1;changedOuter[changedOuter.length-1]^=1;
 const r=preview(s,[first,tail,changedOuter],c);assert.equal(r.duplicateCount,1);assert.equal(r.preview.body.toString(),'ready');assert.deepEqual(r.window.messages[1],tail);
 for(const offset of [8,12]){const bad=Buffer.from(tail);bad[offset]^=1;assert.throws(()=>preview(s,[first,tail,bad],c),/mismatch/);}
 }
});

test('all contexts and original wire sender/route must match even for pending and duplicate messages',()=>{
 for(const profile of profiles){const c=ctx(profile),m=msg(c),s=state(c,100,[m]);
 for(const patch of [{profile:profiles.find(p=>p!==profile)},{sessionId:'s2'},{epoch:2},{windowId:'w2'},{routeKey:2},{senderIdentity:Buffer.alloc(4)}])safe(s,[],c,()=>assert.throws(()=>preview(s,[],{...c,...patch}),/context_mismatch/));
 for(const offset of [8,9,10,11,12,13,14,15]){const bad=Buffer.from(m);bad[offset]^=1;assert.throws(()=>preview(state(c,100,[bad]),[],c),/mismatch/);}
 const fake={...c,epoch:99,sessionId:'s999'};assert.equal(preview(state(fake),[m],fake).observationsAuthenticated,false);
 }
});

test('closed snapshots and dense arrays reject accessors/holes/extras and malformed context/start',()=>{
 const c=ctx(),m=msg(c),s=state(c);let touched=0;
 for(const key of ['context','startSequence','messages']){const bad={...s};Object.defineProperty(bad,key,{get(){touched++;return s[key];}});assert.throws(()=>preview(bad,[m],c),/snapshot/);}
 for(const key of ['epoch','profile','senderIdentity']){const bad={...c};Object.defineProperty(bad,key,{get(){touched++;return c[key];}});assert.throws(()=>preview({...s,context:bad},[m],c),/context/);assert.throws(()=>preview(s,[m],bad),/context/);}
 for(const bad of [null,{},Array(1),Object.assign([m],{extra:1}),Object.assign([m],{[Symbol('x')]:1})]){assert.throws(()=>preview(s,bad,c),/messages/);assert.throws(()=>preview({...s,messages:bad},[],c),/messages/);}
 const accessor=[m];Object.defineProperty(accessor,'0',{get(){touched++;return m;}});assert.throws(()=>preview(s,accessor,c),/messages/);assert.equal(touched,0);
 for(const startSequence of [-1,2**32,1.5,null,undefined])assert.throws(()=>preview({...s,startSequence},[m],c),/start_sequence/);
 for(const context of [null,{}, {...c,extra:1},{...c,profile:'auto'},{...c,epoch:0},{...c,senderIdentity:Buffer.alloc(3)}])assert.throws(()=>preview({...s,context},[m],c));
 assert.throws(()=>preview({...s,extra:1},[m],c),/snapshot/);const frozen=Object.freeze(Object.assign(Object.create(null),s));assert.equal(preview(frozen,Object.freeze([m]),c).preview.chunkCount,1);
});

test('outer and nested framing, DATA bit and GU1416 limit remain strict; late failures are atomic',()=>{
 const c=ctx(),s=state(c),good=msg(c);const nestedLength=Buffer.from(good);nestedLength.writeUInt16BE(1,22);
 for(const bad of [null,new Uint8Array(good),Buffer.alloc(19),good.subarray(0,good.length-1),nestedLength,msg(c,101,Buffer.alloc(0),0),msg(c,101,Buffer.alloc(0),2)])safe(s,[good,bad],c,()=>assert.throws(()=>preview(s,[good,bad],c)));
 const sentinel=Buffer.from(good);sentinel[0]=0xff;assert.throws(()=>preview(s,[sentinel],c),/message/);
 const emptyOuter=Buffer.from(good.subarray(0,20));emptyOuter.writeUInt16BE(0,2);assert.throws(()=>preview(s,[emptyOuter],c),/short_header/);
 const badAckWindow={context:c,base:-1,schedules:[]};
 assert.throws(()=>applyAck(badAckWindow,emptyOuter,c),{name:'TypeError',message:'mhxx_stream_short_header'});
 assert.throws(()=>applyAck(badAckWindow,good,c),{name:'TypeError',message:'mh_ack_invalid_window'});
 assert.throws(()=>applyAck(badAckWindow,good,{...c,epoch:2}),{name:'Error',message:'mh_context_ack_context_mismatch'});
 const badRoute=Buffer.from(good);badRoute[12]^=1;assert.throws(()=>applyAck(badAckWindow,badRoute,c),{name:'Error',message:'mh_context_ack_route_mismatch'});
 const gu=ctx(profiles[1]);assert.equal(preview(state(gu),[msg(gu,100,Buffer.alloc(1416))],gu).preview.body.length,1416);
 assert.throws(()=>preview(state(gu),[msg(gu,100,Buffer.alloc(1417),3,profiles[0])],gu),/mhgu_stream_payload_limit/);
});

test('unique payload total includes terminal tails: exact1MiB passes and plus1 rejects',()=>{
 const c=ctx(),make=(extra=0)=>Array.from({length:17},(_,i)=>msg(c,100+i,Buffer.alloc(i<16?65511:400+extra,i),i===16?3:1));
 const exact=make(),r=preview(state(c),exact,c);assert.equal(r.pendingPayloadBytes,1024*1024);assert.equal(r.preview.body.length,1024*1024);
 assert.throws(()=>preview(state(c),make(1),c),/byte_limit/);
 const tail=make(1);tail[0].writeUInt16BE(3,20);assert.throws(()=>preview(state(c),tail,c),/byte_limit/);
 assert.equal(preview(state(c),[exact[0],exact[0]],c).pendingPayloadBytes,65511);
});

test('complete previews compose with explicit typed-list recovery but do not validate arbitrary application payload',()=>{
 for(const profile of profiles){const c=ctx(profile),body=Buffer.alloc(12);body[0]=0x20;body[8]=1;
 const messages=[msg(c,100,body.subarray(0,3),1),msg(c,101,body.subarray(3,7),1),msg(c,102,body.subarray(7),3)];
 const incomplete=preview(state(c),[messages[2],messages[0]],c),done=preview(incomplete.window,[messages[1]],c);
 const recovered=recoverMhPeerListFromMessages(done.window.messages,c.profile,100,c.routeKey);assert.deepEqual(done.preview.body,recovered.body);assert.equal(recovered.kind,'peer-list');assert.equal(done.payloadValidated,false);
 const arbitrary=preview(state(c),[msg(c,100,Buffer.alloc(12))],c);assert.ok(arbitrary.preview);assert.throws(()=>recoverMhPeerListFromMessages(arbitrary.window.messages,c.profile,100,c.routeKey),/unsupported_type/);
 }
});

test('detached byte ownership and deterministic incremental permutations match strict assembler without consumption',()=>{
 for(const profile of profiles)for(let seed=1;seed<=20;seed++){
 const c=ctx(profile),initial=state(c),messages=Array.from({length:6},(_,i)=>msg(c,100+i,Buffer.from([seed,i]),i===5?3:1)),order=[4,1,5,0,3,2];let current=initial;
 for(let i=0;i<6;i++)current=preview(current,[messages[order[(i+seed)%6]]],c).window;
 const final=preview(current,[],c),chunks=current.messages.map(m=>m.subarray(20,20+m.readUInt16BE(2))),strict=assembleMhStreamChunks(chunks,profile,100);
 assert.deepEqual(final.preview.body,strict.payload);assert.deepEqual(final.preview.streamHeaders,strict.headers);assert.equal(final.window.startSequence,100);assert.equal(final.window.messages.length,6);
 const before=Buffer.from(final.window.messages[0]),body=Buffer.from(final.preview.body),header=Buffer.from(final.preview.streamHeaders[0]);
 final.preview.body.fill(0xff);assert.deepEqual(final.window.messages[0],before);final.window.messages[0].fill(0);assert.deepEqual(final.preview.streamHeaders[0],header);
 messages[0].fill(0);assert.deepEqual(current.messages[0],before);final.window.context.senderIdentity.fill(0);assert.deepEqual(initial.context.senderIdentity,c.senderIdentity);assert.equal(body[0],seed);
 }
});
