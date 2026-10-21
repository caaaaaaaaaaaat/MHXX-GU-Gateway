import assert from 'node:assert/strict';
import test from 'node:test';
import { translateMhBasePeerListStream } from './mh-base-peer-list-stream.mjs';
import { encodeMhStreamMessage, recoverMhPeerListFromMessages } from './mh-system-stream.mjs';
import { MhIdentityMap } from './mh-identity.mjs';
import { deriveMhxxUdsEndpoint, encodeMhxxEndpoint } from './mhxx-endpoint.mjs';
import { encodeMhPacket, decodeMhPacket } from './mh-packet.mjs';
import { encodeYuzuUdpProxyDatagram, decodeYuzuUdpProxyDatagram } from './yuzu-udp-datagram.mjs';
const profiles=['mhxx-1.4','mhgu-v262144'], sourceRouteKey=0x12340001, targetRouteKey=0x98760002;
function setup(profile=profiles[0]) {
  const identityMap=new MhIdentityMap('s');
  const peers=Array.from({length:4},(_,i)=>{
    const seed=Buffer.alloc(8,i+1), gu=Buffer.from([192,0,2,i+1]); identityMap.bind('s',seed,gu);
    const xx=encodeMhxxEndpoint(deriveMhxxUdsEndpoint(seed)).subarray(0,4);
    return profile===profiles[0]?{from:xx,to:gu}:{from:gu,to:xx};
  });
  return {peers,options:{profile,sourceStartSequence:40,sourceRouteKey,targetStartSequence:99,targetRouteKey,
    endpointBranch:'base-first-endpoint-a',identityMap,sessionId:'s'}};
}
function body(peers,variant=1,slot=0,start=0,total=peers.length) {
  const b=Buffer.alloc(12+72*peers.length,0x53); b[0]=0x20;b[1]=total;b[8]=variant;
  if(variant===2){b[9]=slot;b[10]=peers.length;b[11]=start;}
  peers.forEach((p,i)=>{const o=12+i*72; p.from.copy(b,o);b.writeUInt16BE(12345,o+4);
    for(const word of [18,29,35,53,64])p.from.copy(b,o+word);
  });return b;
}
function plan(lengths,start,route,tag=0x31) {
  return lengths.map((payloadLength,i)=>{const outerHeader=Buffer.alloc(20,tag),streamHeader=Buffer.alloc(24,tag+1);
    outerHeader.writeUInt32BE(route,12);streamHeader.writeUInt16BE(i===lengths.length-1?3:1);
    streamHeader.writeUInt32BE(start+i,8);return {outerHeader,streamHeader,payloadLength};});
}
function source(b,profile,lengths=[b.length]) {
  let offset=0;return plan(lengths,40,sourceRouteKey).map(p=>{const payload=b.subarray(offset,offset+p.payloadLength);offset+=p.payloadLength;
    return encodeMhStreamMessage({...p,payload},profile,sourceRouteKey);});
}
function opts(o,b,lengths=[b.length]) {return {...o,targetPlan:plan(lengths,99,targetRouteKey,0xa1)};}
function expected(b,peers){const e=Buffer.from(b);peers.forEach((p,i)=>p.to.copy(e,12+72*i));return e;}
function snapshot(messages,o){return {messages:messages.map(m=>Buffer.from(m)),headers:o.targetPlan.map(p=>({outer:Buffer.from(p.outerHeader),stream:Buffer.from(p.streamHeader)}))};}
function unchanged(messages,o,before){assert.deepEqual(messages,before.messages);o.targetPlan.forEach((p,i)=>{assert.deepEqual(p.outerHeader,before.headers[i].outer);assert.deepEqual(p.streamHeader,before.headers[i].stream);});assert.equal(o.identityMap.size,4);}

test('both directions reassemble split descriptors and resegment only with explicit independent target headers',()=>{
  for(const profile of profiles){const {options,peers}=setup(profile), b=body(peers), input=source(b,profile,[17,74,209]);
    const o=opts(options,b,[1,99,200]),before=snapshot(input,o);
    // Source reassembly permits byte-identical duplicate chunks and unsorted batches.
    const batch=[input[2],input[0],input[1],Buffer.from(input[1])];
    const r=translateMhBasePeerListStream(batch,o);assert.equal(r.profile,profiles.find(p=>p!==profile));
    assert.equal(r.kind,'peer-list');assert.deepEqual(r.body,expected(b,peers));
    for(const flag of ['payloadValidated','applicationConverted','productionReady'])assert.equal(r[flag],false);
    const target=recoverMhPeerListFromMessages(r.messages,r.profile,99,targetRouteKey);assert.deepEqual(target.body,r.body);
    target.outerHeaders.forEach((h,i)=>{const e=Buffer.from(o.targetPlan[i].outerHeader);e.writeUInt16BE(24+o.targetPlan[i].payloadLength,2);assert.deepEqual(h,e);});
    target.streamHeaders.forEach((h,i)=>{const e=Buffer.from(o.targetPlan[i].streamHeader);e.writeUInt16BE(o.targetPlan[i].payloadLength,2);assert.deepEqual(h,e);});
    unchanged(input,o,before);r.body.fill(0);assert.deepEqual(recoverMhPeerListFromMessages(r.messages,r.profile,99,targetRouteKey).body,expected(b,peers));
    r.messages[0].fill(0);unchanged(input,o,before);
    const independent=translateMhBasePeerListStream(input,o), independentBody=Buffer.from(independent.body);
    independent.messages[0].fill(0);assert.deepEqual(independent.body,independentBody);
    const savedMessages=independent.messages.map(m=>Buffer.from(m));
    o.targetPlan.forEach(p=>{p.outerHeader.fill(0);p.streamHeader.fill(0);});
    assert.deepEqual(independent.messages,savedMessages);assert.deepEqual(independent.body,independentBody);assert.deepEqual(input,before.messages);
  }
});

test('variant2 system fragments remain separate with original slot/count/start and unknown bytes',()=>{
  for(const profile of profiles)for(const slot of [0,1]){const {options,peers}=setup(profile),local=peers.slice(slot*2,slot*2+2);
    const b=body(local,2,slot,slot*2,4),r=translateMhBasePeerListStream(source(b,profile,[7,b.length-7]),opts(options,b,[b.length]));
    assert.equal(r.kind,'peer-list-fragment');assert.deepEqual(r.body,expected(b,local));assert.deepEqual(r.body.subarray(0,12),b.subarray(0,12));
  }
});

test('empty lists still demand branch, session, route and complete target framing',()=>{
  const {options}=setup(),b=body([]),input=source(b,options.profile),o=opts(options,b);
  assert.deepEqual(translateMhBasePeerListStream(input,o).body,b);
  const sixtyFour=translateMhBasePeerListStream(input,opts(options,b,[...Array(63).fill(0),b.length]));
  assert.equal(sixtyFour.messages.length,64);assert.deepEqual(sixtyFour.body,b);
  for(const patch of [{endpointBranch:undefined},{sessionId:'stale'},{identityMap:{}},{profile:'unknown'},
    {sourceRouteKey:undefined},{targetRouteKey:undefined},{sourceStartSequence:undefined},{targetStartSequence:undefined}])assert.throws(()=>translateMhBasePeerListStream(input,{...o,...patch}));
  const fragment=body([],2,1,2,2);assert.deepEqual(translateMhBasePeerListStream(source(fragment,options.profile),opts(options,fragment)).body,fragment);
});

test('source stream gaps, conflicts, terminal/route mistakes and non-list bodies reject before returning',()=>{
  const {options,peers}=setup(),b=body(peers),o=opts(options,b),input=source(b,options.profile,[100,200]);
  const wrongRoute=Buffer.from(input[1]);wrongRoute.writeUInt32BE(sourceRouteKey+1,12);
  const conflict=Buffer.from(input[0]);conflict[conflict.length-1]^=1;
  const noEnd=Buffer.from(input[1]);noEnd.writeUInt16BE(1,20);
  for(const batch of [[input[0]],[input[1]],[input[0],wrongRoute],[input[0],conflict,input[1]],[input[0],noEnd],[],Array(1)])assert.throws(()=>translateMhBasePeerListStream(batch,o));
  for(const mutate of [x=>x[0]=0x21,x=>x[8]=3,x=>x[1]=3]){const bad=Buffer.from(b);mutate(bad);assert.throws(()=>translateMhBasePeerListStream(source(bad,options.profile),o));}
  assert.deepEqual(recoverMhPeerListFromMessages(input,options.profile,40,sourceRouteKey).body,b);
});

test('explicit target plan rejects gaps/wrap, bad flags/routes, sparse or inaccurate lengths without mutation',()=>{
  const {options,peers}=setup(),b=body(peers),input=source(b,options.profile),o=opts(options,b,[100,200]),before=snapshot(input,o);
  for(const targetPlan of [undefined,[],Array(1),Array(65),[{...o.targetPlan[0],payloadLength:-1}],
    [{...o.targetPlan[0],payloadLength:0.5}],[{...o.targetPlan[0],payloadLength:301}],
    [{...o.targetPlan[0],payloadLength:100}],o.targetPlan.map((p,i)=>({...p,payloadLength:i?201:100}))])
    assert.throws(()=>translateMhBasePeerListStream(input,{...o,targetPlan}));
  for(const mutate of [p=>p[1].streamHeader.writeUInt32BE(101,8),p=>p[1].streamHeader.writeUInt16BE(1),
    p=>p[0].streamHeader.writeUInt16BE(3),p=>p[0].streamHeader.writeUInt16BE(0),p=>p[1].outerHeader.writeUInt32BE(5,12),
    p=>p[1].outerHeader=Buffer.alloc(19),p=>p[1].streamHeader=Buffer.alloc(23)]){
    const targetPlan=plan([100,200],99,targetRouteKey);mutate(targetPlan);
    const badOptions={...o,targetPlan},badBefore=snapshot(input,badOptions);
    assert.throws(()=>translateMhBasePeerListStream(input,badOptions));unchanged(input,badOptions,badBefore);
  }
  const wrapped=plan([100,200],0,targetRouteKey);wrapped[0].streamHeader.writeUInt32BE(0xffffffff,8);
  assert.throws(()=>translateMhBasePeerListStream(input,{...o,targetStartSequence:0xffffffff,targetPlan:wrapped}),/target_sequence/);
  unchanged(input,o,before);
});

test('late unmapped/unsupported endpoint and reset refuse whole body without binding or partial return',()=>{
  for(const profile of profiles){const {options,peers}=setup(profile),b=body(peers),o=opts(options,b,[150,150]);
    for(const mutate of [x=>x.writeUInt32BE(0x11223344,228),x=>x.writeUInt32BE(0,228),x=>x.writeUInt16BE(9,232)]){
      const bad=Buffer.from(b);mutate(bad);const input=source(bad,profile,[150,150]),before=snapshot(input,o);
      assert.throws(()=>translateMhBasePeerListStream(input,o));unchanged(input,o,before);
    }
    options.identityMap.reset('new');assert.throws(()=>translateMhBasePeerListStream(source(b,profile),o),/session_mismatch/);
    assert.throws(()=>translateMhBasePeerListStream(source(b,profile),{...o,sessionId:'new'}),/unmapped/);
  }
});

test('stream profile capacity and MH packet capacity remain independent of a complete list body',()=>{
  const {options,peers}=setup(), repeated=Array.from({length:20},(_,i)=>peers[i%4]),b=body(repeated);
  assert.equal(b.length,1452);
  const input=source(b,options.profile),single=opts(options,b),before=snapshot(input,single);
  assert.throws(()=>translateMhBasePeerListStream(input,single),/mhgu_stream_payload_limit/);
  unchanged(input,single,before);
  const split=translateMhBasePeerListStream(input,opts(options,b,[700,752]));assert.deepEqual(split.body,expected(b,repeated));
  assert.deepEqual(translateMhBasePeerListStream(input,opts(options,b,[1416,36])).body,split.body);
  const oversized=opts(options,b,[1417,35]),overBefore=snapshot(input,oversized);
  assert.throws(()=>translateMhBasePeerListStream(input,oversized),/mhgu_stream_payload_limit/);unchanged(input,oversized,overBefore);
  const reverse=setup(profiles[1]), gp=Array.from({length:20},(_,i)=>reverse.peers[i%4]),gb=body(gp);
  const largeXX=translateMhBasePeerListStream(source(gb,profiles[1],[700,752]),opts(reverse.options,gb));
  assert.deepEqual(largeXX.body,expected(gb,gp));
  const h=Buffer.alloc(12);h.writeUInt32BE(0x32ab9864);h[4]=1;
  assert.throws(()=>encodeMhPacket({header:h,messages:largeXX.messages},profiles[0]),/limit/);
});

test('mapped GU messages can be independently MH-framed/AES-compressed without another identity mapping pass',()=>{
  const {options,peers}=setup(),b=body(peers),o=opts(options,b,[100,200]),r=translateMhBasePeerListStream(source(b,options.profile),o);
  const h=Buffer.alloc(12,0x39);h.writeUInt32BE(0x32ab9864);h[4]=2;const key=Buffer.alloc(16,0x81);
  const raw=encodeMhPacket({header:h,messages:r.messages},r.profile,key);
  for(const p of ['yuzu-2022-7edc31be2','yuzu-mirror-01052024']){
    const ph=Buffer.alloc(21,0x71);ph[0]=5;ph[1]=ph[8]=p.includes('2022')?0:1;ph[15]=p.includes('2022')?2:3;
    const env=encodeYuzuUdpProxyDatagram(ph,raw,p),decoded=decodeYuzuUdpProxyDatagram(env.bytes,p);
    const packet=decodeMhPacket(decoded.datagram,r.profile,key),recovered=recoverMhPeerListFromMessages(packet.messages,r.profile,99,targetRouteKey);
    assert.deepEqual(recovered.body,expected(b,peers));assert.deepEqual(packet.header,h);
    assert.equal(env.applicationConverted,false);assert.equal(env.productionReady,false);
  }
});
