import assert from 'node:assert/strict';
import test from 'node:test';
import { translateMhBasePeerListStream, translateMhBasePeerListStreamCheckedSender as checked } from './mh-base-peer-list-stream.mjs';
import { MhIdentityMap } from './mh-identity.mjs';
import { deriveMhxxUdsEndpoint, encodeMhxxEndpoint } from './mhxx-endpoint.mjs';
import { encodeMhStreamMessage, recoverMhPeerListFromMessages } from './mh-system-stream.mjs';
const profiles=['mhxx-1.4','mhgu-v262144'];
function fixture(profile=profiles[0],count=2) {
  const map=new MhIdentityMap('session'),pairs=Array.from({length:4},(_,i)=>{
    const seed=Buffer.alloc(8,i+21),gu=Buffer.from([198,51,100,i+1]);map.bind('session',seed,gu);
    const xx=encodeMhxxEndpoint(deriveMhxxUdsEndpoint(seed)).subarray(0,4);
    return profile===profiles[0]?{from:xx,to:gu}:{from:gu,to:xx};
  });
  const b=Buffer.alloc(12+count*72,0x65);b[0]=0x20;b[1]=count;b[8]=1;
  for(let i=0;i<count;i++){const pair=pairs[i%4],off=12+i*72;pair.from.copy(b,off);b.writeUInt16BE(12345,off+4);
    for(const rel of [18,29,35,53,64])pair.from.copy(b,off+rel);
  }
  return {pairs,body:b,options:{profile,sourceSenderIdentity:Buffer.from(pairs[0].from),sourceStartSequence:55,sourceRouteKey:0x44550001,
    targetStartSequence:202,targetRouteKey:0x66770002,endpointBranch:'base-first-endpoint-a',identityMap:map,sessionId:'session'}};
}
function headers(lengths,start,route,sender,tag) {
  return lengths.map((payloadLength,i)=>{const outerHeader=Buffer.alloc(20,tag),streamHeader=Buffer.alloc(24,tag+1);
    outerHeader.writeUInt32BE(route,12);sender.copy(outerHeader,8);streamHeader.writeUInt16BE(i===lengths.length-1?3:1);
    streamHeader.writeUInt32BE(start+i,8);return {outerHeader,streamHeader,payloadLength};});
}
function prepare(f,sourceLengths=[f.body.length],targetLengths=[f.body.length]) {
  const o={...f.options,targetPlan:headers(targetLengths,202,f.options.targetRouteKey,f.pairs[0].to,0x82)};
  let off=0;const messages=headers(sourceLengths,55,o.sourceRouteKey,o.sourceSenderIdentity,0x23).map(h=>{
    const payload=f.body.subarray(off,off+h.payloadLength);off+=h.payloadLength;return encodeMhStreamMessage({...h,payload},o.profile,o.sourceRouteKey);});
  return {messages,options:o};
}
function mappedBody(f){const b=Buffer.from(f.body);for(let i=0;i<b[1];i++)f.pairs[i%4].to.copy(b,12+72*i);return b;}
function snapshot(c){return {messages:c.messages.map(m=>Buffer.from(m)),sender:Buffer.from(c.options.sourceSenderIdentity),
  plan:c.options.targetPlan.map(p=>({outer:Buffer.from(p.outerHeader),stream:Buffer.from(p.streamHeader),length:p.payloadLength}))};}
function unchanged(c,before){assert.deepEqual(c.messages,before.messages);assert.deepEqual(c.options.sourceSenderIdentity,before.sender);
  c.options.targetPlan.forEach((p,i)=>{assert.deepEqual(p.outerHeader,before.plan[i].outer);assert.deepEqual(p.streamHeader,before.plan[i].stream);assert.equal(p.payloadLength,before.plan[i].length);});}
function rejects(c,pattern){const before=snapshot(c);assert.throws(()=>checked(c.messages,c.options),pattern);unchanged(c,before);}

test('checked sender in both directions matches explicit target headers across independent chunk counts',()=>{
  for(const profile of profiles){const f=fixture(profile),c=prepare(f,[17,83,56],[60,96]),before=snapshot(c);
    const result=checked(c.messages,c.options),plain=translateMhBasePeerListStream(c.messages,c.options);
    assert.deepEqual(result.messages,plain.messages);assert.deepEqual(result.body,mappedBody(f));
    assert.equal(result.senderCorrespondenceValidated,true);assert.equal(result.observationsAuthenticated,false);
    for(const flag of ['payloadValidated','applicationConverted','productionReady'])assert.equal(result[flag],false);
    for(const m of result.messages)assert.deepEqual(m.subarray(8,12),f.pairs[0].to);
    unchanged(c,before);assert.equal(c.options.identityMap.size,4);
    assert.deepEqual(recoverMhPeerListFromMessages(result.messages,result.profile,202,c.options.targetRouteKey).body,mappedBody(f));
    // Checked mode preserves one complete variant2 fragment; it does not merge slots.
    f.body[1]=4;f.body[8]=2;f.body[9]=1;f.body[10]=2;f.body[11]=2;
    const fragment=prepare(f,[60,96],[156]),fr=checked(fragment.messages,fragment.options),expected=Buffer.from(f.body);
    f.pairs[0].to.copy(expected,12);f.pairs[1].to.copy(expected,84);
    assert.equal(fr.kind,'peer-list-fragment');assert.deepEqual(fr.body,expected);assert.deepEqual(fr.body.subarray(0,12),f.body.subarray(0,12));
  }
});

test('mixed source sender is rejected even for an otherwise byte-identical duplicate discarded by base recovery',()=>{
  for(const profile of profiles){const f=fixture(profile),c=prepare(f,[60,96],[156]);
    const duplicate=Buffer.from(c.messages[0]);f.pairs[1].from.copy(duplicate,8);c.messages.push(duplicate);
    assert.deepEqual(translateMhBasePeerListStream(c.messages,c.options).body,mappedBody(f));
    rejects(c,/source_sender_mismatch/);
    c.messages.pop();f.pairs[1].from.copy(c.messages[1],8);rejects(c,/source_sender_mismatch/);
    c.messages[1].fill(0,8,12);rejects(c,/source_sender_mismatch/);
  }
});

test('all target headers must already contain mapped sender: no automatic repair, mixed peer or double-direction pass',()=>{
  for(const profile of profiles){const f=fixture(profile);
    for(const wrong of [f.pairs[1].to,f.pairs[0].from,Buffer.alloc(4),Buffer.from([1,2,3,4])]){
      const c=prepare(f,[156],[60,96]);wrong.copy(c.options.targetPlan[1].outerHeader,8);
      // The unguarded API intentionally accepts caller-owned unrelated target sender bytes.
      assert.deepEqual(translateMhBasePeerListStream(c.messages,c.options).body,mappedBody(f));rejects(c,/target_sender_mismatch/);
    }
    const c=prepare(f);assert.throws(()=>checked(c.messages,{...c.options,sourceSenderIdentity:f.pairs[1].from}),/source_sender_mismatch/);
    for(const p of f.pairs){assert.deepEqual(c.options.identityMap.translate('session',profile===profiles[0]?'mhxx-to-mhgu':'mhgu-to-mhxx',p.from),p.to);}
  }
});

test('explicit sender, map, profile, session and binding are required even for an empty peer list',()=>{
  for(const profile of profiles){const f=fixture(profile,0),c=prepare(f);
    for(const sourceSenderIdentity of [undefined,null,'00000000',Buffer.alloc(3),Buffer.alloc(5),new Uint8Array(4)])
      assert.throws(()=>checked(c.messages,{...c.options,sourceSenderIdentity}),/sender_identity/);
    for(const patch of [{profile:'unknown'},{identityMap:{}},{sessionId:'old'},{sourceSenderIdentity:Buffer.from([1,2,3,4])}])
      assert.throws(()=>checked(c.messages,{...c.options,...patch}));
    for(const messages of [undefined,{},[],Array(1),Array(65),[Buffer.alloc(19)],[null]])assert.throws(()=>checked(messages,c.options));
    assert.deepEqual(checked(c.messages,c.options).body,f.body);
  }
});

test('zero sender passes only exact zero correspondence; reset/session reuse is not authenticated by the guard',()=>{
  for(const profile of profiles){const f=fixture(profile,0),c=prepare(f);
    c.options.sourceSenderIdentity.fill(0);c.messages[0].fill(0,8,12);c.options.targetPlan[0].outerHeader.fill(0,8,12);
    assert.equal(checked(c.messages,c.options).senderCorrespondenceValidated,true);
    c.options.identityMap.reset('next');assert.throws(()=>checked(c.messages,c.options),/session_mismatch/);
    c.options.sessionId='next';assert.equal(checked(c.messages,c.options).observationsAuthenticated,false);
    f.pairs[0].to.copy(c.options.targetPlan[0].outerHeader,8);rejects(c,/target_sender_mismatch/);
    f.pairs[0].from.copy(c.options.sourceSenderIdentity);assert.throws(()=>checked(c.messages,c.options),/unmapped/);
    // Reusing a human label alone cannot restore nonzero bindings.
    c.options.identityMap.reset('session');c.options.sessionId='session';assert.throws(()=>checked(c.messages,c.options),/unmapped/);
  }
});

test('hand-authored empty-list messages prove only original sender at +8 is compared, not relay or body bytes',()=>{
  const f=fixture(profiles[1],0),from=Buffer.alloc(4),to=Buffer.alloc(4);
  const message=Buffer.from('110000240102030400000000445500017a7b7c7d0003000c11223344000000375566778899aabbccddeeff00200000000000000001000000','hex');
  const outerHeader=Buffer.from('220000007a7b7c7d000000006677000201020304','hex');
  const streamHeader=Buffer.from('0003000077665544000000caeeddccbb9988776655443322','hex');
  const o={...f.options,sourceSenderIdentity:from,targetPlan:[{outerHeader,streamHeader,payloadLength:12}]};
  const result=checked([message],o);assert.deepEqual(result.messages[0].subarray(8,12),to);
  const expected=Buffer.from(outerHeader);expected.writeUInt16BE(36,2);assert.deepEqual(result.messages[0].subarray(0,20),expected);
  assert.deepEqual(result.body,Buffer.from('200000000000000001000000','hex'));
});

test('sender guard permits XX oversized source resegmentation without a premature target-chunk check',()=>{
  const f=fixture(profiles[0],20),c=prepare(f,[1452],[1416,36]),before=snapshot(c);
  const r=checked(c.messages,c.options);assert.deepEqual(r.body,mappedBody(f));unchanged(c,before);
  const single=prepare(f);rejects(single,/mhgu_stream_payload_limit/);
  const over=prepare(f,[1452],[1417,35]);rejects(over,/mhgu_stream_payload_limit/);
});

test('late body/target errors and returned buffers never mutate source, plans, map or successful sibling result',()=>{
  const f=fixture(),c=prepare(f,[60,96],[60,96]),before=snapshot(c),result=checked(c.messages,c.options);
  const originalBody=Buffer.from(result.body);result.messages[0].fill(0);assert.deepEqual(result.body,originalBody);unchanged(c,before);
  result.body.fill(0);assert.notDeepEqual(result.messages[1],Buffer.alloc(result.messages[1].length));unchanged(c,before);
  const late=prepare(f,[60,96],[60,96]);late.options.targetPlan[1].outerHeader.writeUInt32BE(9,12);rejects(late,/route/);
  const badBody=fixture();badBody.body.writeUInt32BE(0x01020304,84);rejects(prepare(badBody),/unmapped/);
  const sparse=prepare(f,[60,96],[60,96]);delete sparse.messages[1];assert.throws(()=>checked(sparse.messages,sparse.options),/sender_message/);
  assert.equal(c.options.identityMap.size,4);unchanged(c,before);
});
