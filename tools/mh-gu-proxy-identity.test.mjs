import assert from 'node:assert/strict';
import test from 'node:test';
import { translateMhguProxyToMhxx, translateMhxxToMhguProxy } from './mh-gu-proxy-identity.mjs';
import { decodeYuzuUdpProxyDatagram, encodeYuzuUdpProxyDatagram } from './yuzu-udp-datagram.mjs';
import { encodeYuzuUdpProxyPacket } from './yuzu-udp-proxy.mjs';
import { decodeMhPacket, encodeMhPacket } from './mh-packet.mjs';
import { encodeMhStreamMessage } from './mh-system-stream.mjs';
import { MhIdentityMap } from './mh-identity.mjs';
import { deriveMhxxUdsEndpoint, encodeMhxxEndpoint } from './mhxx-endpoint.mjs';

const xx = 'mhxx-1.4', gu = 'mhgu-v262144', route = 0x12340001;
const profiles = ['yuzu-2022-7edc31be2', 'yuzu-mirror-01052024'];
const seed = Buffer.from('0123456789abcdef', 'hex'), guId = Buffer.from([192,0,2,7]);
const xxId = encodeMhxxEndpoint(deriveMhxxUdsEndpoint(seed)).subarray(0,4);
const xxKey = Buffer.alloc(16,0x31), guKey = Buffer.alloc(16,0x42);
function mhHeader(mode, tag = 0x51) {
  const h = Buffer.alloc(12,tag); h.writeUInt32BE(0x32ab9864); h[4]=mode; return h;
}
function proxyHeader(profile, tag = 0x73) {
  const h = Buffer.alloc(21,tag); h[0]=5; h[1]=h[8]=profile===profiles[0]?0:1;
  h[15]=profile===profiles[0]?2:3; h[16]=0x87; h.writeUInt32BE(0xffffffff,17); return h;
}
function options(proxyProfile = profiles[0], mode = 1) {
  const identityMap = new MhIdentityMap('s'); identityMap.bind('s',seed,guId);
  return {proxyProfile, targetProxyHeader:proxyHeader(proxyProfile), targetHeader:mhHeader(mode,0xb6),
    expectedRouteKey:route, identityMap, sessionId:'s', sourceKey:xxKey, targetKey:guKey};
}
function message(profile, identity = profile===xx?xxId:guId, size = 5) {
  const outerHeader=Buffer.alloc(20,0x34), streamHeader=Buffer.alloc(24,0x56);
  identity.copy(outerHeader,8); outerHeader.writeUInt32BE(route,12); streamHeader.writeUInt16BE(3);
  return encodeMhStreamMessage({outerHeader,streamHeader,payload:Buffer.alloc(size,0xa7)},profile,route);
}
function flags(result) {
  assert.equal(result.compressionValidated,true); assert.equal(result.payloadValidated,false);
  assert.equal(result.applicationConverted,false); assert.equal(result.productionReady,false);
}
function mapped(input, id) { const result=Buffer.from(input); id.copy(result,8); return result; }

test('XX raw to GU Room maps identity only across both Proxy profiles and all mode pairs', () => {
  for(const p of profiles) for(const a of [1,2]) for(const b of [1,2]) {
    const o=options(p,b), m=message(xx), raw=encodeMhPacket({header:mhHeader(a),messages:[m]},xx,xxKey);
    const before=Buffer.from(raw), th=Buffer.from(o.targetHeader), ph=Buffer.from(o.targetProxyHeader);
    const result=translateMhxxToMhguProxy(raw,o); flags(result);
    assert.equal(result.profile,gu); assert.equal(result.targetProxyProfile,p);
    assert.equal(result.outputLayer,'yuzu-room-udp-proxy');
    const env=decodeYuzuUdpProxyDatagram(result.bytes,p), expectedHeader=Buffer.from(ph);
    expectedHeader.writeUInt32BE(result.bytes.length-21,17); assert.deepEqual(env.header,expectedHeader);
    const decoded=decodeMhPacket(env.datagram,gu,guKey);
    assert.deepEqual(decoded.header,th); assert.deepEqual(decoded.messages,[mapped(m,guId)]);
    assert.deepEqual(raw,before); assert.deepEqual(o.targetHeader,th); assert.deepEqual(o.targetProxyHeader,ph);
    result.bytes.fill(0); assert.deepEqual(raw,before); assert.deepEqual(o.targetProxyHeader,ph);
  }
});

test('GU Room to XX raw uses independent MH header and preserves opaque trailer and zero peer', () => {
  for(const p of profiles) for(const a of [1,2]) for(const b of [1,2]) {
    const o={...options(p,b),sourceKey:guKey,targetKey:xxKey};
    const messages=[message(gu),message(gu,Buffer.alloc(4))], trailer=Buffer.from([255,4,0,99]);
    const raw=encodeMhPacket({header:mhHeader(a),messages,trailer},gu,guKey);
    const sourceDecoded=decodeMhPacket(raw,gu,guKey);
    const input=encodeYuzuUdpProxyDatagram(proxyHeader(p,0x21),raw,p).bytes, before=Buffer.from(input);
    const result=translateMhguProxyToMhxx(input,o); flags(result);
    assert.equal(result.profile,xx); assert.equal(result.sourceProxyProfile,p); assert.equal(result.outputLayer,'mh-packet');
    const decoded=decodeMhPacket(result.bytes,xx,xxKey);
    assert.deepEqual(decoded.header,o.targetHeader);
    assert.deepEqual(decoded.messages,[mapped(messages[0],xxId),messages[1]]);
    assert.deepEqual(decoded.trailer.subarray(0,sourceDecoded.trailer.length),sourceDecoded.trailer);
    assert.deepEqual(input,before); result.bytes.fill(0); assert.deepEqual(input,before);
  }
});

test('independent handwritten raw Zstd frame feeds a GU packet without using compression encoder', () => {
  // Single-segment FCS=64; final raw block header=(64<<3)|1=513 LE24.
  const raw=Buffer.from('32ab98640110111213141516' +
    '3400002034343434c00002071234000134343434' +
    '000300085656565656565656565656565656565656565656' + 'a7a7a7a700000000','hex');
  // No MH, stream or compression encoder builds this literal input.
  assert.equal(raw.length,64);
  const frameHeader=Buffer.from([0x28,0xb5,0x2f,0xfd,0x20,raw.length]);
  const block=Buffer.alloc(3); block.writeUIntLE((raw.length<<3)|1,0,3);
  const packet=encodeYuzuUdpProxyPacket(proxyHeader(profiles[0]),Buffer.concat([frameHeader,block,raw]),profiles[0]).bytes;
  const o={...options(),sourceKey:guKey,targetKey:xxKey};
  const result=translateMhguProxyToMhxx(packet,o);
  const expected=Buffer.from(raw); o.targetHeader.copy(expected); xxId.copy(expected,20);
  assert.deepEqual(result.bytes,expected); flags(result);
});

test('full roundtrip with independent target headers preserves stream bytes, not compression wire identity', () => {
  for(const p of profiles) {
    const o=options(p,2), m=message(xx), raw=encodeMhPacket({header:mhHeader(1),messages:[m]},xx);
    const env=translateMhxxToMhguProxy(raw,o);
    const back=translateMhguProxyToMhxx(env.bytes,{...o,targetHeader:mhHeader(1,0xc4),sourceKey:guKey,targetKey:xxKey});
    const d=decodeMhPacket(back.bytes,xx); assert.deepEqual(d.messages,[m]); assert.deepEqual(d.header,mhHeader(1,0xc4));
    assert.equal(d.trailer.every(b=>b===255),true); assert.notDeepEqual(back.bytes,raw);
  }
});

test('empty and sentinel-only payloads validate map/session, target headers and explicit profiles', () => {
  for(const trailer of [Buffer.alloc(0),Buffer.from([255,8])]) {
    const raw=encodeMhPacket({header:mhHeader(1),messages:[],trailer},xx), o=options();
    const env=translateMhxxToMhguProxy(raw,o); flags(env);
    assert.deepEqual(decodeMhPacket(decodeYuzuUdpProxyDatagram(env.bytes,o.proxyProfile).datagram,gu).trailer,trailer);
    for(const patch of [{sessionId:'old'},{identityMap:{}},{expectedRouteKey:undefined},{targetHeader:undefined},
      {targetProxyHeader:undefined},{proxyProfile:undefined},{proxyProfile:'EA'}]) {
      assert.throws(()=>translateMhxxToMhguProxy(raw,{...o,...patch}));
    }
    const go={...o,sourceKey:guKey,targetKey:xxKey};
    for(const patch of [{sessionId:'old'},{identityMap:{}},{expectedRouteKey:undefined},{targetHeader:undefined},{proxyProfile:'EA'}]) {
      assert.throws(()=>translateMhguProxyToMhxx(env.bytes,{...go,...patch}));
    }
  }
});

test('outer framing, compression and MH input reject without plaintext, CRLY or UDS fallback', () => {
  const o=options(), gRaw=encodeMhPacket({header:mhHeader(1),messages:[message(gu)]},gu);
  const good=encodeYuzuUdpProxyDatagram(proxyHeader(o.proxyProfile),gRaw,o.proxyProfile).bytes;
  const badEnum=Buffer.from(good); badEnum[15]=3;
  const badLength=Buffer.from(good); badLength.writeUInt32BE(0,17);
  const plain=encodeYuzuUdpProxyPacket(proxyHeader(o.proxyProfile),gRaw,o.proxyProfile).bytes;
  for(const bad of [good.subarray(0,20),badEnum,badLength,plain]) assert.throws(()=>translateMhguProxyToMhxx(bad,o));
  for(const body of [Buffer.from('CRLY'),Buffer.from('UDS'),Buffer.alloc(0),Buffer.alloc(1473)]) {
    const packet=encodeYuzuUdpProxyDatagram(proxyHeader(o.proxyProfile),body,o.proxyProfile).bytes;
    assert.throws(()=>translateMhguProxyToMhxx(packet,o),/mh_packet_/);
    assert.throws(()=>translateMhxxToMhguProxy(body,o),/mh_packet_/);
  }
});

test('late route/unknown identity and reset fail atomically across both layer directions', () => {
  for(const profile of [xx,gu]) for(const kind of ['route','identity','nonstream']) {
    const o=options(), bad=message(profile);
    if(kind==='route') bad.writeUInt32BE(route+1,12);
    if(kind==='identity') Buffer.from([1,2,3,4]).copy(bad,8);
    const invalid=kind==='nonstream'?Buffer.alloc(20):bad;
    const raw=encodeMhPacket({header:mhHeader(1),messages:[message(profile),invalid]},profile);
    const input=profile===xx?raw:encodeYuzuUdpProxyDatagram(proxyHeader(o.proxyProfile),raw,o.proxyProfile).bytes;
    const before=Buffer.from(input), th=Buffer.from(o.targetHeader), ph=Buffer.from(o.targetProxyHeader);
    const run=()=>profile===xx?translateMhxxToMhguProxy(input,o):translateMhguProxyToMhxx(input,o);
    assert.throws(run); assert.deepEqual(input,before); assert.deepEqual(o.targetHeader,th); assert.deepEqual(o.targetProxyHeader,ph);
    assert.equal(o.identityMap.size,1); assert.deepEqual(o.identityMap.translate('s','mhxx-to-mhgu',xxId),guId);
  }
  const o=options(), raw=encodeMhPacket({header:mhHeader(1),messages:[message(xx)]},xx);
  o.identityMap.reset('new'); assert.throws(()=>translateMhxxToMhguProxy(raw,o),/session_mismatch/);
  assert.throws(()=>translateMhxxToMhguProxy(raw,{...o,sessionId:'new'}),/unmapped/);
});

test('explicit AES keys, cipher alignment and target capacity never fall back', () => {
  const o=options(profiles[0],2), m=message(xx), raw=encodeMhPacket({header:mhHeader(2),messages:[m]},xx,xxKey);
  for(const patch of [{sourceKey:undefined},{targetKey:undefined}]) assert.throws(()=>translateMhxxToMhguProxy(raw,{...o,...patch}),/key16/);
  assert.throws(()=>translateMhxxToMhguProxy(raw.subarray(0,raw.length-1),o),/alignment/);
  const gRaw=encodeMhPacket({header:mhHeader(2),messages:[message(gu)]},gu,guKey);
  const env=encodeYuzuUdpProxyDatagram(proxyHeader(o.proxyProfile),gRaw,o.proxyProfile).bytes;
  const go={...o,sourceKey:guKey,targetKey:xxKey};
  for(const patch of [{sourceKey:undefined},{targetKey:undefined}]) assert.throws(()=>translateMhguProxyToMhxx(env,{...go,...patch}),/key16/);
  // Body 1460 is legal plaintext but cannot fit the target 1456 aligned AES bound.
  const full=encodeMhPacket({header:mhHeader(1),messages:[message(xx,xxId,1416)]},xx);
  assert.throws(()=>translateMhxxToMhguProxy(full,o),/limit/);
  const gFull=encodeMhPacket({header:mhHeader(1),messages:[message(gu,guId,1416)]},gu);
  const gEnv=encodeYuzuUdpProxyDatagram(proxyHeader(o.proxyProfile),gFull,o.proxyProfile).bytes;
  assert.throws(()=>translateMhguProxyToMhxx(gEnv,go),/limit/);
});

test('fixed directions ignore conflicting extra fields; explicit headers, key types and state remain guarded', () => {
  for(const p of profiles) {
    const o=options(p,2), raw=encodeMhPacket({header:mhHeader(2),messages:[message(xx)]},xx,xxKey);
    const input=Buffer.from(raw), th=Buffer.from(o.targetHeader), ph=Buffer.from(o.targetProxyHeader);
    const sk=Buffer.from(xxKey), tk=Buffer.from(guKey);
    const env=translateMhxxToMhguProxy(raw,{...o,profile:gu,gameProfile:'wrong'});
    const go={...o,targetHeader:mhHeader(2,0xc1),sourceKey:guKey,targetKey:xxKey};
    const gh=Buffer.from(go.targetHeader), before=Buffer.from(env.bytes);
    const back=translateMhguProxyToMhxx(env.bytes,{...go,profile:xx,gameProfile:'wrong'});
    assert.equal(env.profile,gu); assert.equal(back.profile,xx);
    for(const key of [Buffer.alloc(15),Buffer.alloc(17),'not-a-buffer',null,undefined]) {
      for(const name of ['sourceKey','targetKey']) {
        assert.throws(()=>translateMhxxToMhguProxy(raw,{...o,[name]:key}),/key16/);
        assert.throws(()=>translateMhguProxyToMhxx(env.bytes,{...go,[name]:key}),/key16/);
      }
    }
    for(const offset of [1,8,15]) {
      const bad=Buffer.from(ph); bad[offset]^=0x40;
      assert.throws(()=>translateMhxxToMhguProxy(raw,{...o,targetProxyHeader:bad}),/source_enums/);
    }
    assert.throws(()=>translateMhguProxyToMhxx(env.bytes,{...go,proxyProfile:undefined}),/proxy_profile/);
    // Empty mode2 still needs both keys; no messages cannot bypass target/source key checks.
    const empty=encodeMhPacket({header:mhHeader(2),messages:[]},xx,xxKey);
    const emptyEnv=translateMhxxToMhguProxy(empty,o).bytes;
    for(const name of ['sourceKey','targetKey']) {
      assert.throws(()=>translateMhxxToMhguProxy(empty,{...o,[name]:undefined}),/key16/);
      assert.throws(()=>translateMhguProxyToMhxx(emptyEnv,{...go,[name]:undefined}),/key16/);
    }
    const large=encodeMhPacket({header:mhHeader(1),messages:[message(xx,xxId,1416)]},xx), largeBefore=Buffer.from(large);
    const largeGu=encodeMhPacket({header:mhHeader(1),messages:[message(gu,guId,1416)]},gu);
    const largeEnv=encodeYuzuUdpProxyDatagram(ph,largeGu,p).bytes, largeEnvBefore=Buffer.from(largeEnv);
    assert.throws(()=>translateMhxxToMhguProxy(large,o),/limit/);
    assert.throws(()=>translateMhguProxyToMhxx(largeEnv,go),/limit/);
    assert.deepEqual(large,largeBefore); assert.deepEqual(largeEnv,largeEnvBefore);
    assert.deepEqual(raw,input); assert.deepEqual(env.bytes,before);
    assert.deepEqual(o.targetHeader,th); assert.deepEqual(go.targetHeader,gh); assert.deepEqual(o.targetProxyHeader,ph);
    assert.deepEqual(xxKey,sk); assert.deepEqual(guKey,tk); assert.equal(o.identityMap.size,1);
    assert.deepEqual(o.identityMap.translate('s','mhxx-to-mhgu',xxId),guId);
    assert.deepEqual(o.identityMap.translate('s','mhgu-to-mhxx',guId),xxId);
  }
});
