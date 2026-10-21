// SPDX-License-Identifier: GPL-3.0-or-later
import test from 'node:test';
import assert from 'node:assert/strict';
import zlib from 'node:zlib';
import { decodeBoundedZstdFrame as inflate, encodeBoundedZstdFrame as deflate } from './zstd-frame.mjs';
import { decodeYuzuUdpProxyDatagram as decode, encodeYuzuUdpProxyDatagram as encode } from './yuzu-udp-datagram.mjs';
import { encodeYuzuUdpProxyPacket as wrap, decodeYuzuUdpProxyPacket as unwrap,
  translateYuzuUdpProxyProfile as translate } from './yuzu-udp-proxy.mjs';
const old='yuzu-2022-7edc31be2', mirror='yuzu-mirror-01052024';
const hex=s=>Buffer.from(s,'hex');
const raw=hex('28b52ffd2003190000616263'); // Single segment, known 3 bytes, one raw LAST block: abc.
const header=p=>hex(p===old?'0500c0a801023039000a141e28abcd020100000000':'0501c0a801023039010a141e28abcd030100000000');
const flags=r=>{assert.equal(r.compressionValidated,true);for(const k of ['payloadValidated','applicationConverted','productionReady'])assert.equal(r[k],false);};

test('independent raw, RLE, non-single and empty frames decode',()=>{
  for(const [wire,plain] of [[raw,'abc'],[hex('28b52ffd20052b000061'),'aaaaa'],
    [hex('28b52ffd800003000000190000616263'),'abc'],[hex('28b52ffd2000010000'),'']]) {
    const before=Buffer.from(wire);const out=inflate(wire);
    assert.equal(out.toString(),plain);out.fill(0);assert.deepEqual(wire,before);
  }
});

test('exact compressed cap, adjacent window, 8-byte FCS and multiple blocks are explicit',()=>{
  const padded=Buffer.concat([hex('28b52ffd2004'),Buffer.alloc(21841*3),hex('21000061626364')]);
  assert.equal(padded.length,65536);assert.equal(inflate(padded).toString(),'abcd');
  assert.throws(()=>inflate(Buffer.concat([padded,Buffer.from([0])])),/zstd_input_limit/);
  assert.throws(()=>inflate(hex('28b52ffd803903000000190000616263')),/zstd_window_limit/);
  const wide=hex('28b52ffde00300000000000000190000616263');
  assert.equal(inflate(wide).toString(),'abc');wide.writeBigUInt64LE(9007199254740993n,5);
  assert.throws(()=>inflate(wide),/zstd_output_limit/);
  assert.equal(inflate(hex('28b52ffd2003080000611100006263')).toString(),'abc');
  for(const profile of [old,mirror])assert.throws(()=>encode(header(profile),Buffer.alloc(60001),profile),/zstd_plain_limit/);
});

test('encoder accepts empty and 60000, rejects non-Buffers and 60001',()=>{
  for(const n of [0,1,255,256,60000]) {
    const plain=Buffer.alloc(n,0xa5),copy=Buffer.from(plain),frame=deflate(plain);
    assert.deepEqual(inflate(frame),plain);assert.deepEqual(zlib.zstdDecompressSync(frame),plain);
    frame.fill(0);assert.deepEqual(plain,copy);
  }
  for(const bad of [null,{},[],new Uint8Array(1),Buffer.alloc(60001)])assert.throws(()=>deflate(bad),/zstd_plain_limit/);
  for(const bad of [null,{},new Uint8Array(raw),Buffer.alloc(65537)])assert.throws(()=>inflate(bad),/zstd_input_limit/);
});

test('truncation, trailing, concatenation and skippable frames are rejected',()=>{
  for(let n=0;n<raw.length;n++)assert.throws(()=>inflate(raw.subarray(0,n)));
  for(const b of [Buffer.concat([raw,raw]),Buffer.concat([raw,Buffer.from([0])]),hex('502a4d1800000000')])assert.throws(()=>inflate(b));
  const checksumMissing=Buffer.from(raw);checksumMissing[4]|=4;assert.throws(()=>inflate(checksumMissing));
});

test('reserved bits, dictionary headers, unknown size and oversized windows fail closed',()=>{
  for(const bit of [1,2,3,8,16]){const b=Buffer.from(raw);b[4]|=bit;assert.throws(()=>inflate(b),/dictionary|reserved/);}
  assert.throws(()=>inflate(hex('28b52ffd0000')),/unknown_zstd_content_size/);
  assert.equal(inflate(hex('28b52ffd803803000000190000616263')).toString(),'abc'); // 128 KiB exactly.
  assert.throws(()=>inflate(hex('28b52ffd804003000000190000616263')),/zstd_window_limit/);
  assert.throws(()=>inflate(hex('28b52ffd60ffff010000')),/zstd_output_limit/);
});

test('invalid block type, block bounds and advertised output mismatch are rejected',()=>{
  const invalidType=Buffer.from(raw);invalidType[6]=0x1f;
  const mismatch=Buffer.from(raw);mismatch[5]=4;
  const oversized=Buffer.from(raw);oversized.writeUIntLE((131073<<3)|1,6,3);
  for(const b of [invalidType,mismatch,oversized])assert.throws(()=>inflate(b));
});

test('zero-FCS validates content and checksum in both explicit Room profiles',()=>{
  const valid=[hex('28b52ffd2000010000'),hex('28b52ffd240001000099e9d851')];
  const invalid=[hex('28b52ffd200009000041'),hex('28b52ffd240001000000000000')];
  for(const frame of valid){assert.equal(inflate(frame).length,0);for(const profile of [old,mirror]){
    const packet=wrap(header(profile),frame,profile).bytes;const result=decode(packet,profile);assert.equal(result.datagram.length,0);flags(result);
  }}
  for(const frame of invalid){const copy=Buffer.from(frame);assert.throws(()=>inflate(frame));
    for(const profile of [old,mirror])assert.throws(()=>decode(wrap(header(profile),frame,profile).bytes,profile));assert.deepEqual(frame,copy);
  }
});

test('standard decoder validates checksum rather than trusting a framing walk',()=>{
  const frame=zlib.zstdCompressSync(Buffer.from('checksum fixture'),{params:{[zlib.constants.ZSTD_c_checksumFlag]:1}});
  assert.ok(frame[4]&4);assert.equal(inflate(frame).toString(),'checksum fixture');
  frame[frame.length-1]^=1;assert.throws(()=>inflate(frame));
});

test('independent Room header and raw Zstd bytes decode on both profiles',()=>{
  for(const profile of [old,mirror]){
    const packet=Buffer.concat([header(profile),raw]);packet.writeUInt32BE(raw.length,17);
    const before=Buffer.from(packet),result=decode(packet,profile);flags(result);
    assert.equal(result.datagram.toString(),'abc');assert.deepEqual(result.header,packet.subarray(0,21));
    result.header.fill(0);result.datagram.fill(0);assert.deepEqual(packet,before);
  }
});

test('explicit source/target profiles rebuild with independent target endpoints',()=>{
  for(const source of [old,mirror])for(const target of [old,mirror]){
    const input=wrap(header(source),raw,source).bytes;const sourceCopy=Buffer.from(input);
    const decoded=decode(input,source),targetHeader=header(target);targetHeader[2]=172;targetHeader[16]=127;
    targetHeader.writeUInt32BE(0xdeadbeef,17);const templateCopy=Buffer.from(targetHeader);
    const result=encode(targetHeader,decoded.datagram,target);flags(result);
    const back=decode(result.bytes,target);flags(back);assert.equal(back.datagram.toString(),'abc');
    assert.deepEqual(back.header.subarray(0,17),targetHeader.subarray(0,17));
    assert.deepEqual(targetHeader,templateCopy);assert.deepEqual(input,sourceCopy);
    assert.equal(unwrap(result.bytes,target).data.length,result.bytes.readUInt32BE(17));
    assert.deepEqual(decode(translate(result.bytes,target,source).bytes,source).datagram,decoded.datagram);
  }
});

test('invalid template/profile/envelope or compressed payload never returns success',()=>{
  for(const badProfile of [undefined,null,'yuzu-ea']){
    assert.throws(()=>encode(header(old),Buffer.alloc(0),badProfile),/profile/);
    assert.throws(()=>decode(wrap(header(old),raw,old).bytes,badProfile),/profile/);
  }
  assert.throws(()=>encode(header(old),Buffer.alloc(0),mirror),/source_enums/);
  assert.throws(()=>encode(Buffer.alloc(20),Buffer.alloc(0),old),/header/);
  assert.throws(()=>decode(wrap(header(old),Buffer.from('not zstd'),old).bytes,old));
  const input=wrap(header(old),raw,old).bytes;input.writeUInt32BE(raw.length+1,17);
  assert.throws(()=>decode(input,old),/envelope/);
});

test('deterministic incompressible fixtures respect bounds and remain independent',()=>{
  let x=12345;const next=()=>{x=(Math.imul(x,1664525)+1013904223)>>>0;return x>>>24;};
  for(const size of [0,12,1472,60000]){
    const data=Buffer.alloc(size);for(let i=0;i<size;i++)data[i]=next();
    const copy=Buffer.from(data),result=encode(header(old),data,old);flags(result);
    assert.ok(result.bytes.length<=65557);assert.deepEqual(decode(result.bytes,old).datagram,data);
    result.bytes.fill(0);assert.deepEqual(data,copy);
  }
});
