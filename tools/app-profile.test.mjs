// SPDX-License-Identifier: GPL-3.0-or-later
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import {fileURLToPath} from 'node:url';
import {applicationBoundary,mhPacketHeader,mhMessages,profileApplications,compareApplications} from './app-profile.mjs';

const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const packet=body=>Buffer.concat([Buffer.from('32ab98640100000000000000','hex'),body]);
test('inner framing keeps aligned consecutive messages and opaque padding separate',()=>{
  // Two independent 20-byte headers, lengths 1 and 2, with 3/2 opaque pad bytes.
  const body=Buffer.from('084000010102030405060708090a0b0c0d0e0f10aa998877'+
    '00ff00021112131415161718191a1b1c1d1e1f20bbcc6655','hex');
  assert.deepEqual(mhMessages(packet(body)),{status:'parsed',termination:'exact_end',trailing_bytes:0,
    messages:[{offset:0,control_bits:8,byte1:64,payload_length:1,padding_length:3},
      {offset:24,control_bits:0,byte1:255,payload_length:2,padding_length:2}]});
});
test('inner framing rejects missing header, payload and alignment without partial success',()=>{
  const full=Buffer.from('0000000100000000000000000000000000000000aa000000','hex');
  for(const [body,reason] of [[full.subarray(0,19),'short_message_header'],
    [full.subarray(0,20),'message_length'],[full.subarray(0,21),'short_alignment'],
    [Buffer.alloc(1461),'body_limit']]) {
    assert.deepEqual(mhMessages(packet(body)),{status:'malformed',reason});
  }
  assert.deepEqual(mhMessages(Buffer.from('32ab9864','hex')),{status:'malformed',reason:'short_packet_header'});
});
test('inner framing distinguishes mode, empty body and sentinel without inspecting sentinel remainder',()=>{
  assert.deepEqual(mhMessages(Buffer.alloc(12)),{status:'unrecognized'});
  const encrypted=packet(Buffer.alloc(20));encrypted[4]=2;
  assert.deepEqual(mhMessages(encrypted),{status:'unsupported_mode'});
  assert.deepEqual(mhMessages(packet(Buffer.alloc(0))),{status:'parsed',termination:'exact_end',messages:[],trailing_bytes:0});
  assert.deepEqual(mhMessages(packet(Buffer.from('ff010203','hex'))),
    {status:'parsed',termination:'sentinel',messages:[],trailing_bytes:4});
  const zero=packet(Buffer.alloc(20));
  assert.equal(mhMessages(zero).messages[0].payload_length,0);
});
test('MHXX header reads independent big-endian fields without rejecting unknown modes or zero sequence',()=>{
  assert.deepEqual(mhPacketHeader(Buffer.from('32ab9864feef0000fffe0102aabb','hex')),
    {mode:254,kind:239,sequence:0,relative_time:65534,time_echo:258});
  for(let length=0;length<12;length++) {
    const bytes=Buffer.from('32ab9864011a000100020003','hex').subarray(0,length);
    assert.deepEqual(mhPacketHeader(bytes),length<4?null:{truncated:true});
  }
  assert.equal(mhPacketHeader(Buffer.from('6498ab32011a000100020003','hex')),null);
});
const marker=side=>({manifest_id:'synthetic',run_id:'boundary-test',channel:side==='citra'?'A':'B',
  platform:side,build_id:'synthetic',role:'observer',event_label:'run.begin',stage:'joined',
  direction:'n/a',utc:'2026-10-15T00:00:00Z',monotonic_ms:0,length:0,
  sha256:sha(Buffer.alloc(0)),structure:'marker',decoded:true});
function record(raw,side,extra={}) {
  return {...marker(side),event_label:side==='citra'?'citra.in':'room.c2s',monotonic_ms:1,
    structure:side==='citra'?'citra_secure_data':'yuzu_room_proxy',length:raw.length,
    sha256:sha(raw),raw_hex:raw.toString('hex'),...extra};
}
function wifi(payload) {
  // Handlaid wire fixture, independently sized from the source structs (19+8+14).
  const raw=Buffer.alloc(41+payload.length);
  raw[0]=5;raw[1]=1;raw[2]=11;raw.writeUInt32BE(payload.length+22,15);
  Buffer.from('aaaa03000000876d','hex').copy(raw,19);
  raw.writeUInt16BE(payload.length+14,27);raw.writeUInt16BE(payload.length+10,31);
  raw[34]=243;raw.writeUInt16BE(0xfffa,35);raw.writeUInt16BE(0xffff,37);raw.writeUInt16BE(2,39);
  payload.copy(raw,41);return raw;
}
function proxy(payload,compressed=zlib.zstdCompressSync(payload)) {
  const raw=Buffer.alloc(21+compressed.length);
  Buffer.from('0501c0a80101012301c0a8010204560300','hex').copy(raw);
  raw.writeUInt32BE(compressed.length,17);compressed.copy(raw,21);
  return record(raw,'yuzu',{peer_id:1,local_family:1,remote_family:1,local_ip:'192.168.1.1',
    remote_ip:'192.168.1.2',local_port:291,remote_port:1110,protocol:3,broadcast:false,
    compressed_length:compressed.length,zstd_verified:true,plain_length:payload.length,plain_sha256:sha(payload)});
}
async function withTrace(records,fn) {
  const base=path.join(path.dirname(fileURLToPath(import.meta.url)),'build');
  await fs.mkdir(base,{recursive:true});
  const dir=await fs.mkdtemp(path.join(base,'app-profile-test-'));
  try {
    const file=path.join(dir,'synthetic.jsonl');
    const bytes=Buffer.from(records.map(r=>JSON.stringify(r)).join('\n')+'\n');
    await fs.writeFile(file,bytes);
    return await fn(file,sha(bytes));
  }finally {await fs.rm(dir,{recursive:true,force:true});}
}

test('UDS boundary removes exactly LLC and SecureData, retaining route and sequence independently',()=>{
  const payload=Buffer.from('a synthetic app datagram');
  const value=applicationBoundary(record(wifi(payload),'citra'),'citra');
  assert.deepEqual(value.payload,payload);
  assert.deepEqual(value.route,{transmitter_mac:'000000000000',destination_mac:'000000000000',
    data_channel:243,source_node:2,destination_node:65535});
  assert.equal(value.sequence,0xfffa);
});
test('UDS rejects inconsistent inner sizes and management flag even with a valid outer hash',()=>{
  for(const offset of [27,31,33]) {
    const raw=wifi(Buffer.alloc(10));raw[offset]^=1;
    assert.throws(()=>applicationBoundary(record(raw,'citra'),'citra'));
  }
  const r=record(wifi(Buffer.alloc(2)),'citra');r.sha256='0'.repeat(64);
  assert.throws(()=>applicationBoundary(r,'citra'),/integrity/);
});
test('native Proxy boundary retains different source/destination UDP ports without swapping them',()=>{
  const payload=Buffer.from('native payload');
  const value=applicationBoundary(proxy(payload),'yuzu');
  assert.deepEqual(value.payload,payload);
  assert.deepEqual(value.route,{protocol:3,source_ip:'192.168.1.1',source_port:291,
    destination_ip:'192.168.1.2',destination_port:1110,broadcast:false});
});
test('native Unspecified protocol remains distinct from UDP rather than being normalized',()=>{
  const original=proxy(Buffer.from('unspecified transport'));
  const raw=Buffer.from(original.raw_hex,'hex');raw[15]=0;
  const value=applicationBoundary(record(raw,'yuzu'),'yuzu');
  assert.equal(value.route.protocol,0);
  assert.deepEqual(value.payload,Buffer.from('unspecified transport'));
  raw[15]=4;
  assert.throws(()=>applicationBoundary(record(raw,'yuzu'),'yuzu'),/unsupported_proxy_transport/);
});
test('concatenated, truncated and unknown-size Zstd never count as application datagrams',()=>{
  const payload=Buffer.from('synthetic');const frame=zlib.zstdCompressSync(payload);
  for(const compressed of [Buffer.concat([frame,frame]),frame.subarray(0,-1),Buffer.from('28b52ffd0000','hex')]) {
    assert.throws(()=>applicationBoundary(proxy(payload,compressed),'yuzu'));
  }
});
test('shared bounded decoder rejects oversized windows and dictionary headers in analysis too',()=>{
  for(const compressed of [Buffer.from('28b52ffd804003000000190000616263','hex'),
    Buffer.from('28b52ffd210003190000616263','hex')]) {
    assert.throws(()=>applicationBoundary(proxy(Buffer.from('abc'),compressed),'yuzu'),/zstd_window_limit|zstd_dictionary_unsupported/);
  }
});

test('CRLY and legacy opaque UDS tunnels cannot be mistaken for MHGU application evidence',()=>{
  for(const payload of [Buffer.from('CRLY\x01\x01\x06synthetic'),wifi(Buffer.alloc(4)).subarray(19)]) {
    assert.deepEqual(applicationBoundary(proxy(payload),'yuzu'),{excluded_tunnel:true});
  }
});
test('profiles identify variable offsets by stage and route without exposing any payload bytes',async()=>{
  const a=Buffer.from('secret-payload-A'),b=Buffer.from('secret-payload-B');
  const report=await withTrace([marker('citra'),record(wifi(a),'citra'),record(wifi(b),'citra')],async(file,hash)=>{
    const result=await profileApplications(file,'citra');
    assert.equal(result.report.trace_sha256,hash);return result.report;
  });
  assert.equal(report.passed,true);assert.equal(report.application_records,2);
  assert.deepEqual(report.groups[0].variable_offset_ranges,[[15,15]]);
  assert.equal(JSON.stringify(report).includes('secret-payload'),false);
  assert.equal(JSON.stringify(report).includes(a.toString('hex')),false);
  assert.equal(report.game_verified,false);
});
test('cross-platform exact payload equality remains an observation, never verified conversion',async()=>{
  const payload=Buffer.from('synthetic shared bytes');
  const a=await withTrace([marker('citra'),record(wifi(payload),'citra')],file=>profileApplications(file,'citra'));
  const b=await withTrace([marker('yuzu'),proxy(payload)],file=>profileApplications(file,'yuzu'));
  const compared=compareApplications(a,b);
  assert.equal(b.report.passed,true);assert.equal(compared.exact_shared_payload_hashes,1);
  assert.equal(compared.translation_verified,false);assert.equal(compared.game_verified,false);
});

test('header aggregates retain truncated and nonmatching evidence without changing boundary verdict',async()=>{
  const payloads=['32ab9864011a000100020000','32ab986402ef000000030004','32ab986401','deadbeef'];
  await withTrace([marker('citra'),...payloads.map(hex=>record(wifi(Buffer.from(hex,'hex')),'citra'))],async file=>{
    const {report}=await profileApplications(file,'citra');
    assert.equal(report.passed,true);
    assert.deepEqual(report.mhxx_header,{recognized:2,truncated:1,unrecognized:1,
      mode_counts:{1:1,2:1},kind_counts:{26:1,239:1},
      sequence:{min:0,max:1,zero_count:1},relative_time:{min:2,max:3,zero_count:0},
      time_echo:{min:0,max:4,zero_count:1}});
    assert.equal(report.game_verified,false);
  });
});

test('message report exposes malformed framing separately from valid application boundaries',async()=>{
  const valid=packet(Buffer.alloc(20)),invalid=packet(Buffer.alloc(19));
  await withTrace([marker('citra'),record(wifi(valid),'citra'),record(wifi(invalid),'citra')],async file=>{
    const {report}=await profileApplications(file,'citra');
    assert.equal(report.passed,true);
    assert.deepEqual(report.mhxx_messages,{status_counts:{parsed:1,malformed:1},
      error_reasons:{short_message_header:1},termination_counts:{exact_end:1},messages:1,
      control_bits_counts:{0:1},byte1_counts:{0:1},padding_length_counts:{0:1},
      header_u32_ranges:[4,8,12,16].map(offset=>({offset,count:1,min:0,max:0,
        zero_count:1,all_ones_count:0}))});
    assert.equal(report.game_verified,false);
  });
});
test('message words stay unsigned big-endian and isolated by stage and route',async()=>{
  const first=packet(Buffer.from('0000000001020304ffffffff0000000080000000','hex'));
  const second=packet(Buffer.from('00000000ffffffff000000001122334400000000','hex'));
  await withTrace([marker('citra'),record(wifi(first),'citra',{stage:'search'}),
    record(wifi(second),'citra',{stage:'joined'})],async file=>{
    const {report}=await profileApplications(file,'citra');
    assert.equal(report.passed,true);
    assert.deepEqual(report.mhxx_messages.header_u32_ranges,[
      {offset:4,count:2,min:16909060,max:4294967295,zero_count:0,all_ones_count:1},
      {offset:8,count:2,min:0,max:4294967295,zero_count:1,all_ones_count:1},
      {offset:12,count:2,min:0,max:287454020,zero_count:1,all_ones_count:0},
      {offset:16,count:2,min:0,max:2147483648,zero_count:1,all_ones_count:0},
    ]);
    assert.equal(report.groups.length,2);
    assert.equal(report.groups[0].mhxx_messages.header_u32_ranges[0].max,16909060);
    assert.equal(report.groups[1].mhxx_messages.header_u32_ranges[0].min,4294967295);
    assert.equal(report.game_verified,false);
  });
});

test('malformed messages and transformed bodies never contaminate word ranges',async()=>{
  const partial=packet(Buffer.concat([Buffer.alloc(20),Buffer.alloc(19)]));
  const transformed=packet(Buffer.alloc(20,0xff));transformed[4]=2;
  const sentinel=packet(Buffer.concat([Buffer.from([255]),Buffer.alloc(20,0xff)]));
  await withTrace([marker('citra'),...[partial,transformed,sentinel].map(p=>record(wifi(p),'citra'))],async file=>{
    const {report}=await profileApplications(file,'citra');
    assert.equal(report.mhxx_messages.messages,0);
    assert.equal(report.mhxx_messages.status_counts.malformed,1);
    assert.equal(report.mhxx_messages.status_counts.unsupported_mode,1);
    for(const range of report.mhxx_messages.header_u32_ranges) {
      assert.deepEqual(range,{offset:range.offset,count:0,min:null,max:null,zero_count:0,all_ones_count:0});
    }
  });
});

test('missing raw evidence, corrupt input and bounded-capacity exhaustion stay visible',async()=>{
  const r=record(wifi(Buffer.alloc(3)),'citra');delete r.raw_hex;
  await withTrace([marker('citra'),r],async file=>{
    const {report}=await profileApplications(file,'citra');assert.equal(report.passed,false);assert.equal(report.missing_raw,1);
  });
  await withTrace([marker('citra'),record(wifi(Buffer.alloc(3)),'citra'),record(wifi(Buffer.alloc(4)),'citra')],async file=>{
    const {report}=await profileApplications(file,'citra',{maxGroups:1});
    assert.equal(report.passed,false);assert.equal(report.errors,1);
  });
  await withTrace([marker('citra'),record(wifi(Buffer.alloc(3)),'citra'),{nonsense:true}],async file=>{
    const {report}=await profileApplications(file,'citra');assert.equal(report.passed,false);assert.ok(report.audit_errors>0);
  });
});
