// SPDX-License-Identifier: GPL-3.0-or-later
// Offline application-boundary research. Never emits application bytes or sends traffic.
import fs from 'node:fs';
import readline from 'node:readline';
import crypto from 'node:crypto';
import { decodeBoundedZstdFrame as zstdPlain } from './zstd-frame.mjs';
import {pathToFileURL} from 'node:url';
import {auditTrace} from './trace-audit.mjs';

const digest=b=>crypto.createHash('sha256').update(b).digest('hex');
const secureMagic=Buffer.from('aaaa03000000876d','hex');
const ip=b=>Array.from(b).join('.');

// MHXX 1.4 static serializer + captured datagrams. Recognition is not a
// compatibility check; mode/kind values and zero sequence remain unrestricted.
export function mhPacketHeader(payload) {
  if(payload.length<4 || payload.readUInt32BE(0)!==0x32ab9864)return null;
  if(payload.length<12)return {truncated:true};
  return {mode:payload[4],kind:payload[5],sequence:payload.readUInt16BE(6),
    relative_time:payload.readUInt16BE(8),time_echo:payload.readUInt16BE(10)};
}

// Research parser: metadata only. A mode=2 body must not be interpreted before
// its optional transform. Unassigned fields and padding contents stay opaque.
export function mhMessages(payload) {
  const header=mhPacketHeader(payload);
  if(!header)return {status:'unrecognized'};
  if(header.truncated)return {status:'malformed',reason:'short_packet_header'};
  if(header.mode!==1)return {status:'unsupported_mode'};
  const body=payload.subarray(12);
  if(body.length>1460)return {status:'malformed',reason:'body_limit'};
  const messages=[];
  for(let offset=0;offset<body.length;) {
    if(body[offset]===255)return {status:'parsed',termination:'sentinel',messages,
      trailing_bytes:body.length-offset};
    if(offset+20>body.length)return {status:'malformed',reason:'short_message_header'};
    const length=body.readUInt16BE(offset+2),end=offset+20+length;
    if(end>body.length)return {status:'malformed',reason:'message_length'};
    const stride=Math.ceil((20+length)/4)*4;
    if(offset+stride>body.length)return {status:'malformed',reason:'short_alignment'};
    messages.push({offset,control_bits:body[offset],byte1:body[offset+1],payload_length:length,
      padding_length:stride-20-length});
    offset+=stride;
  }
  return {status:'parsed',termination:'exact_end',messages,trailing_bytes:0};
}

function messageSummary() {
  return {status_counts:{},error_reasons:{},termination_counts:{},messages:0,
    control_bits_counts:{},byte1_counts:{},padding_length_counts:{},
    header_u32_ranges:[4,8,12,16].map(offset=>({offset,count:0,min:null,max:null,
      zero_count:0,all_ones_count:0}))};
}

function observeMessages(summary,payload,result) {
  summary.status_counts[result.status]=(summary.status_counts[result.status]??0)+1;
  if(result.reason)summary.error_reasons[result.reason]=(summary.error_reasons[result.reason]??0)+1;
  if(result.status!=='parsed')return;
  summary.termination_counts[result.termination]=(summary.termination_counts[result.termination]??0)+1;
  summary.messages+=result.messages.length;
  for(const m of result.messages) {
    summary.control_bits_counts[m.control_bits]=(summary.control_bits_counts[m.control_bits]??0)+1;
    summary.byte1_counts[m.byte1]=(summary.byte1_counts[m.byte1]??0)+1;
    summary.padding_length_counts[m.padding_length]=(summary.padding_length_counts[m.padding_length]??0)+1;
    for(const range of summary.header_u32_ranges) {
      const value=payload.readUInt32BE(12+m.offset+range.offset);
      range.min=range.min===null?value:Math.min(range.min,value);
      range.max=range.max===null?value:Math.max(range.max,value);
      range.count++;
      if(value===0)range.zero_count++;
      if(value===0xffffffff)range.all_ones_count++;
    }
  }
}

function headerSummary() {
  return {recognized:0,truncated:0,unrecognized:0,mode_counts:{},kind_counts:{},
    sequence:null,relative_time:null,time_echo:null};
}
function observeHeader(summary,payload) {
  const header=mhPacketHeader(payload);
  if(!header){summary.unrecognized++;return;}
  if(header.truncated){summary.truncated++;return;}
  summary.recognized++;
  for(const field of ['mode','kind']) {
    const counts=summary[`${field}_counts`], key=header[field];
    counts[key]=(counts[key]??0)+1;
  }
  for(const field of ['sequence','relative_time','time_echo']) {
    const value=header[field];
    const range=summary[field]??={min:value,max:value,zero_count:0};
    range.min=Math.min(range.min,value);range.max=Math.max(range.max,value);
    if(value===0)range.zero_count++;
  }
}


export function applicationBoundary(record, side) {
  if(!['citra','yuzu'].includes(side))throw Error('invalid_side');
  const events=side==='citra'?['citra.in','citra.out']:['room.c2s','room.s2c'];
  if(!events.includes(record.event_label))return null;
  if(!Object.hasOwn(record,'raw_hex'))return {missing_raw:true};
  if(typeof record.raw_hex!=='string' || record.raw_hex.length>131072 ||
     !/^(?:[a-fA-F0-9]{2})*$/.test(record.raw_hex))throw Error('invalid_raw_hex');
  const raw=Buffer.from(record.raw_hex,'hex');
  if(raw.length!==record.length || digest(raw)!==record.sha256)throw Error('raw_integrity');
  if(raw[0]!==5)return null;
  if(side==='citra') {
    if(raw.length<19 || raw.readUInt32BE(15)!==raw.length-19)throw Error('wifi_envelope_length');
    if(raw[1]!==1)return null; // Management frames are not application datagrams.
    const body=raw.subarray(19);
    if(body.length<8 || !body.subarray(0,8).equals(secureMagic))return null;
    if(body.length<22)throw Error('short_secure_data');
    const size=body.readUInt16BE(8), secure=body.readUInt16BE(12);
    if(size<14 || secure<10 || size-14!==secure-10 || size+8!==body.length)throw Error('secure_data_length');
    if(body[14]!==0)throw Error('unsupported_management_data');
    return {payload:body.subarray(22),route:{transmitter_mac:raw.subarray(3,9).toString('hex'),
      destination_mac:raw.subarray(9,15).toString('hex'),data_channel:body[15],
      source_node:body.readUInt16BE(20),destination_node:body.readUInt16BE(18)},
      sequence:body.readUInt16BE(16)};
  }
  if(raw.length<21 || raw.readUInt32BE(17)!==raw.length-21)throw Error('proxy_envelope_length');
  if(raw[1]!==1 || raw[8]!==1 || raw[15]>3 || raw[16]>1)throw Error('unsupported_proxy_transport');
  const payload=zstdPlain(raw.subarray(21));
  // Citra peer-relay and the older opaque UDS tunnel are not native MHGU payloads.
  if(payload.subarray(0,4).equals(Buffer.from('CRLY')) || payload.subarray(0,8).equals(secureMagic)) {
    return {excluded_tunnel:true};
  }
  return {payload,route:{protocol:raw[15],source_ip:ip(raw.subarray(2,6)),source_port:raw.readUInt16BE(6),
    destination_ip:ip(raw.subarray(9,13)),destination_port:raw.readUInt16BE(13),broadcast:raw[16]===1}};
}

function ranges(values, predicate) {
  const result=[];
  for(let i=0;i<values.length;i++)if(predicate(values[i])) {
    const start=i; while(i+1<values.length && predicate(values[i+1]))i++;
    result.push([start,i]);
  }
  return result;
}

export async function profileApplications(file,side,{maxGroups=256,maxProfileBytes=1024,maxFingerprints=20000}={}) {
  if(!['citra','yuzu'].includes(side))throw Error('invalid_side');
  if(!Number.isInteger(maxGroups)||maxGroups<1||maxGroups>256 ||
     !Number.isInteger(maxProfileBytes)||maxProfileBytes<1||maxProfileBytes>60000 ||
     maxGroups*maxProfileBytes>262144 || !Number.isInteger(maxFingerprints)||maxFingerprints<1||maxFingerprints>100000)throw Error('invalid_profile_limits');
  const before=fs.statSync(file), audit=await auditTrace(file);
  const report={schema:'crossplay.app-profile/1',side,lines:0,application_records:0,missing_raw:0,
    excluded_tunnels:0,errors:0,error_examples:[],audit_errors:audit.errors,audit_error_reasons:audit.error_reasons,groups:[],
    trace_sha256:null,passed:false,game_verified:false,
    mhxx_header:headerSummary(),
    mhxx_messages:messageSummary(),
    message_scope:'mode=1 research framing only; sentinel remainder opaque; framing failures do not change application-boundary passed verdict',
    header_scope:'12-byte MHXX layout recognition only; kind semantics, counter scope and exact time echo meaning remain unresolved',
    scope:'application boundary lengths, routes and byte variability; no message semantics or compatibility verdict'};
  const groups=new Map(), hash=crypto.createHash('sha256');
  const input=fs.createReadStream(file);
  input.on('data',chunk=>hash.update(chunk));
  const lines=readline.createInterface({input,crlfDelay:Infinity});
  const fingerprints=new Map();
  const error=reason=>{report.errors++;if(report.error_examples.length<20)report.error_examples.push({line:report.lines,reason});};
  try {
    for await(const line of lines) {
      report.lines++;
      if(line.length>2*1024*1024){error('line_limit');continue;}
      let record, value;
      try {record=JSON.parse(line);value=applicationBoundary(record,side);}catch {error('invalid_application_record');continue;}
      if(!value)continue;
      if(value.missing_raw){report.missing_raw++;continue;}
      if(value.excluded_tunnel){report.excluded_tunnels++;continue;}
      if(typeof record.stage!=='string'||record.stage.length>256){error('invalid_stage');continue;}
      const peer=Number.isSafeInteger(record.peer_id)?record.peer_id:null;
      const key=JSON.stringify([record.stage,record.event_label,peer,value.route,value.payload.length]);
      let group=groups.get(key);
      if(!group) {
        if(groups.size>=maxGroups){error('group_limit');continue;}
        const profiled=Math.min(value.payload.length,maxProfileBytes);
        group={stage:record.stage,event:record.event_label,peer_id:peer,route:value.route,payload_length:value.payload.length,
          records:0,distinct:new Uint16Array(profiled),seen:new Uint32Array(profiled*8),
          profiled_bytes:profiled,mhxx_messages:messageSummary()};
        groups.set(key,group);
      }
      const sha=digest(value.payload);
      if(!fingerprints.has(sha) && fingerprints.size>=maxFingerprints){error('fingerprint_limit');continue;}
      fingerprints.set(sha,value.payload.length);
      group.records++; report.application_records++;
      observeHeader(report.mhxx_header,value.payload);
      const messages=mhMessages(value.payload);
      observeMessages(report.mhxx_messages,value.payload,messages);
      observeMessages(group.mhxx_messages,value.payload,messages);
      for(let i=0;i<group.distinct.length;i++) {
        const byte=value.payload[i], offset=i*8+(byte>>>5), mask=1<<(byte&31);
        if(!(group.seen[offset]&mask)){group.seen[offset]|=mask;group.distinct[i]++;}
      }
    }
  } finally {lines.close();input.destroy();}
  report.trace_sha256=hash.digest('hex');
  const after=fs.statSync(file);
  if(before.size!==after.size || before.mtimeMs!==after.mtimeMs)error('trace_changed_during_analysis');
  for(const group of groups.values()) {
    const {seen,distinct,...metadata}=group;
    report.groups.push({...metadata,variable_offset_ranges:ranges(distinct,n=>n>1),
      constant_offset_ranges:ranges(distinct,n=>n===1)});
  }
  report.passed=report.errors===0 && report.audit_errors===0 && report.application_records>0 && report.missing_raw===0;
  return {report,fingerprints};
}

export function compareApplications(a,b) {
  let exact=0;
  for(const sha of a.fingerprints.keys())if(b.fingerprints.has(sha))exact++;
  return {schema:'crossplay.app-comparison/1',citra:a.report,yuzu:b.report,
    exact_shared_payload_hashes:exact,game_verified:false,translation_verified:false,
    scope:'exact payload equality is a research observation, never proof of shared semantics or compatibility'};
}

if(process.argv[1] && import.meta.url===pathToFileURL(process.argv[1]).href) {
  try {
    const args=process.argv.slice(2);
    if(![2,4].includes(args.length)||!['--citra','--yuzu'].includes(args[0])||
       (args.length===4 && (args[2]===args[0]||!['--citra','--yuzu'].includes(args[2]))))throw Error('usage');
    const profiles={};
    for(let i=0;i<args.length;i+=2)profiles[args[i].slice(2)]=await profileApplications(args[i+1],args[i].slice(2));
    const report=args.length===4?compareApplications(profiles.citra,profiles.yuzu):Object.values(profiles)[0].report;
    console.log(JSON.stringify(report,null,2));
    process.exitCode=Object.values(profiles).every(p=>p.report.passed)?0:1;
  }catch {console.error('Application profiling failed. Usage: node app-profile.mjs --citra <trace> [--yuzu <trace>]; no payload or file contents printed.');process.exitCode=2;}
}
