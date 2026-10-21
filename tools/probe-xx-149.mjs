import fs from 'node:fs';
import readline from 'node:readline';
const p = 'G:/mh-evidence/g2-trace/g2a-20261015T083801-local-gwA.jsonl';
const input = fs.createReadStream(p, { encoding: 'utf8' });
const lines = readline.createInterface({ input, crlfDelay: Infinity });
// XX 149B frames = 41B envelope + 108B MH packet (matching GU main-data length)
let n = 0;
const fieldStats = {
  hdr12_kind: {}, hdr12_seq: new Set(), hdr12_rt: new Set(), hdr12_te: new Set(),
  msg_ctrl: {}, msg_len: {}, msg_b1: {},
  sub_flags: {}, sub_len: {}, sub_seq_distinct: new Set(), sub_ack: {},
  payload_head4: {}, sender: {},
};
let samplePrinted = false;
for await (const line of lines) {
  let r;
  try { r = JSON.parse(line); } catch { continue; }
  if (r.structure !== 'citra_secure_data' || !r.raw_hex) continue;
  const payload = Buffer.from(r.raw_hex, 'hex');
  const i = payload.indexOf(Buffer.from('32ab9864', 'hex'));
  if (i < 0 || payload.length - i !== 108) continue;
  n++;
  const pkt = payload.subarray(i);
  const kind = pkt[5];
  fieldStats.hdr12_kind[kind] = (fieldStats.hdr12_kind[kind]??0)+1;
  fieldStats.hdr12_seq.add(pkt.readUInt16BE(6));
  fieldStats.hdr12_rt.add(pkt.readUInt16BE(8));
  fieldStats.hdr12_te.add(pkt.readUInt16BE(10));
  const msg = pkt.subarray(12);
  fieldStats.msg_ctrl[msg[0]] = (fieldStats.msg_ctrl[msg[0]]??0)+1;
  fieldStats.msg_len[msg.readUInt16BE(2)] = (fieldStats.msg_len[msg.readUInt16BE(2)]??0)+1;
  fieldStats.msg_b1[msg[1]] = (fieldStats.msg_b1[msg[1]]??0)+1;
  fieldStats.sender[msg.subarray(8,12).toString('hex')] = (fieldStats.sender[msg.subarray(8,12).toString('hex')]??0)+1;
  const route = msg.readUInt32BE(12);
  const stream = msg.subarray(20);  // 24B subheader + payload
  fieldStats.sub_flags[stream.readUInt16BE(0).toString(16)] = (fieldStats.sub_flags[stream.readUInt16BE(0).toString(16)]??0)+1;
  fieldStats.sub_len[stream.readUInt16BE(2)] = (fieldStats.sub_len[stream.readUInt16BE(2)]??0)+1;
  fieldStats.sub_seq_distinct.add(stream.readUInt32BE(8));
  fieldStats.sub_ack[stream.readUInt32BE(12).toString(16)] = (fieldStats.sub_ack[stream.readUInt32BE(12).toString(16)]??0)+1;
  fieldStats.payload_head4[stream.subarray(24, 28).toString('hex')] = (fieldStats.payload_head4[stream.subarray(24, 28).toString('hex')]??0)+1;
  if (!samplePrinted) {
    console.log('SAMPLE 108B: hdr12=' + pkt.subarray(0,12).toString('hex')
      + ' msg20=' + msg.subarray(0,20).toString('hex')
      + ' sub24=' + stream.subarray(0,24).toString('hex')
      + ' payload48=' + stream.subarray(24,72).toString('hex'));
    samplePrinted = true;
  }
}
console.log('packets:', n);
console.log('kind:', fieldStats.hdr12_kind);
console.log('seq distinct:', fieldStats.hdr12_seq.size, 'rt distinct:', fieldStats.hdr12_rt.size, 'te distinct:', fieldStats.hdr12_te.size);
console.log('msg ctrl:', fieldStats.msg_ctrl);
console.log('msg len top:', Object.entries(fieldStats.msg_len).sort((a,b)=>b[1]-a[1]).slice(0,5));
console.log('msg byte1:', fieldStats.msg_b1);
console.log('senders:', fieldStats.sender);
console.log('sub flags:', fieldStats.sub_flags);
console.log('sub len top:', Object.entries(fieldStats.sub_len).sort((a,b)=>b[1]-a[1]).slice(0,5));
console.log('sub seq distinct:', fieldStats.sub_seq_distinct.size);
console.log('sub ack top:', Object.entries(fieldStats.sub_ack).sort((a,b)=>b[1]-a[1]).slice(0,4));
console.log('payload head4 top:', Object.entries(fieldStats.payload_head4).sort((a,b)=>b[1]-a[1]).slice(0,4));
