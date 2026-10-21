// SPDX-License-Identifier: GPL-3.0-or-later
// Public NetworkInfo IE only; does not decrypt or validate encrypted node data.
import crypto from 'node:crypto';
const sha=(name,b)=>crypto.createHash(name).update(b).digest('hex');

export function udsAdvertisement(record) {
  if(!['citra.in','citra.out'].includes(record.event_label))return null;
  if(typeof record.raw_hex!=='string' || record.raw_hex.length>131072 ||
     !/^(?:[a-fA-F0-9]{2})*$/.test(record.raw_hex))throw Error('missing_or_invalid_raw');
  const raw=Buffer.from(record.raw_hex,'hex');
  if(raw.length!==record.length || sha('sha256',raw)!==record.sha256)throw Error('raw_integrity');
  if(raw[0]!==5 || raw[1]!==0)return null; // Wifi FrameType::Beacon
  if(raw.length<31 || raw.readUInt32BE(15)!==raw.length-19)throw Error('beacon_envelope');
  const body=raw.subarray(19);
  let found=null;
  for(let p=12;p<body.length;) {
    if(p+2>body.length || p+2+body[p+1]>body.length)throw Error('truncated_beacon_ie');
    const tag=body.subarray(p,p+2+body[p+1]);p+=tag.length;
    if(tag[0]!==221 || tag.length<6 || tag.subarray(2,6).toString('hex')!=='001f3215')continue;
    if(found)throw Error('duplicate_network_info');
    if(tag.length<54 || tag[53]>200 || tag.length!==54+tag[53])throw Error('advertisement_length');
    const hashed=Buffer.from(tag.subarray(2));hashed.fill(0,31,51);
    if(sha('sha1',hashed)!==tag.subarray(33,53).toString('hex'))throw Error('advertisement_sha1');
    // network_info is guest NetworkInfo bytes [0x0c,0x2b), no second OUI.
    if(tag[18]>16 || tag[19]>16 || tag[18]>tag[19])throw Error('advertisement_nodes');
    found={transmitter_mac:raw.subarray(3,9).toString('hex'),wifi_channel:raw[2],
      wlan_comm_id_hex:'0x'+tag.readUInt32BE(6).toString(16).padStart(8,'0'),
      id:tag[10],attributes:tag.readUInt16BE(12),
      network_id_hex:'0x'+tag.readUInt32BE(14).toString(16).padStart(8,'0'),
      total_nodes:tag[18],max_nodes:tag[19],
      advertise_length:tag[53],advertise_sha256:sha('sha256',tag.subarray(54)),
      public_ie_sha1_verified:true,encrypted_nodes_verified:false,game_verified:false};
  }
  return found;
}
