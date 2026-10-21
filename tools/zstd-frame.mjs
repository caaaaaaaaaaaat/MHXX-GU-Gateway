// SPDX-License-Identifier: GPL-3.0-or-later
// Offline strict subset, not the emulator's full accepted-input grammar.
import zlib from 'node:zlib';

// Independent Zstd framing walk: exactly one known-size frame, not a concatenation.
// Decoding/checksum verification remains the standard library's responsibility.
export function decodeBoundedZstdFrame(frame) {
  if (!Buffer.isBuffer(frame) || frame.length > 65536) throw Error('zstd_input_limit');
  if (typeof zlib.zstdDecompressSync !== 'function') throw Error('zstd_runtime_unavailable');
  if(frame.length<6 || frame.readUInt32LE(0)!==0xfd2fb528)throw Error('invalid_zstd_magic');
  const d=frame[4], single=!!(d&32), fcs=d>>>6;
  if(d&24)throw Error('reserved_zstd_header');
  const fcsSize=[single?1:0,2,4,8][fcs];
  if(!fcsSize)throw Error('unknown_zstd_content_size');
  if (d&3) throw Error('zstd_dictionary_unsupported');
  if (!single) {
    if (frame.length < 6) throw Error('short_zstd_header');
    const w=frame[5], base=2**(10+(w>>>3));
    if (base + (base/8)*(w&7) > 131072) throw Error('zstd_window_limit');
  }
  let p=5+(single?0:1);
  if(p+fcsSize>frame.length)throw Error('short_zstd_header');
  let length=0n;
  for(let i=0;i<fcsSize;i++)length|=BigInt(frame[p+i])<<BigInt(8*i);
  if(fcs===1)length+=256n;
  if(length>60000n)throw Error('zstd_output_limit');
  p+=fcsSize;
  let last=false;
  while(!last) {
    if(p+3>frame.length)throw Error('short_zstd_block');
    const header=frame.readUIntLE(p,3); p+=3;
    last=!!(header&1);
    const type=(header>>>1)&3, size=header>>>3;
    if(type===3 || size>131072)throw Error('invalid_zstd_block');
    p+=type===1?1:size;
    if(p>frame.length)throw Error('short_zstd_block');
  }
  if(d&4)p+=4;
  if(p!==frame.length)throw Error('zstd_trailing_or_concatenated_frame');
  const plain=zlib.zstdDecompressSync(frame,{maxOutputLength:60000});
  if(BigInt(plain.length)!==length)throw Error('zstd_size_disagreement');
  return plain;
}

export function encodeBoundedZstdFrame(plain) {
  if (!Buffer.isBuffer(plain) || plain.length > 60000) throw Error('zstd_plain_limit');
  if (typeof zlib.zstdCompressSync !== 'function') throw Error('zstd_runtime_unavailable');
  const frame = zlib.zstdCompressSync(plain);
  // Check framing/output consistency, not identity, game validity or authenticity.
  if (!decodeBoundedZstdFrame(frame).equals(plain)) throw Error('zstd_roundtrip_disagreement');
  return frame;
}
