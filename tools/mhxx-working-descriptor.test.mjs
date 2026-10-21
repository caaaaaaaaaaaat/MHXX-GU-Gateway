import assert from 'node:assert/strict';
import test from 'node:test';
import { prepareMhxxDerivedWorkingDescriptor } from './mhxx-working-descriptor.mjs';

test('derived working descriptor preserves order with bit1 set and swaps whole subrecords otherwise', () => {
  for (const flag of [0,1,2,3,128,255]) {
    const input=Buffer.from(Array.from({length:70},(_,i)=>(i+11)&255));
    input[27]=flag;
    // Nonzero fields avoid activating fallback in either selected first record.
    input[62]=129;
    const expected=(flag&2) ? Buffer.from(input) : Buffer.concat([input.subarray(35),input.subarray(0,35)]);
    const output=prepareMhxxDerivedWorkingDescriptor(input,'mhxx-1.4');
    assert.deepEqual(output,expected);
    output.fill(0);
    assert.equal(input[27],flag);
  }
});

test('derived fallback changes only zero bytes25/26/27 of selected first subrecord', () => {
  const flagFallback=Buffer.alloc(70);
  flagFallback[27]=1; // clear bit1 selects the second subrecord, whose flag is zero.
  const filled=prepareMhxxDerivedWorkingDescriptor(flagFallback,'mhxx-1.4');
  assert.equal(filled[27],1);
  assert.equal(flagFallback[62],0);
  for (const keepOrder of [false,true]) {
    const input=Buffer.alloc(70,0x44);
    input[27]=keepOrder ? 2 : 0;
    // Configure the selected first record and the other record independently.
    const first=keepOrder ? 0 : 35;
    const other=35-first;
    input[first+25]=0; input[first+26]=17;
    input[other+25]=33; input[other+26]=99;
    if (!keepOrder) { input[first+27]=0; input[other+27]=0; }
    const original=Buffer.from(input);
    const expected=keepOrder ? Buffer.from(input) : Buffer.concat([input.subarray(35),input.subarray(0,35)]);
    expected[25]=33;
    const output=prepareMhxxDerivedWorkingDescriptor(input,'mhxx-1.4');
    assert.deepEqual(output,expected);
    assert.deepEqual(input,original);
    assert.equal(output[26],17);
  }
});

test('working descriptor stage requires the exact MHXX profile and bounded input', () => {
  for (const profile of [undefined,null,'mhgu-v262144','mhxx',{}]) {
    assert.throws(()=>prepareMhxxDerivedWorkingDescriptor(Buffer.alloc(70),profile),/profile/);
  }
  for (const bytes of [null,[],Buffer.alloc(69),Buffer.alloc(71)]) {
    assert.throws(()=>prepareMhxxDerivedWorkingDescriptor(bytes,'mhxx-1.4'));
  }
});
