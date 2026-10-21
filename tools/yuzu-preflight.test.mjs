// SPDX-License-Identifier: GPL-3.0-or-later
import test from 'node:test';
import assert from 'node:assert/strict';
import {checkConfig,within,inspectBaseline,decodeQtPath,privateLocationAllowed} from './yuzu-preflight.mjs';

test('only dedicated private subtree is allowed inside workspace',()=>{
  const project='G:/project';
  assert.equal(privateLocationAllowed('G:/project/.private-runtime/run/a',project),true);
  assert.equal(privateLocationAllowed('G:/private/a',project),true);
  for(const root of ['G:/project','G:/project/source/a','G:/project/.private-runtime','G:/project/.private-runtime-other/a','G:/project/.private-runtime/../source/a']) {
    assert.equal(privateLocationAllowed(root,project),false);
  }
});

const safe='[WebService]\nenable_telemetry=false\nenable_telemetry\\default=false\n[Multiplayer]\nip=127.0.0.1\nport=24940\nnickname=synthetic-alpha\n';
const root='G:\\isolated-a\\user';
test('portable defaults and explicit internal data paths are accepted',()=>{
  assert.deepEqual(checkConfig(safe,root),[]);
  assert.deepEqual(checkConfig(safe+'[Data%20Storage]\nnand_directory=G:/isolated-a/user/nand\n',root),[]);
});
test('Qt default flag cannot hide enabled telemetry',()=>{
  assert.ok(checkConfig(safe.replace('enable_telemetry\\default=false','enable_telemetry\\default=true'),root).includes('telemetry_enabled'));
  assert.ok(checkConfig(safe.replace('enable_telemetry=false\n',''),root).includes('telemetry_enabled'));
});
test('shared storage, traversal, prefix collisions and ambiguous forms are rejected',()=>{
  for(const value of ['G:/isolated-a/user2/nand','G:/isolated-a/user/../../shared','C:/shared/nand','../nand','@String(G:/isolated-a/user/nand)','\\\\server\\nand']) {
    assert.ok(checkConfig(safe+'[Data Storage]\nnand_directory='+value+'\n',root).includes('external_or_unsupported_nand_directory'));
  }
  assert.equal(within('g:/ISOLATED-A/user/nand',root),true);
  assert.equal(within('g:/isolated-a/user2',root),false);
  assert.equal(within('f:/isolated-a/user',root),false);
});
test('loopback address and port respect Qt default semantics',()=>{
  for(const text of [safe.replace('127.0.0.1','example.invalid'),safe.replace('24940','24930'),safe+'ip\\default=true\n',safe+'port\\default=true\n']) {
    assert.notEqual(checkConfig(text,root).length,0);
  }
});
test('ambiguous duplicate settings fail without exposing config secrets',()=>{
  const failures=checkConfig(safe+'[WebService]\nyuzu_token=synthetic-secret\nenable_telemetry=true\n',root);
  assert.deepEqual(failures,['duplicate_config_key']);
  assert.equal(JSON.stringify(failures).includes('synthetic-secret'),false);
});
test('missing/shared instances never claim readiness or game success',async()=>{
  const report=await inspectBaseline('G:/nonexistent-crossplay-fixture','G:/nonexistent-crossplay-fixture',{workspace:'G:/project'});
  assert.equal(report.passed,false);
  assert.equal(report.game_verified,false);
  assert.ok(report.checks.some(item=>item.name==='distinct_non_nested_roots'&&!item.passed));
  assert.ok(report.pending.includes('installed_update_v262144'));
});
test('Qt-written Windows and Unicode paths decode before isolation checks',()=>{
  const encoded=String.raw`C:\\Users\\\x9a6c\x5149\x8ff0\\private\\user\\nand`;
  const user=String.raw`C:\Users\马光述\private\user`;
  assert.equal(decodeQtPath(encoded),user+'\\nand');
  assert.deepEqual(checkConfig(safe+'[Data%20Storage]\nnand_directory='+encoded+'\n',user),[]);
  const outside=String.raw`C:\\Users\\\x9a6c\x5149\x8ff0\\private\\user\\..\\shared`;
  assert.ok(checkConfig(safe+'[Data Storage]\nnand_directory='+outside+'\n',user).includes('external_or_unsupported_nand_directory'));
  assert.equal(decodeQtPath('"G:/private/user/a,b"'),'G:/private/user/a,b');
  for(const invalid of [String.raw`G:\\private\\user\\\x0`,String.raw`G:\\private\\user\\\q`, 'G:/private/user/a,b'])assert.throws(()=>decodeQtPath(invalid));
});
