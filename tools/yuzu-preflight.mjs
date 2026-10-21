// SPDX-License-Identifier: GPL-3.0-or-later
// Read-only checks. Never prints config values, credentials, saves or key data.
import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { pathToFileURL, fileURLToPath } from 'node:url';

const mainHash = '60ba9d59347e9bab68fd670ecd990c3b03b5bd14e221cf38cb28a802a8b7679a';
const wp = path.win32;
export function within(child, parent) {
  const relative = wp.relative(wp.resolve(parent), wp.resolve(child));
  return relative === '' || (!wp.isAbsolute(relative) && relative !== '..' && !relative.startsWith('..\\'));
}
function ini(text) {
  const entries = new Map();
  let section = '';
  for (const line of text.replace(/^\uFEFF/, '').split(/\r?\n/)) {
    const value = line.trim();
    if (!value || /^[;#]/.test(value)) continue;
    if (value.startsWith('[') && value.endsWith(']')) { section = value.slice(1,-1).replaceAll('%20',' '); continue; }
    const equal = value.indexOf('=');
    if (equal < 1) continue;
    const key = `${section}/${value.slice(0,equal).trim()}`;
    if (entries.has(key)) throw new Error('duplicate_config_key');
    let field = value.slice(equal+1).trim();
    if (!key.startsWith('Data Storage/') && field.startsWith('"') && field.endsWith('"')) field = field.slice(1,-1);
    entries.set(key, field);
  }
  return entries;
}
// QSettings 5.15 iniUnescapedStringList: escaped backslashes, UTF-16 hex
// and octal units. Hex/octal runs consume all digits and wrap to char16_t.
// Primary reference: https://github.com/qt/qtbase/blob/5.15/src/corelib/io/qsettings.cpp
export function decodeQtPath(raw) {
  let value=raw, quoted=false;
  if(value.startsWith('"') && value.endsWith('"')) {value=value.slice(1,-1);quoted=true;}
  if(value.includes('"') || (!quoted&&value.includes(',')) || value.startsWith('@')) throw new Error('unsupported_path_variant');
  const escapes={a:'\x07',b:'\b',f:'\f',n:'\n',r:'\r',t:'\t',v:'\v','"':'"',"'":"'",'?':'?','\\':'\\'};
  let result='';
  for(let i=0;i<value.length;i++) {
    if(value[i]!=='\\'){result+=value[i];continue;}
    const next=value[++i];
    if(Object.hasOwn(escapes,next)){result+=escapes[next];continue;}
    let radix=0, digits='';
    if(next==='x') {radix=16;while(i+1<value.length && /[0-9a-f]/i.test(value[i+1]))digits+=value[++i];}
    else if(/[0-7]/.test(next??'')) {radix=8;digits=next;while(i+1<value.length && /[0-7]/.test(value[i+1]))digits+=value[++i];}
    if(!radix || !digits)throw new Error('unsupported_path_escape');
    let unit=0;for(const digit of digits)unit=(unit*radix+parseInt(digit,radix))&65535;
    result+=String.fromCharCode(unit);
  }
  if(!/^[A-Za-z]:[\\/][^<>:"|?*\x00-\x1f\x7f]*$/.test(result))throw new Error('invalid_absolute_path');
  return result;
}
export function checkConfig(text, userRoot, port = 24940) {
  const failures = [];
  let values;
  try { values = ini(text); } catch { return ['duplicate_config_key']; }
  const effective = (key, fallback) => /^(true|1)$/i.test(values.get(key+'\\default') ?? 'false') ? fallback : (values.get(key) ?? fallback);
  // enable_telemetry defaults true in the pinned 2022 source. A false value
  // with /default=true still enables it, so checking the visible value is wrong.
  if (!/^(false|0)$/i.test(effective('WebService/enable_telemetry','true'))) failures.push('telemetry_enabled');
  if (effective('Multiplayer/ip','') !== '127.0.0.1') failures.push('multiplayer_not_loopback');
  if (effective('Multiplayer/port','24872') !== String(port)) failures.push('multiplayer_port_mismatch');
  const nickname = effective('Multiplayer/nickname','');
  if (!/^[ a-zA-Z0-9._-]{4,20}$/.test(nickname)) failures.push('invalid_nickname');
  for (const key of ['nand_directory','sdmc_directory','load_directory','dump_directory','tas_directory']) {
    const configured = values.get('Data Storage/'+key);
    if (configured === undefined) continue; // Source uses the portable user default.
    try {if(!within(decodeQtPath(configured),userRoot))throw new Error('external_path');}
    catch {failures.push('external_or_unsupported_'+key);}
  }
  // Never return the whole INI or a nickname: it may contain tokens and paths.
  return failures;
}

async function noLinks(target) {
  let current = path.resolve(target);
  while (true) {
    const stat = await fs.lstat(current);
    if (stat.isSymbolicLink()) throw new Error('reparse_or_symlink');
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
}
export function privateLocationAllowed(root, workspace) {
  if (!workspace) return false;
  const privateRoot=path.resolve(workspace,'.private-runtime');
  return !within(root,workspace) || (within(root,privateRoot) && path.resolve(root)!==privateRoot);
}
export async function inspectBaseline(a, b, { workspace, port = 24940 } = {}) {
  const result = { schema:'crossplay.yuzu-preflight/1', checked_utc:new Date().toISOString(),
    passed:false, checks:[], game_verified:false,
    pending:['installed_update_v262144','save_load','distinct_player_identity','same_platform_hunt_and_result'] };
  const check = (slot, name, passed) => result.checks.push({slot,name,passed});
  const roots = [path.resolve(a),path.resolve(b)];
  const separate = !within(roots[0],roots[1]) && !within(roots[1],roots[0]);
  check('pair','distinct_non_nested_roots',separate);
  const nicknames = [];
  for (let i=0;i<roots.length;i++) {
    const slot = i===0?'A':'B', root = roots[i], user = path.join(root,'user');
    check(slot,'private_location_allowed',privateLocationAllowed(root,workspace));
    try {
      await noLinks(root); await noLinks(user);
      check(slot,'portable_user_no_links',(await fs.stat(user)).isDirectory());
      const exe = path.join(root,'yuzu.exe'); await noLinks(exe);
      if ((await fs.stat(exe)).size!==25105408) throw new Error('unexpected_exe_size');
      const digest = crypto.createHash('sha256').update(await fs.readFile(exe)).digest('hex');
      check(slot,'pinned_main_exe',digest===mainHash);
      const config = path.join(user,'config','qt-config.ini'); await noLinks(config);
      if ((await fs.stat(config)).size>2097152) throw new Error('config_too_large');
      const text = await fs.readFile(config,'utf8');
      const failures = checkConfig(text,user,port);
      check(slot,'config_isolation_and_loopback',failures.length===0);
      for (const failure of failures) check(slot,failure,false);
      const values = ini(text);
      nicknames.push(values.get('Multiplayer/nickname'));
      let visited=0;
      for (const folder of ['nand','sdmc','load','dump','tas']) {
        const configured = values.get('Data Storage/'+folder+'_directory');
        const unsupported=failures.includes('external_or_unsupported_'+folder+'_directory');
        if(unsupported)continue;
        const storage = configured===undefined?path.join(user,folder):decodeQtPath(configured);
        // Existing storage trees may contain links below the root too. Do not
        // follow them; an inaccessible tree is an unsuccessful check.
        const walk = async (directory, depth=0) => {
          if (++visited>50000 || depth>64) throw new Error('storage_scan_limit');
          await noLinks(directory);
          for (const entry of await fs.readdir(directory,{withFileTypes:true})) {
            if (entry.isSymbolicLink()) throw new Error('storage_link');
            if (entry.isDirectory()) await walk(path.join(directory,entry.name),depth+1);
          }
        };
        try { await walk(storage); check(slot,folder+'_tree_no_links',true); }
        catch (error) { if (error.code==='ENOENT') check(slot,folder+'_tree_no_links',true); else throw error; }
      }
      // Presence only; never read, hash or print key material.
      const keyPath=path.join(user,'keys','prod.keys');
      try {
        await noLinks(keyPath);
        check(slot,'private_prod_keys_present',(await fs.stat(keyPath)).isFile());
      } catch(error) {
        if(error.code==='ENOENT') check(slot,'private_prod_keys_present',false);
        else throw error;
      }
    } catch (error) { check(slot, ['EACCES','EPERM'].includes(error.code)?'access_denied':'missing_or_unsafe_instance',false); }
  }
  check('pair','distinct_nicknames',nicknames.length===2 && !!nicknames[0] && nicknames[0]!==nicknames[1]);
  result.passed = result.checks.every(item=>item.passed);
  return result;
}

if (process.argv[1] && import.meta.url===pathToFileURL(process.argv[1]).href) {
  const args=process.argv.slice(2);
  if (args.length!==2) { console.error('Usage: node yuzu-preflight.mjs <isolated-dir-A> <isolated-dir-B>');process.exitCode=2; }
  else {
    const actualWorkspace=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
    const report=await inspectBaseline(args[0],args[1],{workspace:actualWorkspace});
    console.log(JSON.stringify(report,null,2));process.exitCode=report.passed?0:1;
  }
}
