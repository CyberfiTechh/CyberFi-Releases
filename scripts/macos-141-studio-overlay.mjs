import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {lstat,readFile,readdir,realpath,rm,mkdir,copyFile,writeFile} from 'node:fs/promises';
import {join,dirname,basename,resolve,sep} from 'node:path';
const SOURCE='12d61923a45ac80fc0defd8d26b51fbccf64f575';
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const allowed=path=>path==='server.mjs';
const safe=path=>typeof path==='string'&&path.length>0&&!path.includes('\\')&&!path.startsWith('/')&&!/[\x00-\x1f:]/u.test(path)&&path.split('/').every(part=>part&&part!=='.'&&part!=='..');
async function files(root,prefix='') {
 const found=[];
 for(const name of await readdir(join(root,prefix))){
  const key=prefix?prefix+'/'+name:name;assert(safe(key));const stat=await lstat(join(root,key));assert(!stat.isSymbolicLink());
  if(stat.isDirectory())found.push(...await files(root,key));else{assert(stat.isFile());found.push(key);}
 }
 return found.sort();
}
export async function studioOverlay(target,payload,manifest,arch) {
 assert.equal(manifest.sourceCommit,SOURCE);assert(['x64','arm64'].includes(arch));assert(manifest.files&&typeof manifest.files==='object'&&!Array.isArray(manifest.files));
 assert.equal(basename(target),'cyberfi-studio');const root=await realpath(target);assert.equal(root,resolve(target));assert(!(await lstat(target)).isSymbolicLink());
 const incoming=await files(payload);assert.deepEqual(incoming,Object.keys(manifest.files).sort());assert.deepEqual(incoming,['server.mjs']);
 for(const name of incoming){assert(safe(name)&&allowed(name));assert(/^[a-f0-9]{64}$/u.test(manifest.files[name]));assert.equal(sha(await readFile(join(payload,name))),manifest.files[name]);assert(!/\.(?:exe|dll|dylib|node|so)$/iu.test(name));}
 const file=join(root,'manifest.json');const before=JSON.parse(await readFile(file,'utf8'));
 assert.equal(before.name,'CyberFi Studio');assert.equal(before.platform,'darwin');assert.equal(before.arch,arch);assert.equal(before.nodeMajor,24);assert.equal(before.codex,false);assert.equal(before.commit,'d9d5c1fce3480a6c1750b408ec08e6ec8cf01575');assert(Array.isArray(before.files));
 const seen=new Set();
 for(const entry of before.files){assert(safe(entry.path)&&/^[a-f0-9]{64}$/u.test(entry.sha256)&&!seen.has(entry.path));seen.add(entry.path);assert.equal(sha(await readFile(join(root,entry.path))),entry.sha256,'Baseline Studio file mismatch: '+entry.path);}
 const protectedEntries=before.files.filter(entry=>!allowed(entry.path));
 for(const name of incoming){const destination=join(root,name);assert(destination.startsWith(root+sep));await mkdir(dirname(destination),{recursive:true});await copyFile(join(payload,name),destination);}
 assert(seen.has('server.mjs'));const after={...before,files:before.files.map(entry=>entry.path==='server.mjs'?{...entry,sha256:manifest.files[entry.path]}:entry)};
 assert.deepEqual({...after,files:before.files},before);await writeFile(file,JSON.stringify(after,null,2)+'\n');
 const actual=await files(root);assert.deepEqual(actual.filter(name=>name!=='manifest.json').sort(),after.files.map(entry=>entry.path).sort());
 for(const entry of after.files)assert.equal(sha(await readFile(join(root,entry.path))),entry.sha256,'Patched Studio file mismatch: '+entry.path);
 return {sourceCommit:SOURCE,studioOverlayFiles:incoming.length,studioManifestSha256:sha(await readFile(file)),studioNativeEntriesPreserved:protectedEntries.length,studioOverlayScope:['server.mjs']};
}
