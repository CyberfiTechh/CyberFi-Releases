import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {createRequire} from 'node:module';
import {readFileSync, lstatSync, readdirSync, readlinkSync} from 'node:fs';
import {rename, writeFile, mkdir, copyFile} from 'node:fs/promises';
import {Readable} from 'node:stream';
import {finished} from 'node:stream/promises';
import {dirname,join,resolve,posix} from 'node:path';
import {pathToFileURL} from 'node:url';
import {execFileSync} from 'node:child_process';

const SOURCE='e8c34954ebcbfe093da57fb2048175c4fd6ed6f5';
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const require=createRequire(import.meta.url);
const asar=require(process.env.CYBERFI_ASAR_MODULE);
const extract=(archive,name)=>asar.extractFile(archive,join(...name.split('/')));
const asarPackage=require(join(dirname(process.env.CYBERFI_ASAR_MODULE),'../package.json'));
assert.equal(asarPackage.version,'3.4.1');
const safe=name=>typeof name==='string'&&name.length>0&&!name.includes('\\')&&!name.startsWith('/')&&name.split('/').every(p=>p&&p!=='.'&&p!=='..')&&!/[\x00-\x1f]/u.test(name);
function entries(header,prefix='') {
 const result=[];
 for(const [name,info] of Object.entries(header.files??{})) {
  const path=prefix?prefix+'/'+name:name;assert(safe(path));result.push({path,info});
  if(info.files)result.push(...entries(info,path));
 }
 return result;
}
function rendererFiles(root,prefix='') {
 const found=[];
 for(const name of readdirSync(join(root,prefix))) {
  const key=prefix?prefix+'/'+name:name;assert(safe(key));const stat=lstatSync(join(root,key));assert(!stat.isSymbolicLink());
  if(stat.isDirectory())found.push(...rendererFiles(root,key));else {assert(stat.isFile());found.push(key);}
 }
 return found.sort();
}
function bundleInventory(root,prefix='') {
 const protectedEntries={};
 for(const name of readdirSync(join(root,prefix))){
  const key=prefix?prefix+'/'+name:name;
  if(['Contents/Resources/app.asar','Contents/Info.plist','Contents/MacOS/CyberFi'].includes(key)||key==='Contents/_CodeSignature')continue;
  const stat=lstatSync(join(root,key));
  if(stat.isSymbolicLink())protectedEntries[key]={link:readlinkSync(join(root,key))};
  else if(stat.isDirectory())Object.assign(protectedEntries,bundleInventory(root,key));
  else {assert(stat.isFile());protectedEntries[key]={sha256:sha(readFileSync(join(root,key))),mode:stat.mode&0o777};}
 }
 return protectedEntries;
}

export async function repackArchive(original,target,renderer,manifest) {
 assert.equal(manifest.sourceCommit,SOURCE);assert(manifest.files&&typeof manifest.files==='object'&&!Array.isArray(manifest.files));
 const files=rendererFiles(renderer);assert(files.length>0&&files.length<=10000);assert.deepEqual(files,Object.keys(manifest.files).sort());assert(files.includes('index.html'));
 for(const name of files){assert(/^[a-f0-9]{64}$/u.test(manifest.files[name]));assert.equal(sha(readFileSync(join(renderer,name))),manifest.files[name]);}
 const before=entries(asar.getRawHeader(original).header);
 assert(before.some(e=>e.path==='dist/renderer'&&e.info.files));
 const pkg=JSON.parse(extract(original,'package.json').toString('utf8'));assert.equal(pkg.version,'0.0.139');
 const nextPackage=Buffer.from(JSON.stringify({...pkg,version:'0.0.140'},null,2)+'\n');
 const streams=[];
 for(const {path,info} of before) {
  if(path==='dist/renderer'||path.startsWith('dist/renderer/'))continue;
  if(info.files){streams.push({path,type:'directory',unpacked:info.unpacked});continue;}
  if(info.link){const link=info.link.replaceAll('\\','/');assert(safe(link));streams.push({path,type:'link',symlink:posix.relative(posix.dirname(path),link),unpacked:info.unpacked,stat:{mode:0o120777,size:0}});continue;}
  const bytes=path==='package.json'?()=>nextPackage:()=>extract(original,path);
  streams.push({path,type:'file',unpacked:info.unpacked,stat:{size:path==='package.json'?nextPackage.length:info.size,mode:info.executable?0o100755:0o100644},streamGenerator:()=>Readable.from([bytes()])});
 }
 streams.push({path:'dist/renderer',type:'directory'});
 const dirs=new Set();
 for(const name of files){const parts=name.split('/');for(let i=1;i<parts.length;i++)dirs.add('dist/renderer/'+parts.slice(0,i).join('/'));}
 for(const path of [...dirs].sort())streams.push({path,type:'directory'});
 for(const name of files){const file=join(renderer,name);streams.push({path:'dist/renderer/'+name,type:'file',stat:{size:lstatSync(file).size,mode:0o100644},streamGenerator:()=>Readable.from([readFileSync(file)])});}
 // shortcut: renderer-only release preserves every native and non-renderer byte; rebuild normally if that scope changes.
 const output=await asar.createPackageFromStreams(target,streams);await finished(output);
 const after=entries(asar.getRawHeader(target).header);const oldMap=new Map(before.map(e=>[e.path,e.info]));
 assert.deepEqual(after.filter(e=>!e.path.startsWith('dist/renderer/')).map(e=>e.path).sort(),before.filter(e=>!e.path.startsWith('dist/renderer/')).map(e=>e.path).sort());
 for(const {path,info} of after){
  if(path==='dist/renderer'||path.startsWith('dist/renderer/'))continue;
  const old=oldMap.get(path);assert(old);assert.equal(Boolean(info.unpacked),Boolean(old.unpacked));assert.equal(Boolean(info.executable),Boolean(old.executable));assert.equal(info.link,old.link);
  if(info.files||info.link)continue;
  if(path==='package.json'){const actual=JSON.parse(extract(target,path));assert.deepEqual(actual,{...pkg,version:'0.0.140'});}
  else assert.equal(sha(extract(target,path)),sha(extract(original,path)),'Changed protected entry: '+path);
 }
 for(const name of files)assert.equal(sha(extract(target,'dist/renderer/'+name)),manifest.files[name]);
 return {sourceCommit:SOURCE,asarSha256:sha(readFileSync(target)),asarHeaderSha256:sha(asar.getRawHeader(target).headerString),protectedEntriesPreserved:before.filter(e=>!e.path.startsWith('dist/renderer/')).length,rendererFiles:files.length};
}

if(process.argv[1]&&pathToFileURL(resolve(process.argv[1])).href===import.meta.url){
 assert.equal(process.platform,'darwin');const [app,renderer,manifestPath,arch,output]=process.argv.slice(2);assert(['x64','arm64'].includes(arch));assert.equal(process.arch,arch);
 for(const p of [app,renderer,manifestPath,output])assert(p&&p.startsWith(process.env.RUNNER_TEMP+'/'));
 const run=(file,args,options={})=>execFileSync(file,args,{encoding:'utf8',stdio:['ignore','pipe','pipe'],...options});
 run('/usr/bin/codesign',['--verify','--deep','--strict',app]);run('/usr/bin/lipo',[join(app,'Contents/MacOS/CyberFi'),'-verify_arch',arch]);
 const native=join(app,'Contents/MacOS/CyberFi');const beforeUnsigned=join(process.env.RUNNER_TEMP,'native-before-'+arch);await copyFile(native,beforeUnsigned);
 run('/usr/bin/codesign',['--remove-signature',beforeUnsigned]);const nativeBefore=sha(readFileSync(beforeUnsigned));
 const protectedBundle=bundleInventory(app);
 const entitlementBefore=run('/usr/bin/codesign',['-d','--entitlements',':-',app]);
 const archive=join(app,'Contents/Resources/app.asar');const next=archive+'.next';
 const report=await repackArchive(archive,next,renderer,JSON.parse(readFileSync(manifestPath,'utf8')));
 await rename(archive,archive+'.baseline');await rename(next,archive);
 // Keep existing .unpacked files and signatures; the new archive retains their exact unpack flags and bytes.
 const plist=join(app,'Contents/Info.plist');
 const plistResult=JSON.parse(run('python3',['-c',`import json,plistlib,sys
p=sys.argv[1]
with open(p,'rb') as f:v=plistlib.load(f)
assert v['CFBundleIdentifier']=='tr.pdrkocum.agent'
assert v['CFBundleShortVersionString']=='0.0.139'
v['CFBundleShortVersionString']='0.0.140';v['CFBundleVersion']='0.0.140'
assert v['ElectronAsarIntegrity']['Resources/app.asar']['algorithm']=='SHA256'
v['ElectronAsarIntegrity']['Resources/app.asar']['hash']=sys.argv[2]
with open(p,'wb') as f:plistlib.dump(v,f)
print(json.dumps({'bundleId':v['CFBundleIdentifier'],'version':v['CFBundleShortVersionString'],'asarIntegrity':v['ElectronAsarIntegrity']}))`,plist,report.asarHeaderSha256]));
 // Baseline and generated unpack copies are outside the shipping bundle before sealing.
 await rename(archive+'.baseline',join(process.env.RUNNER_TEMP,'baseline-app-'+arch+'.asar'));
 await rename(archive+'.next.unpacked',join(process.env.RUNNER_TEMP,'repacked-unpacked-verification-'+arch)).catch(e=>{if(e.code!=='ENOENT')throw e;});
 run('/usr/bin/codesign',['--force','--sign','-','--preserve-metadata=identifier,entitlements,requirements,flags',app]);
 run('/usr/bin/codesign',['--verify','--deep','--strict',app]);assert.equal(run('/usr/bin/codesign',['-d','--entitlements',':-',app]),entitlementBefore);
 const afterUnsigned=join(process.env.RUNNER_TEMP,'native-after-'+arch);await copyFile(native,afterUnsigned);run('/usr/bin/codesign',['--remove-signature',afterUnsigned]);assert.equal(sha(readFileSync(afterUnsigned)),nativeBefore);
 assert.deepEqual(bundleInventory(app),protectedBundle);
 run('/usr/bin/lipo',[join(app,'Contents/MacOS/CyberFi'),'-verify_arch',arch]);
 assert.equal(plistResult.asarIntegrity['Resources/app.asar'].hash,sha(asar.getRawHeader(archive).headerString));
 assert.deepEqual(readdirSync(dirname(app)),['CyberFi.app']);
 await mkdir(dirname(output),{recursive:true});run('/usr/bin/hdiutil',['create','-fs','HFS+','-format','UDZO','-volname','CyberFi 0.0.140','-srcfolder',dirname(app),output]);run('/usr/bin/hdiutil',['verify',output]);
 await writeFile(output+'.report.json',JSON.stringify({...report,...plistResult,arch,codesignStrictVerified:true,entitlementsPreserved:true,nativeUnsignedPayloadPreserved:true,protectedBundleEntries:Object.keys(protectedBundle).length,protectedBundleSha256:sha(JSON.stringify(protectedBundle)),adhocSigned:true,osTrustCertified:false,dmgSha256:sha(readFileSync(output)),dmgBytes:lstatSync(output).size},null,2)+'\n');
 console.log(JSON.stringify({output,arch,...report}));
}
