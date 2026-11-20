import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import {createReadStream} from 'node:fs';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {createRequire} from 'node:module';
import path from 'node:path';
import {createServer} from 'node:net';
import {setTimeout as delay} from 'node:timers/promises';
import updater from './updater.cjs';

// This entry point refuses cross-architecture emulation before reading/launching an app.
assert.equal(process.platform,'darwin','Requires actual macOS ARM runner');
assert.equal(process.arch,'arm64','Requires native ARM Node, not Intel/Rosetta');
const [dmg,sidecar,manifestFile,tools]=process.argv.slice(2);
assert(dmg&&sidecar&&manifestFile&&tools,'dmg sidecar trusted-manifest tools required');
const root=await fs.realpath(process.env.RUNNER_TEMP);
for(const file of [dmg,sidecar,manifestFile,tools])assert((await fs.realpath(file)).startsWith(root+path.sep));
const sha=async file=>{const h=createHash('sha256');for await(const c of createReadStream(file))h.update(c);return h.digest('hex');};
const manifest=JSON.parse(await fs.readFile(manifestFile,'utf8'));
assert.equal(manifest.version,'0.0.142');assert.equal(manifest.arch,'arm64');
assert.equal(manifest.sourceCommit,'766d7bfce90cd40f24b131ee31fa2efcac41011c');
assert.equal(manifest.sourceManifestSha256,'010eb7a5b21a13ff516549de3055e518b993625d6553dfb67cce06904eb3ce67');
assert.equal(Object.keys(manifest.dist).length,556,'Must attest all fresh dist files');
assert(Object.keys(manifest.resources).some(n=>n.endsWith('sources.zip')));
for(const suffix of ['sources.zip','pdr-egitim/SKILL.md','pdr-hukuk-arsivi/SKILL.md'])assert.equal(Object.keys(manifest.resources).filter(n=>n.endsWith(suffix)).length,1);
assert.equal(Object.entries(manifest.resources).find(([n])=>n.endsWith('sources.zip'))[1],'c7a5d47332cff50167a2a4e0aeeca0d12408beb4b812fb48a37504becc2c024a');
const signature=updater.cyberFiUpdateManifestVerify(JSON.parse(await fs.readFile(sidecar,'utf8')),'0.0.142','CyberFi-0.0.142-arm64.dmg');
assert.equal((await fs.stat(dmg)).size,signature.size);assert.equal(await sha(dmg),signature.sha256);
const require=createRequire(path.join(tools,'package.json'));
const asar=require('@electron/asar');process.env.NATIVE_PLAYWRIGHT_ENTRY=require.resolve('playwright');
const {chromium}=require('playwright');const {default:gym}=await import('./gym.cjs');
const runroot=await fs.mkdtemp(path.join(root,'cyberfi-arm142-'));const mount=path.join(runroot,'mount');
await fs.mkdir(mount);let mounted=false,browser,video,outcome,failure,run;
const report={success:false,version:'0.0.142',arch:process.arch,platform:process.platform,sourceCommit:manifest.sourceCommit,packageSha256:signature.sha256,packageSignatureVerified:true,realAccountLoginCovered:false,automaticUpdateCovered:false,developerIdNotarizationClaimed:false,nativeBindingsLoaded:false};
const command=(exe,args)=>execFileSync(exe,args,{encoding:'utf8',timeout:60000,stdio:['ignore','pipe','pipe']}).trim();
function nodeInspectorUrl(entries,port){
 assert(Array.isArray(entries));
 const nodes=entries.filter(item=>item.type==='node');assert.equal(nodes.length,1,'Ambiguous/non-Node inspector');
 const url=new URL(nodes[0].webSocketDebuggerUrl);
 assert(url.protocol==='ws:'&&url.hostname==='127.0.0.1'&&Number(url.port)===port&&!url.username&&!url.password,'Inspector must use the owned loopback port');
 return url.toString();
}
async function inspect(url,expression){
 assert(url.startsWith('ws://127.0.0.1:'));const socket=new WebSocket(url);
 return await new Promise((resolve,reject)=>{const timer=setTimeout(()=>{socket.close();reject(Error('Bounded main inspection timeout'));},15000);
 socket.onopen=()=>socket.send(JSON.stringify({id:1,method:'Runtime.evaluate',params:{expression,awaitPromise:true,returnByValue:true}}));
 socket.onerror=()=>{clearTimeout(timer);reject(Error('Main inspector unavailable'));};
 socket.onmessage=event=>{const value=JSON.parse(event.data);if(value.id!==1)return;clearTimeout(timer);socket.close();if(value.error||value.result.exceptionDetails)reject(Error('Native binding import failed'));else resolve(value.result.result.value);};});
}
try{
 command('/usr/bin/hdiutil',['verify',dmg]);command('/usr/bin/hdiutil',['attach','-readonly','-nobrowse','-mountpoint',mount,dmg]);mounted=true;
 const app=path.join(runroot,'CyberFi.app');command('/usr/bin/ditto',[path.join(mount,'CyberFi.app'),app]);
 command('/usr/bin/hdiutil',['detach',mount]);mounted=false;
 const resources=path.join(app,'Contents/Resources'),executable=path.join(app,'Contents/MacOS/CyberFi');
 assert.equal(command('/usr/libexec/PlistBuddy',['-c','Print :CFBundleShortVersionString',path.join(app,'Contents/Info.plist')]),'0.0.142');
 command('/usr/bin/codesign',['--verify','--deep','--strict',app]);command('/usr/bin/lipo',[executable,'-verify_arch','arm64']);
 const archive=path.join(resources,'app.asar');assert.equal(JSON.parse(asar.extractFile(archive,'package.json')).version,'0.0.142');
 for(const [name,digest]of Object.entries(manifest.dist)){assert(name.startsWith('dist/')&&!name.includes('..'));assert.equal(createHash('sha256').update(asar.extractFile(archive,name)).digest('hex'),digest,name);}
 const versions=Object.keys(manifest.dist).filter(n=>n.startsWith('dist/renderer/')&&n.endsWith('.js')).flatMap(n=>[...asar.extractFile(archive,n).toString('utf8').matchAll(/\bdesktopVersion\s*:\s*([`"'])(0\.0\.\d+)\1/gu)].map(m=>m[2]));
 assert(versions.length>0&&versions.every(v=>v==='0.0.142'));report.rendererVersionVerified=true;
 for(const [name,digest]of Object.entries(manifest.resources)){assert(!path.isAbsolute(name)&&!name.split('/').includes('..'));assert.equal(await sha(path.join(resources,name)),digest,name);}
 report.distFilesVerified=Object.keys(manifest.dist).length;report.resourcesVerified=Object.keys(manifest.resources);
 const binaries=['node_modules/@koromix/koffi-darwin-arm64/darwin_arm64/koffi.node','node_modules/usb/prebuilds/darwin-x64+arm64/node.napi.node'];
 for(const name of binaries)command('/usr/bin/lipo',[path.join(resources,'app.asar.unpacked',name),'-verify_arch','arm64']);
 for(const name of ['profile','home','tmp'])await fs.mkdir(path.join(runroot,name));
 const reserve=createServer();await new Promise(ok=>reserve.listen(0,'127.0.0.1',ok));const port=reserve.address().port;await new Promise(ok=>reserve.close(ok));
 // Explicit allowlist: the app never inherits the job's GitHub token.
 const env={PATH:process.env.PATH,HOME:path.join(runroot,'home'),TMPDIR:path.join(runroot,'tmp'),HAPPY_HOME_DIR:path.join(runroot,'home/.happy'),HAPPY_DESKTOP_WINDOWS_HIDDEN:'1',HAPPY_DESKTOP_DEBUG:'1',HAPPY_DEBUG_RENDERER_PORT:String(port)};
 run=gym.gymElectronProcessRun({executablePath:executable,args:['--user-data-dir='+path.join(runroot,'profile'),'--debug'],env,timeout:150000}).then(v=>outcome=v,e=>failure=e);
 for(let i=0;i<100;i++){if(outcome||failure)throw Error('App exited before readiness');try{browser=await chromium.connectOverCDP('http://127.0.0.1:'+port,{timeout:500});break;}catch{await delay(500);}}
 assert(browser,'ARM renderer unavailable');
 const pids=command('/usr/sbin/lsof',['-nP',`-iTCP:${port}`,'-sTCP:LISTEN','-t']).split(/\s+/u);
 assert.equal(pids.length,1,'Ambiguous renderer port owner');const ownedPid=pids[0];
 const ownedCommand=command('/bin/ps',['-p',ownedPid,'-o','command=']);assert(ownedCommand.includes(executable)&&ownedCommand.includes('--user-data-dir='+path.join(runroot,'profile')),'Unexpected debug listener');
 let page;for(let i=0;i<60&&!page;i++){page=browser.contexts().flatMap(c=>c.pages()).find(p=>!p.url().startsWith('devtools:'));if(!page)await delay(250);}assert(page);
 const errors=[];page.on('pageerror',()=>errors.push('renderer error'));
 video=await gym.gymElectronVideoRecord(page,{path:path.join(runroot,'login.webm'),fps:3});
 await page.locator('[data-happy-desktop-ui="cyberfi-account-login"]').waitFor({timeout:45000});
 assert.equal((await page.evaluate(()=>window.happyDesktop.cyberFiAccountGet())).status,'signedOut');
 await assert.rejects(page.evaluate(()=>window.happyDesktop.runtimeGet()));report.protectedIpcDenied=true;
 assert.equal(await page.locator('input[name=username]').inputValue(),'');assert.equal(await page.locator('input[name=password]').inputValue(),'');
 // debugGet IPC is account-gated. Read only the already opted-in --debug listener owned by this exact process.
 const listeners=command('/usr/sbin/lsof',['-nP','-a','-p',ownedPid,'-iTCP','-sTCP:LISTEN','-Fn']);let mainUrl;
 for(const line of listeners.split('\n')){
  const match=/^n127\.0\.0\.1:(\d+)$/u.exec(line);if(!match||Number(match[1])===port)continue;
  try{const entries=await(await fetch(`http://127.0.0.1:${match[1]}/json/list`,{signal:AbortSignal.timeout(1000)})).json();mainUrl=nodeInspectorUrl(entries,Number(match[1]));if(mainUrl)break;}catch{}
 }
 assert(mainUrl,'Owned Node inspector unavailable');
 const expression=`(()=>{const req=process.getBuiltinModule('module').createRequire(process.resourcesPath+'/app.asar/package.json');const {app,BrowserWindow}=req('electron');const koffi=req('koffi');const usb=req('usb');if(!koffi||!usb)throw Error('Missing native exports');return {version:app.getVersion(),arch:process.arch,pid:process.pid,execPath:process.execPath,userData:app.getPath('userData'),hidden:process.env.HAPPY_DESKTOP_WINDOWS_HIDDEN==='1',windowsHidden:BrowserWindow.getAllWindows().every(w=>!w.isVisible()&&!w.isFocused()),nativeImports:['koffi','usb']};})()`;
 const native=await inspect(mainUrl,expression);assert.equal(String(native.pid),ownedPid);assert.equal(native.execPath,executable);assert.equal(native.version,'0.0.142');assert.equal(native.arch,'arm64');assert.equal(native.userData,path.join(runroot,'profile'));assert(native.hidden&&native.windowsHidden);report.native=native;report.nativeBindingsLoaded=true;report.mainInspectorOwned=true;
 await page.screenshot({path:path.join(runroot,'login.png')});await delay(2000);report.video=await video.stop();video=undefined;assert(report.video.framesWritten>0);assert.equal(errors.length,0);
 const s=await browser.newBrowserCDPSession();await Promise.race([s.send('Browser.close').catch(()=>undefined),delay(3000)]);await run;assert.equal(outcome.exitCode,0);report.success=true;
}catch(error){report.failure=error.message;process.exitCode=1;}
finally{
 if(video)await video.stop().catch(()=>undefined);
 if(browser){const s=await browser.newBrowserCDPSession().catch(()=>undefined);await Promise.race([s?.send('Browser.close').catch(()=>undefined),delay(3000)]);await browser.close().catch(()=>undefined);}
 if(mounted)command('/usr/bin/hdiutil',['detach',mount]);
 if(run)await run;
 await fs.writeFile(path.join(runroot,'report.json'),JSON.stringify(report,null,2)+'\n');
}
console.log(JSON.stringify({success:report.success,report:path.join(runroot,'report.json'),failure:report.failure}));
