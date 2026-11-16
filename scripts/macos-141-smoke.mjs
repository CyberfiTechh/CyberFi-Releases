import assert from 'node:assert/strict';
import {mkdir,writeFile} from 'node:fs/promises';
import {join,dirname,resolve} from 'node:path';
import {readFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
import {createRequire} from 'node:module';
import {createServer} from 'node:net';
import {setTimeout as delay} from 'node:timers/promises';
const tools=process.argv[2];assert(tools?.startsWith(process.env.RUNNER_TEMP+'/'));const arch=process.env.CYBERFI_TARGET_ARCH;
assert.equal(process.platform,'darwin');assert.equal(process.arch,arch);
const {gymElectronProcessRun,gymElectronVideoRecord}=await import(pathToFileURL(join(tools,'gym-launch.ts')).href);
const {chromium}=createRequire(join(tools,'package.json'))('playwright');
const asar=createRequire(join(tools,'package.json'))('@electron/asar');
const bundle=resolve(dirname(process.env.CYBERFI_TEST_APP),'../..');
const nativeVersion=execFileSync('/usr/libexec/PlistBuddy',['-c','Print CFBundleShortVersionString',join(bundle,'Contents/Info.plist')],{encoding:'utf8'}).trim();assert.equal(nativeVersion,'0.0.141');
const manifest=JSON.parse(readFileSync(join(process.env.RUNNER_TEMP,'renderer-manifest.json'),'utf8'));assert.equal(manifest.releaseVersion,'0.0.141');
const preloadSha256=createHash('sha256').update(asar.extractFile(join(bundle,'Contents/Resources/app.asar'),'dist/preload.cjs')).digest('hex');assert.equal(preloadSha256,manifest.files['preload.cjs']);
const desktopVersions=Object.keys(manifest.files).filter(name=>name.endsWith('.js')).flatMap(name=>[...asar.extractFile(join(bundle,'Contents/Resources/app.asar'),'dist/renderer/'+name).toString('utf8').matchAll(/\bdesktopVersion\s*:\s*([`"'])(0\.0\.\d+)\1/gu)].map(match=>match[2]));
assert(desktopVersions.length>0);assert(desktopVersions.every(version=>version===nativeVersion));
const studioManifest=JSON.parse(readFileSync(join(process.env.RUNNER_TEMP,'studio-overlay-manifest.json'),'utf8'));assert.equal(studioManifest.sourceCommit,'12d61923a45ac80fc0defd8d26b51fbccf64f575');
execFileSync(process.execPath,['--check',join(bundle,'Contents/Resources/cyberfi-studio/server.mjs')],{stdio:'pipe'});
const root=join(process.env.RUNNER_TEMP,'cyberfi-smoke-'+arch);await mkdir(root,{mode:0o700});
for(const n of ['profile','home','tmp'])await mkdir(join(root,n));
const server=createServer();await new Promise(ok=>server.listen(0,'127.0.0.1',ok));const port=server.address().port;await new Promise(ok=>server.close(ok));
const report={success:false,sourceCommit:'12d61923a45ac80fc0defd8d26b51fbccf64f575',version:nativeVersion,rendererDesktopVersion:'0.0.141',nativeRendererVersionMatched:true,preloadSha256,preloadHashVerified:true,studioServerSyntaxVerified:true,studioImageEditUiCovered:false,platform:process.platform,arch:process.arch,realAccountLoginCovered:false,automaticUpdateCovered:false,rendererErrors:[]};
const env={PATH:process.env.PATH,HOME:join(root,'home'),USERPROFILE:join(root,'home'),TMPDIR:join(root,'tmp'),HAPPY_HOME_DIR:join(root,'home/.happy'),HAPPY_DESKTOP_DEBUG:'1',HAPPY_DEBUG_RENDERER_PORT:String(port)};
let outcome,failure,browser,video;
const run=gymElectronProcessRun({executablePath:process.env.CYBERFI_TEST_APP,args:['--user-data-dir='+join(root,'profile'),'--debug'],env,timeout:150000}).then(x=>outcome=x,e=>failure=e);
try{
 for(let i=0;i<100;i++){if(outcome||failure)throw failure??Error('App exited before readiness');try{browser=await chromium.connectOverCDP('http://127.0.0.1:'+port,{timeout:500});break;}catch{await delay(500);}}
 assert(browser,'Native renderer unavailable');let p;
 for(let i=0;i<60&&!p;i++){p=browser.contexts().flatMap(c=>c.pages()).find(p=>!p.url().startsWith('devtools:'));if(!p)await delay(250);}
 assert(p);p.on('pageerror',e=>report.rendererErrors.push(e.message));
 video=await gymElectronVideoRecord(p,{path:join(root,'login.webm'),fps:3});
 await p.locator('[data-happy-desktop-ui="cyberfi-account-login"]').waitFor({timeout:45000});
 assert.equal((await p.evaluate(()=>window.happyDesktop.cyberFiAccountGet())).status,'signedOut');
 await assert.rejects(p.evaluate(()=>window.happyDesktop.runtimeGet()));report.protectedIpcDenied=true;
 assert.equal(await p.locator('input[name=username]').inputValue(),'');assert.equal(await p.locator('input[name=password]').inputValue(),'');
 assert.equal(await p.title(),'CyberFi');await p.screenshot({path:join(root,'login.png')});await delay(2500);
 report.video=await video.stop();video=undefined;assert(report.video.framesWritten>0);assert.equal(report.rendererErrors.length,0);
 const session=await browser.newBrowserCDPSession();await Promise.race([session.send('Browser.close').catch(()=>undefined),delay(3000)]);
 await run;assert.equal(outcome?.exitCode,0);report.nativeExitCode=outcome.exitCode;report.success=true;
}catch(e){report.failure=e.message;process.exitCode=1;}
finally{
 await writeFile(join(root,'checkpoint.json'),JSON.stringify(report,null,2));
 if(video)await Promise.race([video.stop().catch(()=>undefined),delay(5000)]);
 if(browser){const s=await browser.newBrowserCDPSession().catch(()=>undefined);await Promise.race([s?.send('Browser.close').catch(()=>undefined),delay(3000)]);await Promise.race([browser.close().catch(()=>undefined),delay(3000)]);}
 await run;await writeFile(join(root,'report.json'),JSON.stringify(report,null,2));
}
console.log(JSON.stringify({success:report.success,failure:report.failure,arch:report.arch}));process.exit(report.success?0:1);
