import assert from "node:assert/strict";
import { createReadStream, createWriteStream } from "node:fs";
import { mkdir, readFile, writeFile, realpath, lstat } from "node:fs/promises";
import { join, dirname, sep, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { setTimeout as delay } from "node:timers/promises";
import { pipeline } from "node:stream/promises";
import { Readable, Transform } from "node:stream";
import { reviewedEngineCarrier, privateAclDiagnostic, ownedQaAclHomes, sanitizedEnvironment, environmentValue, hashFile, allowedRedirect } from "./verify-cyberai-windows-update-135.mjs";
import { pinnedEngineMetadata } from "./native-fixture-hooks-135.mjs";

const exec = promisify(execFile);
const EXPECTED_SOURCE = "8d15d870213ac0ab8f891b2130c748fd27e42044";
const REPO = "CyberfiTechh/CyberFi-Releases";
const binarySha = "9c2e5bd78969ca8b112ce426880dd98bde51eecf041acc2dd61524db7937a5d3";
const quote = value => "'" + value.replaceAll("'", "''") + "'";
function redactStderr(stderr, ownPaths, token = "") {
    assert(Buffer.byteLength(stderr) <= 65536, "Bounded stderr required");
    let safe = stderr.replace(/(-EncodedCommand\s+)[A-Za-z0-9+/=]+/giu, "$1<ENCODED_INITIALIZER>");
    for (const path of [...ownPaths].sort((a, b) => b.length - a.length)) safe = safe.split(path).join("<OWNED_PATH>");
    if (token) safe = safe.split(token).join("<OWNED_SERVER_TOKEN>");
    safe = safe.replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/giu, "Bearer <REDACTED>");
    return safe;
}
function stderrFacts(text) {
    return { ...privateAclDiagnostic(text), operations: [...new Set([...text.matchAll(/Exception calling ["']([A-Za-z]{3,35})["']/gu)].map(m => m[1]))],
        qualifiedErrors: [...new Set([...text.matchAll(/FullyQualifiedErrorId\s*:\s*([A-Za-z0-9_.,]+)/gu)].map(m => m[1]))] };
}
const aclScript = (paths, sid, root) => String.raw`$ErrorActionPreference='Stop'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent();$sid=$identity.User
$principal=[Security.Principal.WindowsPrincipal]::new($identity)
$groups=& (Join-Path $env:SystemRoot 'System32\whoami.exe') /groups /fo csv /nh
$medium=($LASTEXITCODE -eq 0 -and ($groups -join '\n') -match 'S-1-16-8192')
if($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or -not $medium -or $sid.Value -cne ${quote(sid)}){throw 'Expected exact medium nonadmin SID'}
$ownedRoot=${quote(root)}
function Owned([string]$path){$t=Get-Item -LiteralPath $path -Force
 if(-not $t.PSIsContainer -or ($t.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or -not $t.FullName.StartsWith($ownedRoot+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'ACL probe escaped owned root'}
 if($t.GetAccessControl().GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $sid.Value){throw 'ACL probe is not owned by exact synthetic SID'};return $t}
function Rights($t){$acl=$t.GetAccessControl();$rights=0
 foreach($r in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){if($r.IdentityReference.Value -ceq $sid.Value -and $r.AccessControlType -eq 'Allow'){$rights=$rights -bor [int]$r.FileSystemRights}}
 return [pscustomobject]@{owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value;currentSidRights=$rights;writeOwner=(($rights -band [int][Security.AccessControl.FileSystemRights]::TakeOwnership) -ne 0)}}
function SetProbeAccess([string]$path,[string]$rights){$t=Owned $path;$acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false)
 $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,$rights,'ContainerInherit,ObjectInherit','None','Allow'))
 foreach($s in @('S-1-5-18','S-1-5-32-544')){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($s),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
 $t.SetAccessControl($acl)}
function Initialize([string]$path){$t=Owned $path;$before=Rights $t;$operation='SetOwner';$r=[ordered]@{success=$false;before=$before}
 try{$acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetOwner($sid);$acl.SetAccessRuleProtection($true,$false)
 foreach($s in @($sid,[Security.Principal.SecurityIdentifier]::new('S-1-5-18'),[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($s,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
 $operation='SetAccessControl';$t.SetAccessControl($acl);$r.success=$true
 }catch{$e=$_.Exception.GetBaseException();$r.operation=$operation;$r.type=$e.GetType().Name;$r.hresult=$e.HResult;$r.accessDenied=($e -is [UnauthorizedAccessException] -or $e.HResult -eq -2147024891)}
 return [pscustomobject]$r}
$modify=${quote(join(paths.home, "acl-modify-proof"))};$full=${quote(join(paths.home, "acl-full-proof"))}
SetProbeAccess $modify 'Modify';SetProbeAccess $full 'FullControl'
$m=Initialize $modify;$f=Initialize $full
$homes=@();foreach($p in @(${quote(paths.home)},${quote(paths.happyHome)})){$t=Owned $p;$before=Rights $t
 $acl=$t.GetAccessControl([Security.AccessControl.AccessControlSections]::Access)
 $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow'));$t.SetAccessControl($acl)
 $homes+=@{relative=$p.Substring($ownedRoot.Length);before=$before;after=(Rights $t)}}
@{nonAdmin=$true;mediumIntegrity=$medium;modify=$m;fullControl=$f;normalPrivateHomes=$homes;fixturePermissionCalibrationUsed=$true;productionAclChanged=$false}|ConvertTo-Json -Depth 8 -Compress`;

async function main() {
    assert(process.platform === "win32" && process.arch === "x64" && process.env.GITHUB_ACTIONS === "true" && process.env.RUNNER_ENVIRONMENT === "github-hosted" && process.env.GITHUB_REPOSITORY === REPO && process.env.GITHUB_REF === "refs/heads/main");
    assert.equal(process.env.ACCEPTANCE_SOURCE_SHA, EXPECTED_SOURCE);
    const review = JSON.parse(await readFile(new URL("./native-fixture-review-135.json", import.meta.url), "utf8"));
    assert.equal(review.sourceCommit, EXPECTED_SOURCE); const carrier = reviewedEngineCarrier(review);
    assert(!process.env.CYBERAI_USERNAME && !process.env.CYBERAI_PASSWORD, "No portal credentials in cold-start test");
    const token = process.env.GH_TOKEN; assert(token); const safe = sanitizedEnvironment(process.env);
    for (const key of Object.keys(process.env)) if (!Object.hasOwn(safe, key)) delete process.env[key];
    const upstream = await realpath(process.argv[2]); assert.equal(upstream, join(resolve(process.env.GITHUB_WORKSPACE), "upstream"));
    const root = join(await realpath(process.env.RUNNER_TEMP), "cyberfi-windows-auth-update"); await mkdir(root);
    const evidence = join(root, "evidence"); await mkdir(evidence);
    const report = { success: false, kind: "native-engine-cold-starts", sourceCommit: EXPECTED_SOURCE, engineVersion: "0.4.127", engineProvenance: carrier, portalAccountsCreated: false, installerExecuted: false, modelCalls: 0, priorRawStderrLost: true, runs: [] };
    const save = () => writeFile(join(evidence, "engine-cold-starts.json"), JSON.stringify(report, null, 2) + "\n");
    const ps = join(environmentValue(safe, "SystemRoot"), "System32/WindowsPowerShell/v1.0/powershell.exe");
    const system = Object.fromEntries(Object.entries(safe).filter(([key]) => new Set(["path","systemroot","windir","comspec","pathext","systemdrive","programfiles","programfiles(x86)","programw6432","commonprogramfiles","commonprogramfiles(x86)","commonprogramw6432","programdata","allusersprofile","public","userdomain","username","computername","os","processor_architecture","processor_identifier","number_of_processors","sessionname","temp","tmp"]).has(key.toLowerCase())));
    system.PSModulePath = [join(environmentValue(safe, "SystemRoot"), "System32/WindowsPowerShell/v1.0/Modules"), join(environmentValue(safe, "ProgramFiles"), "WindowsPowerShell/Modules")].join(";");
    const command = (file, args, env = system, cwd = root) => exec(file, args, { env, cwd, windowsHide: true, timeout: 90000, maxBuffer: 65536 }).then(r => r.stdout.trim());
    const powershell = (script, env = system) => command(ps, ["-NoLogo","-NoProfile","-NonInteractive","-EncodedCommand",Buffer.from(script,"utf16le").toString("base64")], env);
    let engine;
    const processes = async () => {
        const result = JSON.parse(await powershell(`@((Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -eq ${quote(engine)} }) | Select-Object ProcessId,CreationDate,ExecutablePath)|ConvertTo-Json -Compress`) || "[]");
        return Array.isArray(result) ? result : [result];
    };
    try {
        const selected=await pinnedEngineMetadata(carrier,token);report.engineTransport=selected.provenance;
        const archive = join(root, "engine.tar.gz"), engineDir = join(root, "engine"); await mkdir(engineDir);
        let url = new URL(`https://api.github.com/repos/${selected.repository}/releases/assets/${selected.asset.id}`), downloaded = false;
        for (let i=0;i<5;i++) {
            const r = await fetch(url, { headers: { Accept: "application/octet-stream", ...(url.hostname === "api.github.com" && selected.repository===REPO ? { Authorization: "Bearer " + token } : {}) }, redirect: "manual", signal: AbortSignal.timeout(300000) });
            if ([301,302,303,307,308].includes(r.status)) { url=allowedRedirect(r.headers.get("location")); continue; }
            assert(r.ok && r.body); let bytes=0;
            await pipeline(Readable.fromWeb(r.body),new Transform({transform(c,e,done){bytes+=c.length;done(bytes<=carrier.size?null:Error("Pinned archive size exceeded"),c);}}),createWriteStream(archive,{flags:"wx",mode:0o600}));
            assert.equal(bytes,carrier.size); downloaded=true;break;
        }
        assert(downloaded && await hashFile(archive) === carrier.sha256);
        const tar=join(environmentValue(safe,"SystemRoot"),"System32/tar.exe");
        assert.equal(await command(tar,["-tzf",archive]),"happy-agent-win32-x64.exe"); await command(tar,["-xzf",archive,"-C",engineDir]);
        engine=join(engineDir,"happy-agent-win32-x64.exe");assert.equal(await hashFile(engine),binarySha);assert.equal((await command(engine,["--version"])).split(/\s+/u).at(-1),"0.4.127");
        const gym=name=>pathToFileURL(join(upstream,"packages/happy-desktop-gym/sources/electron",name+".ts")).href;
        const {gymRunPathsCreate}=await import(gym("paths"));const {gymHostEnvironment}=await import(gym("hostEnvironment"));const {happyAgentClientCreate}=await import(gym("happyAgentProtocol"));
        for(let index=1;index<=3;index++){
            const {paths}=await gymRunPathsCreate("smoke");ownedQaAclHomes(paths,dirname(await realpath(process.env.RUNNER_TEMP)));
            const row={index,homeFresh:true,startPassed:false,healthPassed:false,stopPassed:false};report.runs.push(row);await save();
            const env={...system,...gymHostEnvironment(paths),HAPPY_HOME_DIR:paths.happyHome,HAPPY_AGENT_PROJECTS_DIRECTORY:paths.projects,HAPPY_AGENT_WORKSPACES_DIRECTORY:paths.workspaces,HAPPY_AGENT_SERVER_SOCKET_PATH:paths.socketPath,HAPPY_AGENT_SERVER_TOKEN_PATH:paths.tokenPath};
            assert(!Object.keys(env).some(k=>/SECRET|PASSWORD|CREDENTIAL|API_KEY|GH_TOKEN|CYBERAI/iu.test(k)));
            for(const p of [paths.home,paths.happyHome]) assert(await realpath(p)===p && !(await lstat(p)).isSymbolicLink());
            await mkdir(join(paths.home,"acl-modify-proof"));await mkdir(join(paths.home,"acl-full-proof"));
            row.acl=JSON.parse(await powershell(aclScript(paths,environmentValue(safe,"CYBERFI_TEST_EXPECTED_SID"),paths.root),env));
            assert(row.acl.nonAdmin && row.acl.mediumIntegrity && row.acl.fullControl.success && row.acl.normalPrivateHomes.length===2 && row.acl.normalPrivateHomes.every(h=>h.after.writeOwner));await save();
            const config=join(paths.root,"happy/config");await mkdir(config,{recursive:true});
            await writeFile(join(config,"happy.toml"),'[settings]\nhappy_integration = false\nmenu_bar = false\n\n[providers.codex]\ntype = "codex"\nenabled = true\ncredential_isolation = true\n');
            let client;const started=Date.now();
            try{
                await command(engine,["start"],env,paths.root);row.startPassed=true;row.startElapsedMs=Date.now()-started;
                client=happyAgentClientCreate(paths.socketPath,(await readFile(paths.tokenPath,"utf8")).trim());await client.getHealth();row.healthPassed=true;
            }catch(error){
                const text=String(error.stderr??"");row.stderrBytes=Buffer.byteLength(text);row.errorFacts=stderrFacts(text);row.exitCode=Number.isInteger(error.code)?error.code:null;
                const ownToken=await readFile(paths.tokenPath,"utf8").catch(()=>"");
                await writeFile(join(evidence,`engine-stderr-${index}.txt`),redactStderr(text,[paths.root,root],ownToken.trim()),{flag:"wx",mode:0o600});
                row.redactedStderrPreserved=true;await save();
            }finally{
                await command(engine,["stop"],env,paths.root).catch(()=>undefined);
                const until=Date.now()+10000;while(Date.now()<until && (await processes()).length) await delay(100);
                row.stopPassed=(await processes()).length===0;await save();
            }
            assert(row.stopPassed,"Owned daemon must be fully stopped before next cold start");
        }
        report.success=report.runs.length===3&&report.runs.every(r=>r.startPassed&&r.healthPassed&&r.stopPassed);
    }catch(error){
        report.failureType=error.constructor?.name;report.failureCode="owned-cold-start-diagnostic-failed";process.exitCode=1;
        const stderr=String(error.stderr??"");
        if(stderr){
            report.failureFacts=stderrFacts(stderr);
            for(let index=1;index<=3;index++){
                const destination=join(evidence,`engine-stderr-${index}.txt`);
                if(await lstat(destination).catch(()=>undefined))continue;
                await writeFile(destination,redactStderr(stderr,[dirname(await realpath(process.env.RUNNER_TEMP))]),{flag:"wx",mode:0o600});
                report.redactedFailureStderrPreserved=true;break;
            }
        }
    }
    finally{await save();}
    assert(report.success,"Cold-start diagnostic incomplete; inspect redacted evidence");console.log(JSON.stringify({success:true,runs:3,modelCalls:0,installerExecuted:false}));
}
if(process.argv.includes("--self-test")){
    const t='Command failed: powershell.exe -EncodedCommand QUJDRA==\nException calling "SetAccessControl": "Access is denied"\nUnauthorizedAccessException 0x80070005 C:\\owned\\private secret-token';
    const r=redactStderr(t,["C:\\owned\\private"],"secret-token");assert(!r.includes("QUJDRA==")&&!r.includes("secret-token")&&!r.includes("C:\\owned\\private"));
    assert(stderrFacts(r).accessDenied&&stderrFacts(r).setAccessControl);assert.throws(()=>redactStderr("a".repeat(65537),[]));
    console.log("Cold-start bounded redaction/diagnostic selfchecks PASS; no process/network launched");
}else await main();
