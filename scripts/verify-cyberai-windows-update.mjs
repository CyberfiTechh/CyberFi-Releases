import assert from "node:assert/strict";
import { createHash, verify, randomBytes } from "node:crypto";
import { constants, createReadStream, createWriteStream } from "node:fs";
import { copyFile, chmod, mkdir, readFile, readdir, realpath, writeFile, lstat, stat } from "node:fs/promises";
import { createRequire } from "node:module";
import { basename, dirname, join, resolve, sep } from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";
import { execFile, spawn } from "node:child_process";
import { promisify } from "node:util";
import { createServer } from "node:http";
import { Readable, Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import { setTimeout as delay } from "node:timers/promises";
import { EventEmitter } from "node:events";

const REPOSITORY = "CyberfiTechh/CyberFi-Releases", VERSION = "0.0.131";
const EXPECT_REPRO = false;
const TARGET_INSTALLER = `CyberFi-${VERSION}-x64.exe`;
const SOURCE_COMMIT = "d070120ddfdfa8b769e3fcc0b6cacee704306598";
const exec = promisify(execFile);
// Independent pinned public update-verification key; never trust a key supplied by the artifact.
const PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA09ZxJMbpq1uFEnz7n52M\nAJtceCXVQCo57lgwMAmizgJaGVGsgsMpzqgCCRgXBN+bPygE+16S9XwYOwHDlnNG\noq8h+bE9Nxce3PzsQHrscdHTT1lGQ/5XwSmvzTvxLdURtQWpaXZl7lJghUnZHNDA\n8SOHbk8rQ+butE82lhcq0C+hgJgHTUqFl9Irppi2O+MpufsZo8PX5jphD4H0aX0k\nB9P+LUreoBmG/L3T3AMZEzQZG606awc/ZMYsJcJkt4xNMjR3ZMz1aWKErW2AXDeY\nyfAo0zmEAUEAFSc3UEJRnmBAjorVA3C/rHJzYP7QabSh8ORLOUrqQYgqCpTLETpf\nct0J+NphCLuBGNQ5IeId5IPiBNZlKynGzP/HK+oJTvJ31hTHIiaA+5pfIESXELIZ\nJ5awYGW0y7fii0CqRGwFMJnU829APVvAC9LJUzSSz7NP+2rmc/boYInx8cjN2/LO\nLI9HsPvON+oxM4MhjRxDd4CVoKDpI+rB2TthSdfxt3UxAgMBAAE=\n-----END PUBLIC KEY-----";
const id = value => { assert(Number.isSafeInteger(value) && value > 0); return value; };
const sha = value => { assert(typeof value === "string" && /^[a-f0-9]{64}$/u.test(value)); return value; };
function artifactPins(value) {
    assert(value && !Array.isArray(value) && Object.keys(value).sort().join(",") === "assetId,manifestAssetId,manifestSha256,releaseId,sha256");
    id(value.releaseId); id(value.assetId); id(value.manifestAssetId); sha(value.sha256); sha(value.manifestSha256);
    return value;
}
function allowedRedirect(value) {
    const url = new URL(value);
    assert(url.protocol === "https:" && !url.username && !url.password && (!url.port || url.port === "443"));
    assert(url.hostname === "github.com" || url.hostname.endsWith(".githubusercontent.com") || url.hostname.endsWith(".blob.core.windows.net"));
    return url;
}
function signedManifest(data, filename, pin, size) {
    assert(data && sha(data.sha256) === pin && data.size === size && size > 0 && size <= 256 * 1024 ** 2);
    assert.match(data.signature, /^[A-Za-z0-9+/=]{100,700}$/u);
    assert(verify("sha256", Buffer.from(`${VERSION}\n${filename}\n${pin}\n${size}\n`), PUBLIC_KEY, Buffer.from(data.signature, "base64")), "Independent RSA verification failed");
}
function rendererClosedDuringUpdate(error) {
    const line = String(error?.message ?? "").split(/\r?\n/u, 1)[0].trim();
    return /^(?:page\.evaluate: )?(?:Target page, context or browser has been closed|Execution context was destroyed, most likely because of a navigation\.?|Protocol error \(Runtime\.(?:evaluate|callFunctionOn)\): (?:Target closed|Session closed\. Most likely the page has been closed\.|Cannot find context with specified id))$/u.test(line);
}
function updateMonitorKind(error, phase) {
    if (error?.cyberfiUpdateFailure === "updater-error") return "updater-error";
    if (phase === "renderer-poll" && rendererClosedDuringUpdate(error)) return "renderer-closed";
    return phase === "process-poll" ? "process-poll-error" : "unexpected-renderer-error";
}
function publishedReleaseMatches(release, releaseId, tag) {
    return release?.id === releaseId && release?.draft === false && release?.tag_name === tag;
}
function classifyWindowsFailure(input) {
    const text = typeof input === "string" ? input.slice(0, 32768) : "";
    const encoded = /-EncodedCommand[ \t]+([A-Za-z0-9+/=]{16,8192})/iu.exec(text)?.[1];
    const decoded = encoded ? Buffer.from(encoded, "base64").toString("utf16le") : "";
    const powershellIds = [...new Set([...text.matchAll(/FullyQualifiedErrorId\s*:\s*([a-z0-9.,]+)[ \t]*$/gimu)].map(match => match[1]))].slice(0, 8);
    const categories = [...new Set([...text.matchAll(/CategoryInfo\s*:\s*([a-z]+)\s*:/gimu)].map(match => match[1]))].slice(0, 8);
    return {
        textBytes: Buffer.byteLength(text), powershellIds, categories,
        systemPowerShell: /System32[\\/]WindowsPowerShell[\\/]v1[.]0[\\/]powershell[.]exe/iu.test(text),
        privateDirectoryInitializer: /SetAccessControl|HAPPY_PRIVATE_DIRECTORY|DirectorySecurity/iu.test(text + decoded),
        accessDenied: /UnauthorizedAccessException|AccessDenied|Access is denied|access to the path.+denied|Erişim engellendi/iu.test(text),
        ownerAssignmentDenied: /invalid owner|not allowed to be the owner|cannot be assigned as the owner|PrivilegeNotHeld/iu.test(text),
        unknownMethod: /MethodNotFound|does not contain a method named|MethodInvocationException/iu.test(text),
        aclTypeFailure: /Unable to find type|TypeNotFound|DirectorySecurity.*not found/iu.test(text),
        moduleFailure: /could not be loaded|module.+not loaded|CommandNotFoundException|ModuleNotFound|PSModulePath/iu.test(text),
        pathMissing: /ItemNotFound|PathNotFound|Cannot find path/iu.test(text),
        reparsePointRefused: /reparse point/iu.test(text),
        executionPolicy: /PSSecurityException|running scripts is disabled|ExecutionPolicy/iu.test(text),
        timeout: /ETIMEDOUT|timed out|timeout/iu.test(text),
        diagnostics: [...new Set((text.match(/\b(?:EACCES|EPERM|ENOENT|EADDRINUSE|WSAEACCES|ERR_[A-Z_]{3,40})\b/gu) ?? []))].slice(0, 12),
    };
}
async function hashFile(path) {
    const value = createHash("sha256"); for await (const chunk of createReadStream(path)) value.update(chunk); return value.digest("hex");
}
const privateEnvironment = /TOKEN|SECRET|PASSWORD|CREDENTIAL|API_KEY|CYBERAI_USERNAME|NODE_OPTIONS|ELECTRON_RUN_AS_NODE|SMOKE_REPORT|SMOKE_SCREENSHOT|VITE_DEV_SERVER_URL|ACCEPTANCE_ARTIFACTS/iu;
function sanitizedEnvironment(source) { return Object.fromEntries(Object.entries(source).filter(([key, value]) => value !== undefined && !privateEnvironment.test(key))); }
function environmentValue(environment, name) {
    const key = Object.keys(environment).find(key => key.toLowerCase() === name.toLowerCase());
    assert(key && environment[key], "Required native system environment missing");
    return environment[key];
}
function watcherReady(child) {
    return new Promise((done, reject) => {
        let text = "";
        const finish = error => { clearTimeout(timer); child.stderr.off("data", data); child.off("error", failed); child.off("close", closed); error ? reject(error) : done(); };
        const data = value => { text = (text + value.toString()).slice(-4096); if (text.includes("ready")) finish(); };
        const failed = () => finish(Error("Native visibility observer failed"));
        const closed = () => finish(Error("Native visibility observer exited before readiness"));
        const timer = setTimeout(() => finish(Error("Native visibility observer readiness timed out")), 60000);
        child.stderr.on("data", data); child.once("error", failed); child.once("close", closed);
    });
}
function missingOwnedKeychainDefaultConfirmed(defaults, list, reads) {
    const failed = reads.filter(read => !read.success);
    return defaults.length === 0 && list.length === 0 && failed.length === 1 && failed[0].context === "owned-home" && failed[0].verb === "default-keychain" && failed[0].exitCode === 1 && /A default keychain could not be found/iu.test(failed[0].diagnostic);
}
const REVIEWED_ARTIFACTS = {
    "target": {
        "releaseId": 439264052,
        "assetId": 727864145,
        "sha256": "b091452750eed8702c45e21c3d97df9e4e3f02a38db0a372104cdef2a0c79374",
        "manifestAssetId": 727881614,
        "manifestSha256": "3d0a47f49e500b90ac1c1709d95fc21f130ebd08a9fa8494a0b68762cbc5b1ab"
    }
};
async function main() {
    const target = process.env.TARGET;
    assert(target === "windows", "Only Windows update target is supported");
    const windows = target === "windows", arch = target === "macos-arm64" ? "arm64" : "x64";
    assert(process.platform === (windows ? "win32" : "darwin") && process.arch === arch && process.env.GITHUB_ACTIONS === "true" && process.env.RUNNER_ENVIRONMENT === "github-hosted" && process.env.GITHUB_REPOSITORY === REPOSITORY && process.env.GITHUB_REF === "refs/heads/codex/windows-fresh-engine-131", "Only the selected disposable native runner may execute acceptance");
    const pins = Object.fromEntries(Object.entries(REVIEWED_ARTIFACTS).map(([kind, pin]) => [kind, artifactPins(pin)]));
    assert.equal(process.env.ACCEPTANCE_SOURCE_SHA, SOURCE_COMMIT, "Unexpected reviewed source provenance");
    // These lexical variables are never passed to child processes or serialized.
    const token = process.env.GH_TOKEN, username = process.env.CYBERAI_USERNAME, password = process.env.CYBERAI_PASSWORD;
    assert(username && username !== "admin" && password && password.length >= 8, "Disposable role-user credentials are required");
    const safeEnv = sanitizedEnvironment(process.env);
    for (const key of Object.keys(process.env)) if (!Object.hasOwn(safeEnv, key)) delete process.env[key];
    const upstream = await realpath(process.argv[2]);
    assert.equal(upstream, join(resolve(process.env.GITHUB_WORKSPACE), "upstream"));

    const root = join(await realpath(process.env.RUNNER_TEMP), "cyberfi-windows-auth-update"); await mkdir(root);
    const evidence = join(root, "evidence"), applications = join(root, "Applications"); let profile;
    await Promise.all([evidence, applications].map(path => mkdir(path)));
    const report = { success: false, desktopVersion: VERSION, sourceCommit: SOURCE_COMMIT,
        progress: [], events: [], videos: [], errors: [], limits: ["The engine is downloaded and started only by the normal packaged app. No provider authentication is exercised.", "No OS trust-store changes; RSA pins and Authenticode CMS are checked independently."] };
    const save = () => writeFile(join(evidence, "automatic-update.json"), JSON.stringify(report, null, 2) + "\n");
    const command = async (file, args, options = {}) => {
        try { return (await exec(file, args, { env: safeEnv, timeout: 120000, windowsHide: true, maxBuffer: 8 * 1024 ** 2, ...options })).stdout.trim(); }
        catch (error) {
            // Never retain arbitrary stderr, command arguments, HTTP bodies or headers.
            const text = typeof error.stderr === "string" ? error.stderr : "";
            error.cyberaiCommand = { tool: basename(file), verb: ["default-keychain", "list-keychains", "show-keychain-info", "create-keychain", "delete-keychain", "unlock-keychain", "set-keychain-settings", "start", "stop", "--version", "-tzf", "-xzf", "init", "-C"].includes(args[0]) ? args[0] : "native-operation", exitCode: Number.isSafeInteger(error.code) ? error.code : null,
                noDefaultKeychain: /default keychain could not be found/iu.test(text), keychainNotFound: /specified keychain could not be found/iu.test(text), interactionNotAllowed: /interaction is not allowed/iu.test(text), permissionDenied: /permission denied|access is denied/iu.test(text), missingFile: /no such file|cannot find the file/iu.test(text) };
            throw error;
        }
    };
    const ps = windows ? join(environmentValue(safeEnv, "SystemRoot"), "System32/WindowsPowerShell/v1.0/powershell.exe") : undefined;
    const nativePsEnvironment = { ...safeEnv };
    for (const key of Object.keys(nativePsEnvironment)) if (key.toLowerCase() === "psmodulepath") delete nativePsEnvironment[key];
    nativePsEnvironment.PSModulePath = [join(environmentValue(safeEnv, "SystemRoot"), "System32/WindowsPowerShell/v1.0/Modules"), join(environmentValue(safeEnv, "ProgramFiles"), "WindowsPowerShell/Modules")].join(";");
    const powershell = script => command(ps, ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script], { env: nativePsEnvironment });
    const quote = value => "'" + value.replaceAll("'", "''") + "'";
    async function nativeAclProbe(engineHome) {
        const base = await realpath(environmentValue(safeEnv, "USERPROFILE"));
        assert(engineHome.toLowerCase() === join(base, ".pdr-kocum-agent").toLowerCase());
        const lookup = [
            ["engine-home", engineHome], ["happy-home", join(engineHome, ".happy")],
            ["agent-state", join(engineHome, ".happy", "agent")], ["engine-distribution", join(engineHome, ".happy", "dist")],
        ];
        const states = [];
        for (const [kind, path] of lookup) {
            const entry = await lstat(path).catch(() => undefined);
            if (!entry) { states.push({ kind, exists: false }); continue; }
            if (!entry.isDirectory() || entry.isSymbolicLink() ||
                (await realpath(path)).toLowerCase() !== path.toLowerCase()) {
                states.push({ kind, exists: true, canonicalOwnedDirectory: false }); continue;
            }
            const probe = `$ErrorActionPreference='Stop';$entry=Get-Item -LiteralPath ${quote(path)} -Force
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
$owner=$entry.GetAccessControl().GetOwner([Security.Principal.SecurityIdentifier])
$acl=$entry.GetAccessControl()
$allow=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | Where-Object { $_.IdentityReference -eq $sid -and $_.AccessControlType -eq 'Allow' })
$full=[Security.AccessControl.FileSystemRights]::FullControl
@{nativeVersion=$PSVersionTable.PSVersion.ToString();ownerMatchesCurrentUser=$owner.Value -eq $sid.Value;setAccessControlPresent=$null -ne $entry.PSObject.Methods['SetAccessControl'];inheritedRulesDisabled=$acl.AreAccessRulesProtected;currentUserFullControl=@($allow | Where-Object { ($_.FileSystemRights -band $full) -eq $full }).Count -gt 0;reparsePoint=($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0}|ConvertTo-Json -Compress`;
            try {
                const state = JSON.parse(await powershell(probe));
                states.push({ kind, exists: true, canonicalOwnedDirectory: true, ...state });
            } catch (error) {
                states.push({ kind, exists: true, canonicalOwnedDirectory: true, queryFailed: true, reason: classifyWindowsFailure(error.stderr ?? error.message) });
            }
        }
        const log = join(engineHome, ".happy", "agent", "daemon.log");
        const file = await lstat(log).catch(() => undefined);
        const daemonLog = file?.isFile() && !file.isSymbolicLink() && file.size <= 262144 &&
            (await realpath(log).catch(() => "")).toLowerCase() === log.toLowerCase()
            ? classifyWindowsFailure(await readFile(log, "utf8")) : null;
        return { onlyReadAccess: true, states, daemonLog, daemonLogBytes: file?.size ?? 0 };
    }

        const aclInitializer = [
            "$ErrorActionPreference = 'Stop'",
            "$target = Get-Item -LiteralPath $env:HAPPY_PRIVATE_DIRECTORY -Force",
            "if (($target.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Private state cannot be a reparse point.' }",
            "$identity = [Security.Principal.WindowsIdentity]::GetCurrent().User",
            "$acl = [Security.AccessControl.DirectorySecurity]::new()",
            "$acl.SetOwner($identity)",
            "$acl.SetAccessRuleProtection($true, $false)",
            "foreach ($sid in @($identity, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'), [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))) { $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')) }",
            "$target.SetAccessControl($acl)",
        ].join("\n");
    async function runFreshAclInitializer(nativeHome, standardTemp) {
        const probeRoot = join(nativeHome, "cyberfi-synthetic-acl-probe");
        await assert.rejects(lstat(probeRoot), { code: "ENOENT" });
        await mkdir(probeRoot);
        assert.equal((await realpath(probeRoot)).toLowerCase(), probeRoot.toLowerCase());
        let result = [];
        for (const kind of ["launcher-temp", "ordinary-profile-temp"]) {
            const directory = join(probeRoot, kind);
            await mkdir(directory);
            assert.equal((await realpath(directory)).toLowerCase(), directory.toLowerCase());
            const env = { ...safeEnv, HAPPY_PRIVATE_DIRECTORY: directory };
            if (kind === "ordinary-profile-temp") { env.TEMP = standardTemp; env.TMP = standardTemp; }
            const begin = Date.now();
            try {
                const completed = await exec(ps, ["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand",
                    Buffer.from(aclInitializer, "utf16le").toString("base64")],
                    { env, timeout: 30000, maxBuffer: 16384, windowsHide: true });
                result.push({ kind, exitCode: 0, elapsedMs: Date.now() - begin, timedOut: false,
                    stdoutBytes: Buffer.byteLength(completed.stdout), stderr: classifyWindowsFailure(completed.stderr) });
            } catch (error) {
                result.push({ kind, exitCode: Number.isSafeInteger(error.code) ? error.code : null, elapsedMs: Date.now() - begin,
                    timedOut: error.killed === true, signal: /^SIG[A-Z0-9]+$/u.test(error.signal ?? "") ? error.signal : null,
                    stderr: classifyWindowsFailure(error.stderr ?? error.message) });
            }
        }
        return result;
    }
    async function windowsSignature(path) {
        // Check the actual embedded Authenticode CMS cryptographically without
        // installing a root certificate or treating offline chain failures as trust.
        const value = JSON.parse(await powershell(`$ErrorActionPreference='Stop'; Add-Type -AssemblyName System.Security
$path=${quote(path)}; $bytes=[IO.File]::ReadAllBytes($path)
if($bytes.Length -lt 256 -or [BitConverter]::ToUInt16($bytes,0) -ne 0x5a4d){throw 'Invalid PE'}
$pe=[BitConverter]::ToInt32($bytes,0x3c); if($pe -lt 0 -or $pe+24+144 -gt $bytes.Length -or [BitConverter]::ToUInt32($bytes,$pe) -ne 0x4550){throw 'Invalid PE header'}
$optional=$pe+24; $magic=[BitConverter]::ToUInt16($bytes,$optional)
if($magic -eq 0x20b){$directories=$optional+112}elseif($magic -eq 0x10b){$directories=$optional+96}else{throw 'Invalid PE optional header'}
$certificate=[BitConverter]::ToUInt32($bytes,$directories+32);$tableSize=[BitConverter]::ToUInt32($bytes,$directories+36)
if($certificate -lt 256 -or $tableSize -lt 9 -or [long]$certificate+$tableSize -gt $bytes.Length){throw 'Invalid certificate table'}
$length=[BitConverter]::ToUInt32($bytes,$certificate)
if($length -le 8 -or $length -gt $tableSize -or [BitConverter]::ToUInt16($bytes,$certificate+4) -ne 0x200 -or [BitConverter]::ToUInt16($bytes,$certificate+6) -ne 2){throw 'Invalid WIN_CERTIFICATE'}
$payload=New-Object byte[] ($length-8);[Array]::Copy($bytes,[long]$certificate+8,$payload,0,$payload.Length)
$cms=[Security.Cryptography.Pkcs.SignedCms]::new();$cms.Decode($payload);$cms.CheckSignature($true)
if($cms.SignerInfos.Count -ne 1 -or $cms.ContentInfo.ContentType.Value -ne '1.3.6.1.4.1.311.2.1.4' -or $cms.SignerInfos[0].DigestAlgorithm.Value -ne '2.16.840.1.101.3.4.2.1'){throw 'Unexpected Authenticode signature'}
$trust=Get-AuthenticodeSignature -LiteralPath $path
@{status=$trust.Status.ToString();thumbprint=$cms.SignerInfos[0].Certificate.Thumbprint;cmsSignatureVerified=$true}|ConvertTo-Json -Compress`));
        assert.equal(value.thumbprint, "2470547AF0CF456E06BF7065399591BBD7EC79ED");
        assert(value.cmsSignatureVerified === true && ["Valid", "NotTrusted", "UnknownError"].includes(value.status), "Authenticode cryptographic integrity failed");
        return { ...value, osTrustCertified: value.status === "Valid", trustStoreModified: false };
    }
    async function api(path) {
        assert.match(path, /^repos\/CyberfiTechh\/(CyberFi-Releases|CyberFi-Engine)\/releases\/[1-9][0-9]*$/u);
        const response = await fetch("https://api.github.com/" + path, { headers: { Accept: "application/vnd.github+json", ...(token ? { Authorization: "Bearer " + token } : {}) }, redirect: "error", signal: AbortSignal.timeout(45000) });
        assert(response.ok, "Pinned GitHub metadata unavailable"); return response.json();
    }
    async function download(repository, asset, destination) {
        assert([REPOSITORY, "CyberfiTechh/CyberFi-Engine"].includes(repository)); id(asset.id);
        assert(Number.isSafeInteger(asset.size) && asset.size > 0 && asset.size <= 256 * 1024 ** 2);
        let url = new URL(`https://api.github.com/repos/${repository}/releases/assets/${asset.id}`);
        for (let redirects = 0; redirects < 5; redirects++) {
            const response = await fetch(url, { headers: { Accept: "application/octet-stream", ...(url.hostname === "api.github.com" && token ? { Authorization: "Bearer " + token } : {}) }, redirect: "manual", signal: AbortSignal.timeout(300000) });
            if ([301, 302, 303, 307, 308].includes(response.status)) { url = allowedRedirect(response.headers.get("location")); continue; }
            assert(response.ok && response.body, "Pinned asset download unavailable"); let bytes = 0;
            await pipeline(Readable.fromWeb(response.body), new Transform({ transform(chunk, encoding, done) { bytes += chunk.length; done(bytes <= asset.size ? null : Error("Asset exceeded pinned size"), chunk); } }), createWriteStream(destination, { flags: "wx", mode: 0o600 }));
            assert.equal(bytes, asset.size); return;
        }
        throw Error("Asset redirect limit exceeded");
    }

    let executable, engine, engineHome, browser, page, video, run;
    let stage = "published artifacts";
    const alive = pid => { try { process.kill(pid, 0); return true; } catch (error) { if (error.code === "ESRCH") return false; throw error; } };
    async function processes() {
        const value = await powershell(`@(Get-CimInstance Win32_Process | Where-Object { $_.Name -in @('CyberFi.exe','${TARGET_INSTALLER}') } | Select-Object Name,ProcessId,ParentProcessId,ExecutablePath,CommandLine,CreationDate) | ConvertTo-Json -Depth 3 -Compress`);
        const parsed = value ? JSON.parse(value) : []; return Array.isArray(parsed) ? parsed : [parsed];
    }
    try {
        stage = "disposable CI default-profile ownership";
        const nativeIdentity = JSON.parse(await powershell(String.raw`$identity=[Security.Principal.WindowsIdentity]::GetCurrent();$principal=[Security.Principal.WindowsPrincipal]::new($identity);[ordered]@{roaming=[Environment]::GetFolderPath('ApplicationData');home=[Environment]::GetFolderPath('UserProfile');sid=$identity.User.Value;administrator=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);installed=(Test-Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\f8156223-0df4-5c6f-b223-7004db2f68a2')}|ConvertTo-Json -Compress`));
        const roaming = await realpath(environmentValue(safeEnv, "APPDATA")), nativeHome = await realpath(environmentValue(safeEnv, "USERPROFILE"));
        assert.equal((await realpath(nativeIdentity.roaming)).toLowerCase(), roaming.toLowerCase()); assert.equal((await realpath(nativeIdentity.home)).toLowerCase(), nativeHome.toLowerCase());
        assert(roaming.toLowerCase().startsWith(nativeHome.toLowerCase() + sep) && /\\AppData\\Roaming$/iu.test(roaming) && /^S-1-5-21-/u.test(nativeIdentity.sid) && !nativeIdentity.installed, "Fresh hosted-user profile and absent installation required");
        assert.equal(nativeIdentity.sid, environmentValue(safeEnv, "CYBERFI_TEST_EXPECTED_SID"));
        assert.equal(nativeIdentity.administrator, false, "The actual installer test requires a standard user");
        profile = join(roaming, "PDR Koçum Agent");
        engineHome = join(nativeHome, ".pdr-kocum-agent");
        for (const path of [profile, join(roaming, "CyberFi"), engineHome, join(nativeHome, ".agents/skills")])
            await assert.rejects(lstat(path), { code: "ENOENT" });
        report.profileInitiallyAbsent = true;
        report.engineInitiallyAbsent = true;
        report.normalPackagedMode = true;
        stage = "exact owned PowerShell ACL initializer probe";
        const localAppData = await realpath(environmentValue(safeEnv, "LOCALAPPDATA"));
        assert.equal(localAppData.toLowerCase(), join(nativeHome, "AppData", "Local").toLowerCase());
        const standardTemp = join(localAppData, "Temp");
        await mkdir(standardTemp, { recursive: true });
        const standardTempEntry = await lstat(standardTemp);
        assert(standardTempEntry.isDirectory() && !standardTempEntry.isSymbolicLink());
        assert.equal((await realpath(standardTemp)).toLowerCase(), standardTemp.toLowerCase());
        const launcherTemp = environmentValue(safeEnv, "TEMP");
        assert(launcherTemp.toLowerCase().endsWith("\\tmp") && launcherTemp.toLowerCase().includes("\\cf-launch-"));
        const canonicalModulePath = nativePsEnvironment.PSModulePath;
        report.launchEnvironmentClassification = {
            launcherTempIsSeparateOwnedScratch: launcherTemp.toLowerCase() !== standardTemp.toLowerCase(),
            appUsesOrdinarySyntheticUserTemp: true,
            launcherModulePathMatchesNativeSystemModules: environmentValue(safeEnv, "PSModulePath").toLowerCase() === canonicalModulePath.toLowerCase(),
            sandboxOverrideSuppliedToApp: false,
        };
        report.exactNativeAclProbe = await runFreshAclInitializer(nativeHome, standardTemp);

        const artifacts = {};
        for (const [kind, version] of [["target", VERSION]]) {
            const pin = pins[kind], release = await api(`repos/${REPOSITORY}/releases/${pin.releaseId}`);
            assert(release.id === pin.releaseId && release.tag_name === "v" + version && release.draft === true, "Exact signed Windows draft is required");
            const filename = `CyberFi-${version}-x64.exe`, asset = release.assets.find(item => item.id === pin.assetId), manifest = release.assets.find(item => item.id === pin.manifestAssetId);
            assert(asset?.name === filename && asset.digest === "sha256:" + pin.sha256 && asset.state === "uploaded");
            assert(manifest?.name === filename + ".update.json" && manifest.digest === "sha256:" + pin.manifestSha256 && manifest.size <= 4096);
            const path = join(root, filename), manifestPath = path + ".update.json";
            await download(REPOSITORY, manifest, manifestPath);
            assert.equal(await hashFile(manifestPath), pin.manifestSha256);
            const signed = JSON.parse((await readFile(manifestPath, "utf8")).replace(/^\uFEFF/u, ""));
            assert(signed.sha256 === pin.sha256 && signed.size === asset.size && verify("sha256", Buffer.from(`${version}\n${filename}\n${pin.sha256}\n${asset.size}\n`), PUBLIC_KEY, Buffer.from(signed.signature, "base64")), "Pinned versioned RSA manifest invalid");
            {
                await download(REPOSITORY, asset, path);
                assert.equal(await hashFile(path), pin.sha256);
                artifacts.target = { path, signature: await windowsSignature(path) };
            }
        }
        stage = "real signed 0.0.131 draft NSIS installation";
        const installation = join(applications, "CyberFi"); await mkdir(installation);
        // Real per-user NSIS installation, not archive extraction. No trust certificate is installed.
        await command(artifacts.target.path, ["/S", "/D=" + installation], { timeout: 180000 });
        executable = join(installation, "CyberFi.exe"); assert(executable.startsWith(root + sep));
        assert.equal(await powershell(`(Get-Item -LiteralPath ${quote(executable)}).VersionInfo.ProductVersion`), VERSION + ".0");
        report.sourceSignature = await windowsSignature(executable);
        stage = "public stable engine identity";
        const release = await api("repos/CyberfiTechh/CyberFi-Engine/releases/439192562");
        const engineAsset = release.assets.find(a => a.id === 727661918);
        assert(release.tag_name === "v0.4.123" && release.draft === false && release.prerelease === false);
        assert(engineAsset?.digest === "sha256:b8dd42a4f57345220d3c39bffc8d561b406989fab841c23a10d0b580a85ed418");
        report.stableEngineRelease = { releaseId: release.id, assetId: engineAsset.id, archiveBytes: engineAsset.size, digest: engineAsset.digest };
        const gym = name => pathToFileURL(join(upstream, "packages/happy-desktop-gym/sources/electron", name + ".ts")).href;

        const require = createRequire(join(upstream, "packages/happy-desktop-gym/package.json")), { chromium } = require("playwright");
        const port = 19486, endpoint = `http://127.0.0.1:${port}`;
        async function listenerPid() {
            const text = await powershell(`@(Get-NetTCPConnection -LocalAddress 127.0.0.1 -LocalPort ${port} -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique) | ConvertTo-Json -Compress`);
            const values = text ? JSON.parse(text) : [], list = Array.isArray(values) ? values : [values]; assert(list.length <= 1); return list.length ? id(list[0]) : undefined;
        }
        assert.equal(await listenerPid(), undefined);
        const env = { ...safeEnv, TEMP: standardTemp, TMP: standardTemp, HAPPY_DESKTOP_DEBUG: "1", HAPPY_DEBUG_RENDERER_PORT: String(port) };
        for (const key of Object.keys(env)) {
            if (/^(?:HAPPY_|ELECTRON_|CYBERFI_|PDR_)/iu.test(key) &&
                !["HAPPY_DESKTOP_DEBUG", "HAPPY_DEBUG_RENDERER_PORT", "HAPPY_DESKTOP_GYM_FFMPEG"].includes(key)) delete env[key];
        }
        const application = spawn(executable, ["--debug"], { cwd: installation, env, stdio: "ignore", windowsHide: false });
        run = new Promise(resolve => {
            application.once("error", () => resolve());
            application.once("exit", () => resolve());
        });
        async function connect() {
            const until = Date.now() + 90000;
            while (Date.now() < until) {
                try { const response = await fetch(endpoint + "/json/list", { signal: AbortSignal.timeout(1500) }); if (response.ok && (await response.json()).some(item => item.type === "page")) {
                    browser = await chromium.connectOverCDP(endpoint); page = browser.contexts().flatMap(value => value.pages()).find(value => !value.url().startsWith("devtools:"));
                    if (page) { await page.waitForFunction(() => typeof window.happyDesktop?.runtimeGet === "function"); return; }
                } } catch { /* Approved debug endpoint only. */ }
                await delay(200);
            }
            throw Error("Fresh installed normal-mode package did not expose its owned debug endpoint");
        }
        await connect();

        stage = "fresh installed CyberAI login";
        await page.waitForFunction(() => !document.querySelector('[data-testid="desktop-startup-screen"]') && !!document.querySelector('[data-happy-desktop-ui="cyberfi-account-login"] input[name="password"]:not(:disabled)'), undefined, { timeout: 60000 });
        await page.addStyleTag({ content: 'input[name="username"], input[name="password"] { color: transparent !important; text-shadow: none !important; caret-color: transparent !important; }' });
        const sourceLogin = page.locator('[data-happy-desktop-ui="cyberfi-account-login"]');
        assert(await page.evaluate(async () => { try { await window.happyDesktop.runtimeGet(); return false; } catch { return true; } }), "Source must deny privileged IPC before login");
        await sourceLogin.locator('input[name="username"]').fill(username); await sourceLogin.locator('input[name="password"]').fill(password);
        assert.equal(await sourceLogin.getByRole("checkbox", { name: /^(Beni hatırla|Remember me)$/iu }).isChecked(), false);
        await sourceLogin.getByRole("button", { name: /^(Giriş yap|Sign in)$/iu }).click();
        await page.waitForFunction(async () => (await window.happyDesktop.cyberFiAccountGet()).status === "signedIn", undefined, { timeout: 60000 });
        const sourceAccount = await page.evaluate(() => window.happyDesktop.cyberFiAccountGet());
        assert(sourceAccount.user?.role === "user" && sourceAccount.remember === false && sourceAccount.username === username);

        await assert.rejects(lstat(join(profile, "desktop", "cyberai-account.json")), { code: "ENOENT" });
        report.accountAuthenticated = true;
        report.appPid = id(await listenerPid());
        stage = "normal first-run engine preparing and download";
        const startedAt = Date.now(), end = startedAt + (EXPECT_REPRO ? 90_000 : 9 * 60000);
        let lastKey, snapshot, waitingSince;
        while (Date.now() < end) {
            try {
                snapshot = await page.evaluate(async () => {
                    const [runtime, daemon, onboarding] = await Promise.all([
                        window.happyDesktop.runtimeGet(), window.happyDesktop.daemonGet(), window.happyDesktop.onboardingGet(),
                    ]);
                    const visibleText = document.body.innerText;
                    return { runtimePhase: runtime.phase, runningVersion: runtime.activeTarget?.happyAgentVersion,
                        installation: daemon.installation, operation: daemon.operation, engineRuntime: daemon.runtime,
                        installedVersion: daemon.installedVersion, availableVersion: daemon.availableVersion,
                        readyVersion: daemon.readyVersion, errorCode: daemon.errorCode ?? null,
                        errorPresent: Boolean(daemon.error), download: daemon.download && {
                            bytes: daemon.download.receivedBytes, total: daemon.download.totalBytes,
                        }, onboardingStage: onboarding.stage,
                        preparingText: /^(Hazırlanıyor…|Preparing…)$/mu.test(visibleText),
                        downloadingText: /^(İndiriliyor…|Downloading…)$/mu.test(visibleText),
                        startingText: /^(Başlatılıyor…|Starting…)$/mu.test(visibleText) };
                });
            } catch {
                await connect();
                await delay(300);
                continue;
            }
            if (snapshot.installedVersion === "0.4.123" && snapshot.operation === "idle" &&
                snapshot.engineRuntime === "stopped" && snapshot.errorPresent) {
                const messages = await page.evaluate(async () => {
                    const [daemon, onboarding, runtime] = await Promise.all([
                        window.happyDesktop.daemonGet(), window.happyDesktop.onboardingGet(), window.happyDesktop.runtimeGet(),
                    ]);
                    const bounded = value => typeof value === "string" ? value.slice(0, 32768) : "";
                    return { daemon: bounded(daemon.error), onboarding: bounded(onboarding.error ?? onboarding.message),
                        runtime: bounded(runtime.message) };
                });
                report.startFailure = Object.fromEntries(Object.entries(messages).map(([kind, value]) => [kind, classifyWindowsFailure(value)]));
                report.powerShellAcl = await nativeAclProbe(engineHome);
                report.progress.push({ elapsedMs: Date.now() - startedAt, ...snapshot });
                throw Error("Captured normal-mode installed engine start failure.");
            }
            const key = JSON.stringify(snapshot);
            if (key !== lastKey) {
                report.progress.push({ elapsedMs: Date.now() - startedAt, ...snapshot });
                lastKey = key;
            }
            const preparingWithoutDownload = snapshot.preparingText && snapshot.onboardingStage === "daemonDownload" &&
                snapshot.installation === "missing" && snapshot.operation === "idle" && !snapshot.errorPresent && !snapshot.download;
            if (preparingWithoutDownload) waitingSince ??= Date.now();
            else waitingSince = undefined;
            if (EXPECT_REPRO && waitingSince !== undefined && Date.now() - waitingSince >= 25_000) break;
            if (snapshot.runtimePhase === "ready" && snapshot.runningVersion === "0.4.123" &&
                snapshot.engineRuntime === "ready" && snapshot.installedVersion === "0.4.123") break;
            await delay(700);
        }
        engine = join(engineHome, ".happy", "dist", "version", "0.4.123", "happy-agent.exe");
        if (EXPECT_REPRO) {
            assert(waitingSince !== undefined && Date.now() - waitingSince >= 25_000, "Known preparing stall was not reproduced");
            await assert.rejects(lstat(engine), { code: "ENOENT" });
            report.preparingStallReproduced = true;
            report.preparingStallDurationMs = Date.now() - waitingSince;
            await page.screenshot({ path: join(evidence, "fresh-engine-preparing.png"), mask: [page.getByText(username, { exact: true })] });
        } else {
            assert(snapshot?.runtimePhase === "ready" && snapshot.runningVersion === "0.4.123" &&
                snapshot.engineRuntime === "ready" && snapshot.installedVersion === "0.4.123", "Real first-run engine never became ready");
            assert(report.progress.some(row => row.installation === "missing"), "No first-run missing engine state was observed");
            assert(report.progress.some(row => row.operation === "downloading" && row.download?.bytes > 0), "No measured engine download was observed");
            stage = "native engine binary and real renderer readiness";
            const binary = await lstat(engine);
            assert(binary.isFile() && !binary.isSymbolicLink());
            assert.equal((await realpath(engine)).toLowerCase(), engine.toLowerCase());
            assert.equal((await command(engine, ["--version"])).split(/\s+/u).at(-1), "0.4.123");
            report.installedEngineSha256 = await hashFile(engine);
            report.desktopConnected = true;
            report.installedEngineVersion = "0.4.123";
            await page.screenshot({ path: join(evidence, "fresh-engine-ready.png"), mask: [page.getByText(username, { exact: true })] });
        }
        report.success = true;
    } catch (error) {
        report.failedStage = stage;
        report.errors.push("Fresh native engine onboarding did not complete");
        report.commandFailure = error.cyberaiCommand;
        if (page && !page.isClosed()) await page.screenshot({ path: join(evidence, "failure.png"), mask: [page.locator('input[name="username"], input[name="password"]'), page.getByText(username, { exact: true }), page.getByText(/Command failed:|EncodedCommand|happy-agent.exe start/iu)] }).catch(() => undefined);
        process.exitCode = 1;
    } finally {
        if (video) { const value = await video.stop().catch(() => undefined); if (!(value?.framesReceived > 0 && value?.framesWritten > 0)) report.success = false; else report.videos.push(value); }
        try {
            if (engine && (await lstat(engine).catch(() => undefined))?.isFile() &&
                (await realpath(engine).catch(() => "")).toLowerCase() === engine.toLowerCase()) {
                await command(engine, ["stop"], { env: { ...safeEnv, HAPPY_HOME_DIR: join(engineHome, ".happy") } }).catch(() => undefined);
            }
            if (executable?.startsWith(root + sep)) for (const value of (await processes()).filter(value => value.ExecutablePath?.toLowerCase() === executable.toLowerCase())) await command("taskkill.exe", ["/PID", String(value.ProcessId), "/T", "/F"]).catch(() => undefined);
            const cleanupBy = Date.now() + 10000;
            while (executable && Date.now() < cleanupBy && (await processes()).some(value => value.ExecutablePath?.toLowerCase() === executable.toLowerCase())) await delay(100);
            assert(!executable || !(await processes()).some(value => value.ExecutablePath?.toLowerCase() === executable.toLowerCase()), "Owned app cleanup did not finish");
        } catch { report.success = false; report.errors.push("Owned installer/app cleanup failed"); }

        await run; await browser?.close().catch(() => undefined); await save();
    }
    assert(report.success, "Fresh Windows engine onboarding incomplete; inspect automatic-update.json"); console.log(JSON.stringify({ success: true, evidence }));
}
if (process.argv.includes("--self-test")) {
    assert.deepEqual(sanitizedEnvironment({ CYBERAI_USERNAME: "private", CYBERAI_PASSWORD: "private", GH_TOKEN: "private", NODE_OPTIONS: "unsafe", SystemRoot: "C:\\Windows" }), { SystemRoot: "C:\\Windows" });
    assert(rendererClosedDuringUpdate(Error("page.evaluate: Target page, context or browser has been closed\r\nCall log:")));
    assert(rendererClosedDuringUpdate(Error("page.evaluate: Execution context was destroyed, most likely because of a navigation")));
    assert(rendererClosedDuringUpdate(Error("page.evaluate: Protocol error (Runtime.callFunctionOn): Session closed. Most likely the page has been closed.")));
    assert(!rendererClosedDuringUpdate(Error("page.goto: Target page, context or browser has been closed")));
    assert(!rendererClosedDuringUpdate(Error("page.evaluate: Protocol error (Page.navigate): Target closed")));
    assert(!rendererClosedDuringUpdate(Error("permission denied")));
    assert.equal(updateMonitorKind(Error("page.evaluate: Target page, context or browser has been closed"), "process-poll"), "process-poll-error");
    assert.equal(updateMonitorKind({ cyberfiUpdateFailure: "updater-error", message: "page.evaluate: Target page, context or browser has been closed" }, "renderer-poll"), "updater-error");

    assert(publishedReleaseMatches({ id: 1, tag_name: "v" + VERSION, draft: false }, 1, "v" + VERSION));
    assert(!publishedReleaseMatches({ id: 1, tag_name: "v" + VERSION, draft: true }, 1, "v" + VERSION));
    assert(!publishedReleaseMatches({ id: 2, tag_name: "v" + VERSION, draft: false }, 1, "v" + VERSION));

    for (const pin of Object.values(REVIEWED_ARTIFACTS)) artifactPins(pin);
    assert.throws(() => artifactPins({ ...REVIEWED_ARTIFACTS.target, assetId: -1 }));
    assert.throws(() => allowedRedirect("https://api.github.com.evil.test/"));
    assert.throws(() => signedManifest({ sha256: "a".repeat(64), size: 10, signature: "A".repeat(512) }, "bad.exe", "a".repeat(64), 10));
    console.log("Windows fixed pins, redirects and RSA refusal guards passed; no app or network used.");
} else await main();
