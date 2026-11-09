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

const REPOSITORY = "CyberfiTechh/CyberFi-Releases", SOURCE_VERSION = "0.0.129", VERSION = "0.0.130";
const TARGET_INSTALLER = `CyberFi-${VERSION}-x64.exe`;
const SOURCE_COMMIT = "41b2f60fa0e15ce66883c85a7b14fb05b24aaff3";
const exec = promisify(execFile);
// Independent pinned public update-verification key; never trust a key supplied by the artifact.
const PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA09ZxJMbpq1uFEnz7n52M\nAJtceCXVQCo57lgwMAmizgJaGVGsgsMpzqgCCRgXBN+bPygE+16S9XwYOwHDlnNG\noq8h+bE9Nxce3PzsQHrscdHTT1lGQ/5XwSmvzTvxLdURtQWpaXZl7lJghUnZHNDA\n8SOHbk8rQ+butE82lhcq0C+hgJgHTUqFl9Irppi2O+MpufsZo8PX5jphD4H0aX0k\nB9P+LUreoBmG/L3T3AMZEzQZG606awc/ZMYsJcJkt4xNMjR3ZMz1aWKErW2AXDeY\nyfAo0zmEAUEAFSc3UEJRnmBAjorVA3C/rHJzYP7QabSh8ORLOUrqQYgqCpTLETpf\nct0J+NphCLuBGNQ5IeId5IPiBNZlKynGzP/HK+oJTvJ31hTHIiaA+5pfIESXELIZ\nJ5awYGW0y7fii0CqRGwFMJnU829APVvAC9LJUzSSz7NP+2rmc/boYInx8cjN2/LO\nLI9HsPvON+oxM4MhjRxDd4CVoKDpI+rB2TthSdfxt3UxAgMBAAE=\n-----END PUBLIC KEY-----";
const engines = {
    windows: [725557365, "bb54f1d46d3defe4c7678d40729d8952eb44936ca306718c58e0ebf047ae1ab9", "happy-agent-win32-x64.exe"],
    "macos-x64": [725559913, "b74ad8a1cf98d6dda75cb48601c28e4cd265e4a50614cc1d166684ef56e610d8", "happy-agent-darwin-x64"],
    "macos-arm64": [725559914, "20d3c971c7a2f7c044d7dcbd5c276e13de339310a9fd8e904f9d3ccd46e50690", "happy-agent-darwin-arm64"],
};
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
    "source": {
        "releaseId": 438810307,
        "assetId": 726500203,
        "sha256": "cfd08238636ed7d88313225dd45159e113d930ec0a022943c965040ef2c82d66",
        "manifestAssetId": 726515219,
        "manifestSha256": "19ecd45b0f7808e856bba4ac28ebc2f6a0368f7ccf4533f5716392463ec66d3e"
    },
    "target": {
        "releaseId": 439205189,
        "assetId": 727697340,
        "sha256": "9f35e06f2b1373fbf5b6dfea31556fbb76bf3ba48de0e71b37ad84790a6b45b7",
        "manifestAssetId": 727719443,
        "manifestSha256": "40fd8299eefbd46aeee35f41200336aac49b5f3b38de3901d1845aa471e02462"
    }
};
async function main() {
    const target = process.env.TARGET;
    assert(target === "windows", "Only Windows update target is supported");
    const windows = target === "windows", arch = target === "macos-arm64" ? "arm64" : "x64";
    assert(process.platform === (windows ? "win32" : "darwin") && process.arch === arch && process.env.GITHUB_ACTIONS === "true" && process.env.RUNNER_ENVIRONMENT === "github-hosted" && process.env.GITHUB_REPOSITORY === REPOSITORY && process.env.GITHUB_REF === "refs/heads/codex/windows-stable-130-discovery", "Only the selected disposable native runner may execute acceptance");
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
    const report = { success: false, sourceVersion: SOURCE_VERSION, targetVersion: VERSION, sourceCommit: SOURCE_COMMIT,
        progress: [], events: [], videos: [], errors: [], limits: ["Only the installed source is launched. The test stops after the stable target is offered and does not install it.", "No OS trust-store changes; RSA pins and Authenticode CMS are checked independently."] };
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

    let executable, runtime, inference, inferenceToken, paths, browser, page, video, run, runResult, runError, watcher, visibilityDone, watcherStop, newPid, verifiedInstaller, stopWatch = false, monitor, monitorError;
    let stage = "published artifacts", rendererDetached = false, monitorPhase = "process-poll";
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
        // Hidden mode intentionally leaves Electron's default userData: appData/app.getName(), app name CyberFi.
        // The source and target packages use this same hidden-mode contract.
        profile = join(roaming, "CyberFi");
        for (const path of [profile, join(roaming, "PDR Koçum Agent"), join(nativeHome, ".pdr-kocum-agent"), join(nativeHome, ".agents/skills")]) await assert.rejects(lstat(path), { code: "ENOENT" });
        await mkdir(profile); assert.equal((await realpath(profile)).toLowerCase(), profile.toLowerCase());
        report.defaultProfileOwnership = { path: profile, canonicalRoaming: roaming, canonicalHome: nativeHome, sid: nativeIdentity.sid, initiallyAbsent: true, disposableHostedRunnerOnly: true, defaultProfileContract: "Hidden mode appData/CyberFi" };
        const artifacts = {};
        for (const [kind, version] of [["source", SOURCE_VERSION], ["target", VERSION]]) {
            const pin = pins[kind], release = await api(`repos/${REPOSITORY}/releases/${pin.releaseId}`);
            assert(publishedReleaseMatches(release, pin.releaseId, "v" + version), "Both exact Windows releases must be published");
            if (kind === "target") assert.equal(release.prerelease, false, "The reviewed target must be public stable");
            const filename = `CyberFi-${version}-x64.exe`, asset = release.assets.find(item => item.id === pin.assetId), manifest = release.assets.find(item => item.id === pin.manifestAssetId);
            assert(asset?.name === filename && asset.digest === "sha256:" + pin.sha256 && asset.state === "uploaded");
            assert(manifest?.name === filename + ".update.json" && manifest.digest === "sha256:" + pin.manifestSha256 && manifest.size <= 4096);
            const path = join(root, filename), manifestPath = path + ".update.json";
            await download(REPOSITORY, manifest, manifestPath);
            assert.equal(await hashFile(manifestPath), pin.manifestSha256);
            const signed = JSON.parse((await readFile(manifestPath, "utf8")).replace(/^\uFEFF/u, ""));
            assert(signed.sha256 === pin.sha256 && signed.size === asset.size && verify("sha256", Buffer.from(`${version}\n${filename}\n${pin.sha256}\n${asset.size}\n`), PUBLIC_KEY, Buffer.from(signed.signature, "base64")), "Pinned versioned RSA manifest invalid");
            if (kind === "source") {
                await download(REPOSITORY, asset, path);
                assert.equal(await hashFile(path), pin.sha256);
                artifacts.source = { path, signature: await windowsSignature(path) };
            } else report.stableTarget = { releaseId: release.id, assetId: asset.id, manifestAssetId: manifest.id, sha256: pin.sha256, signedManifestVerified: true };
        }
        stage = "real source NSIS installation";
        const installation = join(applications, "CyberFi"); await mkdir(installation);
        // Real per-user NSIS installation, not archive extraction. No trust certificate is installed.
        await command(artifacts.source.path, ["/S", "/D=" + installation], { timeout: 180000 });
        executable = join(installation, "CyberFi.exe"); assert(executable.startsWith(root + sep));
        assert.equal(await powershell(`(Get-Item -LiteralPath ${quote(executable)}).VersionInfo.ProductVersion`), SOURCE_VERSION + ".0");
        report.sourceSignature = await windowsSignature(executable);
            watcherStop = join(root, "visibility-stop");
            const watcherSource = `$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public class CyberAiWindowProof {
 public delegate bool EnumWindow(IntPtr h, IntPtr p);
 [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindow f, IntPtr p);
 [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
 [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint p);
 [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
}
'@
$known=[Collections.Generic.HashSet[int]]::new();$samples=0;$onscreen=0;$active=0;$windows=0
[Console]::Error.WriteLine('ready')
while(-not (Test-Path -LiteralPath $env:WATCH_STOP)) {
 $samples++
 @(Get-CimInstance Win32_Process -Filter "Name='CyberFi.exe'" | Where-Object { $_.ExecutablePath -eq $env:WATCH_EXE -and -not $_.CommandLine.Contains('--type=') }) | ForEach-Object { [void]$known.Add([int]$_.ProcessId) }
 $foreground=[CyberAiWindowProof]::GetForegroundWindow();$fgPid=[uint32]0;[void][CyberAiWindowProof]::GetWindowThreadProcessId($foreground,[ref]$fgPid)
 if($known.Contains([int]$fgPid)) { $active++ }
 $script:sampleWindows=0;$script:sampleVisible=0
 $callback=[CyberAiWindowProof+EnumWindow]{param($h,$p) $ownerPid=[uint32]0;[void][CyberAiWindowProof]::GetWindowThreadProcessId($h,[ref]$ownerPid);if($known.Contains([int]$ownerPid)){ $script:sampleWindows++;if([CyberAiWindowProof]::IsWindowVisible($h)){ $script:sampleVisible++ }};return $true }
 [void][CyberAiWindowProof]::EnumWindows($callback,[IntPtr]::Zero)
 $onscreen+=$script:sampleVisible;$windows=[Math]::Max($windows,$script:sampleWindows)
 if($script:sampleVisible -gt 0 -or $known.Contains([int]$fgPid)) {
  @(Get-CimInstance Win32_Process -Filter "Name='CyberFi.exe'" | Where-Object { $_.ExecutablePath -eq $env:WATCH_EXE }) | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
  break
 }
 Start-Sleep -Milliseconds 75
}
@{samples=$samples;systemWindowsMax=$windows;onscreenSamples=$onscreen;activeSamples=$active;pids=@($known)}|ConvertTo-Json -Depth 4 -Compress`;
            watcher = spawn(ps, ["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(watcherSource, "utf16le").toString("base64")], { env: { ...nativePsEnvironment, WATCH_EXE: executable, WATCH_PROFILE: profile, WATCH_STOP: watcherStop }, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
            let output = ""; watcher.stdout.on("data", value => { output += value; });
            visibilityDone = new Promise((done, reject) => { watcher.on("error", reject); watcher.on("close", code => code === 0 ? done(JSON.parse(output)) : reject(Error("Visibility watcher failed"))); }); visibilityDone.catch(() => undefined);
            await watcherReady(watcher);
            visibilityDone.then(value => { if (value.onscreenSamples > 0 || value.activeSamples > 0) monitorError = Error("Owned window became visible or focused and was stopped"); }, () => { monitorError = Error("Native visibility observer failed"); });
        stage = "owned engine fixture";
        const engineRelease = await api("repos/CyberfiTechh/CyberFi-Engine/releases/438601789"), [engineId, engineSha, engineName] = engines[target];
        assert(engineRelease.tag_name === "v0.4.120" && !engineRelease.draft && !engineRelease.prerelease);
        const engineAsset = engineRelease.assets.find(item => item.id === engineId); assert.equal(engineAsset?.digest, "sha256:" + engineSha);
        const archive = join(root, "engine.tar.gz"), engineRoot = join(root, "engine"); await mkdir(engineRoot);
        stage = "owned engine archive download";
        await download("CyberfiTechh/CyberFi-Engine", engineAsset, archive); assert.equal(await hashFile(archive), engineSha);
        // Git Bash's GNU tar can interpret a Windows drive prefix as a remote
        // archive. Select the OS-native extractor explicitly on both platforms.
        const tar = windows ? join(environmentValue(safeEnv, "SystemRoot"), "System32/tar.exe") : "/usr/bin/tar";
        report.engineArchiveExtractor = windows ? "Windows System32 tar" : "/usr/bin/tar";
        stage = "owned engine archive extraction";
        assert.equal(await command(tar, ["-tzf", archive]), engineName); await command(tar, ["-xzf", archive, "-C", engineRoot]);
        const engine = join(engineRoot, engineName); process.env.HAPPY_DESKTOP_AGENT_EXECUTABLE = engine;
        stage = "owned engine version verification";
        assert.equal((await command(engine, ["--version"])).split(/\s+/u).at(-1), "0.4.120");
        stage = "upstream gym import and isolated paths";
        const gym = name => pathToFileURL(join(upstream, "packages/happy-desktop-gym/sources/electron", name + ".ts")).href;
        const { gymElectronProcessRun, gymElectronVideoRecord } = await import(gym("launch"));
        const { gymRunPathsCreate } = await import(gym("paths"));
        const { gymHostEnvironment } = await import(gym("hostEnvironment"));
        const { happyAgentClientCreate, GymHappyAgentClient } = await import(gym("happyAgentProtocol"));
        ({ paths } = await gymRunPathsCreate("smoke"));
        stage = "production managed engine cache precondition";
        const desktopMain = name => pathToFileURL(join(upstream, "packages/happy-desktop-electron/sources/main", name + ".ts")).href;
        const { happyDaemonPaths, happyAgentBinaryPath } = await import(desktopMain("happyAgentBinaryPaths"));
        const { happyAgentBinarySelected } = await import(desktopMain("happyAgentBinaryConfig"));
        const { happyAgentReleaseInstall } = await import(desktopMain("happyAgentRelease"));
        const cachePaths = happyDaemonPaths({ HAPPY_HOME_DIR: paths.happyHome }, paths.home);
        const cachedEngine = happyAgentBinaryPath(cachePaths, "0.4.120");
        assert(cachedEngine.startsWith(paths.root + sep) && cachePaths.binaryConfigPath.startsWith(paths.root + sep));
        await mkdir(dirname(cachedEngine), { recursive: true, mode: 0o700 });
        await copyFile(engine, cachedEngine, constants.COPYFILE_EXCL); await chmod(cachedEngine, 0o700);
        const extractedBinarySha = await hashFile(engine); assert.equal(await hashFile(cachedEngine), extractedBinarySha);
        // Consume verified cached bytes through the normal lock/data-floor/
        // atomic-selection producer. No fetch interception or forged status.
        const installed = await happyAgentReleaseInstall({ version: "0.4.120", archivedBinaryName: engineName, asset: engineAsset }, cachePaths);
        assert(installed.version === "0.4.120" && installed.path === cachedEngine);
        assert.deepEqual(await happyAgentBinarySelected(cachePaths), installed);
        assert.equal((await command(cachedEngine, ["--version"])).split(/\s+/u).at(-1), "0.4.120");
        const cacheConfig = JSON.parse(await readFile(cachePaths.binaryConfigPath, "utf8"));
        assert.deepEqual(cacheConfig, { downloadedVersions: ["0.4.120"], selectedVersion: "0.4.120" });
        report.managedEnginePrecondition = { producer: "pinned upstream happyAgentReleaseInstall consuming verified cached bytes", version: installed.version, executableSha256: extractedBinarySha, config: cacheConfig, fetchOverridden: false, dataVersionFabricated: false };

        inferenceToken = randomBytes(24).toString("hex"); let inferenceCalls = 0;
        inference = createServer(async (request, response) => {
            for await (const _ of request) { /* Synthetic inputs are never logged. */ }
            if (request.headers.authorization !== "Bearer " + inferenceToken) { response.writeHead(401); response.end(); return; }
            inferenceCalls++; response.writeHead(200, { "content-type": "application/json" });
            response.end(JSON.stringify({ content: [{ type: "text", text: "Native CyberAI chat acceptance confirmed." }], completionDelayMs: 1 }));
        });
        await new Promise(done => inference.listen(0, "127.0.0.1", done));
        const systemNames = new Set(["path", "systemroot", "windir", "comspec", "pathext", "psmodulepath", "systemdrive", "programfiles", "programfiles(x86)", "programw6432", "commonprogramfiles", "commonprogramfiles(x86)", "commonprogramw6432", "programdata", "allusersprofile", "public", "userdomain", "userdnsdomain", "username", "computername", "os", "processor_architecture", "processor_identifier", "number_of_processors", "sessionname", "temp", "tmp"]);
        const systemEnv = Object.fromEntries(Object.entries(safeEnv).filter(([key]) => systemNames.has(key.toLowerCase())));
        const engineEnv = { ...systemEnv, ...gymHostEnvironment(paths), HAPPY_HOME_DIR: paths.happyHome, HAPPY_AGENT_PROJECTS_DIRECTORY: paths.projects, HAPPY_AGENT_WORKSPACES_DIRECTORY: paths.workspaces, HAPPY_AGENT_SERVER_SOCKET_PATH: paths.socketPath, HAPPY_AGENT_SERVER_TOKEN_PATH: paths.tokenPath, HAPPY_GYM_INFERENCE_URL: `http://127.0.0.1:${inference.address().port}/inference`, HAPPY_GYM_TOKEN: inferenceToken };
        if (windows) {
            // The paired native probe proved the runner's inherited Core module
            // path breaks Windows PowerShell5 after HOME isolation. Keep the
            // real engine ACL initializer and supply its native system modules.
            const moduleKey = Object.keys(engineEnv).find(key => key.toLowerCase() === "psmodulepath") ?? "PSModulePath";
            const modules = [join(environmentValue(safeEnv, "SystemRoot"), "System32/WindowsPowerShell/v1.0/Modules"), join(environmentValue(safeEnv, "ProgramFiles"), "WindowsPowerShell/Modules")];
            engineEnv[moduleKey] = modules.join(";");
            report.engineEnvironmentCalibration = { nativeWindowsPowerShellModules: modules, inheritedModulePathReplaced: true, privateDirectoryAclBypassed: false };
        }
        stage = "owned engine fixture";
        const config = join(paths.root, windows ? "happy/config" : "Happy/Config"); await mkdir(config, { recursive: true });
        for (const name of [".config", ".cache", ".local/share", ".local/state", "AppData/Local", "AppData/Roaming"]) await mkdir(join(paths.home, name), { recursive: true });
        await writeFile(join(config, "happy.toml"), '[settings]\nhappy_integration = false\nmenu_bar = false\n\n[providers.codex]\ntype = "codex"\nenabled = true\ncredential_isolation = true\n');
        const stop = () => command(engine, ["stop"], { cwd: paths.root, env: engineEnv }).catch(() => undefined);
        // Windows AF_UNIX sun_path has room for 107 bytes plus the terminator.
        assert(Buffer.byteLength(join(paths.happyHome, "agent", "h.sock")) <= 107, "Owned fixture exceeds the Windows engine socket path limit");
        stage = "owned engine daemon startup";
        runtime = { stop };
        const engineStart = Date.now();
        try { await command(engine, ["start"], { cwd: paths.root, env: engineEnv }); }
        finally { report.engineStartElapsedMs = Date.now() - engineStart; }
        stage = "owned engine authenticated health";
        let client; const healthDeadline = Date.now() + 30000;
        while (Date.now() < healthDeadline) {
            try { client = happyAgentClientCreate(paths.socketPath, (await readFile(paths.tokenPath, "utf8")).trim()); await client.getHealth(); break; } catch { client = undefined; await delay(150); }
        }
        assert(client, "Fixture engine health unavailable"); stage = "synthetic workspace chat fixture";
        const fixtureClient = new GymHappyAgentClient(paths.socketPath, (await readFile(paths.tokenPath, "utf8")).trim());
        const repository = join(paths.projects, "native-login-chat"); await mkdir(repository);
        const gitEnv = { ...systemEnv, ...gymHostEnvironment(paths), GIT_CONFIG_GLOBAL: windows ? "NUL" : "/dev/null", GIT_CONFIG_NOSYSTEM: "1" };
        stage = "fixture Git repository initialization";
        await command("git", ["init", "--initial-branch=main", repository], { env: gitEnv });
        await writeFile(join(repository, "README.md"), "# Disposable native login acceptance\n");
        await command("git", ["-C", repository, "add", "README.md"], { env: gitEnv });
        await command("git", ["-C", repository, "-c", "user.name=CyberAI CI", "-c", "user.email=ci@example.invalid", "commit", "-m", "Owned fixture"], { env: gitEnv });
        stage = "fixture project registration";
        const { project } = await fixtureClient.registerProject(repository);
        stage = "fixture workspace readiness"; await fixtureClient.waitForWorkspace(project.id, "ready", 90000);
        stage = "fixture agent creation";
        const { agent } = await fixtureClient.createAgent(project.id);
        stage = "fixture local-only chat send";
        const turn = await fixtureClient.sendMessage(agent.id, "Confirm this synthetic native chat acceptance.");
        stage = "fixture local-only chat completion";
        await fixtureClient.waitForAgentIdle(agent.id, turn.runId, 60000); assert(inferenceCalls > 0, "The local-only inference fixture was not exercised");
        const configDir = join(profile, "desktop"); await mkdir(configDir);
        await writeFile(join(configDir, "local-onboarding.json"), JSON.stringify({ version: 3, chiefOfStaffSetup: true }));
        await writeFile(join(configDir, "config.json"), JSON.stringify({ appearance: "dark", defaultPermissionMode: "read_only", previewUpdatesEnabled: false }));
        const sentinels = [[join(configDir, "retained-user-note.txt"), "Keep profile settings.\n"], [join(nativeHome, ".agents/skills/retained/SKILL.md"), "# Existing skill\nKeep exact content.\n"]];
        for (const [path, text] of sentinels) { await mkdir(dirname(path), { recursive: true }); await writeFile(path, text); }

        const require = createRequire(join(upstream, "packages/happy-desktop-gym/package.json")), { chromium } = require("playwright");
        const port = 19486, endpoint = `http://127.0.0.1:${port}`;
        async function listenerPid() {
            const text = await powershell(`@(Get-NetTCPConnection -LocalAddress 127.0.0.1 -LocalPort ${port} -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique) | ConvertTo-Json -Compress`);
            const values = text ? JSON.parse(text) : [], list = Array.isArray(values) ? values : [values]; assert(list.length <= 1); return list.length ? id(list[0]) : undefined;
        }
        assert.equal(await listenerPid(), undefined);
        const env = { ...safeEnv, ...engineEnv, HOME: environmentValue(safeEnv, "USERPROFILE"), USERPROFILE: environmentValue(safeEnv, "USERPROFILE"), APPDATA: environmentValue(safeEnv, "APPDATA"), LOCALAPPDATA: environmentValue(safeEnv, "LOCALAPPDATA"), TEMP: environmentValue(safeEnv, "TEMP"), TMP: environmentValue(safeEnv, "TMP"), HAPPY_DESKTOP_WINDOWS_HIDDEN: "1", HAPPY_DESKTOP_DEBUG: "1", HAPPY_DEBUG_RENDERER_PORT: String(port) };
        run = gymElectronProcessRun({ executablePath: executable, args: ["--user-data-dir=" + profile, "--debug"], env, timeout: 15 * 60000 }).then(value => { runResult = value; }, error => { runError = error; });
        async function connect() {
            const until = Date.now() + 90000;
            while (Date.now() < until) {
                try { const response = await fetch(endpoint + "/json/list", { signal: AbortSignal.timeout(1500) }); if (response.ok && (await response.json()).some(item => item.type === "page")) {
                    browser = await chromium.connectOverCDP(endpoint); page = browser.contexts().flatMap(value => value.pages()).find(value => !value.url().startsWith("devtools:"));
                    if (page) { await page.waitForFunction(() => typeof window.happyDesktop?.runtimeGet === "function"); return; }
                } } catch { /* Approved debug endpoint only. */ }
                await delay(200);
            }
            throw Error("Automatic target failed to retain approved hidden/debug endpoint; target was not manually launched");
        }
        await connect();
        video = await gymElectronVideoRecord(page, { path: join(evidence, "actual-source-update.webm"), fps: 5 });
        await page.evaluate(() => { localStorage.setItem("pdr-kocum-agent.language", "tr"); localStorage.setItem("happy.welcome.v1", JSON.stringify({ welcomeAcknowledged: true })); });
        await page.reload({ waitUntil: "commit" });
        stage = "source protected login";
        await page.waitForFunction(() => !document.querySelector('[data-testid="desktop-startup-screen"]') && !!document.querySelector('[data-happy-desktop-ui="cyberfi-account-login"] input[name="password"]:not(:disabled)'), undefined, { timeout: 60000 });
        await page.addStyleTag({ content: 'input[name="username"], input[name="password"] { color: transparent !important; text-shadow: none !important; caret-color: transparent !important; }' });
        const sourceLogin = page.locator('[data-happy-desktop-ui="cyberfi-account-login"]');
        assert(await page.evaluate(async () => { try { await window.happyDesktop.runtimeGet(); return false; } catch { return true; } }), "Source must deny privileged IPC before login");
        await sourceLogin.locator('input[name="username"]').fill(username); await sourceLogin.locator('input[name="password"]').fill(password);
        assert.equal(await sourceLogin.getByRole("checkbox", { name: "Beni hatırla" }).isChecked(), false);
        await sourceLogin.getByRole("button", { name: "Giriş yap", exact: true }).click();
        await page.waitForFunction(async () => (await window.happyDesktop.cyberFiAccountGet()).status === "signedIn", undefined, { timeout: 60000 });
        const sourceAccount = await page.evaluate(() => window.happyDesktop.cyberFiAccountGet());
        assert(sourceAccount.user?.role === "user" && sourceAccount.remember === false && sourceAccount.username === username);
        await assert.rejects(lstat(join(configDir, "cyberai-account.json")), { code: "ENOENT" });
        report.sourceAuthenticated = true;
        const readyUntil = Date.now() + 90000; let startedLocally = false;
        while (Date.now() < readyUntil) {
            if ((await page.evaluate(() => window.happyDesktop.runtimeGet())).phase === "ready") break;
            const start = page.getByRole("button", { name: /^(Start locally|Bu bilgisayarda başlat)$/iu }); if (!startedLocally && await start.isVisible().catch(() => false)) { await start.click(); startedLocally = true; }
            await delay(250);
        }
        assert.equal((await page.evaluate(() => window.happyDesktop.runtimeGet())).phase, "ready");
        const oldPid = await listenerPid(); id(oldPid); report.oldPid = oldPid;
        stage = "stable-only GUI desktop update check";
        await page.locator('[data-happy-desktop-ui="sidebar-footer"]').getByRole("button", { name: /^(Settings|Ayarlar|Open settings|Ayarları aç)$/iu }).click();
        const general = page.getByRole("button", { name: /^(General|Genel)$/iu }).first();
        if (await general.count()) await general.click();
        const preview = page.locator("#happy-agent-settings-preview-updates");
        await preview.waitFor({ state: "visible", timeout: 60000 });
        const previewEnabled = () => page.evaluate(async () => (await window.happyDesktop.desktopConfigGet()).previewUpdatesEnabled);
        assert.equal(await preview.getAttribute("aria-checked"), "false");
        assert.notEqual(await previewEnabled(), true);
        const configPath = join(configDir, "config.json");
        assert.equal(JSON.parse(await readFile(configPath, "utf8")).previewUpdatesEnabled, false);
        const desktopControls = page.locator(".happy-agent-settings__desktop-control");
        const select = desktopControls.locator("#cyberfi-settings-desktop-version");
        await select.waitFor({ state: "visible", timeout: 60000 });
        const check = desktopControls.getByRole("button", { name: /^(Check for updates|Güncellemeleri denetle)$/iu });
        assert.equal(await check.count(), 1);
        await check.click();
        await page.waitForFunction(async version => {
            const update = (await window.happyDesktop.runtimeGet()).update;
            return update?.status === "available" && update.availableVersion === version &&
                update?.versions?.some(value => value.version === version) &&
                !!document.querySelector('#cyberfi-settings-desktop-version option[value="' + version + '"]');
        }, VERSION, { timeout: 60000 });
        assert.equal(await preview.getAttribute("aria-checked"), "false");
        assert.notEqual(await previewEnabled(), true);
        const offer = desktopControls.getByRole("button", { name: /^(Download and reopen|İndir ve yeniden aç)$/iu });
        await offer.waitFor({ state: "visible", timeout: 15000 });
        const option = select.locator('option[value="' + VERSION + '"]');
        assert.equal(await option.count(), 1);
        const label = await option.textContent();
        assert.match(label, /^v0[.]0[.]130(?: · |$)/u);
        assert.equal(await listenerPid(), oldPid);
        assert.equal(await powershell(`(Get-Item -LiteralPath ${quote(executable)}).VersionInfo.ProductVersion`), SOURCE_VERSION + ".0");
        assert(!(await processes()).some(value => value.Name === TARGET_INSTALLER));
        await page.screenshot({ path: join(evidence, "stable-update-offer.png"), mask: [page.getByText(username, { exact: true })] });
        report.previewUpdatesEnabled = false;
        report.desktopCheckClicked = true;
        report.targetOffered = true;
        report.downloadAndReopenOffered = true;
        report.targetOptionLabel = label;
        report.sourceStillRunning = true;
        report.targetInstallationStarted = false;
        report.success = true;
    } catch (error) {
        report.failedStage = stage; report.errors.push("Native update acceptance failed"); report.commandFailure = error.cyberaiCommand;
        if (stage === "owned engine daemon startup" && error?.cyberaiCommand?.tool === engines.windows[2] && error.cyberaiCommand.verb === "start") {
            const logPath = join(paths.happyHome, "agent", "daemon.log");
            const log = await lstat(logPath).catch(() => undefined);
            const content = log?.isFile() && !log.isSymbolicLink() && log.size <= 65536 && await realpath(logPath).catch(() => undefined) === logPath
                ? await readFile(logPath, "utf8").catch(() => "") : "";
            const stderr = String(error.stderr ?? "");
            report.engineStartupDiagnostic = {
                logBytes: log?.size ?? null,
                stderrBytes: Buffer.byteLength(stderr),
                readinessTimeout: /timed out (?:while starting|waiting for)/iu.test(stderr),
                childExit: /daemon failed to start \(exit code (-?[0-9]+)\)/iu.exec(stderr)?.[1] ?? null,
                aclFailure: /SetAccessControl|HAPPY_PRIVATE_DIRECTORY|UnauthorizedAccessException|AccessDenied/iu.test(content + stderr),
                configFailure: /Invalid configuration|TOML parse|failed to parse/iu.test(content + stderr),
                nativeLaunchFailure: /LoadLibrary|unable to open library|DLL_INIT_FAILED|failed to spawn|embedded.{0,40}(?:error|failed)/iu.test(content + stderr),
                socketFailure: /failed to bind|socket.{0,40}(?:already|invalid|error)/iu.test(content + stderr),
                codes: [...new Set((content + stderr).match(/\b(?:EADDRINUSE|EACCES|EPERM|ENOENT|ENAMETOOLONG|EINVAL|ENOTSUP|WSAEINVAL|WSAEACCES|ERR_[A-Z_]{3,45})\b/gu) ?? [])],
            };
        }
        report.handoffDiagnostic = {
            failureCode: monitorError ? "update-monitor-failed" : runError ? "source-launcher-failed" : "acceptance-assertion-failed",
            monitorKind: report.monitorKind ?? null,
            exitCode: Number.isSafeInteger(runResult?.exitCode) ? runResult.exitCode : null,
            signal: typeof runResult?.signal === "string" && /^SIG[A-Z0-9]+$/u.test(runResult.signal) ? runResult.signal : null,
            oldAlive: Number.isSafeInteger(report.oldPid) ? alive(report.oldPid) : null,
            pageClosed: page ? page.isClosed() : null,
            cdpConnected: browser ? browser.isConnected() : null,
            rendererPollingStopped: rendererDetached,
        };
        if (page && !page.isClosed()) await page.screenshot({ path: join(evidence, "failure.png"), mask: [page.locator('input[name="username"], input[name="password"]'), page.getByText(username, { exact: true })] }).catch(() => undefined);
        process.exitCode = 1;
    } finally {
        stopWatch = true; await monitor;
        if (video) { const value = await video.stop().catch(() => undefined); if (!(value?.framesReceived > 0 && value?.framesWritten > 0)) report.success = false; else report.videos.push(value); }
        // Keep the native observer active until the installer cannot launch
        // another target and every exact owned app process has terminated.
        try {
            for (const value of (await processes()).filter(value => value.Name === TARGET_INSTALLER && value.ParentProcessId === report.oldPid && /--updated/u.test(value.CommandLine ?? "") && /--force-run/u.test(value.CommandLine ?? ""))) {
                assert(value.ExecutablePath?.toLowerCase().includes("cyberfi-update-"));
                assert.equal(await hashFile(value.ExecutablePath), pins.target.sha256); await windowsSignature(value.ExecutablePath);
                if (verifiedInstaller) assert(value.ProcessId === verifiedInstaller.ProcessId && value.CreationDate === verifiedInstaller.CreationDate);
                const current = (await processes()).find(item => item.ProcessId === value.ProcessId);
                if (current && current.ExecutablePath === value.ExecutablePath && current.CreationDate === value.CreationDate) await command("taskkill.exe", ["/PID", String(value.ProcessId), "/T", "/F"]);
            }
            if (executable?.startsWith(root + sep)) for (const value of (await processes()).filter(value => value.ExecutablePath?.toLowerCase() === executable.toLowerCase())) await command("taskkill.exe", ["/PID", String(value.ProcessId), "/T", "/F"]).catch(() => undefined);
            const cleanupBy = Date.now() + 10000;
            while (executable && Date.now() < cleanupBy && (await processes()).some(value => value.ExecutablePath?.toLowerCase() === executable.toLowerCase())) await delay(100);
            assert(!executable || !(await processes()).some(value => value.ExecutablePath?.toLowerCase() === executable.toLowerCase()), "Owned app cleanup did not finish");
        } catch { report.success = false; report.errors.push("Owned installer/app cleanup failed"); }
        if (watcher) { await writeFile(watcherStop, "stop\n"); report.visibility = await visibilityDone.catch(() => undefined);
            if (!(report.visibility?.samples > 0 && report.visibility.systemWindowsMax > 0 && report.visibility.pids?.includes(report.oldPid) && report.visibility.onscreenSamples === 0 && report.visibility.activeSamples === 0)) report.success = false; }
        if (report.videos.length !== 1) report.success = false;
        await run; await browser?.close().catch(() => undefined); await runtime?.stop(); await new Promise(done => inference ? inference.close(done) : done()); await save();
    }
    assert(report.success, "Stable Windows update discovery incomplete; inspect automatic-update.json"); console.log(JSON.stringify({ success: true, evidence }));
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
    assert(!publishedReleaseMatches({ id: 1, tag_name: "v" + SOURCE_VERSION, draft: false }, 1, "v" + VERSION));
    for (const pin of Object.values(REVIEWED_ARTIFACTS)) artifactPins(pin);
    assert.throws(() => artifactPins({ ...REVIEWED_ARTIFACTS.source, assetId: -1 }));
    assert.throws(() => allowedRedirect("https://api.github.com.evil.test/"));
    assert.throws(() => signedManifest({ sha256: "a".repeat(64), size: 10, signature: "A".repeat(512) }, "bad.exe", "a".repeat(64), 10));
    console.log("Windows fixed pins, redirects and RSA refusal guards passed; no app or network used.");
} else await main();
