import assert from "node:assert/strict";
import { createHash, verify, randomBytes } from "node:crypto";
import { constants, createReadStream, createWriteStream } from "node:fs";
import { chmod, copyFile, mkdir, readFile, readdir, realpath, writeFile, lstat, stat } from "node:fs/promises";
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

const REPOSITORY = "CyberfiTechh/CyberFi-Releases", VERSION = "0.0.125";
const SOURCE_COMMIT = "ac2f66476304f69e39913d5726b34f65ea7698ab";
const exec = promisify(execFile);
// Independent pinned public update-verification key; never trust a key supplied by the artifact.
const PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA09ZxJMbpq1uFEnz7n52M\nAJtceCXVQCo57lgwMAmizgJaGVGsgsMpzqgCCRgXBN+bPygE+16S9XwYOwHDlnNG\noq8h+bE9Nxce3PzsQHrscdHTT1lGQ/5XwSmvzTvxLdURtQWpaXZl7lJghUnZHNDA\n8SOHbk8rQ+butE82lhcq0C+hgJgHTUqFl9Irppi2O+MpufsZo8PX5jphD4H0aX0k\nB9P+LUreoBmG/L3T3AMZEzQZG606awc/ZMYsJcJkt4xNMjR3ZMz1aWKErW2AXDeY\nyfAo0zmEAUEAFSc3UEJRnmBAjorVA3C/rHJzYP7QabSh8ORLOUrqQYgqCpTLETpf\nct0J+NphCLuBGNQ5IeId5IPiBNZlKynGzP/HK+oJTvJ31hTHIiaA+5pfIESXELIZ\nJ5awYGW0y7fii0CqRGwFMJnU829APVvAC9LJUzSSz7NP+2rmc/boYInx8cjN2/LO\nLI9HsPvON+oxM4MhjRxDd4CVoKDpI+rB2TthSdfxt3UxAgMBAAE=\n-----END PUBLIC KEY-----";
const engines = {
    windows: [723457133, "b4a0afb9b619ba24f59f7071a34dc892a29c4ff2909845c9cf3b912dfec5d03c", "happy-agent-win32-x64.exe"],
    "macos-x64": [723463097, "512bbe2b6eabe31121703b81e30a916b29c7a95cadb9ea8dd486bbdab16211ad", "happy-agent-darwin-x64"],
    "macos-arm64": [723463093, "708418ebdfa9066a3b54c9f089d4e9e079f21ec3347ff6198668d6f32d7d5f77", "happy-agent-darwin-arm64"],
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
function engineDiagnosticText(value, secrets) {
    let text = String(value ?? "").replace(/\x1b\[[0-9;]*m/gu, "");
    for (const secret of secrets.filter(value => typeof value === "string" && value.length > 0)) text = text.replaceAll(secret, "[REDACTED]");
    text = text.replace(/\bBearer\s+[^\s"'<>]+/giu, "Bearer [REDACTED]")
        .replace(/(["']?\b(?:token|password|secret|api[_-]?key)["']?\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;]+)/giu, "$1[REDACTED]")
        .split(/\r?\n/u).filter(line => !/token|password|secret|credential|api[_-]?key|bearer|authorization|cookie/iu.test(line) && !/^\s*(?:headers|request body|response body|HTTP\/\d)\s*[:= ]/iu.test(line) && !/^\s*[\{\[]["\{\[]/u.test(line)).join("\n");
    return Buffer.from(text).subarray(0, 4096).toString("utf8");
}
function dialogErrorFirstLine(value) { return String(value ?? "").split(/\r?\n/u, 1)[0].trim(); }
function knownNoDialogRace(value) {
    return /^(?:dialog\.dismiss: )?Protocol error \(Page\.handleJavaScriptDialog\): No dialog is showing\.?$/u.test(dialogErrorFirstLine(value));
}

async function main() {
    const target = process.env.TARGET;
    assert(Object.hasOwn(engines, target), "Unknown native target");
    const windows = target === "windows", arch = target === "macos-arm64" ? "arm64" : "x64";
    assert(process.platform === (windows ? "win32" : "darwin") && process.arch === arch && process.env.GITHUB_ACTIONS === "true" && process.env.RUNNER_ENVIRONMENT === "github-hosted" && process.env.GITHUB_REPOSITORY === REPOSITORY && process.env.GITHUB_REF === "refs/heads/main", "Only the selected disposable native runner may execute acceptance");
    const pins = artifactPins(JSON.parse(process.env.ACCEPTANCE_ARTIFACTS));
    assert.equal(process.env.ACCEPTANCE_SOURCE_SHA, SOURCE_COMMIT, "Unexpected reviewed source provenance");
    // These lexical variables are never passed to child processes or serialized.
    const token = process.env.GH_TOKEN, username = process.env.CYBERAI_USERNAME, password = process.env.CYBERAI_PASSWORD;
    assert(username && username !== "admin" && password && password.length >= 8, "Disposable role-user credentials are required");
    const safeEnv = sanitizedEnvironment(process.env);
    for (const key of Object.keys(process.env)) if (!Object.hasOwn(safeEnv, key)) delete process.env[key];
    const upstream = await realpath(process.argv[2]);
    assert.equal(upstream, join(resolve(process.env.GITHUB_WORKSPACE), "upstream"));
    const root = join(await realpath(process.env.RUNNER_TEMP), "cyberfi-native-login"); await mkdir(root);
    const evidence = join(root, "evidence"), profile = join(root, "user-data"), applications = join(root, "Applications");
    await Promise.all([evidence, profile, applications].map(path => mkdir(path)));
    const report = { success: false, platform: target, version: VERSION, sourceCommit: SOURCE_COMMIT, sourceCommitEvidence: "reviewed-build-provenance", artifact: pins, checks: {}, videos: [], errors: [], limits: ["Packaged app does not embed source attestation; source commit is bound through reviewed build provenance and exact independently RSA-verified asset pins.", "CI does not certify browser-download Gatekeeper trust.", "macOS hidden startup may transiently have a regular Dock activation policy; only no onscreen window and no focus are certified here."] };
    const save = () => writeFile(join(evidence, "cyberai-login.json"), JSON.stringify(report, null, 2) + "\n");
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
    const powershell = script => command(ps, ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script]);
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
    async function findFiles(directory, name) {
        const found = [];
        for (const item of await readdir(directory, { withFileTypes: true })) {
            const path = join(directory, item.name); assert(!(await lstat(path)).isSymbolicLink());
            if (item.isDirectory()) found.push(...await findFiles(path, name)); else if (item.name === name) found.push(path);
        }
        return found;
    }
    let executable, mounted, runtime, inference, inferenceToken, fixtureEnvironment, paths, browser, page, video, run, runResult, runError, ownedPid, watcher, visibilityDone, watcherStop, keychainCleanup;
    let stage = "artifact verification";
    const alive = pid => { try { process.kill(pid, 0); return true; } catch (error) { if (error.code === "ESRCH") return false; throw error; } };
    async function processProof(pid) {
        id(pid);
        if (windows) {
            const value = JSON.parse(await powershell(`Get-CimInstance Win32_Process -Filter 'ProcessId=${pid}' | Select-Object ExecutablePath,CommandLine | ConvertTo-Json -Compress`));
            assert.equal(value.ExecutablePath.toLowerCase(), executable.toLowerCase());
            assert(value.CommandLine.includes("--user-data-dir=" + profile), "Owned process profile mismatch");
        } else {
            const value = await command("/bin/ps", ["-p", String(pid), "-o", "command="]);
            assert(value.startsWith(executable + " ") && value.includes("--user-data-dir=" + profile), "Owned process identity mismatch");
        }
    }
    async function stopOwned() {
        if (!ownedPid || !alive(ownedPid)) return;
        assert(executable.startsWith(root + sep)); await processProof(ownedPid);
        process.kill(ownedPid, "SIGTERM");
        let until = Date.now() + 10000;
        while (alive(ownedPid) && Date.now() < until) await delay(100);
        if (alive(ownedPid)) {
            await processProof(ownedPid); process.kill(ownedPid, "SIGKILL");
            report.verifiedOwnedForcedTerminations = (report.verifiedOwnedForcedTerminations ?? 0) + 1;
            until = Date.now() + 10000; while (alive(ownedPid) && Date.now() < until) await delay(100);
        }
        assert(!alive(ownedPid), "Owned app did not terminate");
        await run; assert(runResult && !runError, "Owned app exit not observed"); ownedPid = undefined;
    }
    try {
        const release = await api(`repos/${REPOSITORY}/releases/${pins.releaseId}`);
        assert(release.id === pins.releaseId && release.draft === true && release.tag_name === (windows ? "v" : "macos-v") + VERSION);
        const filename = `CyberFi-${VERSION}-${arch}.${windows ? "exe" : "dmg"}`;
        const asset = release.assets.find(item => item.id === pins.assetId), manifest = release.assets.find(item => item.id === pins.manifestAssetId);
        assert(asset?.name === filename && asset.digest === "sha256:" + pins.sha256 && asset.state === "uploaded");
        assert(manifest?.name === filename + ".update.json" && manifest.digest === "sha256:" + pins.manifestSha256 && manifest.size <= 4096);
        const artifact = join(root, filename), manifestFile = artifact + ".update.json";
        await download(REPOSITORY, asset, artifact); await download(REPOSITORY, manifest, manifestFile);
        assert.equal(await hashFile(artifact), pins.sha256); assert.equal(await hashFile(manifestFile), pins.manifestSha256);
        signedManifest(JSON.parse((await readFile(manifestFile, "utf8")).replace(/^\uFEFF/u, "")), filename, pins.sha256, asset.size);
        if (windows) {
            // Trust is not altered. Verify the pinned Authenticode signer and cryptographic signature.
            report.signature = { installer: await windowsSignature(artifact) };
            const seven = join(environmentValue(safeEnv, "ProgramFiles"), "7-Zip/7z.exe"), outer = join(root, "nsis"), inner = join(applications, "CyberFi");
            await command(seven, ["x", "-y", artifact, "-o" + outer]);
            const archives = await findFiles(outer, "app-64.7z"); assert.equal(archives.length, 1);
            await command(seven, ["x", "-y", archives[0], "-o" + inner]); executable = join(inner, "CyberFi.exe");
            assert.equal(await powershell(`(Get-Item -LiteralPath ${quote(executable)}).VersionInfo.ProductVersion`), VERSION + ".0");
            assert.equal(await powershell(`(Get-Item -LiteralPath ${quote(executable)}).VersionInfo.ProductName`), "CyberFi");
            report.signature.executable = await windowsSignature(executable);
            // Observe all HWNDs of the exact owned binary continuously, including startup.
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
 @(Get-CimInstance Win32_Process -Filter "Name='CyberFi.exe'" | Where-Object { $_.ExecutablePath -eq $env:WATCH_EXE -and $_.CommandLine.Contains('--user-data-dir='+$env:WATCH_PROFILE) -and -not $_.CommandLine.Contains('--type=') }) | ForEach-Object { [void]$known.Add([int]$_.ProcessId) }
 $foreground=[CyberAiWindowProof]::GetForegroundWindow();$fgPid=[uint32]0;[void][CyberAiWindowProof]::GetWindowThreadProcessId($foreground,[ref]$fgPid)
 if($known.Contains([int]$fgPid)) { $active++ }
 $script:sampleWindows=0;$script:sampleVisible=0
 $callback=[CyberAiWindowProof+EnumWindow]{param($h,$p) $ownerPid=[uint32]0;[void][CyberAiWindowProof]::GetWindowThreadProcessId($h,[ref]$ownerPid);if($known.Contains([int]$ownerPid)){ $script:sampleWindows++;if([CyberAiWindowProof]::IsWindowVisible($h)){ $script:sampleVisible++ }};return $true }
 [void][CyberAiWindowProof]::EnumWindows($callback,[IntPtr]::Zero)
 $onscreen+=$script:sampleVisible;$windows=[Math]::Max($windows,$script:sampleWindows)
 Start-Sleep -Milliseconds 75
}
@{samples=$samples;systemWindowsMax=$windows;onscreenSamples=$onscreen;activeSamples=$active;pids=@($known)}|ConvertTo-Json -Depth 4 -Compress`;
            watcher = spawn(ps, ["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(watcherSource, "utf16le").toString("base64")], { env: { ...safeEnv, WATCH_EXE: executable, WATCH_PROFILE: profile, WATCH_STOP: watcherStop }, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
            let output = ""; watcher.stdout.on("data", value => { output += value; });
            visibilityDone = new Promise((done, reject) => { watcher.on("error", reject); watcher.on("close", code => code === 0 ? done(JSON.parse(output)) : reject(Error("Visibility watcher failed"))); }); visibilityDone.catch(() => undefined);
            await watcherReady(watcher);
        } else {
            await command("/usr/bin/hdiutil", ["verify", artifact]); mounted = join(root, "mount"); await mkdir(mounted);
            await command("/usr/bin/hdiutil", ["attach", "-readonly", "-nobrowse", "-mountpoint", mounted, artifact]);
            const bundle = join(mounted, "CyberFi.app"), info = join(bundle, "Contents/Info.plist");
            assert.equal(await command("/usr/libexec/PlistBuddy", ["-c", "Print :CFBundleShortVersionString", info]), VERSION);
            assert.equal(await command("/usr/libexec/PlistBuddy", ["-c", "Print :CFBundleIdentifier", info]), "tr.pdrkocum.agent");
            await command("/usr/bin/lipo", [join(bundle, "Contents/MacOS/CyberFi"), "-verify_arch", arch === "x64" ? "x86_64" : "arm64"]);
            await command("/usr/bin/codesign", ["--verify", "--deep", "--strict", bundle]);
            const app = join(applications, "CyberFi.app"); await command("/usr/bin/ditto", ["--rsrc", "--extattr", "--acl", bundle, app]);
            executable = join(app, "Contents/MacOS/CyberFi");
            const watchBinary = join(root, "watch-owned-app");
            await command("/usr/bin/swiftc", ["-O", fileURLToPath(new URL("./macos-update-window-watch.swift", import.meta.url)), "-o", watchBinary], { timeout: 180000 });
            watcher = spawn(watchBinary, ["--bundle", app], { env: safeEnv, stdio: ["ignore", "pipe", "pipe"] });
            let output = ""; watcher.stdout.on("data", value => { output += value; });
            visibilityDone = new Promise((done, reject) => { watcher.on("error", reject); watcher.on("close", code => code === 0 ? done(JSON.parse(output)) : reject(Error("Visibility watcher failed"))); }); visibilityDone.catch(() => undefined);
            await watcherReady(watcher);
        }
        report.binaryIdentity = { rsaVerified: true, executableSha256: await hashFile(executable), quarantineModified: false, fusesModified: false };
        stage = "owned engine fixture";
        const engineRelease = await api("repos/CyberfiTechh/CyberFi-Engine/releases/438140439"), [engineId, engineSha, engineName] = engines[target];
        assert(engineRelease.tag_name === "v0.4.118" && !engineRelease.draft);
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
        assert.equal((await command(engine, ["--version"])).split(/\s+/u).at(-1), "0.4.118");
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
        const cachedEngine = happyAgentBinaryPath(cachePaths, "0.4.118");
        assert(cachedEngine.startsWith(paths.root + sep) && cachePaths.binaryConfigPath.startsWith(paths.root + sep));
        await mkdir(dirname(cachedEngine), { recursive: true, mode: 0o700 });
        await copyFile(engine, cachedEngine, constants.COPYFILE_EXCL); await chmod(cachedEngine, 0o700);
        const extractedBinarySha = await hashFile(engine); assert.equal(await hashFile(cachedEngine), extractedBinarySha);
        // Consume verified cached bytes through the normal lock/data-floor/
        // atomic-selection producer. No fetch interception or forged status.
        const installed = await happyAgentReleaseInstall({ version: "0.4.118", archivedBinaryName: engineName, asset: engineAsset }, cachePaths);
        assert(installed.version === "0.4.118" && installed.path === cachedEngine);
        assert.deepEqual(await happyAgentBinarySelected(cachePaths), installed);
        assert.equal((await command(cachedEngine, ["--version"])).split(/\s+/u).at(-1), "0.4.118");
        const cacheConfig = JSON.parse(await readFile(cachePaths.binaryConfigPath, "utf8"));
        assert.deepEqual(cacheConfig, { downloadedVersions: ["0.4.118"], selectedVersion: "0.4.118" });
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
        fixtureEnvironment = engineEnv;
        if (!windows) {
            stage = "native Keychain environment preflight";
            // HOME alone need not select Foundation's user domain. Observe the
            // real NSHomeDirectory first, then align the isolated OS domain used
            // by both security(1) and Electron across both native lifetimes.
            const homeSource = join(root, "foundation-home.swift"), homeProbe = join(root, "foundation-home");
            await writeFile(homeSource, `import Foundation
import Security
if CommandLine.arguments.count == 3 && CommandLine.arguments[1] == "--keychain" {
    var keychain: SecKeychain?
    let opened = CommandLine.arguments[2].withCString { SecKeychainOpen($0, &keychain) }
    var flags: SecKeychainStatus = 0
    let status = keychain.map { SecKeychainGetStatus($0, &flags) } ?? errSecParam
    let result: [String: Any] = ["openStatus": Int(opened), "status": Int(status),
        "unlocked": flags & UInt32(kSecUnlockStateStatus) != 0,
        "readable": flags & UInt32(kSecReadPermStatus) != 0,
        "writable": flags & UInt32(kSecWritePermStatus) != 0]
    print(String(data: try JSONSerialization.data(withJSONObject: result), encoding: .utf8)!)
} else { print(NSHomeDirectory()) }
`);
            await command("/usr/bin/swiftc", ["-O", homeSource, "-o", homeProbe], { timeout: 180000 });
            const runnerFoundationHome = await command(homeProbe, [], { env: safeEnv });
            const withoutOverride = await command(homeProbe, [], { env: engineEnv });
            engineEnv.CFFIXED_USER_HOME = paths.home;
            const withOverride = await command(homeProbe, [], { env: engineEnv });
            report.keychainFoundationHome = { runner: runnerFoundationHome, isolatedHomeWithoutOverride: withoutOverride, isolatedHomeWithOverride: withOverride, intendedIsolatedHome: paths.home };
            assert.equal(await realpath(withOverride), await realpath(paths.home), "Foundation must resolve the same owned home as the native app");
            const security = (args, env) => command("/usr/bin/security", args, { env, timeout: 30000 });
            const keychains = output => output.split(/\r?\n/u).map(line => line.trim()).filter(Boolean).map(line => { const value = JSON.parse(line); assert(typeof value === "string" && value.startsWith("/") && !value.includes("\n")); return value; });
            report.keychainPreflight = { runnerHome: safeEnv.HOME, ownedHome: engineEnv.HOME, runnerCfFixedUserHomePresent: !!safeEnv.CFFIXED_USER_HOME, ownedCfFixedUserHome: engineEnv.CFFIXED_USER_HOME, reads: [] };
            let keychainReadError;
            const securityRead = async (verb, env, context) => {
                assert(["default-keychain", "list-keychains"].includes(verb));
                try { const output = await security([verb, "-d", "user"], env); report.keychainPreflight.reads.push({ context, verb, success: true, output: output.slice(0, 4096) }); return output; }
                catch (error) {
                    // These two official read-only metadata commands contain no secrets.
                    report.keychainPreflight.reads.push({ context, verb, success: false, exitCode: Number.isSafeInteger(error.code) ? error.code : null, output: String(error.stdout ?? "").slice(0, 4096), diagnostic: String(error.stderr ?? "").slice(0, 4096) });
                    keychainReadError ??= error; return "";
                }
            };
            const actualDefault = keychains(await securityRead("default-keychain", safeEnv, "runner-home"));
            const actualList = keychains(await securityRead("list-keychains", safeEnv, "runner-home"));
            const originalDefault = keychains(await securityRead("default-keychain", engineEnv, "owned-home"));
            const originalList = keychains(await securityRead("list-keychains", engineEnv, "owned-home"));
            const missingOwnedDefault = missingOwnedKeychainDefaultConfirmed(originalDefault, originalList, report.keychainPreflight.reads);
            Object.assign(report.keychainPreflight, { runnerDefault: actualDefault[0], ownedHomeDefault: originalDefault[0], searchListCount: originalList.length, runnerSearchListCount: actualList.length, ownedDefaultInitiallyMissing: missingOwnedDefault });
            if (keychainReadError && !missingOwnedDefault) throw keychainReadError;
            assert((originalDefault.length === 1 || missingOwnedDefault) && actualDefault.length === 1 && originalList.length <= 20 && actualList.length <= 20, "Native user keychain baseline missing");
            assert.notEqual(await realpath(engineEnv.HOME), await realpath(safeEnv.HOME), "Keychain calibration must use an isolated owned home");
            await mkdir(join(paths.home, "Library/Preferences"), { recursive: true });
            await mkdir(join(paths.home, "Library/Keychains"), { recursive: true });
            const keychain = join(paths.home, "Library/Keychains/cyberai-login.keychain-db"), keychainPassword = randomBytes(32).toString("hex");
            report.keychainPreflight.defaultMetadataReadable = originalDefault.length === 1 ? await security(["show-keychain-info", originalDefault[0]], engineEnv).then(() => true, () => false) : false;
            keychainCleanup = async () => {
                // Apple's keychain_default CLI passes NULL to SecKeychainSetDomainDefault
                // when -s has no path, restoring this run's initially absent default.
                await security(["default-keychain", "-d", "user", "-s", ...originalDefault], engineEnv).catch(error => {
                    if (!(missingOwnedDefault && error.code === 1 && /A default keychain could not be found/iu.test(error.stderr ?? ""))) throw error;
                });
                await security(["list-keychains", "-d", "user", "-s", ...originalList], engineEnv);
                assert(keychain.startsWith(paths.home + sep));
                assert.equal(await realpath(dirname(keychain)), join(await realpath(paths.home), "Library/Keychains"));
                await security(["delete-keychain", keychain], engineEnv);
                if (missingOwnedDefault) {
                    const absent = await security(["default-keychain", "-d", "user"], engineEnv).then(() => false, error => error.code === 1 && /A default keychain could not be found/iu.test(error.stderr ?? ""));
                    assert(absent, "Initially missing owned default keychain was not restored");
                } else assert.deepEqual(keychains(await security(["default-keychain", "-d", "user"], engineEnv)), originalDefault);
                assert.deepEqual(keychains(await security(["list-keychains", "-d", "user"], engineEnv)), originalList);
                assert.deepEqual(keychains(await security(["default-keychain", "-d", "user"], safeEnv)), actualDefault);
                assert.deepEqual(keychains(await security(["list-keychains", "-d", "user"], safeEnv)), actualList);
            };
            await security(["create-keychain", "-p", keychainPassword, keychain], engineEnv);
            await security(["set-keychain-settings", "-lut", "21600", keychain], engineEnv);
            await security(["unlock-keychain", "-p", keychainPassword, keychain], engineEnv);
            await security(["list-keychains", "-d", "user", "-s", keychain], engineEnv);
            await security(["default-keychain", "-d", "user", "-s", keychain], engineEnv);
            const configuredDefault = keychains(await securityRead("default-keychain", engineEnv, "owned-home-after-setup"));
            const configuredList = keychains(await securityRead("list-keychains", engineEnv, "owned-home-after-setup"));
            const status = JSON.parse(await command(homeProbe, ["--keychain", keychain], { env: engineEnv, timeout: 30000 }));
            report.keychainConfiguredReadback = { default: configuredDefault, searchList: configuredList, keychain, status };
            assert.equal(configuredDefault.length, 1); assert.equal(configuredList.length, 1);
            const physicalKeychain = await realpath(keychain);
            assert(physicalKeychain.startsWith(await realpath(paths.home) + sep));
            assert.equal(await realpath(configuredDefault[0]), physicalKeychain);
            assert.equal(await realpath(configuredList[0]), physicalKeychain);
            report.keychainConfiguredReadback.physicalPath = physicalKeychain;
            assert(status.openStatus === 0 && status.status === 0 && status.unlocked === true && status.readable === true && status.writable === true, "Owned native keychain must be unlocked and accessible");
            assert.deepEqual(keychains(await security(["default-keychain", "-d", "user"], safeEnv)), actualDefault);
            assert.deepEqual(keychains(await security(["list-keychains", "-d", "user"], safeEnv)), actualList);
            report.keychainCalibration = { ownedDisposableUnlockedDefault: true, cryptoMocked: false, electronItemPreseeded: false, trustStoreModified: false };
        }
        stage = "owned engine fixture";
        const config = join(paths.root, windows ? "happy/config" : "Happy/Config"); await mkdir(config, { recursive: true });
        for (const name of [".config", ".cache", ".local/share", ".local/state", "AppData/Local", "AppData/Roaming"]) await mkdir(join(paths.home, name), { recursive: true });
        await writeFile(join(config, "happy.toml"), '[settings]\nhappy_integration = false\nmenu_bar = false\n\n[providers.codex]\ntype = "codex"\nenabled = true\ncredential_isolation = true\n');
        const stop = () => command(engine, ["stop"], { cwd: paths.root, env: engineEnv }).catch(() => undefined);
        stage = "owned engine daemon startup";
        runtime = { stop }; await command(engine, ["start"], { cwd: paths.root, env: engineEnv });
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
        await writeFile(join(configDir, "config.json"), JSON.stringify({ appearance: "dark", defaultPermissionMode: "read_only" }));
        const sentinels = [[join(configDir, "retained-user-note.txt"), "Keep profile settings.\n"], [join(paths.home, ".agents/skills/retained/SKILL.md"), "# Existing skill\nKeep exact content.\n"]];
        for (const [path, text] of sentinels) { await mkdir(dirname(path), { recursive: true }); await writeFile(path, text); }
        const require = createRequire(join(upstream, "packages/happy-desktop-gym/package.json")); const { chromium } = require("playwright");
        const port = 19485, endpoint = `http://127.0.0.1:${port}`;
        async function listenerPid() {
            if (windows) {
                const output = await powershell(`@(Get-NetTCPConnection -LocalAddress 127.0.0.1 -LocalPort ${port} -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique) | ConvertTo-Json -Compress`);
                const values = output ? JSON.parse(output) : []; const list = Array.isArray(values) ? values : [values]; assert(list.length <= 1); return list.length ? id(list[0]) : undefined;
            }
            const output = await command("/usr/sbin/lsof", ["-nP", `-iTCP@127.0.0.1:${port}`, "-sTCP:LISTEN", "-t"]).catch(error => { if (error.code === 1) return ""; throw error; });
            const list = [...new Set(output.split(/\s+/u).filter(Boolean).map(Number))]; assert(list.length <= 1); return list.length ? id(list[0]) : undefined;
        }
        const env = { ...safeEnv, ...engineEnv, HAPPY_DESKTOP_WINDOWS_HIDDEN: "1", HAPPY_DESKTOP_DEBUG: "1", HAPPY_DEBUG_RENDERER_PORT: String(port), HAPPY_DESKTOP_AGENT_EXECUTABLE: engine };
        const privacyStyle = 'input[name="username"], input[name="password"], [data-happy-desktop-ui="form-row-description"] { color: transparent !important; text-shadow: none !important; }';
        async function launch(label) {
            assert.equal(await listenerPid(), undefined); runResult = undefined; runError = undefined;
            run = gymElectronProcessRun({ executablePath: executable, args: ["--user-data-dir=" + profile, "--debug"], env, timeout: 12 * 60000 }).then(value => { runResult = value; }, () => { runError = true; });
            const deadline = Date.now() + 90000;
            while (Date.now() < deadline && !runError && !runResult) {
                try {
                    const response = await fetch(endpoint + "/json/list", { signal: AbortSignal.timeout(1000) });
                    if (response.ok && (await response.json()).some(item => item.type === "page")) {
                        ownedPid = await listenerPid(); await processProof(ownedPid);
                        browser = await chromium.connectOverCDP(endpoint); page = browser.contexts().flatMap(value => value.pages()).find(value => !value.url().startsWith("devtools:"));
                        if (page) break;
                    }
                } catch { /* The approved loopback endpoint is still starting. */ }
                await delay(200);
            }
            assert(page && ownedPid && !runError && !runResult, "Packaged app endpoint unavailable");
            await page.waitForFunction(() => typeof window.happyDesktop?.cyberFiAccountGet === "function");
            if (label === "login-lifetime") {
                // Only ordinary welcome/language preferences are preselected; account auth stays mandatory.
                await page.evaluate(() => { localStorage.setItem("pdr-kocum-agent.language", "tr"); localStorage.setItem("happy.welcome.v1", JSON.stringify({ welcomeAcknowledged: true })); });
                await page.reload({ waitUntil: "commit" });
            }
            // Credential values remain visually redacted throughout both native recordings.
            await page.addInitScript(style => { document.addEventListener("DOMContentLoaded", () => { const element = document.createElement("style"); element.textContent = style; document.head.append(element); }, { once: true }); }, privacyStyle);
            await page.addStyleTag({ content: privacyStyle });
            video = await gymElectronVideoRecord(page, { path: join(evidence, label + ".webm"), fps: 5 });
        }
        async function endVideo() { const result = await video.stop(); video = undefined; assert(result.framesReceived > 0 && result.framesWritten > 0); report.videos.push({ framesReceived: result.framesReceived, framesWritten: result.framesWritten }); }
        const login = () => page.locator('[data-happy-desktop-ui="cyberfi-account-login"]');
        async function waitLogin() {
            await page.waitForFunction(() => !document.querySelector('[data-testid="desktop-startup-screen"]') && [...document.querySelectorAll('[data-happy-desktop-ui="cyberfi-account-login"] input')].filter(input => ["username", "password"].includes(input.name)).every(input => !input.disabled) && !!document.querySelector('[data-happy-desktop-ui="cyberfi-account-login"] input[name="password"]'), undefined, { timeout: 60000 });
            await login().waitFor({ state: "visible" });
        }
        async function denied() {
            const result = await page.evaluate(async () => {
                const bridge = window.happyDesktop;
                if (typeof bridge.runtimeGet !== "function" || typeof bridge.cyberFiMcpRead !== "function") return [false, false];
                const calls = [() => bridge.runtimeGet(), () => bridge.cyberFiMcpRead()];
                return Promise.all(calls.map(async call => { try { await call(); return false; } catch { return true; } }));
            }); assert.deepEqual(result, [true, true], "Signed-out privileged IPC must reject");
        }
        async function accountReady() {
            await page.waitForFunction(async () => (await window.happyDesktop.cyberFiAccountGet()).status === "signedIn", undefined, { timeout: 60000 });
            const until = Date.now() + 90000; let startedLocally = false;
            while (Date.now() < until) {
                if ((await page.evaluate(() => window.happyDesktop.runtimeGet())).phase === "ready") break;
                const start = page.getByRole("button", { name: /^(Start locally|Bu bilgisayarda başlat)$/iu });
                if (!startedLocally && await start.isVisible().catch(() => false)) { await start.click(); startedLocally = true; }
                await delay(250);
            }
            assert.equal((await page.evaluate(() => window.happyDesktop.runtimeGet())).phase, "ready", "Authenticated native runtime did not become ready");
            const account = await page.evaluate(() => window.happyDesktop.cyberFiAccountGet());
            assert(account.user?.role === "user" && account.remember === true && account.username === username);
            assert(!/token|password|encrypted/iu.test(JSON.stringify(Object.keys(account))) && !JSON.stringify(account).includes(password), "Account snapshot leaked protected fields");
            assert.equal(await login().count(), 0);
        }
        stage = "initial login screen"; await launch("login-lifetime"); await waitLogin();
        assert.match(await login().innerText(), /CyberFi/u); assert.equal(await login().locator('input[name="password"]').getAttribute("type"), "password");
        const remember = login().getByRole("checkbox", { name: "Beni hatırla" }); assert.equal(await remember.isChecked(), false);
        await login().getByRole("button", { name: "Şifreyi göster", exact: true }).click();
        assert.equal(await login().locator('input[name="password"]').getAttribute("type"), "text");
        await login().getByRole("button", { name: "Şifreyi gizle", exact: true }).click();
        await page.screenshot({ path: join(evidence, "login.png") }); await denied();
        const guestDenied = await page.evaluate(async () => {
            const guest = document.createElement("webview"); guest.setAttribute("partition", "happy-html-preview"); guest.setAttribute("src", "http://cyberai-acceptance.localhost/");
            let attached = false; guest.addEventListener("did-attach", () => { attached = true; }); document.body.append(guest);
            await new Promise(done => setTimeout(done, 750));
            let id; try { id = guest.getWebContentsId(); } catch { /* Main refused guest attachment. */ }
            guest.remove(); return !attached && !id;
        }); assert(guestDenied, "Known preview partition attached before authentication"); report.checks.signedOutGuestAttachmentRefused = true;
        stage = "generic wrong-password login";
        await login().locator('input[name="username"]').fill(username); await login().locator('input[name="password"]').fill("invalid-" + randomBytes(12).toString("hex"));
        await login().getByRole("button", { name: "Giriş yap", exact: true }).click();
        await page.waitForFunction(async () => { const value = await window.happyDesktop.cyberFiAccountGet(); return value.status === "signedOut" && !!value.error; });
        const rejection = await page.evaluate(async () => (await window.happyDesktop.cyberFiAccountGet()).error);
        assert(rejection && !/stack|sqlite|token|http|exception/iu.test(rejection) && !rejection.includes(username) && !rejection.includes(password)); await denied();
        report.checks.wrongPasswordGeneric = true;
        stage = "native remembered login availability and authentication";
        await login().locator('input[name="password"]').fill(password); await remember.check();
        await login().getByRole("button", { name: "Giriş yap", exact: true }).click(); await accountReady();
        stage = "encrypted remembered-session file";
        const saved = join(configDir, "cyberai-account.json"), savedText = await readFile(saved, "utf8"), sealed = JSON.parse(savedText);
        assert.deepEqual(Object.keys(sealed).sort(), ["encrypted", "version"]); assert.equal(sealed.version, 1); assert.match(sealed.encrypted, /^[A-Za-z0-9+/]+={0,2}$/u);
        assert(!savedText.includes(username) && !savedText.includes(password));
        report.checks.initialLogin = true; report.checks.privilegedIpcDenied = true; report.checks.wrongPasswordGeneric = true; report.checks.nativeEncryptedStorage = true;
        stage = "first native app termination";
        const firstPid = ownedPid; await endVideo(); await stopOwned(); await browser.close(); browser = undefined; page = undefined;
        stage = "native remembered relaunch"; await launch("reopened-lifetime"); assert.notEqual(ownedPid, firstPid); await accountReady();
        await page.waitForFunction(() => !document.querySelector('[data-testid="desktop-startup-screen"]'), undefined, { timeout: 60000 });
        const row = page.locator(`[data-happy-desktop-ui="sidebar-item"][data-item-id="local/${project.id}"]`); await row.waitFor({ state: "visible", timeout: 45000 }); await row.click();
        const tab = page.locator(`[data-happy-desktop-ui="tab"][data-tab-id="${agent.id}"]`); await tab.waitFor({ state: "visible", timeout: 30000 }); await tab.click();
        await page.getByText("Native CyberAI chat acceptance confirmed.", { exact: true }).first().waitFor({ state: "visible", timeout: 30000 });
        report.checks.actualWorkspaceChatRendered = true;
        await page.screenshot({ path: join(evidence, "reopened.png"), mask: [page.getByText(username, { exact: true })] });
        report.checks.actualTerminateRelaunch = true; report.checks.nativeRememberWithoutPasswordEntry = true;
        // Exercise the existing local renderer transport before revocation.
        stage = "authenticated workspace transport readiness";
        let transport = false; const transportDeadline = Date.now() + 30000;
        report.workspaceTransportProbe = [];
        while (!transport && Date.now() < transportDeadline) {
            const proof = await page.evaluate(async () => {
                const value = await window.happyDesktop.runtimeGet();
                if (!value.activeTarget?.happyAgentHttpUrl) return { ready: false, status: null };
                try { const response = await fetch(value.activeTarget.happyAgentHttpUrl + "/health", { signal: AbortSignal.timeout(3000) }); return { ready: response.ok, status: response.status }; }
                catch { return { ready: false, status: null }; }
            });
            if (JSON.stringify(proof) !== JSON.stringify(report.workspaceTransportProbe.at(-1))) report.workspaceTransportProbe.push(proof);
            transport = proof.ready; if (!transport) await delay(250);
        }
        assert(transport, "Authenticated workspace transport did not open");
        report.checks.authenticatedWorkspaceTransport = true;
        const sockets = new Set(); page.on("websocket", socket => { sockets.add(socket); socket.on("close", () => sockets.delete(socket)); });
        stage = "logout settings navigation";
        await page.locator('[data-happy-desktop-ui="sidebar-footer"]').getByRole("button", { name: /^(Settings|Ayarlar|Open settings|Ayarları aç)$/iu }).click();
        const general = page.getByRole("button", { name: /^(General|Genel)$/iu }).first(); if (await general.count()) await general.click();
        const signOut = page.getByRole("button", { name: /^(Çıkış yap|Sign out)$/iu });
        await signOut.waitFor({ state: "visible", timeout: 30000 });
        // Register a handled STAY response. Playwright's implicit dialog handler
        // races Electron's authoritative forced reload on macOS; never accept
        // the dialog, which would bypass the behavior this test must prove.
        let beforeUnloadSignals = 0, stayDialogs = 0, dismissRaces = 0, unexpectedDialogs = 0, unknownDialogError = false;
        const dialogSettlements = [], unknownDialogDiagnostics = [];
        page.on("console", message => { if (message.text() === "cyberai-acceptance-beforeunload-stay") beforeUnloadSignals++; });
        page.on("dialog", dialog => {
            if (dialog.type() === "beforeunload") stayDialogs++; else unexpectedDialogs++;
            dialogSettlements.push(dialog.dismiss().catch(error => {
                if (knownNoDialogRace(error?.message)) dismissRaces++;
                else {
                    unknownDialogError = true;
                    const firstLine = dialogErrorFirstLine(error?.message);
                    const diagnostic = { kind: error?.name === "ProtocolError" ? "ProtocolError" : "dialog-error" };
                    // Only this known local CDP operation is eligible; never
                    // inspect dialog text or record unrelated HTTP/auth errors.
                    if (/^(?:dialog\.dismiss: )?Protocol error \(Page\.handleJavaScriptDialog\):/u.test(firstLine)) diagnostic.firstLine = engineDiagnosticText(firstLine, [username, password, inferenceToken]).slice(0, 256);
                    unknownDialogDiagnostics.push(diagnostic);
                }
            }));
        });
        const marker = randomBytes(16).toString("hex");
        await page.evaluate(marker => { window.__cyberaiLogoutMarker = marker; window.addEventListener("beforeunload", event => { event.preventDefault(); event.returnValue = "stay"; console.info("cyberai-acceptance-beforeunload-stay"); }); }, marker);
        stage = "forced main-process logout";
        const observedSockets = sockets.size; await signOut.click();
        report.beforeUnloadProof = { signals: beforeUnloadSignals, requestedStayDialogs: stayDialogs, dismissedDialogRaces: dismissRaces, acceptedDialogs: 0, oldContextDestroyed: false };
        await waitLogin();
        stage = "authoritative logout document replacement";
        await page.waitForFunction(() => window.__cyberaiLogoutMarker === undefined && !!document.querySelector('[data-happy-desktop-ui="cyberfi-account-login"]'), undefined, { timeout: 30000 });
        stage = "forced logout beforeunload proof";
        await Promise.all(dialogSettlements);
        report.beforeUnloadProof = { signals: beforeUnloadSignals, requestedStayDialogs: stayDialogs, dismissedDialogRaces: dismissRaces, acceptedDialogs: 0, oldContextDestroyed: true, unknownDialogError, unknownDialogDiagnostics };
        assert(beforeUnloadSignals > 0 && unexpectedDialogs === 0 && !unknownDialogError, "The renderer must actually attempt to prevent logout navigation without unrelated dialog errors");
        await denied(); await assert.rejects(lstat(saved), { code: "ENOENT" });
        assert.equal(sockets.size, 0); report.logoutTransportProof = observedSockets ? "Observed workspace WebSockets closed and old document destroyed" : "Old workspace document destroyed; no WebSocket was observed";
        await page.screenshot({ path: join(evidence, "logout.png"), mask: [login().locator('input[name="username"], input[name="password"]')] });
        for (const [path, text] of sentinels) assert.equal(await readFile(path, "utf8"), text);
        await client.getHealth(); report.checks.forcedLogoutReload = true; report.checks.savedCredentialRemoved = true; report.checks.profileAndSkillsPreserved = true; report.checks.engineStillHealthy = true;
        report.inferenceFixture = { localOnly: true, calls: inferenceCalls, externalProviderCalls: 0 };
        await endVideo(); await stopOwned(); report.success = true;
    } catch (error) {
        // Never serialize browser/HTTP/native error messages: they can include input credentials.
        report.errors.push("Native acceptance failed during " + stage);
        report.failureKind = ["Error", "AssertionError", "TimeoutError", "TypeError"].includes(error?.name) ? error.name : "native-error";
        if (typeof error?.code === "string" && /^[A-Z_0-9]{1,64}$/u.test(error.code)) report.failureCode = error.code;
        if (error?.cyberaiCommand) report.commandFailure = error.cyberaiCommand;
        if (stage === "owned engine daemon startup" && error?.cyberaiCommand?.tool === engines[target][2] && error.cyberaiCommand.verb === "start") {
            let socketToken;
            if (paths?.tokenPath?.startsWith(paths.root + sep)) {
                const info = await lstat(paths.tokenPath).catch(() => undefined);
                if (info?.isFile() && !info.isSymbolicLink() && info.size <= 4096) socketToken = (await readFile(paths.tokenPath, "utf8")).trim();
            }
            const secrets = [username, password, inferenceToken, socketToken];
            report.engineStartDiagnostic = { redactionRan: true, beforeAppAndAccountLogin: true, stdout: engineDiagnosticText(error.stdout, secrets), stderr: engineDiagnosticText(error.stderr, secrets) };
            if (windows && fixtureEnvironment) {
                // Read-only paired probes isolate inherited PowerShell Core module
                // paths from Windows PowerShell5 without changing ACL policy.
                const probe = `$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
[void][Reflection.Assembly]::LoadWithPartialName('System.Web.Extensions')
$commands=@(foreach($name in @('Get-Item','Get-Acl')){try{$cmd=Get-Command $name -ErrorAction Stop;@{name=$name;available=$true;source=$cmd.Source;moduleVersion=$cmd.Module.Version.ToString()}}catch{@{name=$name;available=$false;errorId=$_.FullyQualifiedErrorId;category=$_.CategoryInfo.Category.ToString()}}})
$directories=@(foreach($path in ($env:OWNED_DIRECTORIES_PROBE -split '\\|')){try{$item=Get-Item -LiteralPath $path -Force -ErrorAction Stop;$row=@{path=$path;exists=$true;attributes=$item.Attributes.ToString();setAccessControlMethod=($null -ne $item.PSObject.Methods['SetAccessControl'])};try{$row.owner=(Get-Acl -LiteralPath $path -ErrorAction Stop).Owner}catch{$row.ownerErrorId=$_.FullyQualifiedErrorId};$row}catch{@{path=$path;exists=$false;errorId=$_.FullyQualifiedErrorId;category=$_.CategoryInfo.Category.ToString()}}})
$result=@{edition=$PSVersionTable.PSEdition;version=$PSVersionTable.PSVersion.ToString();modulePath=$env:PSModulePath;commands=$commands;directories=$directories}
[Console]::Out.WriteLine(([System.Web.Script.Serialization.JavaScriptSerializer]::new()).Serialize($result))`;
                report.windowsPrivateDirectoryProbe = [];
                const withoutModulePath = Object.fromEntries(Object.entries(fixtureEnvironment).filter(([key]) => key.toLowerCase() !== "psmodulepath"));
                for (const [kind, environment] of [["same-engine-environment", fixtureEnvironment], ["without-inherited-module-path", withoutModulePath]]) {
                    try {
                        const output = await command(ps, ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", probe], { env: { ...environment, OWNED_DIRECTORIES_PROBE: [paths.root, paths.happyHome, paths.agentHome].join("|") }, timeout: 30000 });
                        report.windowsPrivateDirectoryProbe.push({ kind, success: true, result: JSON.parse(output) });
                    } catch (probeError) { report.windowsPrivateDirectoryProbe.push({ kind, success: false, command: probeError?.cyberaiCommand ?? null }); }
                }
            }
        }
        if (page && !page.isClosed()) report.failureUi = await page.evaluate(() => {
            const login = document.querySelector('[data-happy-desktop-ui="cyberfi-account-login"]');
            const text = login?.textContent ?? "";
            return { loginVisible: !!login, busy: text.includes("Giriş yapılıyor"), wrongPasswordBanner: text.includes("Kullanıcı adı veya şifre hatalı."), secureStorageUnavailableBanner: text.includes("Güvenli depolama kullanılamıyor"), usernameDisabled: login?.querySelector('input[name="username"]')?.disabled === true, passwordDisabled: login?.querySelector('input[name="password"]')?.disabled === true };
        }).catch(() => ({ rendererUnavailable: true }));
        report.rememberedFileExistsAtFailure = await lstat(join(profile, "desktop/cyberai-account.json")).then(() => true, () => false);
    } finally {
        if (video) { try { const value = await video.stop(); report.videos.push({ framesReceived: value.framesReceived, framesWritten: value.framesWritten }); } catch { report.success = false; } }
        try { await stopOwned(); } catch { report.success = false; report.errors.push("Owned app cleanup failed identity or exit verification"); }
        await browser?.close().catch(() => undefined); await runtime?.stop();
        if (inference) await new Promise(done => inference.close(done));
        if (watcher) {
            if (watcherStop) await writeFile(watcherStop, "stop\n"); else watcher.kill("SIGTERM");
            try { report.visibility = await visibilityDone; if (!(report.visibility.systemWindowsMax > 0 && report.visibility.onscreenSamples === 0 && report.visibility.activeSamples === 0 && report.visibility.pids.length === 2)) report.success = false; } catch { report.success = false; }
        }
        if (mounted) await command("/usr/bin/hdiutil", ["detach", mounted]).catch(() => undefined);
        if (keychainCleanup) { try { await keychainCleanup(); report.keychainRestored = true; } catch (error) { report.success = false; report.errors.push("Owned disposable keychain cleanup failed"); if (error?.cyberaiCommand) report.keychainCleanupFailure = error.cyberaiCommand; else report.keychainCleanupFailure = { kind: error?.name === "AssertionError" ? "AssertionError" : "native-error" }; } }
        await save();
    }
    assert(report.success && report.videos.length === 2, "Native login acceptance incomplete; inspect redacted cyberai-login.json");
    console.log(JSON.stringify({ success: true, target, version: VERSION, evidence }));
}

if (process.argv.includes("--self-test")) {
    const pin = { releaseId: 1, assetId: 2, sha256: "a".repeat(64), manifestAssetId: 3, manifestSha256: "b".repeat(64) };
    assert.deepEqual(artifactPins(pin), pin);
    for (const value of [{ ...pin, extra: true }, { ...pin, assetId: 0 }, { ...pin, sha256: "../bad" }, [pin], null]) assert.throws(() => artifactPins(value));
    for (const value of ["http://github.com/a", "https://api.github.com.evil.test/a", "https://a@github.com/a"]) assert.throws(() => allowedRedirect(value));
    assert.equal(allowedRedirect("https://release-assets.githubusercontent.com/file").protocol, "https:");
    assert.deepEqual(sanitizedEnvironment({ PATH: "ok", CYBERAI_USERNAME: "private", CYBERAI_PASSWORD: "private", GH_TOKEN: "private", ACCEPTANCE_ARTIFACTS: "private", SOME_API_KEY: "private" }), { PATH: "ok" });
    assert.equal(environmentValue({ SYSTEMROOT: "system", PROGRAMFILES: "programs" }, "SystemRoot"), "system");
    assert.equal(environmentValue({ SYSTEMROOT: "system", PROGRAMFILES: "programs" }, "ProgramFiles"), "programs");
    assert.throws(() => environmentValue({}, "SystemRoot"));
    const child = new EventEmitter(); child.stderr = new EventEmitter();
    const readiness = watcherReady(child);
    child.stderr.emit("data", Buffer.from("#< CLIXML\n")); child.stderr.emit("data", Buffer.from("rea")); child.stderr.emit("data", Buffer.from("dy\n"));
    await readiness; assert.equal(child.stderr.listenerCount("data"), 0);
    const missing = { success: false, context: "owned-home", verb: "default-keychain", exitCode: 1, diagnostic: "security: SecKeychainCopyDomainDefault user: A default keychain could not be found." };
    assert.equal(missingOwnedKeychainDefaultConfirmed([], [], [missing]), true);
    for (const reads of [[{ ...missing, context: "runner-home" }], [{ ...missing, exitCode: 44 }], [{ ...missing, diagnostic: "Permission denied" }], [missing, missing]]) assert.equal(missingOwnedKeychainDefaultConfirmed([], [], reads), false);
    assert.equal(missingOwnedKeychainDefaultConfirmed([], ["/existing"], [missing]), false);
    const diagnostic = engineDiagnosticText('error: native engine startup\nAuthorization: Bearer private-token\npassword="private-password"\ntoken=generic-token\nuser=private-user\nsecret=generic-secret\nserver_token=server-value\naccessToken=access-value\nsecretKey=secret-value', ["private-token", "private-password", "private-user"]);
    assert(diagnostic.includes("native engine startup"));
    for (const value of ["private-token", "private-password", "private-user", "generic-token", "generic-secret", "Authorization:", "server-value", "access-value", "secret-value", "server_token", "accessToken", "secretKey"]) assert(!diagnostic.includes(value));
    assert(Buffer.byteLength(engineDiagnosticText("x".repeat(9000), [])) <= 4096);
    assert(knownNoDialogRace("dialog.dismiss: Protocol error (Page.handleJavaScriptDialog): No dialog is showing\r\nCall log:\r\n - waiting"));
    assert(knownNoDialogRace("Protocol error (Page.handleJavaScriptDialog): No dialog is showing\nCall log:"));
    assert(!knownNoDialogRace("dialog.dismiss: Protocol error (Page.handleJavaScriptDialog): Internal error\r\nCall log:"));
    assert(!knownNoDialogRace("Target page, context or browser has been closed"));
    assert.throws(() => signedManifest({ sha256: pin.sha256, size: 10, signature: "A".repeat(512) }, "CyberFi-0.0.125-x64.exe", pin.sha256, 10));
    console.log("Strict artifact pins, redirect refusal, independent RSA refusal and credential environment isolation passed. No app or network used.");
} else await main();
