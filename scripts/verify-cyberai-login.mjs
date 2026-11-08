import assert from "node:assert/strict";
import { createHash, verify, randomBytes } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import { mkdir, readFile, readdir, realpath, writeFile, lstat, stat } from "node:fs/promises";
import { createRequire } from "node:module";
import { dirname, join, resolve, sep } from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";
import { execFile, spawn } from "node:child_process";
import { promisify } from "node:util";
import { createServer } from "node:http";
import { Readable, Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import { setTimeout as delay } from "node:timers/promises";

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
    const command = async (file, args, options = {}) => (await exec(file, args, { env: safeEnv, timeout: 120000, windowsHide: true, maxBuffer: 8 * 1024 ** 2, ...options })).stdout.trim();
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
    let executable, mounted, runtime, inference, paths, browser, page, video, run, runResult, runError, ownedPid, watcher, visibilityDone, watcherStop;
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
        const until = Date.now() + 20000;
        while (alive(ownedPid) && Date.now() < until) await delay(100);
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
            const watcherSource = `$ErrorActionPreference='Stop'
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
            await new Promise((done, reject) => { watcher.stderr.once("data", value => value.toString().includes("ready") ? done() : reject(Error("Visibility observer not ready"))); watcher.once("error", reject); });
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
            await new Promise((done, reject) => { watcher.stderr.once("data", value => value.toString().includes("ready") ? done() : reject(Error("Visibility observer not ready"))); watcher.once("error", reject); });
        }
        report.binaryIdentity = { rsaVerified: true, executableSha256: await hashFile(executable), quarantineModified: false, fusesModified: false };
        stage = "owned engine fixture";
        const engineRelease = await api("repos/CyberfiTechh/CyberFi-Engine/releases/438140439"), [engineId, engineSha, engineName] = engines[target];
        assert(engineRelease.tag_name === "v0.4.118" && !engineRelease.draft);
        const engineAsset = engineRelease.assets.find(item => item.id === engineId); assert.equal(engineAsset?.digest, "sha256:" + engineSha);
        const archive = join(root, "engine.tar.gz"), engineRoot = join(root, "engine"); await mkdir(engineRoot);
        await download("CyberfiTechh/CyberFi-Engine", engineAsset, archive); assert.equal(await hashFile(archive), engineSha);
        const tar = windows ? "tar.exe" : "/usr/bin/tar";
        assert.equal(await command(tar, ["-tzf", archive]), engineName); await command(tar, ["-xzf", archive, "-C", engineRoot]);
        const engine = join(engineRoot, engineName); process.env.HAPPY_DESKTOP_AGENT_EXECUTABLE = engine;
        assert.equal((await command(engine, ["--version"])).split(/\s+/u).at(-1), "0.4.118");
        const gym = name => pathToFileURL(join(upstream, "packages/happy-desktop-gym/sources/electron", name + ".ts")).href;
        const { gymElectronProcessRun, gymElectronVideoRecord } = await import(gym("launch"));
        const { gymRunPathsCreate } = await import(gym("paths"));
        const { gymHostEnvironment } = await import(gym("hostEnvironment"));
        const { happyAgentClientCreate, GymHappyAgentClient } = await import(gym("happyAgentProtocol"));
        ({ paths } = await gymRunPathsCreate("smoke"));
        const inferenceToken = randomBytes(24).toString("hex"); let inferenceCalls = 0;
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
        const config = join(paths.root, windows ? "happy/config" : "Happy/Config"); await mkdir(config, { recursive: true });
        for (const name of [".config", ".cache", ".local/share", ".local/state", "AppData/Local", "AppData/Roaming"]) await mkdir(join(paths.home, name), { recursive: true });
        await writeFile(join(config, "happy.toml"), '[settings]\nhappy_integration = false\nmenu_bar = false\n\n[providers.codex]\ntype = "codex"\nenabled = true\ncredential_isolation = true\n');
        const stop = () => command(engine, ["stop"], { cwd: paths.root, env: engineEnv }).catch(() => undefined);
        runtime = { stop }; await command(engine, ["start"], { cwd: paths.root, env: engineEnv });
        let client; const healthDeadline = Date.now() + 30000;
        while (Date.now() < healthDeadline) {
            try { client = happyAgentClientCreate(paths.socketPath, (await readFile(paths.tokenPath, "utf8")).trim()); await client.getHealth(); break; } catch { client = undefined; await delay(150); }
        }
        assert(client, "Fixture engine health unavailable");
        const fixtureClient = new GymHappyAgentClient(paths.socketPath, (await readFile(paths.tokenPath, "utf8")).trim());
        const repository = join(paths.projects, "native-login-chat"); await mkdir(repository);
        const gitEnv = { ...systemEnv, ...gymHostEnvironment(paths), GIT_CONFIG_GLOBAL: windows ? "NUL" : "/dev/null", GIT_CONFIG_NOSYSTEM: "1" };
        await command("git", ["init", "--initial-branch=main", repository], { env: gitEnv });
        await writeFile(join(repository, "README.md"), "# Disposable native login acceptance\n");
        await command("git", ["-C", repository, "add", "README.md"], { env: gitEnv });
        await command("git", ["-C", repository, "-c", "user.name=CyberAI CI", "-c", "user.email=ci@example.invalid", "commit", "-m", "Owned fixture"], { env: gitEnv });
        const { project } = await fixtureClient.registerProject(repository); await fixtureClient.waitForWorkspace(project.id, "ready", 90000);
        const { agent } = await fixtureClient.createAgent(project.id);
        const turn = await fixtureClient.sendMessage(agent.id, "Confirm this synthetic native chat acceptance.");
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
        stage = "initial login"; await launch("login-lifetime"); await waitLogin();
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
        await login().locator('input[name="username"]').fill(username); await login().locator('input[name="password"]').fill("invalid-" + randomBytes(12).toString("hex"));
        await login().getByRole("button", { name: "Giriş yap", exact: true }).click();
        await page.waitForFunction(async () => { const value = await window.happyDesktop.cyberFiAccountGet(); return value.status === "signedOut" && !!value.error; });
        const rejection = await page.evaluate(async () => (await window.happyDesktop.cyberFiAccountGet()).error);
        assert(rejection && !/stack|sqlite|token|http|exception/iu.test(rejection) && !rejection.includes(username) && !rejection.includes(password)); await denied();
        await login().locator('input[name="password"]').fill(password); await remember.check();
        await login().getByRole("button", { name: "Giriş yap", exact: true }).click(); await accountReady();
        const saved = join(configDir, "cyberai-account.json"), savedText = await readFile(saved, "utf8"), sealed = JSON.parse(savedText);
        assert.deepEqual(Object.keys(sealed).sort(), ["encrypted", "version"]); assert.equal(sealed.version, 1); assert.match(sealed.encrypted, /^[A-Za-z0-9+/]+={0,2}$/u);
        assert(!savedText.includes(username) && !savedText.includes(password));
        report.checks.initialLogin = true; report.checks.privilegedIpcDenied = true; report.checks.wrongPasswordGeneric = true; report.checks.nativeEncryptedStorage = true;
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
        const transport = await page.evaluate(async () => {
            const value = await window.happyDesktop.runtimeGet();
            if (!value.activeTarget?.happyAgentHttpUrl) return false;
            const response = await fetch(value.activeTarget.happyAgentHttpUrl + "/health"); return response.ok;
        }); assert(transport, "Authenticated workspace transport did not open");
        report.checks.authenticatedWorkspaceTransport = true;
        const sockets = new Set(); page.on("websocket", socket => { sockets.add(socket); socket.on("close", () => sockets.delete(socket)); });
        const marker = randomBytes(16).toString("hex");
        await page.evaluate(marker => { window.__cyberaiLogoutMarker = marker; window.addEventListener("beforeunload", event => { event.preventDefault(); event.returnValue = "stay"; }); }, marker);
        stage = "forced main-process logout";
        await page.getByRole("button", { name: /settings|ayarlar|ayarları aç/iu }).first().click();
        const general = page.getByRole("button", { name: /^(General|Genel)$/iu }).first(); if (await general.count()) await general.click();
        const observedSockets = sockets.size; await page.getByRole("button", { name: /^(Çıkış yap|Sign out)$/iu }).click();
        await waitLogin(); assert.equal(await page.evaluate(() => window.__cyberaiLogoutMarker), undefined, "Logout must replace the document despite beforeunload prevention");
        await denied(); await assert.rejects(lstat(saved), { code: "ENOENT" });
        assert.equal(sockets.size, 0); report.logoutTransportProof = observedSockets ? "Observed workspace WebSockets closed and old document destroyed" : "Old workspace document destroyed; no WebSocket was observed";
        await page.screenshot({ path: join(evidence, "logout.png"), mask: [login().locator('input[name="username"], input[name="password"]')] });
        for (const [path, text] of sentinels) assert.equal(await readFile(path, "utf8"), text);
        await client.getHealth(); report.checks.forcedLogoutReload = true; report.checks.savedCredentialRemoved = true; report.checks.profileAndSkillsPreserved = true; report.checks.engineStillHealthy = true;
        report.inferenceFixture = { localOnly: true, calls: inferenceCalls, externalProviderCalls: 0 };
        await endVideo(); await stopOwned(); report.success = true;
    } catch {
        // Never serialize browser/HTTP/native error messages: they can include input credentials.
        report.errors.push("Native acceptance failed during " + stage);
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
    assert.throws(() => signedManifest({ sha256: pin.sha256, size: 10, signature: "A".repeat(512) }, "CyberFi-0.0.125-x64.exe", pin.sha256, 10));
    console.log("Strict artifact pins, redirect refusal, independent RSA refusal and credential environment isolation passed. No app or network used.");
} else await main();
