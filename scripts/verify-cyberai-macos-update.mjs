import assert from "node:assert/strict";
import { assertDraftRelease, beginDraftFixture, exerciseDraftRefusals, reviewedDraftPins } from "./native-fixture-hooks.mjs";
import { createHash, verify, randomBytes } from "node:crypto";
import { constants, createReadStream, createWriteStream } from "node:fs";
import { copyFile, chmod, mkdir, readFile, readdir, realpath, lstat, writeFile, stat } from "node:fs/promises";
import { createRequire } from "node:module";
import { basename, dirname, isAbsolute, join, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { execFile, spawn } from "node:child_process";
import { promisify } from "node:util";
import { createServer } from "node:http";
import { Readable, Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import { setTimeout as delay } from "node:timers/promises";

const REPOSITORY = "CyberfiTechh/CyberFi-Releases";
const SOURCE_COMMIT = process.env.ACCEPTANCE_SOURCE_SHA;
const PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA09ZxJMbpq1uFEnz7n52M\nAJtceCXVQCo57lgwMAmizgJaGVGsgsMpzqgCCRgXBN+bPygE+16S9XwYOwHDlnNG\noq8h+bE9Nxce3PzsQHrscdHTT1lGQ/5XwSmvzTvxLdURtQWpaXZl7lJghUnZHNDA\n8SOHbk8rQ+butE82lhcq0C+hgJgHTUqFl9Irppi2O+MpufsZo8PX5jphD4H0aX0k\nB9P+LUreoBmG/L3T3AMZEzQZG606awc/ZMYsJcJkt4xNMjR3ZMz1aWKErW2AXDeY\nyfAo0zmEAUEAFSc3UEJRnmBAjorVA3C/rHJzYP7QabSh8ORLOUrqQYgqCpTLETpf\nct0J+NphCLuBGNQ5IeId5IPiBNZlKynGzP/HK+oJTvJ31hTHIiaA+5pfIESXELIZ\nJ5awYGW0y7fii0CqRGwFMJnU829APVvAC9LJUzSSz7NP+2rmc/boYInx8cjN2/LO\nLI9HsPvON+oxM4MhjRxDd4CVoKDpI+rB2TthSdfxt3UxAgMBAAE=\n-----END PUBLIC KEY-----";
const exec = promisify(execFile);
const hash = value => createHash("sha256").update(value).digest("hex");
const id = value => { assert(Number.isSafeInteger(value) && value > 0); return value; };
const sha = value => { assert.match(value, /^[a-f0-9]{64}$/u); return value; };
function artifactPins(value) {
    assert(value && Object.keys(value).sort().join(",") === "source,target");
    for (const item of Object.values(value)) {
        assert(Object.keys(item).sort().join(",") === "assetId,manifestAssetId,manifestSha256,releaseId,sha256");
        id(item.releaseId); id(item.assetId); id(item.manifestAssetId); sha(item.sha256); sha(item.manifestSha256);
    }
    return value;
}
function signedManifest(data, version, filename, expectedSha, expectedSize) {
    assert(data && sha(data.sha256) === expectedSha && data.size === expectedSize);
    assert(Number.isSafeInteger(data.size) && data.size > 0 && data.size <= 256 * 1024 ** 2);
    assert.match(data.signature, /^[A-Za-z0-9+/=]{100,700}$/u);
    assert(verify("sha256", Buffer.from(`${version}\n${filename}\n${data.sha256}\n${data.size}\n`),
        PUBLIC_KEY, Buffer.from(data.signature, "base64")), "Independent RSA manifest verification failed");
}
function allowedRedirect(value) {
    const url = new URL(value);
    assert(url.protocol === "https:" && !url.username && !url.password && (!url.port || url.port === "443"));
    assert(url.hostname === "github.com" || url.hostname.endsWith(".githubusercontent.com") || url.hostname.endsWith(".blob.core.windows.net"));
    return url;
}
function publishedReleaseMatches(release, releaseId, tag) {
    return release?.id === releaseId && release?.draft === false && release?.tag_name === tag;
}
async function hashFile(path) {
    const value = createHash("sha256");
    for await (const chunk of createReadStream(path)) value.update(chunk);
    return value.digest("hex");
}
async function bundleProof(app) {
    const framework = await readFile(join(app, "Contents/Frameworks/Electron Framework.framework/Electron Framework"));
    const sentinel = Buffer.from("dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX"), fuseWires = [];
    for (let index = framework.indexOf(sentinel); index !== -1; index = framework.indexOf(sentinel, index + sentinel.length)) {
        const at = index + sentinel.length, length = framework[at + 1];
        assert(framework[at] === 1 && length >= 8 && length <= 64);
        const states = framework.subarray(at + 2, at + 2 + length);
        for (const disabled of [0, 2, 3]) assert.equal(states[disabled], 48, "Published security fuse must remain disabled");
        for (const enabled of [1, 4, 5]) assert.equal(states[enabled], 49, "Published integrity fuse must remain enabled");
        fuseWires.push(framework.subarray(at, at + 2 + length).toString("hex"));
    }
    assert(fuseWires.length > 0 && fuseWires.length <= 2);
    return { fuseWires, asarSha256: await hashFile(join(app, "Contents/Resources/app.asar")),
        executableSha256: await hashFile(join(app, "Contents/MacOS/CyberFi")) };
}

function ownedProcessRecords(text, executable, apps) {
    return text.split(/\r?\n/u).flatMap(line => {
        const match = /^\s*([1-9][0-9]*)\s+(.+)$/u.exec(line); if (!match) return [];
        const path = match[2].trim();
        const isApp = path === executable;
        const isHelper = path.startsWith(apps + "/") && /^\.cyberfi-update-[a-f0-9-]{36}\/CyberFiUpdater$/u.test(path.slice(apps.length + 1));
        return isApp || isHelper ? [{ pid: id(Number(match[1])), path, isHelper }] : [];
    });
}

async function main() {
    assert(process.platform === "darwin" && process.env.GITHUB_ACTIONS === "true" &&
        process.env.RUNNER_ENVIRONMENT === "github-hosted" && process.env.GITHUB_REPOSITORY === REPOSITORY &&
        process.env.GITHUB_REF === process.env.ACCEPTANCE_FIXTURE_REF, "Only the disposable native Mac runner may execute this test");
    const arch = process.env.ARCH;
    assert((arch === "x64" || arch === "arm64") && process.arch === arch);
    const pins = artifactPins(reviewedDraftPins(arch));
    const upstream = await realpath(process.argv[2]);
    assert.equal(upstream, join(resolve(process.env.GITHUB_WORKSPACE), "upstream"));
    const root = join(await realpath(process.env.RUNNER_TEMP), "cyberfi-macos-app-update");
    await mkdir(root); // Never reuse a profile, installed app or handoff from another attempt.
    const evidence = join(root, "evidence"), apps = join(root, "Applications"), profile = join(root, "user-data");
    await Promise.all([evidence, apps, profile].map(path => mkdir(path)));
    const app = join(apps, "CyberFi.app"), executable = join(app, "Contents/MacOS/CyberFi");
    const report = { success: false, stage: "artifact verification", architecture: arch, sourceCommit: SOURCE_COMMIT, sourceVersion: "0.0.131", targetVersion: "0.0.132",
        actualGui: false, progress: [], events: [], errors: [], limits: ["macOS startup may transiently report regular Dock activation policy; full Dock absence is not certified.", "CI launches do not prove Gatekeeper acceptance of a browser-quarantined download."] };
    const save = () => writeFile(join(evidence, "automatic-update.json"), JSON.stringify(report, null, 2) + "\n");
    const token = process.env.GH_TOKEN, username = process.env.CYBERAI_USERNAME, password = process.env.CYBERAI_PASSWORD;
    assert(username && username !== "admin" && password && password.length >= 12, "Disposable user credentials required");
    const safeEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) =>
        !/TOKEN|SECRET|PASSWORD|CYBERAI_USERNAME|CREDENTIAL|API_KEY|NODE_OPTIONS|ELECTRON_RUN_AS_NODE|SMOKE_REPORT|SMOKE_SCREENSHOT|VITE_DEV_SERVER_URL|ACCEPTANCE_ARTIFACTS/iu.test(key)));
    for (const key of Object.keys(process.env)) if (!Object.hasOwn(safeEnv, key)) delete process.env[key];
    const command = async (file, args, options = {}) => (await exec(file, args, { env: safeEnv, timeout: 120000, maxBuffer: 8 * 1024 ** 2, ...options })).stdout.trim();
    async function api(path) {
        assert.match(path, /^repos\/(CyberfiTechh\/(CyberFi-Releases|CyberFi-Engine))\/releases\/(tags\/[A-Za-z0-9.-]+|[1-9][0-9]*)$/u);
        const response = await fetch("https://api.github.com/" + path, { headers: { Accept: "application/vnd.github+json", ...(token ? { Authorization: "Bearer " + token } : {}) }, redirect: "error", signal: AbortSignal.timeout(45000) });
        assert(response.ok, `GitHub metadata failed (${response.status})`);
        return response.json();
    }
    async function download(repository, asset, destination) {
        assert([REPOSITORY, "CyberfiTechh/CyberFi-Engine"].includes(repository)); id(asset.id);
        assert(Number.isSafeInteger(asset.size) && asset.size > 0 && asset.size <= 256 * 1024 ** 2);
        let url = new URL(`https://api.github.com/repos/${repository}/releases/assets/${asset.id}`);
        for (let redirects = 0; redirects < 5; redirects++) {
            const response = await fetch(url, { headers: { Accept: "application/octet-stream", ...(url.hostname === "api.github.com" && token ? { Authorization: "Bearer " + token } : {}) }, redirect: "manual", signal: AbortSignal.timeout(300000) });
            if ([301, 302, 303, 307, 308].includes(response.status)) { url = allowedRedirect(response.headers.get("location")); continue; }
            assert(response.ok && response.body, `Asset download failed (${response.status})`);
            let bytes = 0;
            await pipeline(Readable.fromWeb(response.body), new Transform({ transform(chunk, encoding, done) {
                bytes += chunk.length; done(bytes <= asset.size ? null : Error("Asset exceeded pinned size"), chunk);
            } }), createWriteStream(destination, { flags: "wx", mode: 0o600 }));
            assert.equal(bytes, asset.size);
            return;
        }
        throw Error("Too many asset redirects");
    }
    const mounts = [];
    let fixture;
    let paths, runtime, inferenceStop, appRun, appExit, appError, browser, page, video, watcher, observer, monitor, monitorError, stop = false, newPid;
    async function ownedProcesses() {
        return ownedProcessRecords(await command("/bin/ps", ["-ww", "-axo", "pid=,comm="]), executable, apps);
    }
    async function ownedStop(record) {
        const currentPath = () => command("/bin/ps", ["-p", String(record.pid), "-o", "comm="]).catch(error => { if (error.code === 1) return ""; throw error; });
        if (await currentPath() !== record.path) return;
        try { process.kill(record.pid, "SIGTERM"); } catch (error) { if (error.code === "ESRCH") return; throw error; }
        const until = Date.now() + 5000; while (Date.now() < until && await currentPath() === record.path) await delay(100);
        if (await currentPath() === record.path) try { process.kill(record.pid, "SIGKILL"); } catch (error) { if (error.code !== "ESRCH") throw error; }
    }
    try {
        const proofs = {};
        for (const [kind, version] of [["source", "0.0.131"], ["target", "0.0.132"]]) {
            report.stage = kind === "source" ? "published source metadata" : "published target metadata";
            const pin = pins[kind], release = await api(`repos/${REPOSITORY}/releases/${pin.releaseId}`);
            assertDraftRelease(release, kind, pin, "macos-v" + version, SOURCE_COMMIT);
            const filename = `CyberFi-${version}-${arch}.dmg`;
            const asset = release.assets.find(item => item.id === pin.assetId);
            const manifest = release.assets.find(item => item.id === pin.manifestAssetId);
            assert(asset?.name === filename && asset.digest === "sha256:" + pin.sha256 && asset.state === "uploaded");
            assert(manifest?.name === filename + ".update.json" && manifest.digest === "sha256:" + pin.manifestSha256 && manifest.size <= 4096);
            const dmg = join(root, filename), manifestFile = dmg + ".update.json";
            report.stage = kind === "source" ? "source artifact download" : "target artifact download";
            await download(REPOSITORY, asset, dmg); await download(REPOSITORY, manifest, manifestFile);
            assert.equal(await hashFile(dmg), pin.sha256); assert.equal(await hashFile(manifestFile), pin.manifestSha256);
            signedManifest(JSON.parse((await readFile(manifestFile, "utf8")).replace(/^\uFEFF/u, "")), version, filename, pin.sha256, asset.size);
            report.stage = kind === "source" ? "source bundle verification" : "target bundle verification";
            await command("/usr/bin/hdiutil", ["verify", dmg]);
            const mount = join(root, "mount-" + kind); await mkdir(mount);
            await command("/usr/bin/hdiutil", ["attach", "-readonly", "-nobrowse", "-mountpoint", mount, dmg]); mounts.push(mount);
            const bundle = join(mount, "CyberFi.app");
            assert.equal(await command("/usr/libexec/PlistBuddy", ["-c", "Print :CFBundleShortVersionString", join(bundle, "Contents/Info.plist")]), version);
            assert.equal(await command("/usr/libexec/PlistBuddy", ["-c", "Print :CFBundleIdentifier", join(bundle, "Contents/Info.plist")]), "tr.pdrkocum.agent");
            await command("/usr/bin/lipo", [join(bundle, "Contents/MacOS/CyberFi"), "-verify_arch", arch === "x64" ? "x86_64" : "arm64"]);
            await command("/usr/bin/codesign", ["--verify", "--deep", "--strict", bundle]);
            proofs[kind] = await bundleProof(bundle);
            if (kind === "source") await command("/usr/bin/ditto", ["--rsrc", "--extattr", "--acl", bundle, app]);
        }
        assert.deepEqual(await bundleProof(app), proofs.source);
        report.immutableInputs = { pins, sourceFixture: "Public131 source", target: "Exact private draft 132", independentRsaManifests: true, packagedBundleProofs: proofs, fusesModified: false, quarantineModified: false };
        await save();
        report.stage = "pinned engine metadata and download";
        const engineRelease = await api("repos/CyberfiTechh/CyberFi-Engine/releases/439371035");
        const enginePins = arch === "x64" ? [728161015, "acc2532e7831894166723b176eac4092cdbd5bf4a2450abbe03576bdd6c3d2ed"] : [728161005, "93faf99236ff4c3a42cce49861e6504ca7265f6582c7cfbbaebd882e99fd220a"];
        assert(engineRelease.tag_name === "v0.4.125" && !engineRelease.draft && !engineRelease.prerelease);
        const engineAsset = engineRelease.assets.find(item => item.id === enginePins[0]);
        assert(engineAsset?.digest === "sha256:" + enginePins[1]);
        const archive = join(root, "engine.tar.gz"), engineRoot = join(root, "engine"); await mkdir(engineRoot);
        await download("CyberfiTechh/CyberFi-Engine", engineAsset, archive); assert.equal(await hashFile(archive), enginePins[1]);
        assert.equal(await command("/usr/bin/tar", ["-tzf", archive]), `happy-agent-darwin-${arch}`);
        await command("/usr/bin/tar", ["-xzf", archive, "-C", engineRoot]);
        const engineName = `happy-agent-darwin-${arch}`, engine = join(engineRoot, engineName);
        process.env.HAPPY_DESKTOP_AGENT_EXECUTABLE = engine;
        const gym = name => pathToFileURL(join(upstream, "packages/happy-desktop-gym/sources/electron", name + ".ts")).href;
        const { gymElectronProcessRun, gymElectronVideoRecord } = await import(gym("launch"));
        const { gymRunPathsCreate } = await import(gym("paths"));
        
        const { happyAgentRuntimeCreate } = await import(gym("happyAgentRuntime"));
        ({ paths } = await gymRunPathsCreate("smoke"));
        report.stage = "production managed engine cache precondition";
        const desktopMain = name => pathToFileURL(join(upstream, "packages/happy-desktop-electron/sources/main", name + ".ts")).href;
        const { happyDaemonPaths, happyAgentBinaryPath } = await import(desktopMain("happyAgentBinaryPaths"));
        const { happyAgentBinarySelected } = await import(desktopMain("happyAgentBinaryConfig"));
        const { happyAgentReleaseInstall } = await import(desktopMain("happyAgentRelease"));
        const cachePaths = happyDaemonPaths({ HAPPY_HOME_DIR: paths.happyHome }, paths.home);
        const cachedEngine = happyAgentBinaryPath(cachePaths, "0.4.125");
        assert(cachedEngine.startsWith(paths.root + sep) && cachePaths.binaryConfigPath.startsWith(paths.root + sep));
        await mkdir(dirname(cachedEngine), { recursive: true, mode: 0o700 });
        await copyFile(engine, cachedEngine, constants.COPYFILE_EXCL); await chmod(cachedEngine, 0o700);
        const extractedBinarySha = await hashFile(engine); assert.equal(await hashFile(cachedEngine), extractedBinarySha);
        // Consume verified cached bytes through the normal lock/data-floor/
        // atomic-selection producer. No fetch interception or forged status.
        const installed = await happyAgentReleaseInstall({ version: "0.4.125", archivedBinaryName: engineName, asset: engineAsset }, cachePaths);
        assert(installed.version === "0.4.125" && installed.path === cachedEngine);
        assert.deepEqual(await happyAgentBinarySelected(cachePaths), installed);
        assert.equal((await command(cachedEngine, ["--version"])).split(/\s+/u).at(-1), "0.4.125");
        const managedCacheConfig = JSON.parse(await readFile(cachePaths.binaryConfigPath, "utf8"));
        assert.deepEqual(managedCacheConfig, { downloadedVersions: ["0.4.125"], selectedVersion: "0.4.125" });
        report.managedEnginePrecondition = { producer: "pinned upstream happyAgentReleaseInstall consuming verified cached bytes", version: installed.version, executableSha256: extractedBinarySha, config: managedCacheConfig, fetchOverridden: false, dataVersionFabricated: false };

        const inferenceToken = randomBytes(24).toString("hex"); let inferenceCalls = 0;
        const inferenceServer = createServer(async (request, response) => {
            for await (const _ of request) { /* Synthetic fixture only. */ }
            if (request.headers.authorization !== "Bearer " + inferenceToken) { response.writeHead(401); response.end(); return; }
            inferenceCalls++; response.writeHead(200, { "content-type": "application/json" });
            response.end(JSON.stringify({ content: [{ type: "text", text: "Native CyberAI update chat confirmed." }], completionDelayMs: 1 }));
        });
        await new Promise(done => inferenceServer.listen(0, "127.0.0.1", done));
        const inference = { url: `http://127.0.0.1:${inferenceServer.address().port}/inference`, token: inferenceToken, stop: () => new Promise(done => inferenceServer.close(done)) };
        inferenceStop = inference.stop;
        report.stage = "owned engine startup";
        runtime = await happyAgentRuntimeCreate(paths, inference);
        report.stage = "synthetic chat fixture";
        const repository = join(paths.projects, "update-chat"); await mkdir(repository);
        const gitEnv = { ...runtime.environment, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1" };
        await command("/usr/bin/git", ["init", "--initial-branch=main", repository], { env: gitEnv });
        await writeFile(join(repository, "README.md"), "# Owned update fixture\n");
        await command("/usr/bin/git", ["-C", repository, "add", "README.md"], { env: gitEnv });
        await command("/usr/bin/git", ["-C", repository, "-c", "user.name=CI", "-c", "user.email=ci@example.invalid", "commit", "-m", "Fixture"], { env: gitEnv });
        const { project } = await runtime.client.registerProject(repository); await runtime.client.waitForWorkspace(project.id, "ready", 90000);
        const { agent } = await runtime.client.createAgent(project.id);
        const submission = await runtime.client.sendMessage(agent.id, "Confirm this synthetic update acceptance.");
        await runtime.client.waitForAgentIdle(agent.id, submission.runId, 60000); assert(inferenceCalls > 0);
        const configDir = join(profile, "desktop"); await mkdir(configDir);
        await writeFile(join(configDir, "local-onboarding.json"), JSON.stringify({ version: 3, chiefOfStaffSetup: true }));
        await writeFile(join(configDir, "config.json"), JSON.stringify({ appearance: "dark", defaultPermissionMode: "read_only", previewUpdatesEnabled: false }));
        const settingsNote = join(configDir, "retained-user-note.txt"), skillsNote = join(paths.home, ".agents/skills/acceptance-retained/SKILL.md");
        await mkdir(dirname(skillsNote), { recursive: true });
        const sentinels = [[settingsNote, "Keep the existing desktop profile.\n"], [skillsNote, "# Existing user skill\nKeep this exact text.\n"]];
        for (const [path, text] of sentinels) await writeFile(path, text);
        report.stage = "native updater and observer setup";
        const helper = join(app, "Contents/Resources/cyberfi-updater/CyberFiUpdater");
        await command("/usr/bin/codesign", ["--verify", "--strict", helper]);
        const watcherExecutable = join(root, "watch-owned-app");
        await command("/usr/bin/swiftc", ["-O", fileURLToPath(new URL("./macos-update-window-watch.swift", import.meta.url)), "-o", watcherExecutable], { timeout: 180000 });
        watcher = spawn(watcherExecutable, ["--bundle", app], { env: safeEnv, stdio: ["ignore", "pipe", "pipe"] });
        let observerText = ""; watcher.stdout.on("data", value => { observerText += value; });
        const observerDone = new Promise((done, reject) => { watcher.on("error", reject); watcher.on("close", code => code === 0 ? done() : reject(Error("Native visibility watcher failed"))); });
        observerDone.catch(() => undefined);
        await new Promise((done, reject) => { watcher.stderr.once("data", value => value.toString().includes("ready") ? done() : reject(Error("Observer not ready"))); watcher.once("error", reject); });
        observer = async () => { watcher.kill("SIGTERM"); await observerDone; return JSON.parse(observerText); };
        const port = 19483, endpoint = `http://127.0.0.1:${port}`;
        const listenerPid = async () => {
            const value = await command("/usr/sbin/lsof", ["-nP", `-iTCP@127.0.0.1:${port}`, "-sTCP:LISTEN", "-t"]).catch(error => {
                if (error.code === 1) return "";
                throw error;
            });
            const unique = [...new Set(value.split(/\s+/u).filter(Boolean).map(Number))];
            assert(unique.length <= 1, "The owned loopback endpoint has multiple listeners");
            return unique.length ? id(unique[0]) : undefined;
        };
        assert.equal(await listenerPid(), undefined, "The reserved test endpoint must initially be unused");
        const owner = randomBytes(16).toString("hex");
        const env = { ...safeEnv, ...runtime.environment, CYBERFI_UPDATE_FIXTURE_OWNER: owner, HAPPY_DESKTOP_WINDOWS_HIDDEN: "1", HAPPY_DESKTOP_DEBUG: "1", HAPPY_DEBUG_RENDERER_PORT: String(port) };
        report.stage = "source application startup";
        appRun = gymElectronProcessRun({ executablePath: executable, args: ["--user-data-dir=" + profile, "--debug"], env, timeout: 15 * 60000 })
            .then(result => { appExit = result; }, error => { appError = error; });
        const require = createRequire(join(upstream, "packages/happy-desktop-gym/package.json"));
        const { chromium } = require("playwright");
        async function rendererConnect() {
            const deadline = Date.now() + 90000;
            while (Date.now() < deadline) {
                try {
                    const response = await fetch(endpoint + "/json/list", { signal: AbortSignal.timeout(1500) });
                    if (response.ok && (await response.json()).some(item => item.type === "page")) {
                        browser = await chromium.connectOverCDP(endpoint);
                        page = browser.contexts().flatMap(context => context.pages()).find(item => !item.url().startsWith("devtools:"));
                        if (page) { await page.waitForFunction(() => typeof window.happyDesktop?.runtimeGet === "function", undefined, { timeout: 30000 }); return; }
                    }
                } catch { /* Existing signed --debug startup is still publishing its loopback endpoint. */ }
                await delay(200);
            }
            throw Error("Actual packaged renderer did not expose its approved debug endpoint");
        }
        await rendererConnect();
        video = await gymElectronVideoRecord(page, { path: join(evidence, "actual-source-update.webm"), fps: 5 });
        await page.evaluate(() => { localStorage.setItem("pdr-kocum-agent.language", "tr"); localStorage.setItem("happy.welcome.v1", JSON.stringify({ welcomeAcknowledged: true })); });
        await page.reload({ waitUntil: "commit" });
        report.stage = "source130 protected login";
        await page.waitForFunction(() => !document.querySelector('[data-testid="desktop-startup-screen"]') && !!document.querySelector('[data-happy-desktop-ui="cyberfi-account-login"] input[name="password"]:not(:disabled)'), undefined, { timeout: 60000 });
        await page.addStyleTag({ content: 'input[name="username"], input[name="password"] { color: transparent !important; text-shadow: none !important; caret-color: transparent !important; }' });
        const sourceLogin = page.locator('[data-happy-desktop-ui="cyberfi-account-login"]');
        assert(await page.evaluate(async () => { try { await window.happyDesktop.runtimeGet(); return false; } catch { return true; } }), "Source128 must deny privileged IPC before login");
        await sourceLogin.locator('input[name="username"]').fill(username); await sourceLogin.locator('input[name="password"]').fill(password);
        assert.equal(await sourceLogin.getByRole("checkbox", { name: "Beni hatırla" }).isChecked(), false);
        await sourceLogin.getByRole("button", { name: "Giriş yap", exact: true }).click();
        await page.waitForFunction(async () => (await window.happyDesktop.cyberFiAccountGet()).status === "signedIn", undefined, { timeout: 60000 });
        const sourceAccount = await page.evaluate(() => window.happyDesktop.cyberFiAccountGet());
        assert(sourceAccount.user?.role === "user" && sourceAccount.remember === false && sourceAccount.username === username);
        await assert.rejects(lstat(join(configDir, "cyberai-account.json")), { code: "ENOENT" });
        report.sourceAuthenticated = true;
        await page.waitForFunction(async () => typeof window.happyDesktop?.runtimeGet === "function" && (await window.happyDesktop.runtimeGet()).phase === "ready", undefined, { timeout: 90000 });
        const oldPid = await listenerPid(); report.oldPid = oldPid;
        id(oldPid);
        const alive = pid => { try { process.kill(pid, 0); return true; } catch (error) { if (error.code === "ESRCH") return false; throw error; } };
        report.stage = "attach owned draft feed fixture";
        fixture = await beginDraftFixture({ pid: oldPid, executable, profile, root, rendererPort: port, owner, pin: pins.target });
        report.stage = "stable-only GUI desktop update check";
        await page.locator('[data-happy-desktop-ui="sidebar-footer"]').getByRole("button", { name: /^(Settings|Ayarlar|Open settings|Ayarları aç)$/iu }).click();
        const general = page.getByRole("button", { name: /^(General|Genel)$/iu }).first(); if (await general.count()) await general.click();
        const select = page.locator("#cyberfi-settings-desktop-version"); await select.waitFor({ state: "visible", timeout: 60000 });
        const preview = page.locator("#happy-agent-settings-preview-updates");
        await preview.waitFor({ state: "visible", timeout: 60000 });
        assert.equal(await preview.getAttribute("aria-checked"), "false");
        assert.notEqual(await page.evaluate(async () => (await window.happyDesktop.desktopConfigGet()).previewUpdatesEnabled), true);
        assert.equal(JSON.parse(await readFile(join(configDir, "config.json"), "utf8")).previewUpdatesEnabled, false);
        report.previewUpdatesEnabled = false;
        const check = page.getByRole("button", { name: /^(Check for updates|Güncellemeleri denetle)$/iu }).first();
        await check.click();
        await page.waitForFunction(async () => (await window.happyDesktop.runtimeGet()).update?.versions?.some(item => item.version === "0.0.132"), undefined, { timeout: 45000 });
        await select.selectOption("0.0.132");
        const button = page.getByRole("button", { name: /^(Download and reopen|İndir ve yeniden aç|Kur ve yeniden aç)$/iu }); await button.waitFor({ state: "visible" });
        report.stage = "altered signature and bytes are refused";
        report.updateFixture = await exerciseDraftRefusals({ fixture, page, check, select, button,
            verifySource: async () => {
                assert.equal(await listenerPid(), oldPid);
                assert.deepEqual(await bundleProof(app), proofs.source);
                assert(!(await readdir(apps)).some(name => name.startsWith(".cyberfi-update-")));
                for (const [path, text] of sentinels) assert.equal(await readFile(path, "utf8"), text);
            },
        });
        let ticket, ready, stagePath, oldExitObserved = false;
        monitor = Promise.all([(async () => {
            while (!stop) {
                if (!stagePath) {
                    const names = (await readdir(apps)).filter(name => /^\.cyberfi-update-[a-f0-9-]{36}$/u.test(name));
                    assert(names.length <= 1, "Only one app-owned update stage is permitted");
                    if (names.length) stagePath = join(apps, names[0]);
                }
                if (stagePath && !ticket && await lstat(join(stagePath, "ready.json")).catch(error => { if (error.code !== "ENOENT") throw error; })) {
                    ticket = JSON.parse(await readFile(join(stagePath, "ticket.json"), "utf8"));
                    if (ticket) assert(ticket.targetApp === app && ticket.userDataPath === profile && ticket.parentPid === oldPid && ticket.version === "0.0.132" && ticket.hidden === true);
                }
                if (ticket && !ready) {
                    ready = await readFile(ticket.readyPath, "utf8").then(JSON.parse).catch(error => { if (error.code !== "ENOENT") throw error; });
                    if (ready) {
                        assert(ready.nonce === ticket.nonce && ready.parentPid === oldPid && alive(oldPid), "Helper readiness must be observed while the actual parent is alive");
                        report.events.push({ type: "helper-ready", at: Date.now(), helperPid: ready.helperPid });
                    }
                }
                if (!oldExitObserved && !alive(oldPid)) {
                    assert(ready, "Old app exited before an observed helper readiness handshake"); oldExitObserved = true;
                    report.events.push({ type: "old-parent-exited", at: Date.now() });
                }
                await delay(20);
            }
        })(), (async () => {
            while (!stop) {
                if (!oldExitObserved) {
                    try {
                        const state = await page.evaluate(async () => {
                            const update = (await window.happyDesktop.runtimeGet()).update;
                            const bar = document.querySelector('[role="progressbar"][aria-label="Masaüstü indirmesi"], [role="progressbar"][aria-label="Desktop download"]');
                            const visible = !!bar?.getClientRects().length && getComputedStyle(bar).visibility !== "hidden";
                            return { status: update.status, fraction: update.downloadedFraction, message: update.message,
                                domPercent: visible ? Number(bar.getAttribute("aria-valuenow")) : null, domText: visible ? bar.parentElement?.innerText : null };
                        });
                        assert.notEqual(state.status, "error", state.message);
                        if (JSON.stringify(state) !== JSON.stringify(report.progress.at(-1))) report.progress.push(state);
                    } catch (error) { if (alive(oldPid) && !ready) throw error; }
                }
                await delay(100);
            }
        })()]).catch(error => { monitorError = error; });
        report.stage = "real GUI download and helper handoff";
        await button.click(); report.actualGui = true;
        const until = Date.now() + 12 * 60000;
        while (!appExit && !appError && !monitorError && Date.now() < until) await delay(100);
        assert(!monitorError, "Update handoff monitor failed"); assert(!appError, "Source application process failed");
        assert(appExit?.exitCode === 0, "Actual old app did not exit cleanly"); await appRun;
        const sourceVideo = await video.stop(); video = undefined; assert(sourceVideo.framesReceived > 0 && sourceVideo.framesWritten > 0); report.sourceVideo = sourceVideo;
        let receipt, result;
        report.stage = "automatic helper receipt and target ACK";
        const receiptDeadline = Date.now() + 120000;
        while (Date.now() < receiptDeadline) {
            if (monitorError) throw monitorError;
            if (ticket) {
                receipt = await readFile(ticket.receiptPath, "utf8").then(JSON.parse).catch(error => { if (error.code !== "ENOENT") throw error; });
                result = await readFile(join(stagePath, "result.json"), "utf8").then(JSON.parse).catch(error => { if (error.code !== "ENOENT") throw error; });
                if (result?.status === "rolled-back") throw Error("Production helper rolled back: " + result.reason);
                if (receipt && result?.status === "acknowledged") break;
            }
            await delay(50);
        }
        assert(oldExitObserved && ticket && ready && receipt && result?.status === "acknowledged");
        assert(receipt.nonce === ticket.nonce && result.nonce === ticket.nonce && receipt.version === "0.0.132" && receipt.executablePath === executable && receipt.pid !== oldPid);
        assert(result.oldBundleRemoved === true, "The old bundle must only be removed after matching acknowledgment");
        await assert.rejects(lstat(ticket.candidatePath), { code: "ENOENT" });
        newPid = id(receipt.pid); assert(!alive(oldPid) && alive(newPid));
        const targetStat = await stat(app); assert(targetStat.dev === ticket.candidateDevice && targetStat.ino === ticket.candidateInode);
        assert.deepEqual(await bundleProof(app), proofs.target); await command("/usr/bin/codesign", ["--verify", "--deep", "--strict", app]);
        report.receipt = { version: receipt.version, pid: newPid, executablePath: executable, nonceSha256: hash(ticket.nonce), status: result.status, oldBundleRemoved: result.oldBundleRemoved };
        report.events.push({ type: "new-target-acknowledged", at: Date.now(), pid: newPid });
        const endpointDeadline = Date.now() + 60000;
        while (await listenerPid() !== newPid && Date.now() < endpointDeadline) await delay(100);
        assert.equal(await listenerPid(), newPid, "The replacement must own the loopback endpoint before reconnection");
        report.stage = "auto-reopened target login";
        await rendererConnect();
        video = await gymElectronVideoRecord(page, { path: join(evidence, "actual-reopened-target.webm"), fps: 5 });
        const login = page.locator('[data-happy-desktop-ui="cyberfi-account-login"]');
        await page.waitForFunction(() => !document.querySelector('[data-testid="desktop-startup-screen"]') && !!document.querySelector('[data-happy-desktop-ui="cyberfi-account-login"] input[name="password"]:not(:disabled)'), undefined, { timeout: 60000 });
        await login.waitFor({ state: "visible" });
        const gate = await page.evaluate(async () => { try { await window.happyDesktop.runtimeGet(); return false; } catch { return true; } }); assert(gate, "Auto-reopened signed-out target must deny runtime IPC");
        const privacy = 'input[name="username"], input[name="password"], [data-happy-desktop-ui="form-row-description"] { color: transparent !important; text-shadow: none !important; caret-color: transparent !important; }';
        await page.addStyleTag({ content: privacy });
        report.stage = "target UI login";
        await login.locator('input[name="username"]').fill(username); await login.locator('input[name="password"]').fill(password);
        assert.equal(await login.getByRole("checkbox", { name: "Beni hatırla" }).isChecked(), false);
        await login.getByRole("button", { name: "Giriş yap", exact: true }).click();
        await page.waitForFunction(async () => (await window.happyDesktop.cyberFiAccountGet()).status === "signedIn", undefined, { timeout: 60000 });
        report.stage = "authenticated target runtime startup";
        await page.waitForFunction(async () => (await window.happyDesktop.runtimeGet()).phase === "ready", undefined, { timeout: 90000 });
        const account = await page.evaluate(() => window.happyDesktop.cyberFiAccountGet()); assert(account.user?.role === "user" && account.remember === false && account.username === username);
        await assert.rejects(lstat(join(configDir, "cyberai-account.json")), { code: "ENOENT" });
        const projectRow = page.locator(`[data-happy-desktop-ui="sidebar-item"][data-item-id="local/${project.id}"]`); await projectRow.waitFor({ state: "visible", timeout: 45000 }); await projectRow.click();
        const chatTab = page.locator(`[data-happy-desktop-ui="tab"][data-tab-id="${agent.id}"]`); await chatTab.waitFor({ state: "visible", timeout: 30000 }); await chatTab.click();
        await page.getByText("Native CyberAI update chat confirmed.", { exact: true }).first().waitFor({ state: "visible", timeout: 30000 });
        report.stage = "authenticated target chat rendered";
        report.authenticatedTargetChat = true; report.loginGateAcknowledgedBeforeLogin = true; report.sessionRemembered = false;
        await delay(1000); await page.screenshot({ path: join(evidence, "reopened-target.png"), mask: [page.getByText(username, { exact: true })] });
        report.reopenedRuntime = await page.evaluate(async () => { const value = await window.happyDesktop.runtimeGet(); return { phase: value.phase, currentVersion: value.update?.currentVersion }; });
        assert.equal(await command("/usr/libexec/PlistBuddy", ["-c", "Print :CFBundleShortVersionString", join(app, "Contents/Info.plist")]), "0.0.132");
        for (const [path, text] of sentinels) assert.equal(await readFile(path, "utf8"), text);
        const config = JSON.parse(await readFile(join(configDir, "config.json"), "utf8")); assert.equal(config.appearance, "dark"); assert.equal(config.defaultPermissionMode, "read_only");
        await runtime.client.health(); report.ownedEngineStillHealthy = true;
        const percentages = report.progress.filter(item => item.domPercent !== null);
        assert(percentages.some(item => item.domPercent > 0 && /%\s*\d|\d\s*%/u.test(item.domText ?? "")), "Actual visible DOM progress above zero is required");
        assert(percentages.every((item, index) => Number.isFinite(item.domPercent) && item.domPercent >= 0 && item.domPercent <= 100 && (index === 0 || item.domPercent >= percentages[index - 1].domPercent)));
        assert(report.progress.some(item => item.status === "downloading" && Number.isFinite(item.fraction) && item.fraction > 0 && item.fraction <= 1));
        report.profilePreserved = true; report.actualDomProgress = true; report.targetManuallyLaunched = false;
        report.success = true;
    } catch (error) {
        report.failedStage = report.stage;
        report.failureCode = error?.name === "AssertionError" ? "assertion_failed" : error?.name === "TimeoutError" ? "ui_timeout" : error?.name === "AbortError" ? "operation_timeout" : "native_operation_failed";
        report.errors.push("Native update acceptance failed");
        if (page && !page.isClosed()) await page.screenshot({ path: join(evidence, "failure.png"), mask: [page.locator('input[name="username"], input[name="password"]'), page.getByText(username, { exact: true })] }).catch(() => undefined);
        process.exitCode = 1;
    } finally {
        fixture?.close();
        stop = true; await monitor;
        if (monitorError) { report.success = false; report.errors.push("Update handoff monitor failed"); report.failedStage ??= "update handoff monitor"; }
        if (video) { report.targetVideo = await video.stop().catch(() => ({ error: "Target video stop failed" })); if (!(report.targetVideo.framesWritten > 0)) report.success = false; }
        // Stop owned staged helpers first so none can perform a late launch;
        // observe the app until all exact task-owned processes have terminated.
        try {
            for (const record of (await ownedProcesses()).filter(value => value.isHelper)) await ownedStop(record);
            for (const record of (await ownedProcesses()).filter(value => !value.isHelper)) await ownedStop(record);
            const cleanupBy = Date.now() + 5000; while (Date.now() < cleanupBy && (await ownedProcesses()).length) await delay(100);
            assert.equal((await ownedProcesses()).length, 0, "Owned helper/app cleanup incomplete");
        } catch { report.success = false; report.errors.push("Owned helper/app cleanup failed"); report.failedStage ??= "owned helper/app cleanup"; }
        await browser?.close().catch(() => undefined);
        if (appRun) { const closed = await Promise.race([appRun.then(() => true), delay(10000).then(() => false)]); if (!closed) report.success = false; }
        if (observer) {
            report.visibility = await observer().catch(() => ({ error: "Native observer failed" }));
            if (!(report.visibility.systemWindowsMax > 0 && report.visibility.pids?.includes(report.oldPid) && report.visibility.pids?.includes(newPid) && report.visibility.policySamplesByPid?.[String(report.oldPid)] > 0 && report.visibility.policySamplesByPid?.[String(newPid)] > 0 && report.visibility.onscreenSamples === 0 && report.visibility.activeSamples === 0)) report.success = false;
        }
        await runtime?.stop(); await inferenceStop?.().catch(() => undefined);
        await save();
        for (const mount of mounts.reverse()) await command("/usr/bin/hdiutil", ["detach", mount]).catch(() => undefined);
    }
    assert(report.success, "Automatic update evidence incomplete; inspect automatic-update.json");
    console.log(JSON.stringify({ success: report.success, source: report.sourceVersion, target: report.targetVersion, receipt: report.receipt, evidence }));
}

if (process.argv.includes("--self-test")) {
    const app = "/owned/Applications/CyberFi.app/Contents/MacOS/CyberFi", apps = "/owned/Applications";
    const helper = apps + "/.cyberfi-update-00000000-0000-4000-a000-000000000000/CyberFiUpdater";
    const records = ownedProcessRecords(` 12 ${app}\n 13 ${helper}\n 14 /other/Applications/CyberFi.app/Contents/MacOS/CyberFi\n 15 /owned/Applications/OtherHelper\n 16 /owned/Applications/../other/CyberFiUpdater\n`, app, apps);
    assert.deepEqual(records.map(value => [value.pid, value.isHelper]), [[12, false], [13, true]]);
    assert(publishedReleaseMatches({ id: 1, tag_name: "v0.0.131", draft: false }, 1, "v0.0.131"));
    assert(!publishedReleaseMatches({ id: 1, tag_name: "v0.0.131", draft: true }, 1, "v0.0.131"));
    assert(!publishedReleaseMatches({ id: 2, tag_name: "v0.0.131", draft: false }, 1, "v0.0.131"));
    assert(!publishedReleaseMatches({ id: 1, tag_name: "v0.0.130", draft: false }, 1, "v0.0.131"));
    const pin = { releaseId: 1, assetId: 2, manifestAssetId: 3, sha256: "a".repeat(64), manifestSha256: "b".repeat(64) };
    assert.deepEqual(artifactPins({ source: pin, target: pin }), { source: pin, target: pin });
    assert.throws(() => artifactPins({ source: { ...pin, assetId: -1 }, target: pin }));
    assert.throws(() => artifactPins({ source: { ...pin, sha256: "../bad" }, target: pin }));
    assert.throws(() => allowedRedirect("https://api.github.com.evil.test/file"));
    assert.throws(() => allowedRedirect("http://github.com/file"));
    assert.deepEqual(JSON.parse(('\uFEFF{"sha256":"' + "a".repeat(64) + '"}').replace(/^\uFEFF/u, "")), { sha256: "a".repeat(64) });
    assert.throws(() => JSON.parse('\uFEFF\uFEFF{}'.replace(/^\uFEFF/u, "")));
    assert.throws(() => signedManifest({ sha256: "a".repeat(64), size: 10, signature: "A".repeat(512) }, "0.0.132", "CyberFi-0.0.132-x64.dmg", "a".repeat(64), 10));
    console.log("Mac automatic update input, redirect and RSA refusal guards passed; no app or network used.");
} else await main();
