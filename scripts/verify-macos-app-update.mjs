import assert from "node:assert/strict";
import { createHash, verify } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import { mkdir, readFile, readdir, realpath, lstat, writeFile, stat } from "node:fs/promises";
import { createRequire } from "node:module";
import { basename, dirname, isAbsolute, join, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { execFile, spawn } from "node:child_process";
import { promisify } from "node:util";
import { Readable, Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import { setTimeout as delay } from "node:timers/promises";

const REPOSITORY = "CyberfiTechh/CyberFi-Releases";
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

async function main() {
    assert(process.platform === "darwin" && process.env.GITHUB_ACTIONS === "true" &&
        process.env.RUNNER_ENVIRONMENT === "github-hosted" && process.env.GITHUB_REPOSITORY === REPOSITORY &&
        process.env.GITHUB_REF === "refs/heads/main", "Only the disposable native Mac runner may execute this test");
    const arch = process.env.ARCH;
    assert((arch === "x64" || arch === "arm64") && process.arch === arch);
    const pins = artifactPins(JSON.parse(process.env.ACCEPTANCE_ARTIFACTS));
    const upstream = await realpath(process.argv[2]);
    assert.equal(upstream, join(resolve(process.env.GITHUB_WORKSPACE), "upstream"));
    const root = join(await realpath(process.env.RUNNER_TEMP), "cyberfi-macos-app-update");
    await mkdir(root); // Never reuse a profile, installed app or handoff from another attempt.
    const evidence = join(root, "evidence"), apps = join(root, "Applications"), profile = join(root, "user-data");
    await Promise.all([evidence, apps, profile].map(path => mkdir(path)));
    const app = join(apps, "CyberFi.app"), executable = join(app, "Contents/MacOS/CyberFi");
    const report = { success: false, architecture: arch, sourceVersion: "0.0.123", targetVersion: "0.0.124",
        actualGui: false, progress: [], events: [], errors: [], limits: ["CI launches do not prove Gatekeeper acceptance of a browser-quarantined download."] };
    const save = () => writeFile(join(evidence, "automatic-update.json"), JSON.stringify(report, null, 2) + "\n");
    const token = process.env.GH_TOKEN;
    const safeEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) =>
        !/TOKEN|SECRET|PASSWORD|CREDENTIAL|API_KEY|NODE_OPTIONS|ELECTRON_RUN_AS_NODE|SMOKE_REPORT|SMOKE_SCREENSHOT|VITE_DEV_SERVER_URL|ACCEPTANCE_ARTIFACTS/iu.test(key)));
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
    let paths, runtime, appRun, appExit, appError, browser, page, video, watcher, observer, monitor, monitorError, stop = false, newPid;
    try {
        const proofs = {};
        for (const [kind, version] of [["source", "0.0.123"], ["target", "0.0.124"]]) {
            const pin = pins[kind], release = await api(`repos/${REPOSITORY}/releases/${pin.releaseId}`);
            assert(release.id === pin.releaseId && release.tag_name === "macos-v" + version && release.draft === (kind === "source"));
            const filename = `CyberFi-${version}-${arch}.dmg`;
            const asset = release.assets.find(item => item.id === pin.assetId);
            const manifest = release.assets.find(item => item.id === pin.manifestAssetId);
            assert(asset?.name === filename && asset.digest === "sha256:" + pin.sha256 && asset.state === "uploaded");
            assert(manifest?.name === filename + ".update.json" && manifest.digest === "sha256:" + pin.manifestSha256 && manifest.size <= 4096);
            const dmg = join(root, filename), manifestFile = dmg + ".update.json";
            await download(REPOSITORY, asset, dmg); await download(REPOSITORY, manifest, manifestFile);
            assert.equal(await hashFile(dmg), pin.sha256); assert.equal(await hashFile(manifestFile), pin.manifestSha256);
            signedManifest(JSON.parse((await readFile(manifestFile, "utf8")).replace(/^\uFEFF/u, "")), version, filename, pin.sha256, asset.size);
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
        report.immutableInputs = { pins, sourceFixture: "Exact signed draft123 bootstrap test fixture; not a historical public release", target: "Public124 preview", independentRsaManifests: true, packagedBundleProofs: proofs, fusesModified: false, quarantineModified: false };
        await save();
        const engineRelease = await api("repos/CyberfiTechh/CyberFi-Engine/releases/438140439");
        const enginePins = arch === "x64" ? [723463097, "512bbe2b6eabe31121703b81e30a916b29c7a95cadb9ea8dd486bbdab16211ad"] : [723463093, "708418ebdfa9066a3b54c9f089d4e9e079f21ec3347ff6198668d6f32d7d5f77"];
        assert(engineRelease.tag_name === "v0.4.118" && !engineRelease.draft);
        const engineAsset = engineRelease.assets.find(item => item.id === enginePins[0]);
        assert(engineAsset?.digest === "sha256:" + enginePins[1]);
        const archive = join(root, "engine.tar.gz"), engineRoot = join(root, "engine"); await mkdir(engineRoot);
        await download("CyberfiTechh/CyberFi-Engine", engineAsset, archive); assert.equal(await hashFile(archive), enginePins[1]);
        assert.equal(await command("/usr/bin/tar", ["-tzf", archive]), `happy-agent-darwin-${arch}`);
        await command("/usr/bin/tar", ["-xzf", archive, "-C", engineRoot]);
        process.env.HAPPY_DESKTOP_AGENT_EXECUTABLE = join(engineRoot, `happy-agent-darwin-${arch}`);
        const gym = name => pathToFileURL(join(upstream, "packages/happy-desktop-gym/sources/electron", name + ".ts")).href;
        const { gymElectronProcessRun, gymElectronVideoRecord } = await import(gym("launch"));
        const { gymRunPathsCreate } = await import(gym("paths"));
        const { gymManifestRead } = await import(gym("manifest"));
        const { gymInferenceServerCreate } = await import(gym("inferenceServer"));
        const { happyAgentRuntimeCreate } = await import(gym("happyAgentRuntime"));
        ({ paths } = await gymRunPathsCreate("smoke"));
        const inference = gymInferenceServerCreate(gymManifestRead("smoke"), join(evidence, "inference.jsonl")); await inference.start();
        runtime = await happyAgentRuntimeCreate(paths, inference);
        const configDir = join(profile, "desktop"); await mkdir(configDir);
        await writeFile(join(configDir, "local-onboarding.json"), JSON.stringify({ version: 3, chiefOfStaffSetup: true }));
        await writeFile(join(configDir, "config.json"), JSON.stringify({ appearance: "dark", defaultPermissionMode: "read_only" }));
        const settingsNote = join(configDir, "retained-user-note.txt"), skillsNote = join(paths.home, ".agents/skills/acceptance-retained/SKILL.md");
        await mkdir(dirname(skillsNote), { recursive: true });
        const sentinels = [[settingsNote, "Keep the existing desktop profile.\n"], [skillsNote, "# Existing user skill\nKeep this exact text.\n"]];
        for (const [path, text] of sentinels) await writeFile(path, text);
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
        const env = { ...safeEnv, ...runtime.environment, HAPPY_DESKTOP_WINDOWS_HIDDEN: "1", HAPPY_DESKTOP_DEBUG: "1", HAPPY_DEBUG_RENDERER_PORT: String(port) };
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
        await page.waitForFunction(async () => typeof window.happyDesktop?.runtimeGet === "function" && (await window.happyDesktop.runtimeGet()).phase === "ready", undefined, { timeout: 90000 });
        const oldPid = await listenerPid(); report.oldPid = oldPid;
        id(oldPid);
        const alive = pid => { try { process.kill(pid, 0); return true; } catch (error) { if (error.code === "ESRCH") return false; throw error; } };
        await page.getByRole("button", { name: /settings|ayarlar|ayarları aç/iu }).first().click();
        const general = page.getByRole("button", { name: /^(General|Genel)$/iu }).first(); if (await general.count()) await general.click();
        const select = page.locator("#cyberfi-settings-desktop-version"); await select.waitFor({ state: "visible", timeout: 60000 });
        await page.getByRole("button", { name: /^(Check for updates|Güncellemeleri denetle)$/iu }).first().click();
        await page.waitForFunction(async () => (await window.happyDesktop.runtimeGet()).update?.versions?.some(item => item.version === "0.0.124"), undefined, { timeout: 45000 });
        await select.selectOption("0.0.124");
        const button = page.getByRole("button", { name: /^(Download and reopen|İndir ve yeniden aç|Kur ve yeniden aç)$/iu }); await button.waitFor({ state: "visible" });
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
                    if (ticket) assert(ticket.targetApp === app && ticket.userDataPath === profile && ticket.parentPid === oldPid && ticket.version === "0.0.124" && ticket.hidden === true);
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
        await button.click(); report.actualGui = true;
        const until = Date.now() + 12 * 60000;
        while (!appExit && !appError && !monitorError && Date.now() < until) await delay(100);
        assert(!monitorError, String(monitorError)); assert(!appError, String(appError));
        assert(appExit?.exitCode === 0, appExit?.output ?? "Actual old app did not exit"); await appRun;
        const sourceVideo = await video.stop(); video = undefined; assert(sourceVideo.framesReceived > 0 && sourceVideo.framesWritten > 0); report.sourceVideo = sourceVideo;
        let receipt, result;
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
        assert(receipt.nonce === ticket.nonce && result.nonce === ticket.nonce && receipt.version === "0.0.124" && receipt.executablePath === executable && receipt.pid !== oldPid);
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
        await rendererConnect();
        video = await gymElectronVideoRecord(page, { path: join(evidence, "actual-reopened-target.webm"), fps: 5 });
        await page.waitForFunction(async () => (await window.happyDesktop.runtimeGet()).phase === "ready", undefined, { timeout: 60000 });
        await delay(1000); await page.screenshot({ path: join(evidence, "reopened-target.png") });
        report.reopenedRuntime = await page.evaluate(async () => { const value = await window.happyDesktop.runtimeGet(); return { phase: value.phase, currentVersion: value.update?.currentVersion }; });
        assert.equal(await command("/usr/libexec/PlistBuddy", ["-c", "Print :CFBundleShortVersionString", join(app, "Contents/Info.plist")]), "0.0.124");
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
        report.errors.push(String(error));
        if (page && !page.isClosed()) await page.screenshot({ path: join(evidence, "failure.png") }).catch(() => undefined);
        throw error;
    } finally {
        stop = true; await monitor;
        if (monitorError) { report.success = false; report.errors.push(String(monitorError)); }
        if (video) { report.targetVideo = await video.stop().catch(error => ({ error: String(error) })); if (!(report.targetVideo.framesWritten > 0)) report.success = false; }
        if (observer) {
            report.visibility = await observer().catch(error => ({ error: String(error) }));
            if (!(report.visibility.systemWindowsMax > 0 && report.visibility.pids?.includes(report.oldPid) && report.visibility.pids?.includes(newPid) && report.visibility.onscreenSamples === 0 && report.visibility.regularPolicySamples === 0 && report.visibility.activeSamples === 0)) report.success = false;
        }
        await save();
        // Terminate only the acknowledged process at the owned replacement path, after observing it.
        if (newPid && executable.startsWith(root + sep)) { try { process.kill(newPid, "SIGTERM"); } catch (error) { if (error.code !== "ESRCH") throw error; } }
        if (!appExit && page && !page.isClosed()) await page.evaluate(() => window.happyDesktop?.windowClose?.()).catch(() => undefined);
        await runtime?.stop();
        for (const mount of mounts.reverse()) await command("/usr/bin/hdiutil", ["detach", mount]).catch(() => undefined);
    }
    assert(report.success, "Automatic update evidence incomplete; inspect automatic-update.json");
    console.log(JSON.stringify({ success: report.success, source: report.sourceVersion, target: report.targetVersion, receipt: report.receipt, evidence }));
}

if (process.argv.includes("--self-test")) {
    const pin = { releaseId: 1, assetId: 2, manifestAssetId: 3, sha256: "a".repeat(64), manifestSha256: "b".repeat(64) };
    assert.deepEqual(artifactPins({ source: pin, target: pin }), { source: pin, target: pin });
    assert.throws(() => artifactPins({ source: { ...pin, assetId: -1 }, target: pin }));
    assert.throws(() => artifactPins({ source: { ...pin, sha256: "../bad" }, target: pin }));
    assert.throws(() => allowedRedirect("https://api.github.com.evil.test/file"));
    assert.throws(() => allowedRedirect("http://github.com/file"));
    assert.deepEqual(JSON.parse(('\uFEFF{"sha256":"' + "a".repeat(64) + '"}').replace(/^\uFEFF/u, "")), { sha256: "a".repeat(64) });
    assert.throws(() => JSON.parse('\uFEFF\uFEFF{}'.replace(/^\uFEFF/u, "")));
    assert.throws(() => signedManifest({ sha256: "a".repeat(64), size: 10, signature: "A".repeat(512) }, "0.0.124", "CyberFi-0.0.124-x64.dmg", "a".repeat(64), 10));
    console.log("Mac automatic update input, redirect and RSA refusal guards passed; no app or network used.");
} else await main();
