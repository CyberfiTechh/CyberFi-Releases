import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash, generateKeyPairSync, sign, verify } from "node:crypto";
import { createReadStream } from "node:fs";
import { lstat, mkdtemp, readFile, realpath, rmdir, unlink, writeFile } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const REPOSITORY = "CyberfiTechh/CyberFi-Releases";
const FEED = "https://api.github.com/repos/" + REPOSITORY + "/releases?per_page=30";
const FALLBACK = "https://raw.githubusercontent.com/" + REPOSITORY + "/main/updates.json";
const SOURCE_VERSION = "0.0.131";
const VERSION = "0.0.132";
const MAX_PACKAGE = 256 * 1024 * 1024;
const MODES = ["bad-signature", "bad-body", "exact"];

function within(root, path) {
    const rest = relative(root, path);
    return rest !== "" && rest !== ".." && !rest.startsWith(".." + sep) && !isAbsolute(rest);
}

async function hashFile(path) {
    const hash = createHash("sha256");
    for await (const chunk of createReadStream(path)) hash.update(chunk);
    return hash.digest("hex");
}

async function checkedAssets(root, platform, arch, packageSha256, manifestSha256) {
    assert(platform === "win32" ? arch === "x64" : platform === "darwin" && ["x64", "arm64"].includes(arch));
    assert(/^[a-f0-9]{64}$/u.test(packageSha256) && /^[a-f0-9]{64}$/u.test(manifestSha256));
    const filename = "CyberFi-" + VERSION + "-" + arch + (platform === "win32" ? ".exe" : ".dmg");
    const packagePath = join(root, filename);
    const manifestPath = packagePath + ".update.json";
    const packageInfo = await lstat(packagePath), manifestInfo = await lstat(manifestPath);
    assert(packageInfo.isFile() && manifestInfo.isFile() && packageInfo.nlink === 1 && manifestInfo.nlink === 1, "Expected owned regular update assets");
    assert(packageInfo.size > 0 && packageInfo.size <= MAX_PACKAGE && manifestInfo.size > 0 && manifestInfo.size <= 4096);
    assert.equal(await hashFile(packagePath), packageSha256, "Draft package SHA-256 mismatch");
    const manifestBytes = await readFile(manifestPath);
    assert.equal(createHash("sha256").update(manifestBytes).digest("hex"), manifestSha256, "Draft manifest SHA-256 mismatch");
    const manifest = JSON.parse(manifestBytes.toString("utf8"));
    assert.equal(manifest.sha256, packageSha256);
    assert.equal(manifest.size, packageInfo.size);
    assert(/^[A-Za-z0-9+/=]{100,700}$/u.test(manifest.signature), "Expected signed update manifest");
    const tag = (platform === "darwin" ? "macos-v" : "v") + VERSION;
    const download = "https://github.com/" + REPOSITORY + "/releases/download/" + tag + "/" + filename;
    return { FEED, FALLBACK, tag, filename, download, packagePath, manifestText: manifestBytes.toString("utf8"), size: packageInfo.size };
}

// This function is evaluated only in the validated, run-owned source process.
function installFetchFixture(config) {
    const key = Symbol.for("cyberfi.owned.update.fixture.132");
    if (globalThis[key] !== undefined) throw new Error("Fixture already installed");
    const { createReadStream } = process.getBuiltinModule("node:fs");
    const { Readable } = process.getBuiltinModule("node:stream");
    const { setTimeout } = process.getBuiltinModule("node:timers/promises");
    const original = globalThis.fetch;
    let mode = "bad-signature";
    const hits = { feed: 0, fallback: 0, manifest: 0, package: 0 };
    const release = [{ tag_name: config.tag, draft: false, prerelease: false, assets: [
        { name: config.filename, state: "uploaded" },
        { name: config.filename + ".update.json", state: "uploaded" },
    ] }];
    const wrapped = async function (input, init) {
        const url = typeof input === "string" ? input : input instanceof URL ? input.href : input instanceof Request ? input.url : undefined;
        const method = init?.method ?? (input instanceof Request ? input.method : "GET");
        if (method !== "GET") return original.call(this, input, init);
        if (![config.FEED, config.FALLBACK, config.download, config.download + ".update.json"].includes(url)) {
            return original.call(this, input, init);
        }
        const signal = init?.signal ?? (input instanceof Request ? input.signal : undefined);
        signal?.throwIfAborted();
        if (url === config.FEED || url === config.FALLBACK) {
            hits[url === config.FEED ? "feed" : "fallback"]++;
            return Response.json(release);
        }
        if (url.endsWith(".update.json")) {
            hits.manifest++;
            if (mode !== "bad-signature") return new Response(config.manifestText, {
                headers: { "content-type": "application/json" },
            });
            const manifest = JSON.parse(config.manifestText);
            manifest.signature = (manifest.signature[0] === "A" ? "B" : "A") + manifest.signature.slice(1);
            return Response.json(manifest);
        }
        hits.package++;
        const corrupt = mode === "bad-body";
        const file = createReadStream(config.packagePath, { highWaterMark: 1024 * 1024, signal });
        const stream = Readable.from(async function* () {
            try {
                let first = true;
                for await (const chunk of file) {
                    if (first && corrupt) chunk[0] ^= 1;
                    first = false;
                    // Leave enough time for the real progress observer to sample large local assets.
                    if (config.size > 4 * 1024 * 1024) await setTimeout(10, undefined, { signal });
                    yield chunk;
                }
            } finally {
                file.destroy();
            }
        }());
        return new Response(Readable.toWeb(stream), { headers: { "content-length": String(config.size) } });
    };
    globalThis.fetch = wrapped;
    globalThis[key] = {
        setMode(value) {
            if (!["bad-signature", "bad-body", "exact"].includes(value)) throw new Error("Invalid fixture mode");
            mode = value;
            return mode;
        },
        report: () => ({ mode, hits: { ...hits } }),
        restore() {
            if (globalThis.fetch !== wrapped) throw new Error("Fixture no longer owns fetch");
            globalThis.fetch = original;
            delete globalThis[key];
            return true;
        },
    };
    return true;
}

function verifyOwnedSource(expected) {
    const fs = process.getBuiltinModule("node:fs");
    const path = process.getBuiltinModule("node:path");
    const fail = (reason) => { throw new Error("Owned source check failed: " + reason); };
    const canonical = (value) => {
        const result = fs.realpathSync.native(value);
        return process.platform === "win32" ? result.toLowerCase() : result;
    };
    if (process.pid !== expected.pid || process.platform !== expected.platform || process.arch !== expected.arch) fail("identity");
    if (process.type !== "browser" || typeof process.versions.electron !== "string") fail("electron browser");
    if (canonical(process.execPath) !== canonical(expected.executable)) fail("executable");
    if (process.env.GITHUB_ACTIONS !== "true" || process.env.RUNNER_ENVIRONMENT !== "github-hosted" ||
        process.env.GITHUB_REPOSITORY !== expected.repository || process.env.GITHUB_REF !== expected.ref) fail("runner");
    if (process.env.CYBERFI_UPDATE_FIXTURE_OWNER !== expected.owner ||
        process.env.HAPPY_DESKTOP_WINDOWS_HIDDEN !== "1" || process.env.HAPPY_DESKTOP_DEBUG !== "1" ||
        !process.argv.includes("--debug") || !process.argv.includes("--user-data-dir=" + expected.profile)) fail("launch");
    if (process.platform === "win32" &&
        (process.env.CYBERFI_TEST_EXPECTED_SID !== expected.sid || !/^cfprobe[a-f0-9]{12}$/iu.test(process.env.USERNAME ?? ""))) fail("owned windows user");
    const require = process.getBuiltinModule("node:module").createRequire(process.execPath);
    const { app, BrowserWindow } = require("electron");
    if (!app.isPackaged || app.getVersion() !== expected.sourceVersion || app.getName() !== "CyberFi") fail("installed version");
    const windows = BrowserWindow.getAllWindows();
    if (canonical(app.getPath("userData")) !== canonical(expected.profile) ||
        windows.length === 0 || windows.some(window => window.isVisible() || window.isFocused())) fail("hidden profile");
    const nested = path.relative(canonical(process.env.RUNNER_TEMP), canonical(expected.executable));
    if (!nested || nested === ".." || nested.startsWith(".." + path.sep) || path.isAbsolute(nested)) fail("owned installation root");
    return true;
}

async function connectInspector(address) {
    const url = new URL(address);
    assert(url.protocol === "ws:" && url.hostname === "127.0.0.1" && url.port && !url.username && !url.password &&
        !url.search && !url.hash && /^\/[a-f0-9-]{36}$/u.test(url.pathname), "Expected exact loopback Node inspector");
    const socket = new WebSocket(url);
    try {
        await new Promise((accept, reject) => {
            const timer = setTimeout(() => reject(new Error("Inspector connection timeout")), 5000);
            socket.addEventListener("open", () => { clearTimeout(timer); accept(); }, { once: true });
            socket.addEventListener("error", () => { clearTimeout(timer); reject(new Error("Inspector connection failed")); }, { once: true });
        });
    } catch (error) {
        socket.close();
        throw error;
    }
    let id = 0;
    return {
        evaluate(expression) {
            const requestId = ++id;
            return new Promise((accept, reject) => {
                const listeners = new AbortController();
                const done = (error, value) => {
                    clearTimeout(timer);
                    listeners.abort();
                    if (error) reject(error); else accept(value);
                };
                const timer = setTimeout(() => done(new Error("Inspector evaluation timeout")), 10000);
                socket.addEventListener("close", () => done(new Error("Inspector closed")), { signal: listeners.signal });
                socket.addEventListener("message", ({ data }) => {
                    const message = JSON.parse(data);
                    if (message.id !== requestId) return;
                    if (message.error || message.result?.exceptionDetails) {
                        const reason = message.result?.exceptionDetails?.exception?.description?.split("\n", 1)[0] ?? "";
                        const safe = /^Error: Owned source check failed: [a-z ]+$/u.test(reason) ? " (" + reason + ")" : "";
                        done(new Error("Inspector evaluation refused" + safe));
                        return;
                    }
                    done(undefined, message.result.result.value);
                }, { signal: listeners.signal });
                try {
                    socket.send(JSON.stringify({ id: requestId, method: "Runtime.evaluate", params: { expression, returnByValue: true, awaitPromise: true } }));
                } catch (error) {
                    done(error);
                }
            });
        },
        close: () => socket.close(),
    };
}

const call = (fn, arg) => "(" + fn.toString() + ")(" + JSON.stringify(arg) + ")";
const control = 'globalThis[Symbol.for("cyberfi.owned.update.fixture.132")]';

export async function attachUpdateFixture(options) {
    const { pid, executable, profile, assetsRoot, inspectorUrl, owner, ref, packageSha256, manifestSha256 } = options;
    assert(process.env.GITHUB_ACTIONS === "true" && process.env.RUNNER_ENVIRONMENT === "github-hosted" &&
        process.env.GITHUB_REPOSITORY === REPOSITORY && process.env.GITHUB_REF === ref &&
        /^refs\/heads\/codex\/[a-z0-9-]*132[a-z0-9-]*$/u.test(ref), "Only the owned hosted 132 acceptance branch can attach");
    assert(Number.isSafeInteger(pid) && pid > 0 && /^[a-f0-9]{32}$/u.test(owner), "Missing owned process identity");
    assert([executable, profile, assetsRoot].every(isAbsolute), "Expected absolute owned fixture paths");
    const runnerRoot = await realpath(process.env.RUNNER_TEMP);
    const [binary, appProfile, assets] = await Promise.all([executable, profile, assetsRoot].map(realpath));
    assert(within(runnerRoot, binary) && within(runnerRoot, assets) &&
        basename(binary).toLowerCase() === (process.platform === "win32" ? "cyberfi.exe" : "cyberfi"),
        "Unexpected source installation or asset location");
    const profileRoot = process.platform === "win32" ? await realpath(process.env.APPDATA) : runnerRoot;
    if (process.platform === "win32") {
        assert(/^S-1-5-21-(?:\d+-){3}\d+$/u.test(process.env.CYBERFI_TEST_EXPECTED_SID ?? "") && /^cfprobe[a-f0-9]{12}$/iu.test(process.env.USERNAME ?? ""),
            "Windows requires the existing disposable local-user launcher");
    }
    assert(within(profileRoot, appProfile), "Unexpected profile location");
    const fixture = await checkedAssets(assets, process.platform, process.arch, packageSha256, manifestSha256);
    const expected = { pid, executable: binary, profile, owner, platform: process.platform, arch: process.arch, ref,
        repository: REPOSITORY, sourceVersion: SOURCE_VERSION, sid: process.env.CYBERFI_TEST_EXPECTED_SID };
    const inspector = await connectInspector(inspectorUrl);
    try {
        assert.equal(await inspector.evaluate(call(verifyOwnedSource, expected)), true);
        assert.equal(await inspector.evaluate(call(installFetchFixture, fixture)), true);
    } catch (error) {
        inspector.close();
        throw error;
    }
    return {
        setMode(mode) {
            assert(MODES.includes(mode));
            return inspector.evaluate(control + ".setMode(" + JSON.stringify(mode) + ")");
        },
        report: () => inspector.evaluate(control + ".report()"),
        restore: () => inspector.evaluate(control + ".restore()"),
        close: inspector.close,
    };
}

async function selfTest() {
    const root = await mkdtemp(join(dirname(fileURLToPath(import.meta.url)), ".self-test-"));
    const packagePath = join(root, "CyberFi-0.0.132-x64.exe"), manifestPath = packagePath + ".update.json";
    let child, inspector;
    try {
        const file = Buffer.from("signed-candidate fixture bytes");
        const hash = createHash("sha256").update(file).digest("hex");
        const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
        const signed = Buffer.from(VERSION + "\n" + basename(packagePath) + "\n" + hash + "\n" + file.length + "\n");
        const manifest = { sha256: hash, size: file.length, signature: sign("sha256", signed, privateKey).toString("base64") };
        const valid = ({ signature }) => verify("sha256", signed, publicKey, Buffer.from(signature, "base64"));
        const manifestText = JSON.stringify(manifest);
        await writeFile(packagePath, file, { flag: "wx" });
        await writeFile(manifestPath, manifestText, { flag: "wx" });
        const manifestHash = createHash("sha256").update(manifestText).digest("hex");
        const fixture = await checkedAssets(root, "win32", "x64", hash, manifestHash);
        await assert.rejects(() => checkedAssets(root, "win32", "x64", "f".repeat(64), manifestHash), /package SHA-256/u);
        child = spawn(process.execPath, ["--input-type=module", "-e",
            'import inspector from "node:inspector"; inspector.open(0, "127.0.0.1"); process.send(inspector.url()); process.on("disconnect", () => inspector.close());'],
            { stdio: ["ignore", "ignore", "ignore", "ipc"], windowsHide: true });
        const address = await new Promise((accept, reject) => {
            const timer = setTimeout(() => reject(new Error("Self-test inspector did not start")), 5000);
            child.once("message", value => { clearTimeout(timer); accept(value); });
            child.once("error", error => { clearTimeout(timer); reject(error); });
        });
        inspector = await connectInspector(address);
        await assert.rejects(() => inspector.evaluate(call(verifyOwnedSource, { pid: child.pid, platform: process.platform, arch: process.arch })), /electron browser/u);
        assert.equal(await inspector.evaluate(call(installFetchFixture, fixture)), true);
        const get = (url, suffix) => inspector.evaluate("fetch(" + JSON.stringify(url) + ").then(r => r." + suffix + "())");
        assert.equal((await get(FEED, "json"))[0].tag_name, fixture.tag);
        assert.equal((await get(FALLBACK, "json"))[0].tag_name, fixture.tag);
        assert.equal(await get("data:text/plain,passthrough", "text"), "passthrough");
        assert.equal(valid(await get(fixture.download + ".update.json", "json")), false);
        assert.equal(await inspector.evaluate(control + '.setMode("bad-body")'), "bad-body");
        assert.notEqual(await get(fixture.download, "text"), file.toString());
        assert.equal(await inspector.evaluate(control + '.setMode("exact")'), "exact");
        assert.equal(await get(fixture.download, "text"), file.toString());
        assert.equal(await get(fixture.download + ".update.json", "text"), manifestText);
        assert.equal(valid(JSON.parse(manifestText)), true);
        assert.deepEqual(await inspector.evaluate(control + ".report()"),
            { mode: "exact", hits: { feed: 1, fallback: 1, manifest: 2, package: 2 } });
        assert.equal(await inspector.evaluate(control + ".restore()"), true);
        assert.equal(await inspector.evaluate("typeof " + control), "undefined");
        console.log("Owned Node inspector fixture self-test passed.");
    } finally {
        inspector?.close();
        if (child?.connected) child.disconnect();
        child?.kill();
        for (const path of [packagePath, manifestPath]) await unlink(path).catch(error => { if (error.code !== "ENOENT") throw error; });
        await rmdir(root);
    }
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
    assert.deepEqual(process.argv.slice(2), ["--self-test"]);
    await selfTest();
}
