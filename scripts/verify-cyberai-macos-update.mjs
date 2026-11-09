import assert from "node:assert/strict";
import { createHash, verify } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import { mkdir, readFile, readdir, realpath, writeFile } from "node:fs/promises";
import { basename, isAbsolute, join, resolve } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { Readable, Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import { setTimeout as delay } from "node:timers/promises";
import { verifyMacFreshEngine } from "./verify-macos-fresh-engine.mjs";

const REPOSITORY = "CyberfiTechh/CyberFi-Releases";
const SOURCE_COMMIT = "d070120ddfdfa8b769e3fcc0b6cacee704306598";
const PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA09ZxJMbpq1uFEnz7n52M\nAJtceCXVQCo57lgwMAmizgJaGVGsgsMpzqgCCRgXBN+bPygE+16S9XwYOwHDlnNG\noq8h+bE9Nxce3PzsQHrscdHTT1lGQ/5XwSmvzTvxLdURtQWpaXZl7lJghUnZHNDA\n8SOHbk8rQ+butE82lhcq0C+hgJgHTUqFl9Irppi2O+MpufsZo8PX5jphD4H0aX0k\nB9P+LUreoBmG/L3T3AMZEzQZG606awc/ZMYsJcJkt4xNMjR3ZMz1aWKErW2AXDeY\nyfAo0zmEAUEAFSc3UEJRnmBAjorVA3C/rHJzYP7QabSh8ORLOUrqQYgqCpTLETpf\nct0J+NphCLuBGNQ5IeId5IPiBNZlKynGzP/HK+oJTvJ31hTHIiaA+5pfIESXELIZ\nJ5awYGW0y7fii0CqRGwFMJnU829APVvAC9LJUzSSz7NP+2rmc/boYInx8cjN2/LO\nLI9HsPvON+oxM4MhjRxDd4CVoKDpI+rB2TthSdfxt3UxAgMBAAE=\n-----END PUBLIC KEY-----";
const REVIEWED_ARTIFACTS = {
    "x64": {
        "source": {
            "releaseId": 439214570,
            "assetId": 727723926,
            "sha256": "39e88bf8396c57adda75b23c1970e0e3fea4405380b51e8a7e2c218932036af7",
            "manifestAssetId": 727743516,
            "manifestSha256": "1faac2a785469aa8d6cc5df9d400109056ee1b07595388bd17d195c0b870ba99"
        },
        "target": {
            "releaseId": 439509221,
            "assetId": 728583328,
            "sha256": "6fcb73e87fb2e194320b307e3090942a4d561eb0c04991d0cf5aa6f12bb6cd3d",
            "manifestAssetId": 728593299,
            "manifestSha256": "806b73eaf68273a1ff1d4d289bc3f1e2e94a5d38a2d28dca424c95e4e7fbcb02"
        }
    },
    "arm64": {
        "source": {
            "releaseId": 439214570,
            "assetId": 727743752,
            "sha256": "aa6fd4c9befd1769f240feb108a3f0032812481cb72cc0575c5efa1666b52a4c",
            "manifestAssetId": 727761788,
            "manifestSha256": "85f88b44080bba1299d93b97f2b15204c8595ea8f83ab4291568076768e979fd"
        },
        "target": {
            "releaseId": 439509221,
            "assetId": 728593458,
            "sha256": "7de37a5efe2493b68aa16dc9bb1c570062618e017957dbfbd2a3ba75788558cf",
            "manifestAssetId": 728603520,
            "manifestSha256": "cb139dd6bef39f52e076a45a3dfa75bcaaf214bf0b09152df409c515894f592c"
        }
    }
};
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
        process.env.GITHUB_REF === "refs/heads/codex/macos-fresh-engine-131-acceptance", "Only the disposable native Mac runner may execute this test");
    assert.equal(process.env.ACCEPTANCE_SOURCE_SHA, SOURCE_COMMIT, "Unexpected reviewed target source provenance");
    const arch = process.env.ARCH;
    assert((arch === "x64" || arch === "arm64") && process.arch === arch);
    const pins = artifactPins(REVIEWED_ARTIFACTS[arch]);
    const upstream = await realpath(process.argv[2]);
    assert.equal(upstream, join(resolve(process.env.GITHUB_WORKSPACE), "upstream"));
    const root = join(await realpath(process.env.RUNNER_TEMP), "cyberfi-macos-app-update");
    await mkdir(root); // Never reuse a profile, installed app or handoff from another attempt.
    const evidence = join(root, "evidence"), apps = join(root, "Applications"), profile = join(root, "user-data");
    await Promise.all([evidence, apps, profile].map(path => mkdir(path)));
    const app = join(apps, "CyberFi.app"), executable = join(app, "Contents/MacOS/CyberFi");
    const report = { success: false, stage: "artifact verification", architecture: arch, sourceCommit: SOURCE_COMMIT, mode: "fresh", targetVersion: "0.0.131",
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
        for (const [kind, version] of [["target", "0.0.131"]]) {
            report.stage = kind === "source" ? "published source metadata" : "published target metadata";
            const pin = pins[kind], release = await api(`repos/${REPOSITORY}/releases/${pin.releaseId}`);
            assert(release.id === pin.releaseId && release.tag_name === "macos-v" + version && typeof release.draft === "boolean");
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
            await command("/usr/bin/ditto", ["--rsrc", "--extattr", "--acl", bundle, app]);
        }
        assert.deepEqual(await bundleProof(app), proofs.target);
        report.immutableInputs = { target: pins.target, independentRsaManifests: true, packagedBundleProofs: proofs, fusesModified: false, quarantineModified: false };
        await save();
        report.stage = "pinned engine metadata and download";
        const engineRelease = await api("repos/CyberfiTechh/CyberFi-Engine/releases/439371035");
        const enginePins = arch === "x64" ? [728161015, "acc2532e7831894166723b176eac4092cdbd5bf4a2450abbe03576bdd6c3d2ed"] : [728161005, "93faf99236ff4c3a42cce49861e6504ca7265f6582c7cfbbaebd882e99fd220a"];
        assert(engineRelease.tag_name === "v0.4.125" && !engineRelease.draft && !engineRelease.prerelease);
        const engineAsset = engineRelease.assets.find(item => item.id === enginePins[0]);
        assert(engineAsset?.digest === "sha256:" + enginePins[1]);
        assert.equal(engineAsset.size, arch === "x64" ? 204619668 : 193764811);
        report.stableEngineRelease = { releaseId: engineRelease.id, assetId: engineAsset.id, archiveBytes: engineAsset.size, digest: engineAsset.digest };
        await verifyMacFreshEngine({ upstream, root, executable, profile, evidence, engineAsset, command, hashFile, username, password, report });
        report.success = true;
        return;
    } catch (error) {
        report.failedStage = report.stage;
        report.failureCode = error?.name === "AssertionError" ? "assertion_failed" : error?.name === "TimeoutError" ? "ui_timeout" : error?.name === "AbortError" ? "operation_timeout" : "native_operation_failed";
        report.errors.push("Fresh Mac engine setup failed");
        process.exitCode = 1;
    } finally {
        // Stop owned staged helpers first so none can perform a late launch;
        // observe the app until all exact task-owned processes have terminated.
        try {
            for (const record of (await ownedProcesses()).filter(value => value.isHelper)) await ownedStop(record);
            for (const record of (await ownedProcesses()).filter(value => !value.isHelper)) await ownedStop(record);
            const cleanupBy = Date.now() + 5000; while (Date.now() < cleanupBy && (await ownedProcesses()).length) await delay(100);
            assert.equal((await ownedProcesses()).length, 0, "Owned helper/app cleanup incomplete");
        } catch { report.success = false; report.errors.push("Owned helper/app cleanup failed"); report.failedStage ??= "owned helper/app cleanup"; }
        await save();
        for (const mount of mounts.reverse()) await command("/usr/bin/hdiutil", ["detach", mount]).catch(() => undefined);
        assert(report.success, "Fresh Mac engine setup evidence incomplete; inspect automatic-update.json");
        console.log(JSON.stringify({ success: true, target: report.targetVersion, engine: report.installedEngineVersion, evidence }));
    }
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
    assert.throws(() => signedManifest({ sha256: "a".repeat(64), size: 10, signature: "A".repeat(512) }, "0.0.131", "CyberFi-0.0.131-x64.dmg", "a".repeat(64), 10));
    console.log("Mac automatic update input, redirect and RSA refusal guards passed; no app or network used.");
} else await main();
