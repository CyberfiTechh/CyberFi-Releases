import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import {
    cp,
    mkdir,
    mkdtemp,
    rm,
    lstat,
    readFile,
    readdir,
    realpath,
    symlink,
    writeFile,
} from "node:fs/promises";
import { createRequire } from "node:module";
import { dirname, basename, isAbsolute, join, relative, resolve, sep } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { spawnSync } from "node:child_process";

const DESKTOP_REPO = "CyberfiTechh/CyberFi-Releases";
const ENGINE_REPO = "CyberfiTechh/CyberFi-Engine";
function desktopVersion(value) {
    assert(["0.0.116", "0.0.117"].includes(value));
    return value;
}
const UPSTREAM_COMMIT = "c9feffb54cdb3591220dafced4070e118e3d297a";
const ELECTRON_VERSION = "45.0.0";
function engineTagAllowed(value) {
    assert(["v0.4.116", "v0.4.117-preview.1"].includes(value));
    return value;
}
function identifier(value) {
    assert.match(value ?? "", /^[1-9][0-9]*$/);
    return value;
}
function digest(value) {
    assert.match(value ?? "", /^[0-9a-f]{64}$/);
    return value;
}
function archivePath(value) {
    const normalized = value.replaceAll("\\", "/").replace(/^\/+/, "");
    assert(!value.startsWith("/") && !value.includes("\\") && !/^[A-Za-z]:/.test(value));
    assert(normalized.split("/").every((part) => part !== ".."));
    return normalized;
}
function redirectLocation(value) {
    const url = new URL(value);
    assert.equal(url.protocol, "https:");
    assert(!url.username && !url.password && (!url.port || url.port === "443"));
    assert(
        url.hostname === "github.com" ||
            url.hostname.endsWith(".githubusercontent.com") ||
            url.hostname.endsWith(".blob.core.windows.net"),
    );
    return url;
}
function releaseAsset(release, { releaseId, assetId, sha, tag, name }) {
    assert.equal(String(release.id), identifier(releaseId));
    assert.equal(release.tag_name, tag);
    const asset = release.assets?.find((asset) => String(asset.id) === identifier(assetId));
    assert(asset && asset.name === name && asset.digest === "sha256:" + digest(sha));
    assert(Number.isSafeInteger(asset.size) && asset.size > 0 && asset.size < 2 * 1024 ** 3);
    return asset;
}
function assertVersionOutput(output, expected) {
    const token = output.trim().split(/\s+/).at(-1);
    assert.equal(token, expected, "Released engine version token differs from pinned tag");
}
function asarReader(upstream) {
    const desktopRequire = createRequire(
        join(upstream, "packages/happy-desktop-electron/package.json"),
    );
    const builderRequire = createRequire(desktopRequire.resolve("electron-builder/package.json"));
    return createRequire(builderRequire.resolve("app-builder-lib/package.json"))("@electron/asar");
}
function extractReleasedAsar(asar, archive, destination) {
    let entries = 0;
    for (const path of asar.listPackage(archive)) {
        // listPackage generates host-native separators and one leading separator.
        assert(path.startsWith(sep) && !path.startsWith(sep + sep));
        const relativePath = path.slice(1);
        const normalized = relativePath.replaceAll(sep, "/");
        archivePath(normalized);
        assert(
            !asar.statFile(archive, relativePath, false).link,
            "ASAR symbolic links are not accepted by this verifier",
        );
        entries++;
    }
    assert(entries > 0 && entries < 100_000);
    asar.extractAll(archive, destination);
    return entries;
}
async function asarSelfTest(upstreamArg, archiveArg) {
    assert(upstreamArg && archiveArg);
    const upstream = resolve(upstreamArg),
        archive = resolve(archiveArg);
    const destination = await mkdtemp(join(tmpdir(), "cyberfi-ui-asar-"));
    try {
        const entries = extractReleasedAsar(asarReader(upstream), archive, destination);
        for (const path of ["main.js", "preload.cjs", "renderer/index.html"])
            assert((await lstat(join(destination, "dist", path))).isFile());
        console.log(JSON.stringify({ asarListStatExtractGuardPassed: true, entries }));
    } finally {
        assert.equal(dirname(destination), resolve(tmpdir()));
        assert(basename(destination).startsWith("cyberfi-ui-asar-"));
        await rm(destination, { recursive: true, force: true });
    }
}
function cleanEnvironment() {
    return Object.fromEntries(
        Object.entries(process.env).filter(
            ([key]) =>
                !/TOKEN|SECRET|PASSWORD|CREDENTIAL|API_KEY|CODEX|OPENAI|ANTHROPIC|NODE_OPTIONS|ELECTRON_RUN_AS_NODE|HAPPY_|CYBERFI_RELEASED_RESOURCES/i.test(
                    key,
                ),
        ),
    );
}
async function hashFile(path) {
    const hash = createHash("sha256");
    for await (const chunk of createReadStream(path)) hash.update(chunk);
    return hash.digest("hex");
}
async function apiJson(path) {
    const response = await fetch("https://api.github.com/" + path, {
        headers: {
            Accept: "application/vnd.github+json",
            ...(process.env.GH_TOKEN ? { Authorization: "Bearer " + process.env.GH_TOKEN } : {}),
        },
        redirect: "error",
        signal: AbortSignal.timeout(60_000),
    });
    assert(response.ok, "GitHub metadata request failed: " + response.status);
    return await response.json();
}
async function download(initial, destination, authorize = false) {
    let url = new URL(initial);
    for (let redirects = 0; redirects < 5; redirects++) {
        let response;
        try {
            response = await fetch(url, {
                headers: {
                    Accept: "application/octet-stream",
                    ...(authorize && url.hostname === "api.github.com" && process.env.GH_TOKEN
                        ? { Authorization: "Bearer " + process.env.GH_TOKEN }
                        : {}),
                },
                redirect: "manual",
                signal: AbortSignal.timeout(5 * 60_000),
            });
        } catch {
            throw Error("Artifact network transfer failed (signed URL intentionally omitted)");
        }
        if ([301, 302, 303, 307, 308].includes(response.status)) {
            url = redirectLocation(response.headers.get("location"));
            authorize = false; // Never forward GitHub credentials to signed asset/blob hosts.
            continue;
        }
        assert(response.ok && response.body, "Artifact download failed: " + response.status);
        await pipeline(
            Readable.fromWeb(response.body),
            createWriteStream(destination, { flags: "wx", mode: 0o600 }),
        );
        return;
    }
    throw Error("Too many artifact redirects");
}
function command(command, args, { cwd, env, log } = {}) {
    const run = spawnSync(command, args, {
        cwd,
        env,
        encoding: "utf8",
        maxBuffer: 64 * 1024 ** 2,
        timeout: 25 * 60_000,
    });
    if (log) {
        return Promise.all([
            writeFile(log, run.stdout ?? ""),
            writeFile(log + ".stderr.log", (run.stderr ?? "") + (run.error?.message ?? "")),
        ]).then(() => {
            assert.equal(run.status, 0, "Command failed; inspect " + log);
            return run.stdout;
        });
    }
    assert.equal(run.status, 0, "Command failed: " + command);
    return run.stdout;
}
async function absent(path) {
    await assert.rejects(lstat(path), { code: "ENOENT" });
}
async function safeResourceLinks(root) {
    const canonical = await realpath(root);
    const queue = [root];
    let visited = 0;
    while (queue.length) {
        for (const entry of await readdir(queue.shift(), { withFileTypes: true })) {
            assert(++visited < 100_000, "Published dependency tree exceeds guard");
            const path = join(entry.parentPath, entry.name);
            if (entry.isSymbolicLink()) {
                const target = await realpath(path);
                const rel = relative(canonical, target);
                assert(
                    !isAbsolute(rel) && rel !== ".." && !rel.startsWith("../"),
                    "Published dependency symlink escapes resources",
                );
            } else if (entry.isDirectory()) queue.push(path);
        }
    }
}
function selfTest() {
    assert.equal(desktopVersion("0.0.117"), "0.0.117");
    assert.equal(desktopVersion("0.0.116"), "0.0.116");
    assert.throws(() => desktopVersion("0.0.118"));
    assert.throws(() => desktopVersion("0.0.115"));
    const sha = "a".repeat(64);
    const release = {
        id: 123,
        tag_name: "macos-v0.0.115",
        assets: [{ id: 456, name: "CyberFi-0.0.115-x64.dmg", digest: "sha256:" + sha, size: 100 }],
    };
    const ask = {
        releaseId: "123",
        assetId: "456",
        sha,
        tag: "macos-v0.0.115",
        name: "CyberFi-0.0.115-x64.dmg",
    };
    assert.equal(releaseAsset(release, ask).id, 456);
    assert.throws(() => releaseAsset(release, { ...ask, sha: "b".repeat(64) }));
    assert.throws(() => releaseAsset(release, { ...ask, tag: "v0.0.115" }));
    assert.throws(() => identifier("1; echo unsafe"));
    assert.throws(() => archivePath("../outside"));
    assert.throws(() => archivePath("/absolute"));
    assert.throws(() => redirectLocation("http://release-assets.githubusercontent.com/file"));
    assert.throws(() => redirectLocation("https://attacker.example/file"));
    assert.equal(
        redirectLocation("https://release-assets.githubusercontent.com/file?signature=ram-only")
            .hostname,
        "release-assets.githubusercontent.com",
    );
    assertVersionOutput("Happy Agent 0.4.116\n", "0.4.116");
    assertVersionOutput("Happy Agent 0.4.117-preview.1", "0.4.117-preview.1");
    assert.equal(engineTagAllowed("v0.4.117-preview.1"), "v0.4.117-preview.1");
    assert.throws(() => engineTagAllowed("v0.4.117"));
    assert.throws(() => engineTagAllowed("v0.4.117-preview.2"));
    assert.throws(() => assertVersionOutput("Happy Agent 0.4.116", "0.4.117"));
    assert.throws(() => assertVersionOutput("Happy Agent 0.4.117-dev", "0.4.117"));
    console.log("Released UI verifier pure guard checks passed");
}
async function main() {
    assert.equal(process.platform, "darwin");
    const [upstreamArg, rootArg] = process.argv.slice(2);
    assert(upstreamArg && rootArg && isAbsolute(rootArg));
    const upstream = resolve(upstreamArg),
        root = resolve(rootArg);
    assert(process.env.RUNNER_TEMP && isAbsolute(process.env.RUNNER_TEMP));
    assert.equal(root, join(resolve(process.env.RUNNER_TEMP), "cyberfi-released-ui"));
    assert(
        process.env.GITHUB_WORKSPACE &&
            upstream === join(resolve(process.env.GITHUB_WORKSPACE), "public-upstream"),
    );
    const arch = process.env.ARCH;
    assert(arch === "x64" || arch === "arm64");
    assert.equal(process.arch, arch);
    const version = desktopVersion(process.env.DESKTOP_VERSION);
    const desktopTag = "macos-v" + version;
    const engineTag = engineTagAllowed(process.env.ENGINE_TAG);
    const engineVersion = engineTag.slice(1);
    await mkdir(root); // Fresh owned extraction; never reuse another run's files.
    const evidence = join(root, "evidence");
    await mkdir(evidence);
    let attached = false;
    const mount = join(root, "mount");
    await mkdir(mount);
    try {
        const desktopRelease = await apiJson(
            `repos/${DESKTOP_REPO}/releases/${identifier(process.env.DESKTOP_RELEASE_ID)}`,
        );
        const desktopAsset = releaseAsset(desktopRelease, {
            releaseId: process.env.DESKTOP_RELEASE_ID,
            assetId: process.env.DESKTOP_ASSET_ID,
            sha: process.env.DESKTOP_SHA256,
            tag: desktopTag,
            name: `CyberFi-${version}-${arch}.dmg`,
        });
        const engineRelease = await apiJson(
            `repos/${ENGINE_REPO}/releases/${identifier(process.env.ENGINE_RELEASE_ID)}`,
        );
        const engineAsset = releaseAsset(engineRelease, {
            releaseId: process.env.ENGINE_RELEASE_ID,
            assetId: process.env.ENGINE_ASSET_ID,
            sha: process.env.ENGINE_SHA256,
            tag: engineTag,
            name: `happy-agent-${engineVersion}-darwin-${arch}.tar.gz`,
        });
        await writeFile(
            join(evidence, "verified-inputs.json"),
            JSON.stringify(
                {
                    desktop: {
                        repo: DESKTOP_REPO,
                        release: desktopRelease.id,
                        tag: desktopTag,
                        asset: desktopAsset.id,
                        sha256: process.env.DESKTOP_SHA256,
                    },
                    engine: {
                        repo: ENGINE_REPO,
                        release: engineRelease.id,
                        tag: engineTag,
                        asset: engineAsset.id,
                        sha256: process.env.ENGINE_SHA256,
                    },
                    publicGymCommit: UPSTREAM_COMMIT,
                    arch,
                },
                null,
                2,
            ),
        );
        const dmg = join(root, "desktop.dmg"),
            engineTar = join(root, "engine.tar.gz");
        await download(
            `https://api.github.com/repos/${DESKTOP_REPO}/releases/assets/${desktopAsset.id}`,
            dmg,
            true,
        );
        await download(
            `https://api.github.com/repos/${ENGINE_REPO}/releases/assets/${engineAsset.id}`,
            engineTar,
            true,
        );
        assert.equal(await hashFile(dmg), process.env.DESKTOP_SHA256);
        assert.equal(await hashFile(engineTar), process.env.ENGINE_SHA256);
        await command("hdiutil", ["verify", dmg], { log: join(evidence, "dmg-integrity.log") });
        command("hdiutil", ["attach", "-readonly", "-nobrowse", "-mountpoint", mount, dmg]);
        attached = true;
        const app = join(mount, "CyberFi.app"),
            resources = join(app, "Contents/Resources");
        const packagedExecutable = join(app, "Contents/MacOS/CyberFi");
        command("lipo", [packagedExecutable, "-verify_arch", arch === "x64" ? "x86_64" : "arm64"]);
        assert.equal(
            command("/usr/libexec/PlistBuddy", [
                "-c",
                "Print CFBundleShortVersionString",
                join(app, "Contents/Info.plist"),
            ]).trim(),
            version,
        );
        if (arch === "arm64") command("codesign", ["--verify", "--deep", "--strict", app]);
        const env = cleanEnvironment();
        const smokePath = join(evidence, "packaged-smoke.json");
        await command(
            process.execPath,
            ["--import", "tsx", "packages/happy-desktop-gym/sources/electron/cli.ts", "smoke"],
            {
                cwd: upstream,
                env: {
                    ...env,
                    HAPPY_DESKTOP_GYM_PACKAGED: "1",
                    HAPPY_DESKTOP_ELECTRON_EXECUTABLE: packagedExecutable,
                    HAPPY_DESKTOP_GYM_SCREENSHOT: join(evidence, "packaged-welcome.png"),
                },
                log: smokePath,
            },
        );
        const smoke = JSON.parse(await readFile(smokePath, "utf8"));
        assert(
            smoke.packaged &&
                smoke.platform === "darwin" &&
                smoke.arch === arch &&
                smoke.welcomeVisible &&
                smoke.windowTitle === "CyberFi",
        );
        const engineRoot = join(root, "engine");
        await mkdir(engineRoot);
        const tarEntries = command("tar", ["-tzf", engineTar]).trim().split("\n");
        assert.deepEqual(tarEntries.map(archivePath), [`happy-agent-darwin-${arch}`]);
        command("tar", ["-xzf", engineTar, "-C", engineRoot]);
        const engine = join(engineRoot, `happy-agent-darwin-${arch}`);
        command("chmod", ["755", engine]);
        command("lipo", [engine, "-verify_arch", arch === "x64" ? "x86_64" : "arm64"]);
        assertVersionOutput(command(engine, ["--version"], { env }), engineVersion);
        const desktopRequire = createRequire(
            join(upstream, "packages/happy-desktop-electron/package.json"),
        );
        const electronPackage = desktopRequire("electron/package.json");
        assert.equal(electronPackage.version, ELECTRON_VERSION);
        const electronName = `electron-v${ELECTRON_VERSION}-darwin-${arch}.zip`;
        const electronSha = desktopRequire("electron/checksums.json")[electronName];
        digest(electronSha);
        const electronZip = join(root, "stock-electron.zip");
        await download(
            `https://github.com/electron/electron/releases/download/v${ELECTRON_VERSION}/${electronName}`,
            electronZip,
        );
        assert.equal(await hashFile(electronZip), electronSha);
        const stock = join(root, "stock-electron");
        await mkdir(stock);
        command("ditto", ["-x", "-k", electronZip, stock]);
        const stockExecutable = join(stock, "Electron.app/Contents/MacOS/Electron");
        const application = join(root, "released-application");
        await mkdir(application);
        extractReleasedAsar(asarReader(upstream), join(resources, "app.asar"), application);
        const runtimeModules = join(resources, "node_modules");
        await safeResourceLinks(runtimeModules);
        const extractedModules = join(application, "node_modules");
        const extractedStat = await lstat(extractedModules).catch((error) => {
            if (error.code !== "ENOENT") throw error;
        });
        if (extractedStat) {
            assert(extractedStat.isDirectory());
            await safeResourceLinks(extractedModules);
        } else await symlink(runtimeModules, extractedModules);
        const publicDist = join(upstream, "packages/happy-desktop-electron/dist");
        await absent(publicDist);
        await symlink(join(application, "dist"), publicDist);
        for (const path of ["main.js", "preload.cjs", "renderer/index.html"])
            assert((await lstat(join(publicDist, path))).isFile());
        const publicContext = join(upstream, ".context");
        await mkdir(publicContext, { recursive: true });
        const roleHarness = join(publicContext, "cyberfi-released-role-qa.mts");
        const roleReport = join(publicContext, "cyberfi-released-role-qa-report.json");
        await absent(roleHarness);
        await cp(join(dirname(fileURLToPath(import.meta.url)), "released-role-harness.mts"), roleHarness);
        try {
            await command(process.execPath, ["--import", "tsx", roleHarness], {
                cwd: upstream,
                env: {
                    ...env,
                    HAPPY_DESKTOP_AGENT_EXECUTABLE: engine,
                    CYBERFI_RELEASED_RESOURCES: resources,
                    CYBERFI_ROLE_QA_BINARY_SHA256: await hashFile(engine),
                    CYBERFI_ROLE_QA_REPORT: roleReport,
                    CYBERFI_ROLE_QA_BATCH_SIZE: "8",
                    CYBERFI_ROLE_QA_LIMIT: "490",
                },
                log: join(evidence, "native-role-harness.log"),
            });
        } finally {
            if (await lstat(roleReport).catch(() => undefined)) await cp(roleReport, join(evidence, "native-role-read-qa-report.json"));
        }
        const roleProof = JSON.parse(await readFile(roleReport, "utf8"));
        assert(roleProof.success === true && roleProof.exactReadCount === 490 && roleProof.childExact === true, "Native role-body and read-only child checks failed");
        const harness = join(publicContext, "cyberfi-115-integrated-qa.mts");
        await absent(harness);
        await cp(join(dirname(fileURLToPath(import.meta.url)), "released-ui-harness.mts"), harness);
        await command(process.execPath, ["--import", "tsx", harness], {
            cwd: upstream,
            env: {
                ...env,
                HAPPY_DESKTOP_ELECTRON_EXECUTABLE: stockExecutable,
                HAPPY_DESKTOP_AGENT_EXECUTABLE: engine,
                CYBERFI_RELEASED_RESOURCES: resources,
                CYBERFI_QA_FIXTURES: join(dirname(fileURLToPath(import.meta.url)), "fixtures"),
            },
            log: join(evidence, "compiled-ui-harness.log"),
        });
        for (const name of await readdir(publicContext))
            if (name.startsWith("cyberfi-115-integrated-") && !name.endsWith(".mts"))
                await cp(join(publicContext, name), join(evidence, name));
        const report = JSON.parse(
            await readFile(join(evidence, "cyberfi-115-integrated-qa-report.json"), "utf8"),
        );
        assert(
            report.checks?.length &&
                !report.fatal &&
                !report.errors?.length &&
                report.checks.every((check) => check.pass === true),
            "Compiled UI/native clipboard checks failed; inspect preserved report",
        );
        await writeFile(
            join(evidence, "validation-summary.json"),
            JSON.stringify(
                {
                    success: true,
                    platform: "darwin",
                    arch,
                    packagedBoot: smoke,
                    nativeRoleAccess: { exactRoleBodies: roleProof.exactReadCount, realReadOnlyChild: roleProof.childExact, binarySha256: roleProof.binarySha256 },
                    compiledArtifactUi: {
                        checks: report.checks,
                        stockElectronVersion: ELECTRON_VERSION,
                        stockElectronSha256: electronSha,
                    },
                    limits: [
                        "UI and clipboard exercised released compiled artifacts in stock Electron; published app debugger fuses were not modified.",
                        "No private application TypeScript checked out or published.",
                        "Inference is a local deterministic test provider, not a paid/vendor model.",
                    ],
                },
                null,
                2,
            ),
        );
    } finally {
        if (attached) command("hdiutil", ["detach", mount]);
    }
}
if (process.argv.includes("--self-test")) selfTest();
else if (process.argv[2] === "--asar-self-test")
    await asarSelfTest(process.argv[3], process.argv[4]);
else await main();
