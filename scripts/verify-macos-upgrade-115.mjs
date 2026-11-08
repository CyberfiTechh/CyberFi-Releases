import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { access, lstat, mkdir, readFile, readdir, realpath, rename, writeFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { homedir } from "node:os";
import { basename, dirname, join, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";
import { gunzipSync } from "node:zlib";

assert.equal(process.platform, "darwin");
assert(["x64", "arm64"].includes(process.arch));
const expected = {
    x64: { old: "8ee5f945082c6da0ddbca28f0721c90788b2cf1a22e65ecd0d14693f23e0b77c", new: "eec14b750cfe87c57d7ae49f9432c0e0f4cc71cdf959da1495675da6c5ba503d" },
    arm64: { old: "6629c214083e33ae7fdb317c87cf594defa46a34bb820a2022534851fd4f3977", new: "b3dc2cb6f5579f91bb0695c3abc968ba670a7f2ab6612614f88b4ce632dd0564" },
};
const newVersion = process.env.TARGET_VERSION || "0.0.115";
assert(["0.0.115", "0.0.116", "0.0.117"].includes(newVersion));
const oldVersion = newVersion !== "0.0.115" ? "0.0.115" : "0.0.114";
if (newVersion !== "0.0.115") {
    assert(/^[a-f0-9]{64}$/u.test(process.env.EXPECTED_NEW_SHA || ""), "The target requires the explicit published native DMG digest");
    for (const arch of ["x64", "arm64"]) expected[arch] = { old: expected[arch].new, new: process.env.EXPECTED_NEW_SHA };
}
const [sourceArgument, rootArgument, oldArgument, newArgument] = process.argv.slice(2);
assert(sourceArgument && rootArgument && oldArgument && newArgument,
    "Usage: node --import tsx verify-macos-upgrade-115.mjs <public-upstream> <new-owned-run-root> <previous-native.dmg> <target-native.dmg>");
const source = await realpath(sourceArgument);
const root = resolve(rootArgument);
assert(root.startsWith((await realpath(homedir())) + sep), "Run root must be inside the Mac user's home.");
assert.equal(await realpath(dirname(root)), dirname(root), "Run-root parent must not be a symlink.");
await access(join(source, "pnpm-lock.yaml"));
await mkdir(root); // A prior acceptance run is never overwritten.
const { gymElectronProcessRun } = await import(
    pathToFileURL(join(source, "packages/happy-desktop-gym/sources/electron/launch.ts")).href
);
const appDirectory = join(root, "Applications");
const application = join(appDirectory, "CyberFi.app");
const profile = join(root, "user-data");
const home = join(root, "home");
await Promise.all([mkdir(appDirectory), mkdir(profile), mkdir(home)]);
const report = { success: false, root, mode: "manual-dmg-install-and-replacement", stages: [],
    limits: ["No automatic Mac updater installer exists in this release.",
        "Direct app launch does not establish Gatekeeper acceptance of a browser-quarantined download.",
        "Hidden launch deliberately skips normal automatic MCP bootstrap.",
        "Agent/provider inference and full MCP tool calls are separate acceptance work."] };
const hash = (data) => createHash("sha256").update(data).digest("hex");
async function archiveHash(path) {
    const digest = createHash("sha256");
    for await (const data of createReadStream(path)) digest.update(data);
    return digest.digest("hex");
}
function run(command, args) {
    return execFileSync(command, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}
async function install(dmg, version, expected) {
    assert.equal(await archiveHash(dmg), expected, "DMG must be the exact previously published asset.");
    run("/usr/bin/hdiutil", ["verify", dmg]);
    const mount = join(root, "mount-" + version);
    const staged = join(appDirectory, "CyberFi-" + version + ".staged.app");
    await mkdir(mount);
    run("/usr/bin/hdiutil", ["attach", "-readonly", "-nobrowse", "-mountpoint", mount, dmg]);
    try {
        assert((await lstat(join(mount, "CyberFi.app"))).isDirectory());
        run("/usr/bin/ditto", [join(mount, "CyberFi.app"), staged]);
    } finally {
        run("/usr/bin/hdiutil", ["detach", mount]);
    }
    assert.equal(run("/usr/libexec/PlistBuddy", ["-c", "Print :CFBundleShortVersionString",
        join(staged, "Contents/Info.plist")]), version);
    run("/usr/bin/lipo", [join(staged, "Contents/MacOS/CyberFi"), "-verify_arch", process.arch === "arm64" ? "arm64" : "x86_64"]);
    if (process.arch === "arm64") run("/usr/bin/codesign", ["--verify", "--deep", "--strict", staged]);
    try {
        await lstat(application);
        await rename(application, join(appDirectory, `CyberFi-${oldVersion}.rollback.app`));
    } catch (error) {
        if (error.code !== "ENOENT") throw error;
    }
    await rename(staged, application);
    return { version, dmgSHA256: expected, installedPath: application };
}
async function launch(version, targetHome = home, userData = profile, suffix = version) {
    const reportPath = join(root, "smoke-" + suffix + ".json");
    const screenshot = join(root, "welcome-" + suffix + ".png");
    const environment = Object.fromEntries(Object.entries(process.env).filter(([key, value]) =>
        value !== undefined && !/TOKEN|SECRET|PASSWORD|CREDENTIAL/i.test(key) && !["HAPPY_AGENT_SERVER_SOCKET_PATH", "HAPPY_AGENT_SERVER_TOKEN_PATH",
            "HAPPY_HOME_DIR", "NODE_OPTIONS", "ELECTRON_RUN_AS_NODE", "VITE_DEV_SERVER_URL",
            "HAPPY_DESKTOP_GYM_PROFILE"].includes(key)));
    Object.assign(environment, { HOME: targetHome, USERPROFILE: targetHome,
        HAPPY_HOME_DIR: join(targetHome, ".pdr-kocum-agent", ".happy"),
        HAPPY_DESKTOP_SMOKE_REPORT: reportPath, HAPPY_DESKTOP_SMOKE_SCREENSHOT: screenshot });
    const exit = await gymElectronProcessRun({ executablePath: join(application, "Contents/MacOS/CyberFi"),
        args: ["--user-data-dir=" + userData], cwd: source, env: environment, timeout: 120000 });
    assert.equal(exit.exitCode, 0, exit.output);
    const smoke = JSON.parse(await readFile(reportPath, "utf8"));
    assert(smoke.packaged && smoke.platform === "darwin" && smoke.arch === process.arch);
    assert(smoke.welcomeVisible && smoke.screenshotWritten && smoke.windowTitle === "CyberFi");
    assert(smoke.hiddenMode && !smoke.dockVisible && !smoke.focusedWindow);
    assert(smoke.windows.length > 0 && smoke.windows.every((window) => !window.visible && !window.focused));
    assert((await lstat(screenshot)).size > 0);
    return { version, smoke, screenshot, exitCode: exit.exitCode };
}
async function validateCatalog(targetHome) {
    const skills = join(targetHome, ".agents/skills");
    const resources = join(application, "Contents/Resources");
    const catalog = JSON.parse(gunzipSync(await readFile(join(resources, "pdr-catalog/cyberfi-catalog.json.gz"))));
    const folders = new Set();
    for (const [path, encoded] of Object.entries(catalog)) {
        const destination = resolve(skills, path);
        assert(destination.startsWith(skills + sep));
        assert.equal(hash(await readFile(destination)), hash(Buffer.from(encoded, "base64")), path);
        folders.add(path.split("/")[0]);
    }
    const base = await readdir(join(resources, "pdr-skills"), { withFileTypes: true });
    const baseRoles = base.filter((entry) => entry.isDirectory());
    for (const entry of baseRoles) {
        const path = entry.name + "/SKILL.md";
        assert.equal(hash(await readFile(join(skills, path))), hash(await readFile(join(resources, "pdr-skills", path))));
    }
    return { archiveFilesVerified: Object.keys(catalog).length, archiveFoldersVerified: folders.size,
        baseFoldersVerified: baseRoles.length, totalBundledFolders: folders.size + baseRoles.length };
}
try {
    console.log("Stage: install and launch previous published release");
    const oldInstall = await install(resolve(oldArgument), oldVersion,
        expected[process.arch].old);
    report.stages.push({ ...oldInstall, ...(await launch(oldVersion)), catalog: await validateCatalog(home) });
    const configPath = join(profile, "desktop/config.json");
    const config = await readFile(configPath, "utf8").then(JSON.parse).catch((error) => {
        if (error.code === "ENOENT") return {};
        throw error;
    });
    await writeFile(configPath, JSON.stringify({ ...config, appearance: "dark", defaultPermissionMode: "read_only" }, null, 4) + "\n");
    const sentinels = [
        [join(profile, "desktop/acceptance-user-note.txt"), "Existing user data retained through upgrade.\n"],
        [join(home, ".agents/skills/pdr-arastirmaci/SKILL.md"), "# User role override\nPreserve this exact existing role.\n"],
    ];
    for (const [path, text] of sentinels) await writeFile(path, text);
    const engineConfig = join(home, ".pdr-kocum-agent/Happy/Config");
    const userToml = join(engineConfig, "happy.toml");
    const previousToml = await readFile(userToml, "utf8");
    const retainedToml = previousToml + "\n# Acceptance: keep existing user configuration.\n";
    await writeFile(userToml, retainedToml);
    console.log("Stage: replace the same app with released target and preserve profile");
    const newInstall = await install(resolve(newArgument), newVersion,
        expected[process.arch].new);
    report.stages.push({ ...newInstall, ...(await launch(newVersion)) });
    for (const [path, text] of sentinels) assert.equal(await readFile(path, "utf8"), text);
    assert.equal(await readFile(userToml, "utf8"), retainedToml);
    const retainedConfig = JSON.parse(await readFile(configPath, "utf8"));
    assert.equal(retainedConfig.appearance, "dark");
    assert.equal(retainedConfig.defaultPermissionMode, "read_only");
    report.profilePreserved = true;
    console.log("Stage: launch released target with a fresh isolated profile");
    const freshHome = join(root, "fresh-home");
    const freshData = join(root, "fresh-user-data");
    await Promise.all([mkdir(freshHome), mkdir(freshData)]);
    report.stages.push({ ...(await launch(newVersion, freshHome, freshData, newVersion + "-fresh")),
        catalog: await validateCatalog(freshHome), mode: "fresh-target-profile" });
    report.success = true;
} catch (error) {
    report.error = error instanceof Error ? error.message : String(error);
    throw error;
} finally {
    await writeFile(join(root, "install-upgrade-report.json"), JSON.stringify(report, null, 2) + "\n");
    console.log(JSON.stringify(report, null, 2));
}
