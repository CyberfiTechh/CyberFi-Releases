import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { createReadStream } from "node:fs";
import { mkdir, readFile, realpath, writeFile, stat } from "node:fs/promises";
import { createServer } from "node:http";
import { createRequire } from "node:module";
import { join, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { setTimeout as delay } from "node:timers/promises";
const exec = promisify(execFile);
assert(process.platform === "win32" && process.env.GITHUB_ACTIONS === "true" &&
    process.env.RUNNER_ENVIRONMENT === "github-hosted" && process.env.GITHUB_REPOSITORY === "CyberfiTechh/CyberFi-Releases" &&
    process.env.GITHUB_REF === "refs/heads/main", "Only the disposable public Windows runner may execute this GUI test");
const [upstreamArg] = process.argv.slice(2);
const upstream = await realpath(upstreamArg);
const root = await realpath(process.env.ACCEPTANCE_UI_ROOT);
const evidence = join(root, "evidence");
const executable = resolve(process.env.ACCEPTANCE_EXE);
const userData = resolve(process.env.ACCEPTANCE_USER_DATA);
assert(executable.startsWith(root + sep));
const report = { success: false, mode: "actual signed116 GUI updater to117", phase: "capability", progress: [], processes: [], errors: [] };
const save = () => writeFile(join(evidence, "in-app-update.json"), JSON.stringify(report, null, 2));
const gymPath = name => pathToFileURL(join(upstream, "packages/happy-desktop-gym/sources/electron", name + ".ts")).href;
const { gymElectronProcessRun, gymElectronVideoRecord } = await import(gymPath("launch"));
const { gymRunPathsCreate, gymRunClean } = await import(gymPath("paths"));
const { happyAgentRuntimeCreate } = await import(gymPath("happyAgentRuntime"));
const require = createRequire(join(upstream, "packages/happy-desktop-gym/package.json"));
const { chromium } = require("playwright");
const { paths } = await gymRunPathsCreate("smoke");
process.env.HAPPY_DESKTOP_AGENT_EXECUTABLE = process.env.ACCEPTANCE_ENGINE_EXE;
const inference = createServer(async (req, res) => {
    for await (const _ of req) { /* No real provider requests or credentials. */ }
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ content: [{ type: "text", text: "Owned update acceptance baseline." }], completionDelayMs: 1 }));
});
await new Promise(resolve => inference.listen(0, "127.0.0.1", resolve));
let runtime, browser, page, video, run, runResult, runError, stopWatch = false, watch;
const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/TOKEN|SECRET|PASSWORD|CREDENTIAL|API_KEY|SMOKE_REPORT|SMOKE_SCREENSHOT|NODE_OPTIONS|ELECTRON_RUN_AS_NODE|VITE_DEV_SERVER_URL/iu.test(key)));
const ps = join(process.env.SystemRoot, "System32/WindowsPowerShell/v1.0/powershell.exe");
async function processes() {
    const { stdout } = await exec(ps, ["-NoProfile", "-NonInteractive", "-Command",
        "@(Get-CimInstance Win32_Process | Where-Object { $_.Name -in @('CyberFi.exe','CyberFi-0.0.117-x64.exe') } | Select-Object Name,ProcessId,ParentProcessId,ExecutablePath,CommandLine,CreationDate) | ConvertTo-Json -Depth 3 -Compress"],
        { timeout: 15000, windowsHide: true, env, maxBuffer: 256 * 1024 });
    const parsed = stdout.trim() ? JSON.parse(stdout) : [];
    return Array.isArray(parsed) ? parsed : [parsed];
}
try {
    runtime = await happyAgentRuntimeCreate(paths, { url: `http://127.0.0.1:${inference.address().port}/inference`,
        token: randomBytes(24).toString("hex"), start: async () => {}, stop: async () => {} });
    report.engineHealth = await runtime.client.health();
    // A legitimate persisted onboarding preference, matching the existing native gym.
    await writeFile(join(userData, "desktop/local-onboarding.json"), JSON.stringify({ version: 3, chiefOfStaffSetup: true }));
    const port = 19371;
    Object.assign(env, runtime.environment, { HOME: process.env.HOME, USERPROFILE: process.env.USERPROFILE,
        APPDATA: process.env.APPDATA, LOCALAPPDATA: process.env.LOCALAPPDATA,
        TEMP: process.env.TEMP, TMP: process.env.TMP,
        HAPPY_HOME_DIR: process.env.HAPPY_HOME_DIR, HAPPY_DESKTOP_WINDOWS_HIDDEN: "1",
        HAPPY_DESKTOP_DEBUG: "1", HAPPY_DEBUG_RENDERER_PORT: String(port) });
    for (const key of Object.keys(env)) if (/SMOKE_REPORT|SMOKE_SCREENSHOT/iu.test(key)) delete env[key];
    run = gymElectronProcessRun({ executablePath: executable, args: [`--user-data-dir=${userData}`, "--debug"], env,
        timeout: 12 * 60_000 }).then(value => { runResult = value; return value; }).catch(error => { runError = error; });
    const endpoint = `http://127.0.0.1:${port}`;
    const deadline = Date.now() + 90000;
    let targets;
    while (Date.now() < deadline) {
        if (runError || runResult) throw runError ?? new Error(`116 exited before CDP capability: ${runResult.output}`);
        try { const response = await fetch(endpoint + "/json/list", { signal: AbortSignal.timeout(1500) });
            if (response.ok) { targets = await response.json(); break; } } catch { /* Only loopback startup polling. */ }
        await delay(300);
    }
    assert(targets?.some(target => target.type === "page"), "Approved signed116 --debug did not expose a renderer CDP page");
    report.approvedDebug = { endpoint, rawInspectorArgumentsUsed: false, fuseChanges: false };
    browser = await chromium.connectOverCDP(endpoint);
    page = browser.contexts().flatMap(context => context.pages()).find(candidate => !candidate.url().startsWith("devtools:"));
    assert(page, "No actual116 renderer page");
    await page.waitForFunction(() => typeof window.happyDesktop?.runtimeGet === "function", undefined, { timeout: 30000 });
    video = await gymElectronVideoRecord(page, { path: join(evidence, "in-app-update.webm"), fps: 5 });
    // One legitimate main-origin preference write; never a persistent frame init script.
    await page.evaluate(() => {
        localStorage.setItem("pdr-kocum-agent.language", "tr");
        localStorage.setItem("happy.welcome.v1", JSON.stringify({ welcomeAcknowledged: true }));
    });
    await page.reload({ waitUntil: "commit" });
    await page.waitForFunction(() => typeof window.happyDesktop?.runtimeGet === "function", undefined, { timeout: 30000 });
    const before = (await processes()).filter(item => item.ExecutablePath?.toLowerCase() === executable.toLowerCase() && !item.CommandLine?.includes("--type="));
    assert.equal(before.length, 1, "One owned116 main process required");
    report.oldMainProcessId = before[0].ProcessId;
    const { stdout: nativeText } = await exec(ps, ["-NoProfile", "-NonInteractive", "-Command",
        `Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public static class UpdateProbe{[DllImport("user32.dll")]public static extern bool IsWindowVisible(IntPtr h);[DllImport("user32.dll")]public static extern IntPtr GetForegroundWindow();[DllImport("user32.dll")]public static extern uint GetWindowThreadProcessId(IntPtr h,out uint p);}';$p=Get-Process -Id ${report.oldMainProcessId};[uint32]$fg=0;$null=[UpdateProbe]::GetWindowThreadProcessId([UpdateProbe]::GetForegroundWindow(),[ref]$fg);$listener=Get-NetTCPConnection -LocalAddress 127.0.0.1 -LocalPort ${port} -State Listen;@{visible=($p.MainWindowHandle -ne 0 -and [UpdateProbe]::IsWindowVisible($p.MainWindowHandle));foregroundPid=$fg;listenerPids=@($listener.OwningProcess)}|ConvertTo-Json -Compress`],
        { env, timeout: 15000, windowsHide: true });
    report.nativeHiddenCapability = JSON.parse(nativeText);
    assert.equal(report.nativeHiddenCapability.visible, false);
    assert.notEqual(report.nativeHiddenCapability.foregroundPid, report.oldMainProcessId);
    assert(report.nativeHiddenCapability.listenerPids.includes(report.oldMainProcessId), "Loopback CDP listener is not owned by signed116 process");
    const readyBy = Date.now() + 90000;
    let startedLocally = false;
    while (Date.now() < readyBy) {
        const state = await page.evaluate(() => window.happyDesktop.runtimeGet());
        if (state.phase === "ready") break;
        const start = page.getByRole("button", { name: /^(Start locally|Bu bilgisayarda başlat)$/i });
        if (!startedLocally && await start.isVisible().catch(() => false)) {
            await start.click();
            startedLocally = true;
        }
        await delay(300);
    }
    assert.equal((await page.evaluate(() => window.happyDesktop.runtimeGet())).phase, "ready", "Real owned engine baseline did not reach ready");
    report.capabilityDom = await page.locator("body").innerText();
    // Real navigation controls only. Never invoke updateInstall or manufacture runtime state.
    const settings = page.getByRole("button", { name: /settings|ayarlar|ayarları aç/i }).first();
    await settings.waitFor({ state: "visible", timeout: 30000 });
    await settings.click();
    const general = page.getByRole("button", { name: /^(General|Genel)$/i }).first();
    if (await general.count()) await general.click();
    const select = page.locator("#cyberfi-settings-desktop-version");
    try { await select.waitFor({ state: "visible", timeout: 60000 }); }
    catch {
        report.capabilityDom = await page.locator("body").innerText();
        await page.screenshot({ path: join(evidence, "ui-capability-blocked.png") });
        throw new Error("Real signed116 General settings updater was not reachable; no runtime spoof or direct IPC fallback used");
    }
    report.phase = "real updater";
    await page.getByRole("button", { name: /^(Check for updates|Güncellemeleri denetle)$/i }).first().click();
    await page.waitForFunction(async () => (await window.happyDesktop.runtimeGet()).update?.versions?.some(entry => entry.version === "0.0.117"), undefined, { timeout: 45000 });
    await select.selectOption("0.0.117");
    const button = page.getByRole("button", { name: /^(Download and reopen|İndir ve yeniden aç)$/i });
    await button.waitFor({ state: "visible", timeout: 15000 });
    await page.screenshot({ path: join(evidence, "before-real-download.png") });
    watch = Promise.all([
        (async () => {
            while (!stopWatch) {
                report.processes.push(...(await processes()).filter(item => item.Name === "CyberFi-0.0.117-x64.exe"));
                await delay(300);
            }
        })(),
        (async () => {
            while (!stopWatch) {
                try {
                    const update = await page.evaluate(async () => {
                        const data = (await window.happyDesktop.runtimeGet()).update;
                        return { status: data.status, availableVersion: data.availableVersion, downloadedFraction: data.downloadedFraction, message: data.message };
                    });
                    if (JSON.stringify(report.progress.at(-1)) !== JSON.stringify(update)) report.progress.push(update);
                } catch { /* Expected renderer closure on real updater handoff. */ }
                await delay(100);
            }
        })(),
    ]);
    // Prevent an observer rejection becoming unhandled while the app is exiting;
    // the original promise is still awaited below and any failure is rethrown.
    watch.catch(() => undefined);
    report.clickedActualGuiButton = true;
    await button.click();
    await run;
    assert(!runError && runResult?.exitCode === 0, runError?.message ?? runResult?.output);
    const until = Date.now() + 30000;
    while (!report.processes.some(item => item.ParentProcessId === report.oldMainProcessId) && Date.now() < until) await delay(300);
    stopWatch = true;
    await watch;
    const installer = report.processes.find(item => item.ParentProcessId === report.oldMainProcessId &&
        /--updated/.test(item.CommandLine ?? "") && /\/S/.test(item.CommandLine ?? "") && /--force-run/.test(item.CommandLine ?? ""));
    assert(installer, "No installer process spawned by the actual old app with production update arguments was observed");
    assert(installer.ExecutablePath?.toLowerCase().includes("cyberfi-update-"), "Installer must originate in the app's own new update directory");
    const bytes = await stat(installer.ExecutablePath);
    const digest = createHash("sha256");
    for await (const chunk of createReadStream(installer.ExecutablePath)) digest.update(chunk);
    assert.equal(digest.digest("hex"), process.env.ACCEPTANCE_TARGET_SHA256);
    assert.equal(bytes.size, 143680592);
    assert(report.progress.some(update => update.status === "downloading"), "Real runtime download progress was not observed");
    const fractions = report.progress.filter(update => typeof update.downloadedFraction === "number").map(update => update.downloadedFraction);
    assert(fractions.length > 0 && fractions.every(value => Number.isFinite(value) && value >= 0 && value <= 1) && fractions.some(value => value > 0),
        "At least one finite actual download percentage in0..100 is required");
    report.ownInstaller = installer;
    report.appDownloadedSHA256 = process.env.ACCEPTANCE_TARGET_SHA256;
    report.appDownloadedSize = bytes.size;
    report.success = true;
    report.phase = "app-own installer handoff observed; outer harness verifies automatic117/profile";
} catch (error) {
    report.errors.push(String(error));
    if (page && !page.isClosed()) await page.screenshot({ path: join(evidence, "in-app-failure.png") }).catch(() => {});
    throw error;
} finally {
    stopWatch = true;
    await watch?.catch(() => {});
    if (video) report.video = await video.stop().catch(error => ({ error: String(error) }));
    if (!(report.video?.framesReceived > 0 && report.video.framesWritten > 0)) {
        report.success = false;
        report.errors.push("Mandatory gym compositor video missing");
    }
    await save();
    // On a capability failure, ask the owned116 app to quit; never start117 manually.
    if (!report.success && page && !page.isClosed()) await page.evaluate(() => window.happyDesktop.windowClose?.()).catch(() => {});
    if (!report.success) {
        for (const item of (await processes()).filter(item => item.ExecutablePath?.toLowerCase() === executable.toLowerCase()))
            await exec("taskkill.exe", ["/PID", String(item.ProcessId), "/T", "/F"], { windowsHide: true }).catch(() => {});
    }
    await run?.catch(() => {});
    await runtime?.stop();
    inference.close();
    await gymRunClean(paths.root);
}
assert(report.video?.framesReceived > 0 && report.video.framesWritten > 0, "Mandatory gym compositor video missing");
console.log(JSON.stringify({ success: true, oldMainProcessId: report.oldMainProcessId, installerProcessId: report.ownInstaller.ProcessId }));
