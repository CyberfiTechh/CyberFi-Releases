import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import { lstat, mkdir, readFile, realpath } from "node:fs/promises";
import { join, sep } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

// The caller has already rehashed and validated the exact signed target app bundle.
export async function verifyMacFreshEngine(input) {
    const { upstream, root, executable, profile, evidence, engineAsset, command, hashFile, username, password, report } = input;
    const home = join(root, "fresh-home"), happyHome = join(home, ".happy"), tmp = join(root, "fresh-tmp");
    const engine = join(happyHome, "dist", "version", "0.4.125", "happy-agent");
    await assert.rejects(lstat(home), { code: "ENOENT" });
    await Promise.all([mkdir(home), mkdir(tmp)]);
    await assert.rejects(lstat(join(profile, "desktop")), { code: "ENOENT" });
    await assert.rejects(lstat(engine), { code: "ENOENT" });
    assert(Buffer.byteLength(join(happyHome, "agent", "server.sock")) <= 100);
    report.profileInitiallyAbsent = true;
    report.engineInitiallyAbsent = true;
    report.progress = [];

    const env = {
        HOME: home, HAPPY_HOME_DIR: happyHome, TMPDIR: tmp, SHELL: "/bin/zsh",
        PATH: "/usr/bin:/bin:/usr/sbin:/sbin", LANG: "en_US.UTF-8",
        HAPPY_DESKTOP_WINDOWS_HIDDEN: "1", HAPPY_DESKTOP_DEBUG: "1", HAPPY_DEBUG_RENDERER_PORT: "19484",
    };
    const port = 19484, endpoint = `http://127.0.0.1:${port}`;
    const listenerPid = async () => {
        const text = await command("/usr/sbin/lsof", ["-nP", `-iTCP@127.0.0.1:${port}`, "-sTCP:LISTEN", "-t"]).catch(error => {
            if (error.code === 1) return "";
            throw error;
        });
        const pids = [...new Set(text.split(/\s+/u).filter(Boolean))];
        assert(pids.length <= 1);
        return pids.length ? Number(pids[0]) : undefined;
    };
    assert.equal(await listenerPid(), undefined);
    const require = createRequire(join(upstream, "packages/happy-desktop-gym/package.json"));
    const { chromium } = require("playwright");
    const app = spawn(executable, ["--user-data-dir=" + profile, "--debug"], { cwd: root, env, stdio: "ignore" });
    let exit, browser, page, startedAt;
    const done = new Promise(resolve => {
        app.once("error", () => { exit = { spawnError: true }; resolve(); });
        app.once("exit", (code, signal) => { exit = { code, signal }; resolve(); });
    });

    try {
        report.stage = "fresh installed Mac app startup";
        const deadline = Date.now() + 90000;
        while (Date.now() < deadline && !exit) {
            try {
                const response = await fetch(endpoint + "/json/list", { signal: AbortSignal.timeout(1500) });
                if (response.ok && (await response.json()).some(item => item.type === "page")) {
                    browser = await chromium.connectOverCDP(endpoint);
                    page = browser.contexts().flatMap(context => context.pages()).find(p => !p.url().startsWith("devtools:"));
                    if (page) break;
                    await browser.close(); browser = undefined;
                }
            } catch { /* Debug endpoint still starting. */ }
            await delay(200);
        }
        assert(page && !exit, "Fresh target did not open its renderer");
        assert.equal(await listenerPid(), app.pid, "The exact owned target must own the debug endpoint");

        report.stage = "fresh Mac protected login";
        await page.waitForFunction(() => !document.querySelector('[data-testid="desktop-startup-screen"]') && !!document.querySelector('[data-happy-desktop-ui="cyberfi-account-login"] input[name="password"]:not(:disabled)'), undefined, { timeout: 60000 });
        assert(await page.evaluate(async () => { try { await window.happyDesktop.runtimeGet(); return false; } catch { return true; } }));
        await page.addStyleTag({ content: 'input[name="username"], input[name="password"] { color: transparent !important; text-shadow: none !important; caret-color: transparent !important; }' });
        const login = page.locator('[data-happy-desktop-ui="cyberfi-account-login"]');
        await login.locator('input[name="username"]').fill(username);
        await login.locator('input[name="password"]').fill(password);
        assert.equal(await login.getByRole("checkbox", { name: /^(Beni hatırla|Remember me)$/iu }).isChecked(), false);
        await login.getByRole("button", { name: /^(Giriş yap|Sign in)$/iu }).click();
        await page.waitForFunction(async () => (await window.happyDesktop.cyberFiAccountGet()).status === "signedIn", undefined, { timeout: 60000 });
        const account = await page.evaluate(() => window.happyDesktop.cyberFiAccountGet());
        assert(account.user?.role === "user" && account.remember === false && account.username === username);
        report.accountAuthenticated = true;
        report.actualGui = true;

        report.stage = "fresh Mac automatically downloads and starts engine";
        startedAt = Date.now();
        let snapshot, last;
        while (Date.now() - startedAt < 5 * 60000 && !exit) {
            try {
                snapshot = await page.evaluate(async () => {
                    const [runtime, daemon, onboarding] = await Promise.all([window.happyDesktop.runtimeGet(), window.happyDesktop.daemonGet(), window.happyDesktop.onboardingGet()]);
                    return { phase: runtime.phase, runningVersion: runtime.activeTarget?.happyAgentVersion,
                        installation: daemon.installation, operation: daemon.operation, engineRuntime: daemon.runtime,
                        installedVersion: daemon.installedVersion, errorCode: daemon.errorCode ?? null,
                        download: daemon.download && { bytes: daemon.download.receivedBytes, total: daemon.download.totalBytes },
                        onboardingStage: onboarding.stage };
                });
            } catch { await delay(200); continue; }
            const key = JSON.stringify(snapshot);
            if (key !== last) { report.progress.push({ elapsedMs: Date.now() - startedAt, ...snapshot }); last = key; }
            if (snapshot.phase === "ready" && snapshot.runningVersion === "0.4.125" && snapshot.installedVersion === "0.4.125" && snapshot.engineRuntime === "ready") break;
            await delay(200);
        }
        assert(snapshot?.phase === "ready" && snapshot.runningVersion === "0.4.125" && snapshot.installedVersion === "0.4.125" && snapshot.engineRuntime === "ready", "Fresh Mac engine never became ready");
        assert(report.progress.some(row => row.operation === "downloading" && row.download?.bytes > 0 && row.download.total === engineAsset.size), "No actual measured engine download");
        const installed = await lstat(engine);
        assert(installed.isFile() && !installed.isSymbolicLink() && await realpath(engine) === engine);
        const pid = (await readFile(join(happyHome, "agent", "daemon.pid"), "utf8")).trim();
        assert.match(pid, /^[1-9][0-9]{0,9}$/u);
        assert.equal(await command("/bin/ps", ["-ww", "-p", pid, "-o", "comm="]), engine);
        report.installedEngineSha256 = await hashFile(engine);
        report.runningEnginePid = Number(pid);
        report.desktopConnected = true;
        report.installedEngineVersion = "0.4.125";
        await page.screenshot({ path: join(evidence, "fresh-engine-ready.png"), mask: [page.getByText(username, { exact: true })] });
    } catch (error) {
        if (page && !page.isClosed()) await page.screenshot({ path: join(evidence, "fresh-failure.png"), mask: [page.locator('input[name="username"], input[name="password"]'), page.getByText(username, { exact: true })] }).catch(() => undefined);
        throw error;
    } finally {
        if (!exit && app.pid) app.kill("SIGTERM");
        await Promise.race([done, delay(5000)]);
        if (!exit && app.pid) app.kill("SIGKILL");
        await browser?.close().catch(() => undefined);
        if ((await lstat(engine).catch(() => undefined))?.isFile() && await realpath(engine).catch(() => "") === engine && engine.startsWith(root + sep))
            await command(engine, ["stop"], { env, timeout: 30000 }).catch(() => undefined);
    }
}
