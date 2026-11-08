import { happyAgentClientCreate } from "../packages/happy-desktop-gym/sources/electron/happyAgentProtocol.ts";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { createReadStream } from "node:fs";
import { mkdir, writeFile, readFile, cp, realpath } from "node:fs/promises";
import { tmpdir } from "node:os";
import { gunzipSync } from "node:zlib";
import { extname, join, resolve } from "node:path";
import {
    gymElectronInvisibleAssert,
    gymElectronLaunch,
    gymElectronVideoRecord,
} from "../packages/happy-desktop-gym/sources/electron/launch.ts";
import {
    electronEntrypointResolve,
    gymRunClean,
    gymRunPathsCreate,
} from "../packages/happy-desktop-gym/sources/electron/paths.ts";
import { gymInferenceServerCreate } from "../packages/happy-desktop-gym/sources/electron/inferenceServer.ts";
import { gymManifestRead } from "../packages/happy-desktop-gym/sources/electron/manifest.ts";
import { happyAgentRuntimeCreate } from "../packages/happy-desktop-gym/sources/electron/happyAgentRuntime.ts";
const report: any = {
    renderer: "packages/happy-desktop-electron/dist/renderer",
    checks: [],
    errors: [],
    console: [],
};
const rendererRoot = resolve(report.renderer);
const mime: any = {
    ".html": "text/html",
    ".css": "text/css",
    ".js": "text/javascript",
    ".svg": "image/svg+xml",
    ".woff2": "font/woff2",
    ".png": "image/png",
    ".wasm": "application/wasm",
};
const server = createServer((req, res) => {
    const path = new URL(req.url || "/", "http://localhost").pathname;
    const file = path === "/" ? "/index.html" : path;
    if (!/^\/[\w./-]+$/.test(file) || file.includes("..")) {
        res.writeHead(404).end();
        return;
    }
    const read = createReadStream(join(rendererRoot, file));
    read.on("error", () => res.writeHead(404).end());
    read.on("open", () => {
        res.setHeader("content-type", mime[extname(file)] || "application/octet-stream");
        read.pipe(res);
    });
});
await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
// macOS exposes /var as an alias of /private/var. Record the real temporary
// directory before creating the isolated workspace; production path guards stay intact.
const canonicalTemporaryDirectory = await realpath(tmpdir());
process.env.TMPDIR = canonicalTemporaryDirectory;
report.canonicalTemporaryDirectory = canonicalTemporaryDirectory;
const { paths } = await gymRunPathsCreate("smoke");
const inferenceBase = gymInferenceServerCreate(gymManifestRead("smoke"), paths.inferenceLog);
await inferenceBase.start();
let syntheticCalls = 0;
const diagram =
    '<svg xmlns="http://www.w3.org/2000/svg" width="400" height="220" viewBox="0 0 400 220"><path d="M40 185 L200 30 L360 185 Z" fill="#d8f4ed" stroke="#126d60" stroke-width="3"/><text x="195" y="22">A</text><text x="20" y="205">B</text><text x="365" y="205">C</text></svg>';
const fixtureRoot = process.env.CYBERFI_QA_FIXTURES;
assert.ok(fixtureRoot, "Pinned synthetic output fixtures are required");
const fixtureManifest = JSON.parse(await readFile(join(fixtureRoot, "manifest.json"), "utf8"));
assert.deepEqual(fixtureManifest.map((item: any) => item.name).sort(), ["qa-support.docx", "qa-support.pdf", "qa-support.png"]);
const outputFixtures = await Promise.all(fixtureManifest.map(async (item: any) => {
    assert.match(item.name, /^qa-support\.(png|pdf|docx)$/);
    const bytes = await readFile(join(fixtureRoot, item.name));
    assert.equal(bytes.length, item.size);
    assert.equal(createHash("sha256").update(bytes).digest("hex"), item.sha256);
    return { ...item, bytes };
}));
const presentedPaths = ["qa-diagram.svg", ...outputFixtures.map((item: any) => item.name)];
const synthetic = createServer(async (req, res) => {
    for await (const _ of req) {
    }
    const step = syntheticCalls++;
    const content =
        step === 0
            ? [
                  {
                      type: "toolCall",
                      name: "present_files",
                      arguments: { filepaths: presentedPaths },
                  },
              ]
            : [
                  {
                      type: "text",
                      text: "Üçgenin iç açıları toplamı 180 derecedir. İki açı 50 derece olduğunda üçüncü açı 80 derecedir. Şekil yalnızca açıklamayı destekler.",
                  },
              ];
    res.writeHead(200, { "content-type": "application/json" });
    res.end(
        JSON.stringify({
            content,
            textDeltaChunkSize: 96,
            textDeltaDelayMs: 10,
            completionDelayMs: 10,
        }),
    );
});
await new Promise<void>((r) => synthetic.listen(0, "127.0.0.1", r));
const inference = {
    url: "http://127.0.0.1:" + (synthetic.address() as any).port + "/inference",
    token: inferenceBase.token,
    start: async () => {},
    stop: async () => {
        synthetic.close();
        await inferenceBase.stop();
    },
};
let runtime: any, app: any, video: any, clipboardBefore: any;
try {
    // Only data already published in the verified DMG, never private application source.
    const resources = process.env.CYBERFI_RELEASED_RESOURCES;
    assert.ok(resources, "Verified released resources must be supplied");
    const skillsRoot = join(paths.home, ".agents", "skills");
    await cp(join(resources, "pdr-skills"), skillsRoot, { recursive: true, errorOnExist: true });
    const catalog = JSON.parse(
        gunzipSync(await readFile(join(resources, "pdr-catalog", "cyberfi-catalog.json.gz")), {
            maxOutputLength: 24 * 1024 * 1024,
        }).toString("utf8"),
    );
    for (const [relative, encoded] of Object.entries(catalog)) {
        const parts = relative.split("/");
        assert.ok(
            parts.length > 1 &&
                parts.every(
                    (part) => /^[a-zA-Z0-9._-]+$/.test(part) && part !== "." && part !== "..",
                ),
        );
        assert.equal(typeof encoded, "string");
        await mkdir(join(skillsRoot, ...parts.slice(0, -1)), { recursive: true });
        await writeFile(join(skillsRoot, ...parts), Buffer.from(encoded as string, "base64"), {
            flag: "wx",
        });
    }
    report.evidenceKind =
        "Released compiled main/preload/renderer in stock Electron 45 development shell; packaged boot is tested separately.";
    runtime = await happyAgentRuntimeCreate(paths, inference);
    const profile = join(paths.electronUserData, "integrated");
    await mkdir(join(profile, "desktop"), { recursive: true });
    await writeFile(
        join(profile, "desktop", "local-onboarding.json"),
        JSON.stringify({ version: 3, chiefOfStaffSetup: true }),
    );
    const electronEnvironment = { ...runtime.environment };
    const entry = electronEntrypointResolve();
    app = await gymElectronLaunch({
        executablePath: entry.executable,
        args: [
            `--user-data-dir=${profile}`,
            ...(process.env.HAPPY_DESKTOP_GYM_PACKAGED === "1" ? [] : [entry.main]),
        ],
        cwd: paths.workspaceRoot,
        env: {
            ...electronEnvironment,
            ...(process.env.HAPPY_DESKTOP_GYM_PACKAGED === "1"
                ? {}
                : { VITE_DEV_SERVER_URL: `http://127.0.0.1:${(server.address() as any).port}` }),
            HAPPY_ALLOW_SOURCE_AGENT: "1",
            HAPPY_DESKTOP_GYM_PROFILE: "smoke",
            HAPPY_DESKTOP_GYM_ELECTRON_USER_DATA: profile,
        },
        timeout: 60000,
    });
    report.clipboardBackup = await app.evaluate(async ({ clipboard, ClipboardItem }: any) => {
        const readItems = await clipboard.read();
        // macOS may return a zero-MIME placeholder for an empty clipboard.
        const items = readItems.filter((item: any) => item.types.length > 0);
        (globalThis as any).__cyberfiQaClipboard = await Promise.all(
            items.map(
                async (item: any) =>
                    new ClipboardItem(
                        Object.fromEntries(
                            await Promise.all(
                                item.types.map(async (type: string) => [
                                    type,
                                    await item.getType(type),
                                ]),
                            ),
                        ),
                    ),
            ),
        );
        return { preservedItems: items.length, emptyPlaceholders: readItems.length - items.length };
    });
    clipboardBefore = true;
    const page = await app.firstWindow();
    page.on("response", (response: any) => {
        if (response.status() >= 400) {
            (report.failedResources ??= []).push({
                url: response.url(),
                status: response.status(),
            });
        }
    });
    page.on("pageerror", (e: any) => report.errors.push(e.message));
    page.on("console", (m: any) => {
        if (m.type() === "error") report.console.push(m.text().slice(0, 400));
    });
    video = await gymElectronVideoRecord(page, {
        path: resolve(".context/cyberfi-115-integrated-qa.webm"),
        scale: 0.75,
        fps: 12,
    });
    await page.addInitScript(() => {
        localStorage.setItem("pdr-kocum-agent.language", "tr");
        localStorage.setItem("happy.welcome.v1", JSON.stringify({ welcomeAcknowledged: true }));
    });
    await page.reload({ waitUntil: "commit" });
    await app.evaluate(({ BrowserWindow }: any) =>
        BrowserWindow.getAllWindows()[0]?.setSize(1400, 900),
    );
    await page.locator(".cyberfi-workspace").waitFor({ timeout: 45000 });
    await gymElectronInvisibleAssert(app);
    report.checks.push({ name: "hidden real Electron shell", pass: true });
    const run = async (name: string, fn: () => Promise<any>) => {
        try {
            report.checks.push({ name, pass: true, result: await fn() });
        } catch (e) {
            report.checks.push({ name, pass: false, error: String(e) });
        }
    };
    await run("startup routes to home, not settings", async () => {
        await page.waitForTimeout(3300);
        const text = await page.locator("body").innerText();
        report.startupText = text.slice(0, 6000);
        assert.ok(!text.includes("Bilgisayarın uykuya geçmesini engelle"));
        return { url: page.url(), tabs: await page.getByRole("tab").allTextContents() };
    });
    await run(
        "actual memory IPC isolated owner read create prepare acknowledge",
        async () =>
            await page.evaluate(async () => {
                const b = (window as any).happyDesktop;
                const owner = "integrated-qa-owner";
                const initial = await b.cyberFiMemoryRead(owner);
                if (initial.records.length) throw Error("owner not fresh");
                const added = await b.cyberFiMemoryChange(owner, {
                    type: "create",
                    draft: {
                        title: "QA kısa yanıt",
                        content: "Yanıtları kısa ve Türkçe yaz.",
                        scope: { type: "user" },
                        category: "preference",
                    },
                });
                const prepared = await b.cyberFiMemoryPrepare(owner, {
                    chatId: "qa-chat",
                    messageId: "qa-message",
                    text: "Bir üçgenin açılarını açıkla.",
                });
                if (
                    added.records.length !== 1 ||
                    prepared.used.length !== 1 ||
                    !prepared.text.includes("Yanıtları kısa")
                )
                    throw Error("memory payload mismatch");
                const saved = await b.cyberFiMemoryAcknowledge(owner, prepared.receipt);
                if (saved.usages.length !== 1) throw Error("usage receipt not saved");
                const other = await b.cyberFiMemoryRead("integrated-qa-other");
                if (other.records.length) throw Error("owner leakage");
                return {
                    records: added.records.length,
                    used: prepared.used.length,
                    usages: saved.usages.length,
                    isolated: true,
                };
            }),
    );
    await run("memory UI navigation from empty home", async () => {
        const button = page.getByRole("button", { name: "Hafıza", exact: true }).first();
        await button.waitFor({ timeout: 10000 });
        await button.click();
        await page
            .getByRole("switch", { name: /Otomatik hafıza/ })
            .first()
            .waitFor({ timeout: 10000 });
        return await page.getByRole("tab").allTextContents();
    });
    await run("open Siber chat", async () => {
        const button = page.getByRole("button", { name: /Siber.*Çalışma alanı/ }).first();
        await button.waitFor({ timeout: 10000 });
        await button.click();
        return await page.getByRole("tab").allTextContents();
    });
    await writeFile(
        resolve(".context/cyberfi-115-integrated-dom.txt"),
        await page.locator("body").innerText(),
    );
    await run("work center opens and keyboard resize preserves Files", async () => {
        const toggle = page.locator(".happy-desktop-app-shell__panel-toggle").first();
        if (await toggle.count()) {
            if (
                !(await page
                    .locator(".cyberfi-work-center")
                    .isVisible()
                    .catch(() => false))
            )
                await toggle.click();
        } else {
            const buttons = await page.getByRole("button").evaluateAll((els: any) =>
                els.map((e: any) => ({
                    label: e.getAttribute("aria-label"),
                    title: e.getAttribute("title"),
                })),
            );
            report.buttons = buttons;
            throw Error("panel toggle selector unavailable");
        }
        const center = page.locator(".cyberfi-work-center");
        await center.waitFor({ timeout: 10000 });
        const separator = center.getByRole("separator", { name: "Ajan alanını boyutlandır" });
        await separator.focus();
        const before = await separator.getAttribute("aria-valuenow");
        await separator.press("ArrowDown");
        const after = await separator.getAttribute("aria-valuenow");
        assert.notEqual(before, after);
        await center.getByRole("tab", { name: /Dosyalar/ }).click();
        await center.getByPlaceholder("Değişikliklerde ara").waitFor();
        const panelText = await center.innerText();
        assert.ok(panelText.includes("Dosyalar"));
        assert.ok(panelText.includes("Tüm dosyalar"));
        assert.ok(panelText.includes("Değişiklikler"));
        assert.ok(panelText.includes("Değişen dosya yok."));
        assert.ok(panelText.includes("0 dosya"));
        assert.ok(!panelText.includes("No changed files"));
        await center.getByPlaceholder("Değişikliklerde ara").waitFor();
        return { before, after };
    });
    await run("real daemon deterministic prose plus supporting diagram", async () => {
        const api = happyAgentClientCreate(runtime.socketPath, runtime.token);
        const bots = await api.listBots();
        const bot = bots.bots[0];
        if (!bot) throw Error("No isolated bot");
        await api.writeFile(bot.workspaceId, {
            path: "qa-diagram.svg",
            content: Buffer.from(diagram).toString("base64"),
            expectedHash: null,
        });
        for (const item of outputFixtures) await api.writeFile(bot.workspaceId, {
            path: item.name, content: item.bytes.toString("base64"), expectedHash: null,
        });
        report.outputFixtureManifest = fixtureManifest;
        report.syntheticSource = { agentId: bot.agent.id, workspaceId: bot.workspaceId };
        const input = page.getByRole("textbox").first();
        await input.fill("Test: üçgenin açılarını kısa açıkla ve yalnız yardımcı şekli göster.");
        await page.getByRole("button", { name: "Mesaj gönder", exact: true }).click();
        await page
            .getByText("Üçgenin iç açıları toplamı 180 derecedir.", { exact: false })
            .first()
            .waitFor({ timeout: 30000 });
        const imgs = page.locator("img");
        await page.waitForFunction(
            () =>
                Array.from(document.images).some(
                    (i) => i.naturalWidth === 400 && i.naturalHeight === 220,
                ),
            undefined,
            { timeout: 15000 },
        );

        let idle = false;
        for (let attempt = 0; attempt < 100; attempt++) {
            if ((await api.getAgent(bot.agent.id)).agent.status === "idle") {
                idle = true;
                break;
            }
            await page.waitForTimeout(100);
        }
        assert.ok(idle, "native run reaches idle");
        await page.waitForTimeout(250);
        await writeFile(
            resolve(".context/cyberfi-115-integrated-native-history.json"),
            JSON.stringify(await api.getMessages(bot.agent.id, { limit: 100 }), null, 2),
        );
        report.projectionSnapshots = await page.evaluate(() => {
            const element = document.querySelector(
                '[data-happy-desktop-ui="conversation-view"]',
            ) as any;
            if (!element) return [];
            const key = Object.keys(element).find((k) => k.startsWith("__reactFiber"));
            let fiber = element[key!];
            const snapshots: any[] = [];
            for (let n = 0; fiber && n < 35; n++, fiber = fiber.return) {
                const props = fiber.memoizedProps;
                if (props && Array.isArray(props.entries))
                    snapshots.push({
                        component:
                            typeof fiber.type === "function" ? fiber.type.name : String(fiber.type),
                        entries: props.entries.map((e: any) => ({
                            id: e.id,
                            kind: e.kind,
                            resultGroupId: e.resultGroupId,
                            resultGroupSettled: e.resultGroupSettled,
                            status: e.status,
                            copyText: !!e.copyText,
                            sender: e.message?.sender?.kind,
                            generationStatus: e.message?.generationStatus,
                            activityKind: e.activity?.kind,
                            toolStatus: e.activity?.tool?.status,
                            toolFailed: e.activity?.tool?.failed,
                            presentation: e.activity?.tool?.presentation?.type,
                        })),
                    });
            }
            return snapshots;
        });
        const geometry = await page.evaluate(() => {
            const img = Array.from(document.images).find(
                (i) => i.naturalWidth === 400 && i.naturalHeight === 220,
            )!;
            const prose = Array.from(document.querySelectorAll("p")).find((p) =>
                p.textContent?.startsWith("Üçgenin iç açıları toplamı 180 derecedir."),
            )!;
            if (!prose) throw Error("Final prose paragraph missing");
            const p = prose.getBoundingClientRect(),
                i = img.getBoundingClientRect();
            return {
                proseTop: p.y,
                proseBottom: p.bottom,
                imageTop: i.y,
                imageBottom: i.bottom,
                sameConversation:
                    prose.closest('[data-happy-desktop-ui="conversation-view"]') !== null &&
                    prose.closest('[data-happy-desktop-ui="conversation-view"]') ===
                        img.closest('[data-happy-desktop-ui="conversation-view"]'),
            };
        });
        report.proseDiagramGeometry = geometry;
        assert.ok(geometry.sameConversation, "prose and diagram share the same conversation");
        assert.ok(
            geometry.proseBottom <= geometry.imageTop + 1,
            "final normal prose precedes supporting diagram",
        );
        report.proseDiagramGeometry = geometry;
        report.syntheticCalls = syntheticCalls;
        await writeFile(
            resolve(".context/cyberfi-115-integrated-chat-dom.txt"),
            await page.locator("body").innerText(),
        );
        return { text: true, diagram400x220: true, calls: syntheticCalls };
    });
    await run(
        "native final-output clipboard excludes tool logs and respects selection",
        async () => {
            const expected =
                "Üçgenin iç açıları toplamı 180 derecedir. İki açı 50 derece olduğunda üçüncü açı 80 derecedir. Şekil yalnızca açıklamayı destekler.";
            const button = page.locator('[data-happy-desktop-ui="turn-summary-copy"]').last();
            await button.click();
            await page.waitForTimeout(150);
            assert.equal(
                await app.evaluate(({ clipboard }: any) => clipboard.readText()),
                expected,
            );
            const selected = await page.evaluate(() => {
                const paragraph = Array.from(document.querySelectorAll("p")).find((p) =>
                    p.textContent?.startsWith("Üçgenin iç açıları toplamı"),
                )!;
                const range = document.createRange();
                range.setStart(paragraph.firstChild!, 0);
                range.setEnd(paragraph.firstChild!, 7);
                const selection = window.getSelection()!;
                selection.removeAllRanges();
                selection.addRange(range);
                return selection.toString();
            });
            await button.click();
            await page.waitForTimeout(150);
            assert.equal(
                await app.evaluate(({ clipboard }: any) => clipboard.readText()),
                selected,
            );
            await page.evaluate(() => window.getSelection()?.removeAllRanges());
            return { nativeClipboardReadback: true, finalOnly: true, selectedOnly: true };
        },
    );
    const footer = page.locator(".happy-sidebar-footer[data-control-labels]");
    for (const theme of [
        { name: "Açık", key: "light" },
        { name: "Koyu", key: "dark" },
    ])
        await run("capture " + theme.key, async () => {
            await footer.getByRole("button", { name: "Tema", exact: true }).click();
            await page.getByRole("menuitem", { name: theme.name, exact: true }).click();
            await page.waitForTimeout(350);
            await gymElectronInvisibleAssert(app);
            const png = await app.evaluate(async ({ BrowserWindow }: any) =>
                (
                    await BrowserWindow.getAllWindows()[0].webContents.capturePage(undefined, {
                        stayHidden: true,
                    })
                )
                    .toPNG()
                    .toString("base64"),
            );
            await writeFile(
                resolve(`.context/cyberfi-115-integrated-${theme.key}.png`),
                Buffer.from(png, "base64"),
            );
            return true;
        });
    await run("presented diagram reaches shared Outputs via app subscription", async () => {
        await page.getByRole("button", { name: "Çıktılar", exact: true }).first().click();
        await page.getByRole("searchbox", { name: "Çıktılarda ara" }).fill("qa-diagram");
        await page.getByText("qa-diagram.svg", { exact: true }).first().waitFor({ timeout: 20000 });
        const text = await page
            .locator('[data-happy-desktop-ui="happy-agent-artifacts"]')
            .innerText();
        assert.ok(
            !/Any bot|Any task|Any project root|Any workspace|Any other conversation|Chief of Staff/.test(
                text,
            ),
            "Outputs source labels are Turkish",
        );
        return { nativePresentedOutputVisible: true, sourceLabelsTurkish: true };
    });
    await run("all presented files have shared registry records without refresh", async () => {
        const api = happyAgentClientCreate(runtime.socketPath, runtime.token);
        let records: any[] = [];
        for (let attempt = 0; attempt < 100; attempt++) {
            const registry = (await api.getArtifact("ocyberfioutputsregistry01")).artifact;
            const file = await api.getArtifactFile(registry.id, registry.latestVersion, "index.md");
            assert.ok(file);
            records = JSON.parse(new TextDecoder().decode(file.data)).outputs;
            if (presentedPaths.every(name => records.some(item => item.name === name))) break;
            await page.waitForTimeout(200);
        }
        report.sharedOutputRecords = [];
        for (const name of presentedPaths) {
            const record = records.find((item: any) => item.name === name);
            assert.ok(record, `Missing shared output record: ${name}`);
            assert.match(record.artifactId, /^[a-z0-9]+$/);
            const actual = (await api.getArtifact(record.artifactId)).artifact;
            assert.equal(actual.id, record.artifactId);
            const expectedHash = name === "qa-diagram.svg"
                ? createHash("sha256").update(diagram).digest("hex")
                : outputFixtures.find((item: any) => item.name === name).sha256;
            assert.equal(record.sha256, expectedHash);
            const version = (await api.getArtifactVersion(actual.id, actual.latestVersion)).version;
            assert.ok(version.files.some((file: any) => file.sha256 === expectedHash), "Stored output version retains exact fixture bytes");
            report.sharedOutputRecords.push({ name, artifactId: actual.id, sha256: record.sha256 });
            await page.getByRole("searchbox", { name: "Çıktılarda ara" }).fill(name);
            await page.getByText(name, { exact: true }).first().waitFor({ timeout: 20000 });
        }
        return { records: report.sharedOutputRecords, noRefresh: true };
    });
    await run("PNG and PDF open while Office offers honest file download", async () => {
        const open = async (name: string) => {
            await page.getByRole("searchbox", { name: "Çıktılarda ara" }).fill(name);
            await page.locator('[data-happy-desktop-ui="happy-agent-artifact-row"]').filter({ hasText: name }).first().click();
        };
        const captureOutput = async (name: string) => {
            await gymElectronInvisibleAssert(app);
            const png = await app.evaluate(async ({ BrowserWindow }: any) =>
                (await BrowserWindow.getAllWindows()[0].webContents.capturePage(undefined, { stayHidden: true })).toPNG().toString("base64"));
            await writeFile(resolve(`.context/cyberfi-115-integrated-output-${name}.png`), Buffer.from(png, "base64"));
        };
        await open("qa-support.png");
        await page.waitForFunction(() => Array.from(document.images).some(image => image.naturalWidth === 400 && image.naturalHeight === 220 && image.closest('[data-happy-desktop-ui="happy-agent-artifact-viewer"]')));
        await open("qa-support.pdf");
        const pdf = page.locator('iframe[data-happy-desktop-ui="happy-agent-artifact-document"]').first();
        await pdf.waitFor();
        const pdfEvidence = await pdf.evaluate(async (frame: HTMLIFrameElement) => {
            const url = frame.src;
            const response = await fetch(url);
            const bytes = new Uint8Array(await response.arrayBuffer());
            const loaded = await new Promise<boolean>(resolve => {
                const timer = setTimeout(() => resolve(false), 15000);
                frame.addEventListener("load", () => { clearTimeout(timer); resolve(true); }, { once: true });
                frame.src = url;
            });
            return { loaded, status: response.status, signature: new TextDecoder().decode(bytes.slice(0, 5)), bytes: bytes.length };
        });
        assert.equal(pdfEvidence.loaded, true, "Native PDF frame emits load");
        assert.equal(pdfEvidence.status, 200);
        assert.equal(pdfEvidence.signature, "%PDF-");
        assert.equal(pdfEvidence.bytes, outputFixtures.find((item: any) => item.name === "qa-support.pdf").size);
        await captureOutput("pdf");
        await open("qa-support.docx");
        await page.getByRole("button", { name: "İndir", exact: true }).first().waitFor();
        await captureOutput("docx");
        report.outputPreviewEvidence = { png400x220: true, pdf: { ...pdfEvidence, readablePageVisuallyVerified: false, screenshot: "cyberfi-115-integrated-output-pdf.png" }, officeDownloadOffered: true, officeEditingTested: false, officeScreenshot: "cyberfi-115-integrated-output-docx.png" };
        return report.outputPreviewEvidence;
    });
    report.limits = ["Model response is deterministic test provider; no live vendor/model called."];
} catch (e) {
    report.fatal = String(e);
} finally {
    if (app) {
        const page = await app.firstWindow().catch(() => undefined);
        if (page) report.finalText = (await page.locator("body").innerText()).slice(0, 6000);
    }
    if (video) await video.stop().catch((e: any) => report.errors.push(String(e)));
    if (app && clipboardBefore)
        await app
            .evaluate(async ({ clipboard }: any) => {
                const items = (globalThis as any).__cyberfiQaClipboard;
                if (items.length > 0) await clipboard.write(items);
                else clipboard.clear();
                delete (globalThis as any).__cyberfiQaClipboard;
            })
            .catch((error: any) =>
                report.errors.push("Clipboard restoration failed: " + String(error)),
            );
    if (app) await app.close().catch(() => {});
    if (runtime) await runtime.stop().catch(() => {});
    await gymRunClean(paths.root);
    synthetic.close();
    server.close();
    await writeFile(
        resolve(".context/cyberfi-115-integrated-qa-report.json"),
        JSON.stringify(report, null, 2),
    );
    console.log(JSON.stringify(report, null, 2));
}
