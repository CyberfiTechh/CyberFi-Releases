import assert from "node:assert/strict";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { homedir } from "node:os";
import { pathToFileURL } from "node:url";
import { withMcpCallerPrecondition } from "./mcp-acceptance-fixture.mjs";

const [upstream, executable] = process.argv.slice(2);
assert(process.platform === "darwin" && upstream && executable);
const root = join(homedir(), `CyberFi-mcp-${process.env.GITHUB_RUN_ID}-${process.env.GITHUB_RUN_ATTEMPT}`);
await mkdir(root); // Never overwrite another acceptance run.
const home = join(root, "home"), userData = join(root, "user-data");
await Promise.all([mkdir(home), mkdir(userData)]);
await writeFile(join(root, "owned-acceptance.json"), JSON.stringify({
    purpose: "CyberFi isolated MCP acceptance", home, userData,
}));
const report = join(root, "mcp-acceptance.json");
const env = Object.fromEntries(Object.entries(process.env).filter(([key]) =>
    !/TOKEN|SECRET|PASSWORD|CREDENTIAL|API_KEY|CODEX|OPENAI|ANTHROPIC|HAPPY_AGENT|NODE_OPTIONS|ELECTRON_RUN_AS_NODE/iu.test(key)));
Object.assign(env, { HOME: home, USERPROFILE: home,
    CYBERFI_MCP_ACCEPTANCE: "1", CYBERFI_MCP_ACCEPTANCE_ROOT: root,
    CYBERFI_MCP_ACCEPTANCE_REPORT: report });
const { gymElectronProcessRun } = await import(pathToFileURL(join(resolve(upstream),
    "packages/happy-desktop-gym/sources/electron/launch.ts")).href);
console.log("Fresh isolated MCP runtime:", root);
const progress = setInterval(async () => {
    try {
        const setup = JSON.parse(await readFile(join(home, ".pdr-kocum-agent/mcp-runtime/setup-report.json"), "utf8"));
        const calls = await readFile(report, "utf8").then(JSON.parse).catch(() => ({ calls: [] }));
        console.log(JSON.stringify({ stage: "production-MCP", servers: setup.servers.map(({ name, state }) => ({ name, state })),
            completedCalls: calls.calls.map(({ name }) => name) }));
    } catch { /* Preparation has not created its report yet. */ }
}, 30_000);
let exit;
try {
    exit = await withMcpCallerPrecondition(root, gymElectronProcessRun({ executablePath: resolve(executable),
        args: ["--user-data-dir=" + userData], env, timeout: 40 * 60_000 }));
} finally { clearInterval(progress); }
assert.equal(exit.exitCode, 0, exit.output);
const result = JSON.parse(await readFile(report, "utf8"));
assert(result.success && result.platform === "darwin" && result.arch === process.arch);
assert.equal(result.bootstrap.servers.length, 9);
assert(result.bootstrap.servers.every(server => server.state === "ready"));
assert.equal(result.calls.length, 9);
assert.equal(new Set(result.calls.map(call => call.name)).size, 9);
assert(result.calls.every(call => call.toolCount > 0 && call.result && !call.result.isError));
console.log(JSON.stringify({ success: true, arch: result.arch, realCalls: result.calls.map(({ name, tool, toolCount }) => ({ name, tool, toolCount })) }));
