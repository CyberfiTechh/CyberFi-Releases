import assert from "node:assert/strict";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { homedir } from "node:os";
import { pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";
import { withMcpCallerPrecondition } from "./mcp-acceptance-fixture.mjs";
import { prepareMcpAccessoryContainer } from "./macos-mcp-container.mjs";

const [upstream, executable] = process.argv.slice(2);
assert(process.platform === "darwin" && upstream && executable);
const root = join(homedir(), `CyberFi-mcp-${process.env.GITHUB_RUN_ID}-${process.env.GITHUB_RUN_ATTEMPT}`);
await mkdir(root); // Never overwrite another acceptance run.
const home = join(root, "home"), userData = join(root, "user-data");
await Promise.all([mkdir(home), mkdir(userData)]);
const toolchain = join(root, "absent-toolchain");
await mkdir(toolchain);
await Promise.all([mkdir(join(toolchain, "cargo")), mkdir(join(toolchain, "rustup"))]);
await writeFile(join(root, "owned-acceptance.json"), JSON.stringify({
    purpose: "CyberFi isolated MCP acceptance", home, userData,
}));
const report = join(root, "mcp-acceptance.json");
const env = Object.fromEntries(Object.entries(process.env).filter(([key]) =>
    !/TOKEN|SECRET|PASSWORD|CREDENTIAL|API_KEY|CODEX|OPENAI|ANTHROPIC|HAPPY_AGENT|NODE_OPTIONS|ELECTRON_RUN_AS_NODE/iu.test(key)));
Object.assign(env, { HOME: home, USERPROFILE: home,
    PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
    CARGO_HOME: join(toolchain, "cargo"), RUSTUP_HOME: join(toolchain, "rustup"),
    CYBERFI_MCP_ACCEPTANCE: "1", CYBERFI_MCP_ACCEPTANCE_ROOT: root,
    CYBERFI_MCP_ACCEPTANCE_REPORT: report });
const availability = ["rustc", "cargo"].map(command => {
    const probe = spawnSync("/usr/bin/which", [command], { env, encoding: "utf8", timeout: 5000 });
    assert(!probe.error && probe.status === 1 && probe.stdout.trim() === "",
        `Hosted ${command} must be absent from the isolated child environment.`);
    return { command, status: probe.status, available: false };
});
const childEnvironmentProof = { perProcessOnly: true, PATH: env.PATH,
    CARGO_HOME: env.CARGO_HOME, RUSTUP_HOME: env.RUSTUP_HOME,
    hostedRustToolsExcluded: true, probes: availability };
console.log(JSON.stringify({ stage: "isolated-toolchain-check", ...childEnvironmentProof }));
const { gymElectronProcessRun } = await import(pathToFileURL(join(resolve(upstream),
    "packages/happy-desktop-gym/sources/electron/launch.ts")).href);
const target = process.env.DERIVED_ACCESSORY_CONTAINER === "true"
    ? await prepareMcpAccessoryContainer(executable, root) : resolve(executable);
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
    exit = await withMcpCallerPrecondition(root, gymElectronProcessRun({ executablePath: target,
        args: ["--user-data-dir=" + userData], env, timeout: 40 * 60_000 }));
} finally {
    clearInterval(progress);
    // Supplement only the public fixture's report; leave production MCP results unchanged.
    const fixture = join(root, "normal-caller-precondition.json");
    const precondition = await readFile(fixture, "utf8").then(JSON.parse).catch(error => {
        if (error.code === "ENOENT") return undefined;
        throw error;
    });
    if (precondition) await writeFile(fixture, JSON.stringify({ ...precondition, childEnvironmentProof }, null, 2) + "\n");
}
assert.equal(exit.exitCode, 0, exit.output);
const result = JSON.parse(await readFile(report, "utf8"));
assert(result.success && result.platform === "darwin" && result.arch === process.arch);
assert.equal(result.bootstrap.servers.length, 9);
assert(result.bootstrap.servers.every(server => server.state === "ready"));
assert.equal(result.calls.length, 9);
assert.equal(new Set(result.calls.map(call => call.name)).size, 9);
assert(result.calls.every(call => call.toolCount > 0 && call.result && !call.result.isError));
console.log(JSON.stringify({ success: true, arch: result.arch, realCalls: result.calls.map(({ name, tool, toolCount }) => ({ name, tool, toolCount })) }));
