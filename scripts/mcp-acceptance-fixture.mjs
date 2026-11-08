import assert from "node:assert/strict";
import { lstat, mkdir, readFile, readdir, realpath, writeFile } from "node:fs/promises";
import { join, resolve, sep } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

/** Supply the normal startup caller's empty directory after the fresh-HOME guard. */
export async function withMcpCallerPrecondition(root, child) {
    let settled = false;
    // Observe rejection immediately while polling, then propagate it from await child.
    void child.then(() => { settled = true; }, () => { settled = true; });
    const runtime = join(root, "home/.pdr-kocum-agent/mcp-runtime");
    const directory = join(root, "home/.pdr-kocum-agent",
        process.platform === "darwin" ? "Happy/Config" : "happy/config");
    assert(resolve(directory).startsWith(resolve(root) + sep));
    let declared = false, fixtureError;
    const deadline = Date.now() + 60_000;
    while (!settled && Date.now() < deadline) {
        try {
            const lock = join(runtime, ".setup.lock");
            assert((await lstat(lock)).isFile() && await realpath(runtime) === runtime);
            const owner = await readFile(lock, "utf8");
            if (owner === "") { await delay(100); continue; }
            assert(/^[1-9][0-9]*$/u.test(owner));
            const parent = join(root, "home/.pdr-kocum-agent");
            assert(await realpath(parent) === parent);
            await mkdir(directory, { recursive: true, mode: 0o700 });
            assert(await realpath(directory) === directory && (await lstat(directory)).isDirectory());
            assert.deepEqual(await readdir(directory), []);
            const declaration = { purpose: "Normal production caller precondition", directory,
                afterFreshHomeGuard: true, observedOwnedBootstrapLock: true,
                createdOnlyEmptyDirectory: true, registrationsOrResultsWritten: false };
            await writeFile(join(root, "normal-caller-precondition.json"), JSON.stringify(declaration, null, 2) + "\n", { flag: "wx" });
            console.log(JSON.stringify(declaration));
            declared = true;
            break;
        } catch (error) {
            if (error.code !== "ENOENT") { fixtureError = error; break; }
        }
        await delay(100);
    }
    // Always settle the bounded gym child, including when preparation or polling failed.
    // Its packaged helper aborts and cleans up its own MCP children on completion.
    const result = await child;
    if (fixtureError) throw fixtureError;
    assert(declared, "Owned bootstrap lock was not observed during the bounded fixture poll.");
    return result;
}
