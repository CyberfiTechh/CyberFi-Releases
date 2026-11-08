import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";

const run = (command, args) => execFileSync(command, args, {
    encoding: "utf8", timeout: 120_000, stdio: ["ignore", "pipe", "pipe"],
});
async function digest(path) {
    const hash = createHash("sha256");
    for await (const bytes of createReadStream(path)) hash.update(bytes);
    return hash.digest("hex");
}
async function snapshot(app) {
    const resources = join(app, "Contents/Resources");
    const framework = await readFile(join(app, "Contents/Frameworks/Electron Framework.framework/Electron Framework"));
    // Read-only Electron fuse-wire format from @electron/fuses: sentinel,
    // version byte, length byte, then states. Never flip or remove a fuse.
    const sentinel = Buffer.from("dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX");
    const wires = [];
    for (let index = framework.indexOf(sentinel); index !== -1; index = framework.indexOf(sentinel, index + sentinel.length)) {
        const position = index + sentinel.length;
        const length = framework[position + 1];
        assert(framework[position] === 1 && length >= 8 && length <= 64);
        wires.push(framework.subarray(position, position + 2 + length).toString("hex"));
    }
    assert(wires.length > 0 && wires.length <= 2);
    return { asarSHA256: await digest(join(resources, "app.asar")),
        mcpSourcesSHA256: await digest(join(resources, "pdr-mcp/sources.zip")), fuseWires: wires };
}

/** A declared CI-only accessory container; the published bundle is never modified. */
export async function prepareMcpAccessoryContainer(executable, root) {
    assert.equal(process.platform, "darwin");
    const original = resolve(dirname(executable), "../..");
    assert(original.endsWith(".app"));
    const before = await snapshot(original);
    let originalSignature = "verified";
    try { run("/usr/bin/codesign", ["--verify", "--deep", "--strict", original]); }
    catch (error) {
        const message = String(error.stderr);
        assert(process.arch === "x64" && message.includes("not signed at all"), message);
        originalSignature = "unsigned Intel bundle; exact published DMG SHA verified by workflow";
    }
    const parent = join(root, "test-container");
    const copy = join(parent, "CyberFi.app");
    await mkdir(parent); // Never replace a prior test container.
    run("/usr/bin/ditto", [original, copy]);
    assert.deepEqual(await snapshot(copy), before);
    const plist = join(copy, "Contents/Info.plist");
    try { run("/usr/libexec/PlistBuddy", ["-c", "Set :LSUIElement true", plist]); }
    catch { run("/usr/libexec/PlistBuddy", ["-c", "Add :LSUIElement bool true", plist]); }
    assert.equal(run("/usr/libexec/PlistBuddy", ["-c", "Print :LSUIElement", plist]).trim(), "true");
    run("/usr/bin/codesign", ["--force", "--deep", "--sign", "-",
        "--preserve-metadata=entitlements,requirements,flags,runtime", "--timestamp=none", copy]);
    run("/usr/bin/codesign", ["--verify", "--deep", "--strict", copy]);
    const after = await snapshot(copy);
    assert.deepEqual(after, before);
    const proof = { mode: "derived CI accessory test container", originalSignature,
        originalAssetSHA256: process.env.EXPECTED_SHA, exactOriginalBundleExecutedByMcpTest: false,
        codeAndMcpResourcesUnchanged: true, fusesUnchanged: true,
        activationMetadata: "LSUIElement=true", copySignature: "legitimate ad-hoc signature",
        hiddenWindowAndDockGuardsUnchanged: true, original: before, derived: after };
    await writeFile(join(root, "derived-container.json"), JSON.stringify(proof, null, 2) + "\n", { flag: "wx" });
    console.log(JSON.stringify(proof));
    return join(copy, "Contents/MacOS/CyberFi");
}
