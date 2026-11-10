import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { promisify } from "node:util";
import { attachUpdateFixture } from "./update-fixture.mjs";

const exec = promisify(execFile);
const repo = "CyberfiTechh/CyberFi-Releases";
const sourcePins = {
    windows: { releaseId: 439264052, assetId: 727864145,
        sha256: "b091452750eed8702c45e21c3d97df9e4e3f02a38db0a372104cdef2a0c79374",
        manifestAssetId: 727881614, manifestSha256: "3d0a47f49e500b90ac1c1709d95fc21f130ebd08a9fa8494a0b68762cbc5b1ab" },
    x64: { releaseId: 439509221, assetId: 728583328,
        sha256: "6fcb73e87fb2e194320b307e3090942a4d561eb0c04991d0cf5aa6f12bb6cd3d",
        manifestAssetId: 728593299, manifestSha256: "806b73eaf68273a1ff1d4d289bc3f1e2e94a5d38a2d28dca424c95e4e7fbcb02" },
    arm64: { releaseId: 439509221, assetId: 728593458,
        sha256: "7de37a5efe2493b68aa16dc9bb1c570062618e017957dbfbd2a3ba75788558cf",
        manifestAssetId: 728603520, manifestSha256: "cb139dd6bef39f52e076a45a3dfa75bcaaf214bf0b09152df409c515894f592c" },
};

export function reviewedDraftPins(platform) {
    assert(Object.hasOwn(sourcePins, platform), "Unexpected native target");
    const ref = process.env.ACCEPTANCE_FIXTURE_REF, sourceCommit = process.env.ACCEPTANCE_SOURCE_SHA;
    assert(process.env.GITHUB_ACTIONS === "true" && process.env.RUNNER_ENVIRONMENT === "github-hosted" &&
        process.env.GITHUB_REPOSITORY === repo && process.env.GITHUB_REF === ref &&
        /^refs\/heads\/codex\/[a-z0-9-]*132[a-z0-9-]*$/u.test(ref), "Unexpected hosted fixture branch");
    assert(/^[a-f0-9]{40}$/u.test(sourceCommit), "A reviewed final desktop SHA is required");
    const target = JSON.parse(process.env.ACCEPTANCE_ARTIFACTS);
    assert(target.releaseId !== sourcePins[platform].releaseId, "The draft must differ from public 131");
    return { source: sourcePins[platform], target };
}

export function assertDraftRelease(release, kind, pin, tag, sourceCommit) {
    assert(release.id === pin.releaseId && release.tag_name === tag, "Release identity differs from pins");
    if (kind === "source") {
        assert(release.draft === false && release.prerelease === false, "Source must be public stable 131");
    } else {
        assert(kind === "target" && release.draft === true && release.prerelease === true, "Target must remain private draft 132");
        assert(release.body.includes("https://github.com/CyberfiTechh/CyberFi/commit/" + sourceCommit),
            "Draft notes do not bind the reviewed desktop SHA");
    }
}

async function ownedInspectorUrl(pid, rendererPort) {
    assert(Number.isSafeInteger(pid) && pid > 0 && Number.isSafeInteger(rendererPort) && rendererPort > 0 && rendererPort < 65536);
    const cmd = process.platform === "win32" ?
        join(process.env.SystemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe") : "/usr/sbin/lsof";
    const args = process.platform === "win32" ? ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
        "Get-NetTCPConnection -OwningProcess " + pid + " -State Listen -LocalAddress '127.0.0.1' | Select-Object -ExpandProperty LocalPort"] :
        ["-nP", "-a", "-p", String(pid), "-iTCP@127.0.0.1", "-sTCP:LISTEN", "-Fn"];
    for (let attempt = 0; attempt < 5; attempt++) {
        const { stdout } = await exec(cmd, args, { windowsHide: true, timeout: 10000, maxBuffer: 8192 })
            .catch(error => error.code === 1 ? { stdout: "" } : Promise.reject(error));
        const ports = [...new Set(stdout.split(/\r?\n/u).flatMap(line => {
            const match = /^(?:n127[.]0[.]0[.]1:)?([1-9][0-9]{0,4})$/u.exec(line.trim());
            return match ? [Number(match[1])] : [];
        }))].filter(port => port !== rendererPort && port < 65536);
        const nodes = [];
        for (const port of ports) {
            const data = await fetch("http://127.0.0.1:" + port + "/json/list", {
                redirect: "error", signal: AbortSignal.timeout(750),
            }).then(response => response.ok ? response.json() : null).catch(() => null);
            for (const node of Array.isArray(data) ? data : []) {
                if (node.type === "node" && typeof node.webSocketDebuggerUrl === "string" &&
                    node.webSocketDebuggerUrl.startsWith("ws://127.0.0.1:" + port + "/"))
                    nodes.push(node.webSocketDebuggerUrl);
            }
        }
        if (nodes.length === 1) return nodes[0];
        assert(nodes.length === 0, "Several inspectors belong to the source PID");
        await delay(200);
    }
    throw new Error("Owned source Node inspector was unavailable");
}

export async function beginDraftFixture({ pid, executable, profile, root, rendererPort, owner, pin }) {
    return attachUpdateFixture({
        pid, executable, profile, assetsRoot: root, inspectorUrl: await ownedInspectorUrl(pid, rendererPort), owner,
        ref: process.env.ACCEPTANCE_FIXTURE_REF, packageSha256: pin.sha256, manifestSha256: pin.manifestSha256,
    });
}

export async function exerciseDraftRefusals({ fixture, page, check, select, button, verifySource }) {
    const version = "0.0.132";
    const offer = async () => {
        await check.click();
        await page.waitForFunction(async target => {
            const update = (await window.happyDesktop.runtimeGet()).update;
            return update?.status === "available" && update.availableVersion === target;
        }, version, { timeout: 30000 });
        await select.selectOption(version);
        await button.waitFor({ state: "visible", timeout: 15000 });
    };
    const proof = [];
    for (const [mode, message, expectedPackages] of [
        ["bad-signature", "CyberFi güncelleme imzası doğrulanamadı.", 0],
        ["bad-body", "İndirilen paket imzalı dosya özetiyle eşleşmedi.", 1],
    ]) {
        await fixture.setMode(mode);
        await offer();
        await button.click();
        await page.waitForFunction(async expected => {
            const update = (await window.happyDesktop.runtimeGet()).update;
            return update?.status === "error" && update.message === expected;
        }, message, { timeout: 60000 });
        await verifySource();
        const evidence = await fixture.report();
        assert.equal(evidence.hits.package, expectedPackages, "Wrong failure boundary");
        assert.equal(evidence.hits.manifest, proof.length + 1);
        proof.push({ ...evidence, sourceUnchanged: true, error: message });
    }
    await fixture.setMode("exact");
    await offer();
    return { feed: "owned exact draft fixture", publicFeedVerified: false, negativeCases: proof,
        positiveTransport: await fixture.report() };
}
