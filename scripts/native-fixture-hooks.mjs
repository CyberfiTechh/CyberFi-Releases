import assert from "node:assert/strict";
import { setTimeout as delay } from "node:timers/promises";
import { attachUpdateFixture } from "./update-fixture.mjs";

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

export async function beginDraftFixture({ page, pid, executable, profile, root, rendererPort, owner, pin }) {
    // Only the authenticated, hidden source renderer can open its main-process inspector.
    let stage = "inspector-bridge";
    try {
        const main = await page.evaluate(async () => {
            return (await window.happyDesktop.debugMainInspectorStart()).main;
        });
        assert(main?.status === "running" && typeof main.url === "string", "Owned main inspector did not start");
        stage = "inspector-loopback";
        const endpoint = new URL(main.url);
        const port = Number(endpoint.port);
        assert(endpoint.protocol === "ws:" && endpoint.hostname === "127.0.0.1" && port > 0 && port !== rendererPort &&
            !endpoint.username && !endpoint.password && !endpoint.search && !endpoint.hash &&
            /^\/[a-f0-9-]{36}$/u.test(endpoint.pathname), "Unexpected main inspector address");
        // The loopback endpoint comes from the authenticated source. The fixture checks the exact PID before mutation.
        stage = "fixture-inputs";
        return await attachUpdateFixture({
            pid, executable, profile, assetsRoot: root, inspectorUrl: endpoint.href, owner,
            ref: process.env.ACCEPTANCE_FIXTURE_REF, packageSha256: pin.sha256, manifestSha256: pin.manifestSha256,
        });
    } catch (error) {
        await page.evaluate(() => window.happyDesktop.debugMainInspectorStop()).catch(() => undefined);
        if (error instanceof Error && !error.fixtureCode) error.fixtureCode = stage;
        throw error;
    }
}

export async function exerciseDraftRefusals({ fixture, page, check, select, button, verifySource }) {
    const version = "0.0.132";
    const offer = async () => {
        const initial = (await fixture.report()).hits;
        await check.click();
        const deadline = Date.now() + 15000;
        let observed;
        do {
            observed = (await fixture.report()).hits;
            if (observed.feed + observed.fallback > initial.feed + initial.fallback) break;
            await delay(100);
        } while (Date.now() < deadline);
        assert(observed.feed + observed.fallback > initial.feed + initial.fallback, "The update check must make a new feed request");
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
        let step = "offer";
        try {
            await fixture.setMode(mode);
            await offer();
            await button.click();
            step = "ui-refusal";
            await page.waitForFunction(async expected => {
                const update = (await window.happyDesktop.runtimeGet()).update;
                return update?.status === "error" && update.message === expected;
            }, message, { timeout: 60000 });
            step = "source-preserved";
            await verifySource();
            step = "transport-counts";
            const evidence = await fixture.report();
            assert.equal(evidence.hits.package, expectedPackages, "Wrong failure boundary");
            assert.equal(evidence.hits.manifest, proof.length + 1);
            proof.push({ ...evidence, sourceUnchanged: true, error: message });
        } catch (error) {
            if (error instanceof Error) {
                const observed = await fixture.report().catch(() => null);
                error.draftRefusal = { mode, step, hits: Object.fromEntries(
                    ["feed", "fallback", "manifest", "package"].map(key => {
                        const value = observed?.hits?.[key];
                        return [key, Number.isSafeInteger(value) && value >= 0 && value <= 1000 ? value : null];
                    }),
                ) };
            }
            throw error;
        }
    }
    await fixture.setMode("exact");
    await offer();
    return { feed: "owned exact draft fixture", publicFeedVerified: false, negativeCases: proof,
        positiveTransport: await fixture.report() };
}
