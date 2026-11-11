import assert from "node:assert/strict";
import { setTimeout as delay } from "node:timers/promises";
import { attachUpdateFixture } from "./update-fixture.mjs";

const repo = "CyberfiTechh/CyberFi-Releases";
const sourcePins = {
    "windows": {
        "releaseId": 440614314,
        "assetId": 732120783,
        "sha256": "7c07a95d528ea8d1354333439a1e95c61b37e037af85bee5fa846cfb080e4924",
        "manifestAssetId": 732139702,
        "manifestSha256": "f580bcf517a3b14eb84acef2806333b862424a9e56618558294f026f041cf365"
    },
    "x64": {
        "releaseId": 440615056,
        "assetId": 732122918,
        "sha256": "1e61db905aed107915113befb95a031fc2b1052eb99c682747a1fa7a439d3e03",
        "manifestAssetId": 732144559,
        "manifestSha256": "9cf1f907d9c4070c6b88c10f7871702b177ac3ba5fbe72b9d4734ad176d04bfa"
    },
    "arm64": {
        "releaseId": 440615056,
        "assetId": 732144865,
        "sha256": "f66112fbbbdf628c211c26e2d57e2d59916bc788574e43c791d03bf572300f32",
        "manifestAssetId": 732164870,
        "manifestSha256": "92821c9034cfd7ae2fa9de4289e9c7c233ab5fa70e1a508fa105f8f85b6543d4"
    }
};

export function reviewedDraftPins(platform) {
    assert(Object.hasOwn(sourcePins, platform), "Unexpected native target");
    const ref = process.env.ACCEPTANCE_FIXTURE_REF, sourceCommit = process.env.ACCEPTANCE_SOURCE_SHA;
    assert(process.env.GITHUB_ACTIONS === "true" && process.env.RUNNER_ENVIRONMENT === "github-hosted" &&
        process.env.GITHUB_REPOSITORY === repo && process.env.GITHUB_REF === ref &&
        /^refs\/heads\/main$/u.test(ref), "Unexpected hosted fixture branch");
    assert(/^[a-f0-9]{40}$/u.test(sourceCommit), "A reviewed final desktop SHA is required");
    const target = JSON.parse(process.env.ACCEPTANCE_ARTIFACTS);
    assert(target.releaseId !== sourcePins[platform].releaseId, "The draft must differ from public 132");
    return { source: sourcePins[platform], target };
}

export function assertDraftRelease(release, kind, pin, tag, sourceCommit) {
    assert(release.id === pin.releaseId && release.tag_name === tag, "Release identity differs from pins");
    if (kind === "source") {
        assert(release.draft === false && release.prerelease === false, "Source must be public stable 132");
    } else {
        assert(kind === "target" && release.draft === true && release.prerelease === true, "Target must remain private draft 133");
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

export async function offerDraftUpdate({ fixture, page, check, select, button }) {
    const version = "0.0.133";
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
}

export async function exerciseDraftRefusals({ fixture, page, check, select, button, verifySource }) {
    const proof = [];
    for (const [mode, message, expectedPackages] of [
        ["bad-signature", "CyberFi güncelleme imzası doğrulanamadı.", 0],
        ["bad-body", "İndirilen paket imzalı dosya özetiyle eşleşmedi.", 1],
    ]) {
        let step = "offer";
        try {
            await fixture.setMode(mode);
            await offerDraftUpdate({ fixture, page, check, select, button });
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
    await offerDraftUpdate({ fixture, page, check, select, button });
    return { feed: "owned exact draft fixture", publicFeedVerified: false, negativeCases: proof,
        positiveTransport: await fixture.report() };
}
