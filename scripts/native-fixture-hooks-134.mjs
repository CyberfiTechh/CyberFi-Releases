import assert from "node:assert/strict";
import { setTimeout as delay } from "node:timers/promises";
import { attachUpdateFixture } from "./update-fixture-134.mjs";

const repo = "CyberfiTechh/CyberFi-Releases";
const reviewedSourceCommit = "99c5bcdf9b7ae19cb4b19aae46f7eec69281ea66";
const sourcePins = {
    "windows": {
        "releaseId": 442136549,
        "assetId": 736736800,
        "sha256": "50dbc9c3bff90641a498771e3388c8af97e9d12f958ab03f47b59f9212817ae3",
        "manifestAssetId": 736745424,
        "manifestSha256": "9e36860b2393f7fca14498bd6ee9280ca67caf6abce14e69313718c323bd3488"
    }
};

export function reviewedDraftPins(platform) {
    assert(Object.hasOwn(sourcePins, platform), "Unexpected native target");
    const ref = process.env.ACCEPTANCE_FIXTURE_REF, sourceCommit = process.env.ACCEPTANCE_SOURCE_SHA;
    assert(process.env.GITHUB_ACTIONS === "true" && process.env.RUNNER_ENVIRONMENT === "github-hosted" &&
        process.env.GITHUB_REPOSITORY === repo && process.env.GITHUB_REF === ref &&
        /^refs\/heads\/main$/u.test(ref), "Unexpected hosted fixture branch");
    assert.equal(sourceCommit, reviewedSourceCommit, "The reviewed 134 desktop SHA is required");
    const target = JSON.parse(process.env.ACCEPTANCE_ARTIFACTS);
    assert(target && typeof target === "object" && !Array.isArray(target) &&
        Object.keys(target).sort().join(",") === "appAsarSha256,assetId,manifestAssetId,manifestSha256,releaseId,sha256", "Exact target pin fields are required");
    assert([target.releaseId, target.assetId, target.manifestAssetId].every(value => Number.isSafeInteger(value) && value > 0), "Positive target asset identities are required");
    assert([target.sha256, target.manifestSha256, target.appAsarSha256].every(value => typeof value === "string" && /^[a-f0-9]{64}$/u.test(value)), "Exact target SHA-256 pins are required");
    assert(target.releaseId !== sourcePins[platform].releaseId && target.assetId !== target.manifestAssetId &&
        ![target.assetId, target.manifestAssetId].some(value => [sourcePins[platform].assetId, sourcePins[platform].manifestAssetId].includes(value)) &&
        target.sha256 !== sourcePins[platform].sha256 && target.manifestSha256 !== sourcePins[platform].manifestSha256,
        "The draft must differ from public 133");
    return { source: sourcePins[platform], target };
}

export function assertDraftRelease(release, kind, pin, tag, sourceCommit) {
    assert(release.id === pin.releaseId && release.tag_name === tag, "Release identity differs from pins");
    if (kind === "source") {
        assert(release.draft === false && release.prerelease === false, "Source must be public stable 133");
    } else {
        assert(kind === "target" && release.draft === true && release.prerelease === true, "Target must remain private draft 134");
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
    const version = "0.0.134";
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
