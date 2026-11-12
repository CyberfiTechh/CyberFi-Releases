import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { setTimeout as delay } from "node:timers/promises";
import { attachUpdateFixture } from "./update-fixture-135.mjs";

const repo = "CyberfiTechh/CyberFi-Releases";
const sourcePins = {
    "windows": {
        "releaseId": 442284162,
        "assetId": 737215955,
        "sha256": "0a8128052ee163337ae85e9a21ce94adea3ffbae38d0d57f588f69576c876caf",
        "manifestAssetId": 737226451,
        "manifestSha256": "2c1333ad1188aa26b00fd25747e4c4cccf9d66a31ca523d83b064607a811ab1c"
    },
    "x64": {
        "releaseId": 442144163,
        "assetId": 736759534,
        "sha256": "aa658ca2c0188bb916c60127343f5047afce52b284a789f42cb338ab4c453d11",
        "manifestAssetId": 736768838,
        "manifestSha256": "9fb9ba6d5faba9572239a7487c2edc6f040a4f1f5f4c0ed6e673eb9bea93e7b4"
    },
    "arm64": {
        "releaseId": 442144163,
        "assetId": 736769052,
        "sha256": "9b96768075044a84c3c2ecce78bd5b5507ff47d06c674f179a2e79f319f325e4",
        "manifestAssetId": 736779160,
        "manifestSha256": "e4c435d9c614f452d4af354e0e8cda25f0458dd0a698719ec8086ef98a90f2b9"
    }
};
const review = JSON.parse(readFileSync(new URL("./native-fixture-review-135.json", import.meta.url), "utf8"));

export async function pinnedEngineMetadata(carrier, token, fetcher = fetch) {
    assert(carrier.engineRepository === "CyberfiTechh/CyberFi-Engine" && carrier.engineReleaseId === 442894294 &&
        carrier.engineSourceCommit === "62a29b5872534ba627412b7903fc8103fa629331");
    assert(carrier.repository === repo && [443152400, 443218651].includes(carrier.releaseId));
    assert(/^[a-f0-9]{64}$/u.test(carrier.sha256) && Number.isSafeInteger(carrier.size) && carrier.size > 0);
    const canonicalName = carrier.name.replace(/^qa-only-native135-engine-/u, "happy-agent-");
    assert(/^happy-agent-0[.]4[.]127-(?:win32-x64|darwin-x64|darwin-arm64)[.]tar[.]gz$/u.test(canonicalName));
    const headers = { Accept: "application/vnd.github+json", ...(token ? { Authorization: "Bearer " + token } : {}) };
    const original = await fetcher(`https://api.github.com/repos/${carrier.engineRepository}/releases/${carrier.engineReleaseId}`,
        { headers: { Accept: "application/vnd.github+json" }, redirect: "error", signal: AbortSignal.timeout(45000) });
    const findAsset = (release, identity, name) => {
        const matches = release.assets.filter(asset => asset.id === identity);
        assert(matches.length === 1 && matches[0].name === name && matches[0].size === carrier.size && matches[0].digest === "sha256:" + carrier.sha256,
            "Exact original engine bytes and archive identity are required");
        return matches[0];
    };
    if (original.status === 200) {
        const release = await original.json();
        assert(release.id === carrier.engineReleaseId && release.tag_name === "v0.4.127" &&
            release.target_commitish === carrier.engineSourceCommit && release.prerelease === false, "Exact original engine version/source is required");
        return { repository: carrier.engineRepository, asset: findAsset(release, carrier.engineAssetId, canonicalName),
            provenance: { ...carrier, transport: "canonical-original", originalMetadataHttpStatus: 200 } };
    }
    assert([403, 404].includes(original.status), `Original pinned engine metadata failed (HTTP ${original.status}); no carrier fallback allowed`);
    const response = await fetcher(`https://api.github.com/repos/${repo}/releases/${carrier.releaseId}`,
        { headers, redirect: "error", signal: AbortSignal.timeout(45000) });
    assert(response.status === 200, `Own pinned engine carrier unavailable (HTTP ${response.status})`);
    const release = await response.json(), tag = canonicalName.includes("darwin-") ? "macos-v0.0.135" : "v0.0.135";
    assert(release.id === carrier.releaseId && release.tag_name === tag && release.draft === true && release.prerelease === true &&
        release.body.includes("https://github.com/CyberfiTechh/CyberFi/commit/" + review.sourceCommit), "Carrier must stay on the exact reviewed own private draft");
    return { repository: repo, asset: findAsset(release, carrier.assetId, carrier.name),
        provenance: { ...carrier, transport: "owned-private-qa-carrier", originalMetadataHttpStatus: original.status, carrierMetadataHttpStatus: response.status } };
}

export function reviewedDraftPins(platform) {
    assert(Object.hasOwn(sourcePins, platform), "Unexpected native target");
    const ref = process.env.ACCEPTANCE_FIXTURE_REF, sourceCommit = process.env.ACCEPTANCE_SOURCE_SHA;
    assert(process.env.GITHUB_ACTIONS === "true" && process.env.RUNNER_ENVIRONMENT === "github-hosted" &&
        process.env.GITHUB_REPOSITORY === repo && process.env.GITHUB_REF === ref &&
        /^refs\/heads\/main$/u.test(ref), "Unexpected hosted fixture branch");
    assert(/^[a-f0-9]{40}$/u.test(review.sourceCommit ?? ""), "Final reviewed 135 source is not frozen");
    assert.equal(sourceCommit, review.sourceCommit, "The reviewed 135 desktop SHA is required");
    const target = JSON.parse(process.env.ACCEPTANCE_ARTIFACTS);
    assert.deepEqual(target, review.targets?.[platform], "Final reviewed target pins are not frozen");
    assert(target && typeof target === "object" && !Array.isArray(target) &&
        Object.keys(target).sort().join(",") === "appAsarSha256,assetId,manifestAssetId,manifestSha256,releaseId,sha256", "Exact target pin fields are required");
    assert([target.releaseId, target.assetId, target.manifestAssetId].every(value => Number.isSafeInteger(value) && value > 0), "Positive target asset identities are required");
    assert([target.sha256, target.manifestSha256, target.appAsarSha256].every(value => typeof value === "string" && /^[a-f0-9]{64}$/u.test(value)), "Exact target SHA-256 pins are required");
    assert(target.releaseId !== sourcePins[platform].releaseId && target.assetId !== target.manifestAssetId &&
        ![target.assetId, target.manifestAssetId].some(value => [sourcePins[platform].assetId, sourcePins[platform].manifestAssetId].includes(value)) &&
        target.sha256 !== sourcePins[platform].sha256 && target.manifestSha256 !== sourcePins[platform].manifestSha256,
        "The draft must differ from the public source");
    return { source: sourcePins[platform], target };
}

export function assertDraftRelease(release, kind, pin, tag, sourceCommit) {
    assert(release.id === pin.releaseId && release.tag_name === tag, "Release identity differs from pins");
    if (kind === "source") {
        assert(release.draft === false && release.prerelease === false, "Source must be the pinned public stable version");
    } else {
        assert(kind === "target" && release.draft === true && release.prerelease === true, "Target must remain private draft 135");
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
    const version = "0.0.135";
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
