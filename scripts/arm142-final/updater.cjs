"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// packages/happy-desktop-electron/sources/main/cyberfiRelease.ts
var cyberfiRelease_exports = {};
__export(cyberfiRelease_exports, {
  cyberFiDownloadUpdate: () => cyberFiDownloadUpdate,
  cyberFiNewerRelease: () => cyberFiNewerRelease,
  cyberFiReleaseCheck: () => cyberFiReleaseCheck,
  cyberFiReleaseTag: () => cyberFiReleaseTag,
  cyberFiReleaseVersions: () => cyberFiReleaseVersions,
  cyberFiReleasesUrl: () => cyberFiReleasesUrl,
  cyberFiUpdateManifestVerify: () => cyberFiUpdateManifestVerify
});
module.exports = __toCommonJS(cyberfiRelease_exports);
var import_node_crypto = require("node:crypto");
var import_node_fs = require("node:fs");
var import_promises = require("node:fs/promises");
var import_node_os = require("node:os");
var import_node_path = require("node:path");
var import_promises2 = require("node:stream/promises");

// packages/happy-desktop-electron/sources/main/happyAgentVersion.ts
function happyAgentVersionNewer(candidate, current) {
  const left = versionParse(candidate);
  const right = versionParse(current);
  for (let index = 0; index < 3; index += 1) {
    if (left.core[index] !== right.core[index]) return left.core[index] > right.core[index];
  }
  if (left.prerelease.length === 0 || right.prerelease.length === 0)
    return left.prerelease.length === 0 && right.prerelease.length > 0;
  for (let index = 0; index < Math.max(left.prerelease.length, right.prerelease.length); index += 1) {
    const a = left.prerelease[index];
    const b = right.prerelease[index];
    if (a === void 0) return false;
    if (b === void 0) return true;
    if (a === b) continue;
    const numericA = /^\d+$/u.test(a);
    const numericB = /^\d+$/u.test(b);
    if (numericA && numericB) return BigInt(a) > BigInt(b);
    return numericA !== numericB ? !numericA : a > b;
  }
  return false;
}
var VERSION_PATTERN = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/u;
function versionParse(version) {
  const match = VERSION_PATTERN.exec(version);
  if (!match) throw new Error(`Happy Agent version is invalid: ${version}`);
  return {
    core: [BigInt(match[1]), BigInt(match[2]), BigInt(match[3])],
    prerelease: match[4]?.split(".") ?? []
  };
}

// packages/happy-desktop-electron/sources/main/cyberfiRelease.ts
var cyberFiReleasesUrl = "https://github.com/CyberfiTechh/CyberFi-Releases/releases";
var api = "https://api.github.com/repos/CyberfiTechh/CyberFi-Releases/releases";
var publicIndex = "https://raw.githubusercontent.com/CyberfiTechh/CyberFi-Releases/main/updates.json";
var stableVersion = /^(0|[1-9]\d{0,8})\.(0|[1-9]\d{0,8})\.(0|[1-9]\d{0,8})$/u;
async function publishedReleaseEntries(fetchRelease = globalThis.fetch, signal) {
  const failures = [];
  for (const url of [api + "?per_page=30", publicIndex]) {
    signal?.throwIfAborted();
    try {
      const timeout = AbortSignal.timeout(12e3);
      const response = await fetchRelease(url, {
        headers: {
          accept: "application/vnd.github+json",
          "user-agent": "CyberFi update check"
        },
        redirect: "error",
        signal: signal ? AbortSignal.any([signal, timeout]) : timeout
      });
      if (!response.ok) {
        const limited = response.status === 429 || response.status === 403 && response.headers.get("x-ratelimit-remaining") === "0";
        throw new Error(
          limited ? `GitHub API istek s\u0131n\u0131r\u0131na ula\u015F\u0131ld\u0131 (HTTP ${response.status}).` : `S\xFCr\xFCm listesi al\u0131namad\u0131 (HTTP ${response.status}).`
        );
      }
      const entries = await response.json();
      if (!Array.isArray(entries) || entries.length > 30 || entries.some(
        (entry) => !entry || typeof entry !== "object" || typeof entry.tag_name !== "string" || entry.tag_name.length > 128 || typeof entry.draft !== "boolean" || !Array.isArray(entry.assets) || entry.assets.length > 500 || entry.assets.some(
          (asset) => !asset || typeof asset !== "object" || !("name" in asset) || typeof asset.name !== "string" || asset.name.length > 256 || !("state" in asset) || typeof asset.state !== "string"
        )
      ))
        throw new Error("G\xFCncelleme s\xFCr\xFCm listesi ge\xE7ersiz.");
      return entries.filter((entry) => entry.draft === false);
    } catch (error) {
      if (signal?.aborted) throw error;
      failures.push(
        error instanceof SyntaxError ? "G\xFCncelleme s\xFCr\xFCm listesi ge\xE7ersiz." : error instanceof TypeError ? "G\xFCncelleme sunucusuna ba\u011Flant\u0131 kurulamad\u0131." : error instanceof Error ? error.message : "S\xFCr\xFCm denetimi tamamlanamad\u0131."
      );
    }
  }
  throw new Error(
    `G\xFCncelleme denetimi tamamlanamad\u0131. ${failures[0]} Yedek kaynak: ${failures[1]}`
  );
}
function cyberFiReleaseTag(version, platform) {
  const modern = happyAgentVersionNewer(version, "0.0.138");
  const prefix = platform === "darwin" ? modern ? "mac-v" : "macos-v" : modern ? "windows-v" : "v";
  return `${prefix}${version}`;
}
function uploadedAsset(entries, name) {
  return entries.some(
    (asset) => typeof asset === "object" && asset !== null && "name" in asset && asset.name === name && "state" in asset && asset.state === "uploaded"
  );
}
function cyberFiNewerRelease(entries, current, platform, arch) {
  if (!Array.isArray(entries) || !stableVersion.test(current)) return void 0;
  const extension = platform === "win32" ? "exe" : platform === "darwin" ? "dmg" : void 0;
  if (!extension || !["x64", "arm64"].includes(arch) || platform === "win32" && arch !== "x64")
    return void 0;
  const prefixes = platform === "darwin" ? ["macos-v", "mac-v"] : ["windows-v", "v"];
  let version = current;
  for (const release of entries) {
    if (!release || release.draft !== false || typeof release.tag_name !== "string" || !prefixes.some((prefix2) => release.tag_name.startsWith(prefix2)) || !Array.isArray(release.assets))
      continue;
    const prefix = prefixes.find((prefix2) => release.tag_name.startsWith(prefix2));
    const candidate = release.tag_name.slice(prefix.length);
    if (!stableVersion.test(candidate) || !happyAgentVersionNewer(candidate, version)) continue;
    if (cyberFiReleaseTag(candidate, platform) !== release.tag_name) continue;
    const filename = `CyberFi-${candidate}-${arch}.${extension}`;
    if (uploadedAsset(release.assets, filename) && uploadedAsset(release.assets, filename + ".update.json"))
      version = candidate;
  }
  return version === current ? void 0 : version;
}
async function cyberFiReleaseCheck(current, platform, arch, fetchRelease = globalThis.fetch) {
  const versions = await cyberFiReleaseVersions(platform, arch, fetchRelease);
  return versions.find((version) => happyAgentVersionNewer(version, current));
}
async function cyberFiReleaseVersions(platform, arch, fetchRelease = globalThis.fetch) {
  const entries = await publishedReleaseEntries(fetchRelease);
  return [
    ...new Set(
      entries.flatMap((entry) => {
        const version = cyberFiNewerRelease([entry], "0.0.0", platform, arch);
        return version ? [version] : [];
      })
    )
  ].sort((left, right) => left === right ? 0 : happyAgentVersionNewer(left, right) ? -1 : 1);
}
var updatePublicKey = `-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA09ZxJMbpq1uFEnz7n52M
AJtceCXVQCo57lgwMAmizgJaGVGsgsMpzqgCCRgXBN+bPygE+16S9XwYOwHDlnNG
oq8h+bE9Nxce3PzsQHrscdHTT1lGQ/5XwSmvzTvxLdURtQWpaXZl7lJghUnZHNDA
8SOHbk8rQ+butE82lhcq0C+hgJgHTUqFl9Irppi2O+MpufsZo8PX5jphD4H0aX0k
B9P+LUreoBmG/L3T3AMZEzQZG606awc/ZMYsJcJkt4xNMjR3ZMz1aWKErW2AXDeY
yfAo0zmEAUEAFSc3UEJRnmBAjorVA3C/rHJzYP7QabSh8ORLOUrqQYgqCpTLETpf
ct0J+NphCLuBGNQ5IeId5IPiBNZlKynGzP/HK+oJTvJ31hTHIiaA+5pfIESXELIZ
J5awYGW0y7fii0CqRGwFMJnU829APVvAC9LJUzSSz7NP+2rmc/boYInx8cjN2/LO
LI9HsPvON+oxM4MhjRxDd4CVoKDpI+rB2TthSdfxt3UxAgMBAAE=
-----END PUBLIC KEY-----`;
var maximumInstallerBytes = 512 * 1024 * 1024;
function cyberFiUpdateManifestVerify(data, version, filename, key = updatePublicKey) {
  if (typeof data !== "object" || data === null || !("sha256" in data) || typeof data.sha256 !== "string" || !/^[0-9a-f]{64}$/u.test(data.sha256) || !("size" in data) || typeof data.size !== "number" || !Number.isSafeInteger(data.size) || data.size <= 0 || data.size > maximumInstallerBytes || !("signature" in data) || typeof data.signature !== "string" || !/^[A-Za-z0-9+/=]{100,700}$/u.test(data.signature))
    throw new Error("G\xFCncelleme imza dosyas\u0131 ge\xE7ersiz.");
  const { sha256, size } = data;
  const signed = Buffer.from(`${version}
${filename}
${sha256}
${size}
`);
  if (!(0, import_node_crypto.verify)("sha256", signed, key, Buffer.from(data.signature, "base64"))) {
    throw new Error("CyberFi g\xFCncelleme imzas\u0131 do\u011Frulanamad\u0131.");
  }
  return { sha256, size };
}
async function releaseAsset(tag, filename, signal, assetId) {
  let response = await fetch(`${cyberFiReleasesUrl}/download/${tag}/${filename}`, {
    redirect: "manual",
    signal
  }).catch((error) => {
    signal.throwIfAborted();
    if (!(error instanceof TypeError)) throw error;
    return void 0;
  });
  if (!response || response.status >= 500 || response.status === 429) {
    signal.throwIfAborted();
    if (typeof assetId !== "number" || !Number.isSafeInteger(assetId) || assetId <= 0)
      throw new Error("GitHub paket dosyas\u0131n\u0131 vermedi.");
    await response?.body?.cancel().catch(() => void 0);
    response = await fetch(`${api}/assets/${assetId}`, {
      headers: {
        accept: "application/octet-stream",
        "user-agent": "CyberFi update download"
      },
      redirect: "manual",
      signal
    });
  }
  if (response.status !== 302) {
    if (!response.ok) throw new Error("GitHub paket dosyas\u0131n\u0131 vermedi.");
    return response;
  }
  const url = new URL(response.headers.get("location") ?? "");
  if (url.protocol !== "https:" || !!url.username || !!url.password || url.port !== "" && url.port !== "443" || !["release-assets.githubusercontent.com", "objects.githubusercontent.com"].includes(
    url.hostname
  )) {
    throw new Error("Paketin indirme adresi do\u011Frulanamad\u0131.");
  }
  const download = await fetch(url, { redirect: "error", signal });
  if (!download.ok) throw new Error("Paket indirilemedi.");
  return download;
}
async function cyberFiDownloadUpdate(version, onProgress, platform = process.platform, arch = process.arch) {
  const extension = platform === "win32" ? "exe" : platform === "darwin" ? "dmg" : void 0;
  if (!extension || !["x64", "arm64"].includes(arch) || platform === "win32" && arch !== "x64" || !stableVersion.test(version))
    return void 0;
  const tag = cyberFiReleaseTag(version, platform);
  const signal = AbortSignal.timeout(5 * 60 * 1e3);
  const data = (await publishedReleaseEntries(globalThis.fetch, signal)).find(
    (entry) => entry.tag_name === tag
  );
  if (!data) return void 0;
  const filename = `CyberFi-${version}-${arch}.${extension}`;
  const manifestName = filename + ".update.json";
  if (!uploadedAsset(data.assets, filename) || !uploadedAsset(data.assets, manifestName))
    return void 0;
  const manifest = await releaseAsset(
    tag,
    manifestName,
    signal,
    data.assets.find((asset) => asset.name === manifestName && asset.state === "uploaded")?.id
  );
  const manifestReader = manifest.body?.getReader();
  if (!manifestReader) throw new Error("G\xFCncelleme imza dosyas\u0131 okunamad\u0131.");
  const chunks = [];
  let manifestSize = 0;
  try {
    for (; ; ) {
      const { value, done } = await manifestReader.read();
      if (done) break;
      manifestSize += value.byteLength;
      if (manifestSize > 4096) throw new Error("G\xFCncelleme imza dosyas\u0131 \xE7ok b\xFCy\xFCk.");
      chunks.push(value);
    }
  } finally {
    await manifestReader.cancel().catch(() => void 0);
  }
  const expected = cyberFiUpdateManifestVerify(
    JSON.parse(Buffer.concat(chunks).toString("utf8")),
    version,
    filename
  );
  const response = await releaseAsset(
    tag,
    filename,
    signal,
    data.assets.find((asset) => asset.name === filename && asset.state === "uploaded")?.id
  );
  const reader = response.body?.getReader();
  if (!reader) throw new Error("Paket okunamad\u0131.");
  const directory = await (0, import_promises.mkdtemp)((0, import_node_path.join)((0, import_node_os.tmpdir)(), "cyberfi-update-"));
  const path = (0, import_node_path.join)(directory, filename);
  const hash = (0, import_node_crypto.createHash)("sha256");
  let size = 0;
  let reportedPercent = -1;
  try {
    await (0, import_promises2.pipeline)(
      async function* () {
        for (; ; ) {
          const { value, done } = await reader.read();
          if (done) break;
          size += value.byteLength;
          if (size > expected.size)
            throw new Error("\u0130ndirilen paket imzal\u0131 boyutu a\u015Ft\u0131.");
          hash.update(value);
          const percent = Math.floor(size / expected.size * 100);
          if (percent !== reportedPercent) {
            reportedPercent = percent;
            onProgress?.(size / expected.size);
          }
          yield value;
        }
      },
      (0, import_node_fs.createWriteStream)(path, { flags: "wx", mode: 384 }),
      { signal }
    );
    if (size !== expected.size || hash.digest("hex") !== expected.sha256) {
      throw new Error("\u0130ndirilen paket imzal\u0131 dosya \xF6zetiyle e\u015Fle\u015Fmedi.");
    }
    return path;
  } catch (error) {
    await (0, import_promises.rm)(path, { force: true });
    throw error;
  } finally {
    await reader.cancel().catch(() => void 0);
  }
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  cyberFiDownloadUpdate,
  cyberFiNewerRelease,
  cyberFiReleaseCheck,
  cyberFiReleaseTag,
  cyberFiReleaseVersions,
  cyberFiReleasesUrl,
  cyberFiUpdateManifestVerify
});
