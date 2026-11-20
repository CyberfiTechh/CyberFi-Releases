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

// packages/happy-desktop-gym/sources/electron/launch.ts
var launch_exports = {};
__export(launch_exports, {
  gymElectronInvisibility: () => gymElectronInvisibility,
  gymElectronInvisibleAssert: () => gymElectronInvisibleAssert,
  gymElectronLaunch: () => gymElectronLaunch,
  gymElectronProcessRun: () => gymElectronProcessRun,
  gymElectronVideoRecord: () => gymElectronVideoRecord
});
module.exports = __toCommonJS(launch_exports);
var import_node_child_process = require("node:child_process");
var import_node_fs = require("node:fs");
var import_node_os = require("node:os");
var import_node_path = require("node:path");
var import_node_perf_hooks = require("node:perf_hooks");

// native-existing:existing
var api = require(process.env.NATIVE_PLAYWRIGHT_ENTRY);
var _electron = api._electron;

// packages/happy-desktop-gym/sources/electron/launch.ts
async function gymElectronLaunch(options) {
  if (!options.args.some((argument) => argument.startsWith("--user-data-dir=")))
    throw new Error("gymElectronLaunch requires an owned --user-data-dir.");
  if ("recordVideo" in options)
    throw new Error("Use gymElectronVideoRecord instead of Playwright recordVideo.");
  const app = await _electron.launch({
    args: [...options.args],
    env: { ...options.env, HAPPY_DESKTOP_WINDOWS_HIDDEN: "1" },
    executablePath: options.executablePath,
    timeout: options.timeout ?? 6e4,
    ...options.cwd ? { cwd: options.cwd } : {}
  });
  const invisibility = await gymElectronInvisibility(app).catch(async (error) => {
    await app.close().catch(() => void 0);
    throw error;
  });
  if (!invisibility.hiddenMode) {
    await app.close().catch(() => void 0);
    throw new Error(
      "This desktop build has no hidden-window mode. Rebuild happy-desktop-electron."
    );
  }
  await app.evaluate(({ app: electronApp }) => {
    if (electronApp.dock) electronApp.dock.setBadge = () => void 0;
  });
  await gymElectronDockWatch(app).catch(async (error) => {
    await app.close().catch(() => void 0);
    throw error;
  });
  return app;
}
async function gymElectronDockWatch(app) {
  await app.evaluate(({ app: electronApp, BrowserWindow, Menu, powerSaveBlocker }) => {
    globalThis.__name ??= (value) => value;
    if (process.platform !== "darwin" || !electronApp.dock) return;
    const started = Date.now();
    const recent = [];
    const record = (what, stack = true) => {
      recent.push({
        at: Date.now() - started,
        what,
        ...stack ? { stack: new Error().stack?.split("\n").slice(3, 12).join("\n") } : {}
      });
      if (recent.length > 60) recent.shift();
    };
    const wrap = (owner, name, label) => {
      const target = owner;
      const original = target[name];
      if (typeof original !== "function") return;
      target[name] = function(...args) {
        record(
          `${label}.${name}(${args.map((arg) => {
            try {
              return JSON.stringify(arg) ?? typeof arg;
            } catch {
              return typeof arg;
            }
          }).join(", ").slice(0, 120)})`
        );
        return original.apply(this, args);
      };
    };
    const dock = electronApp.dock;
    for (const name of ["show", "hide", "bounce", "setIcon", "setMenu", "downloadFinished"])
      wrap(dock, name, "dock");
    for (const name of ["focus", "show", "hide", "setActivationPolicy", "setBadgeCount"])
      wrap(electronApp, name, "app");
    for (const name of [
      "show",
      "showInactive",
      "focus",
      "moveTop",
      "restore",
      "setFullScreen",
      "setSimpleFullScreen",
      "setKiosk",
      "setVisibleOnAllWorkspaces",
      "setAlwaysOnTop",
      "setParentWindow",
      "setSheetOffset"
    ])
      wrap(BrowserWindow.prototype, name, "window");
    wrap(Menu, "setApplicationMenu", "Menu");
    wrap(powerSaveBlocker, "start", "powerSaveBlocker");
    for (const event of [
      "activate",
      "did-become-active",
      "did-resign-active",
      "browser-window-created",
      "web-contents-created",
      "open-url",
      "open-file",
      "second-instance",
      "child-process-gone",
      "render-process-gone"
    ])
      electronApp.on(
        event,
        () => record(`event ${event}`, false)
      );
    let shown = dock.isVisible();
    setInterval(() => {
      const now = dock.isVisible();
      if (now === shown) return;
      shown = now;
      const windows = BrowserWindow.getAllWindows().map((window2) => ({
        id: window2.id,
        title: window2.getTitle(),
        visible: window2.isVisible(),
        focused: window2.isFocused(),
        url: window2.webContents.getURL().slice(0, 120)
      }));
      console.error(
        `[gym-dock] the Dock tile ${now ? "appeared" : "went away"} at ${String(Date.now() - started)} ms; windows ${JSON.stringify(windows)}`
      );
      for (const entry of recent)
        console.error(
          `[gym-dock]   +${String(entry.at)} ms ${entry.what}${entry.stack ? `
${entry.stack}` : ""}`
        );
    }, 10).unref();
  });
}
async function gymElectronProcessRun(options) {
  if (!options.args.some((argument) => argument.startsWith("--user-data-dir=")))
    throw new Error("gymElectronProcessRun requires an owned --user-data-dir.");
  const child = (0, import_node_child_process.spawn)(options.executablePath, [...options.args], {
    env: { ...options.env, HAPPY_DESKTOP_WINDOWS_HIDDEN: "1" },
    stdio: ["ignore", "pipe", "pipe"],
    ...options.cwd ? { cwd: options.cwd } : {}
  });
  let output = "";
  const keep = (chunk) => {
    output = (output + chunk.toString()).slice(-8192);
  };
  child.stdout.on("data", keep);
  child.stderr.on("data", keep);
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`The desktop app did not exit within its timeout:
${output}`));
    }, options.timeout ?? 6e4);
    child.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on("exit", (exitCode, signal) => {
      clearTimeout(timer);
      resolve({ exitCode, signal, output });
    });
  });
}
async function gymElectronInvisibility(app) {
  return app.evaluate(({ app: electronApp, BrowserWindow }) => ({
    hiddenMode: process.env.HAPPY_DESKTOP_WINDOWS_HIDDEN === "1",
    dockVisible: electronApp.dock ? electronApp.dock.isVisible() : null,
    focusedWindow: BrowserWindow.getFocusedWindow() !== null,
    windows: BrowserWindow.getAllWindows().map((window2) => ({
      id: window2.id,
      visible: window2.isVisible(),
      focused: window2.isFocused(),
      minimized: window2.isMinimized(),
      bounds: window2.getBounds()
    }))
  }));
}
async function gymElectronInvisibleAssert(app) {
  const state = await gymElectronInvisibility(app);
  const shown = state.windows.filter((window2) => window2.visible || window2.focused);
  if (!state.hiddenMode || state.dockVisible === true || state.focusedWindow || shown.length > 0)
    throw new Error(`The desktop app became visible to the person: ${JSON.stringify(state)}`);
  return state;
}
async function gymElectronVideoRecord(page, options) {
  const fps = options.fps ?? 25;
  const scale = options.scale ?? 1;
  const viewport = await page.evaluate(() => ({
    width: window.innerWidth,
    height: window.innerHeight
  }));
  const even = (value) => Math.max(2, Math.round(value * scale / 2) * 2);
  const width = even(viewport.width);
  const height = even(viewport.height);
  const h264 = options.codec === "h264";
  const encoder = (0, import_node_child_process.spawn)(
    h264 ? process.env.HAPPY_DESKTOP_GYM_FFMPEG?.trim() || "ffmpeg" : ffmpegExecutable(),
    // The screencast's JPEG frames in at a constant rate, VP8 WebM or
    // H.264 Matroska out; a resized window keeps the first frame's size,
    // letterboxed.
    [
      "-loglevel",
      "error",
      "-y",
      "-f",
      "image2pipe",
      "-c:v",
      "mjpeg",
      "-framerate",
      String(fps),
      "-i",
      "pipe:0",
      "-an",
      ...h264 ? ["-c:v", "libx264", "-preset", "ultrafast", "-crf", "18", "-f", "matroska"] : [
        "-c:v",
        "vp8",
        "-b:v",
        "4M",
        "-crf",
        "6",
        "-qmin",
        "0",
        "-qmax",
        "40",
        "-deadline",
        "realtime",
        "-cpu-used",
        "8"
      ],
      "-pix_fmt",
      "yuv420p",
      "-vf",
      `scale=${width}:${height}:force_original_aspect_ratio=decrease,pad=${width}:${height}:(ow-iw)/2:(oh-ih)/2:color=black`,
      options.path
    ],
    { stdio: ["pipe", "ignore", "pipe"] }
  );
  let encoderError = "";
  encoder.stderr.on("data", (chunk) => {
    encoderError += chunk.toString();
  });
  const encoded = new Promise((resolve, reject) => {
    encoder.on("error", reject);
    encoder.on(
      "close",
      (code) => code === 0 ? resolve() : reject(new Error(`ffmpeg exited ${code}: ${encoderError}`))
    );
  });
  encoded.catch(() => void 0);
  const cdp = await page.context().newCDPSession(page);
  let latest;
  let framesReceived = 0;
  let framesWritten = 0;
  let started = 0;
  let firstResolve = () => void 0;
  const first = new Promise((resolve) => {
    firstResolve = resolve;
  });
  cdp.on("Page.screencastFrame", (frame) => {
    latest = Buffer.from(frame.data, "base64");
    framesReceived++;
    firstResolve();
    void cdp.send("Page.screencastFrameAck", { sessionId: frame.sessionId }).catch(() => {
    });
  });
  await cdp.send("Page.startScreencast", {
    format: "jpeg",
    quality: 90,
    maxWidth: width,
    maxHeight: height,
    everyNthFrame: 1
  });
  await Promise.race([
    first,
    new Promise(
      (_, reject) => setTimeout(() => reject(new Error("The hidden window sent no frame.")), 1e4)
    )
  ]);
  started = import_node_perf_hooks.performance.now();
  const pump = () => {
    const due = Math.floor((import_node_perf_hooks.performance.now() - started) * fps / 1e3) + 1;
    while (latest && framesWritten < due) {
      encoder.stdin.write(latest);
      framesWritten++;
    }
  };
  const timer = setInterval(pump, 1e3 / fps / 2);
  return {
    async stop() {
      pump();
      clearInterval(timer);
      const durationMs = import_node_perf_hooks.performance.now() - started;
      await cdp.send("Page.stopScreencast").catch(() => void 0);
      await cdp.detach().catch(() => void 0);
      encoder.stdin.end();
      await encoded;
      return {
        path: options.path,
        width,
        height,
        durationMs: Math.round(durationMs),
        framesReceived,
        framesWritten
      };
    }
  };
}
function ffmpegExecutable() {
  const configured = process.env.HAPPY_DESKTOP_GYM_FFMPEG?.trim();
  if (configured) return configured;
  const caches = [
    process.env.PLAYWRIGHT_BROWSERS_PATH,
    process.platform === "darwin" ? (0, import_node_path.join)((0, import_node_os.homedir)(), "Library", "Caches", "ms-playwright") : process.platform === "win32" ? (0, import_node_path.join)(process.env.LOCALAPPDATA ?? (0, import_node_os.homedir)(), "ms-playwright") : (0, import_node_path.join)((0, import_node_os.homedir)(), ".cache", "ms-playwright")
  ];
  const binary = process.platform === "darwin" ? "ffmpeg-mac" : process.platform === "win32" ? "ffmpeg-win64.exe" : "ffmpeg-linux";
  for (const cache of caches) {
    if (!cache || !(0, import_node_fs.existsSync)(cache)) continue;
    for (const entry of (0, import_node_fs.readdirSync)(cache).filter((name) => name.startsWith("ffmpeg-")).sort().reverse()) {
      const candidate = (0, import_node_path.join)(cache, entry, binary);
      if ((0, import_node_fs.existsSync)(candidate)) return candidate;
    }
  }
  return "ffmpeg";
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  gymElectronInvisibility,
  gymElectronInvisibleAssert,
  gymElectronLaunch,
  gymElectronProcessRun,
  gymElectronVideoRecord
});
