// Same public WindowServer/NSWorkspace observations as the gym watcher, across PID changes.
import AppKit
import CoreGraphics
import Foundation

guard CommandLine.arguments.count == 3, CommandLine.arguments[1] == "--bundle" else { exit(2) }
let target = URL(fileURLWithPath: CommandLine.arguments[2]).resolvingSymlinksInPath().path
guard target.hasSuffix("/CyberFi.app") else { exit(2) }
let started = Date()
var samples = 0, systemWindowsMax = 0, onscreenSamples = 0, regularPolicySamples = 0, activeSamples = 0
var pids = Set<Int32>(), windows = Set<Int>()
var policySamplesByPid: [String: Int] = [:]
var policiesByPid: [String: Set<Int>] = [:]
var violations: [[String: Any]] = []

func sample() {
    samples += 1
    for app in NSWorkspace.shared.runningApplications where app.bundleURL?.resolvingSymlinksInPath().path == target {
        pids.insert(app.processIdentifier)
        let policy = app.activationPolicy
        // Count only explicit known AppKit policies; unknown values cannot prove Dock absence.
        if policy == .regular || policy == .accessory || policy == .prohibited {
            let key = String(app.processIdentifier)
            policySamplesByPid[key, default: 0] += 1
            policiesByPid[key, default: []].insert(policy.rawValue)
        }
        if policy == .regular { regularPolicySamples += 1 }
        if app.isActive { activeSamples += 1 }
    }
    guard let list = CGWindowListCopyWindowInfo([.optionAll], kCGNullWindowID) as? [[String: Any]] else { return }
    systemWindowsMax = max(systemWindowsMax, list.count)
    for window in list {
        guard let pid = window[kCGWindowOwnerPID as String] as? Int32, pids.contains(pid) else { continue }
        windows.insert(window[kCGWindowNumber as String] as? Int ?? -1)
        if window[kCGWindowIsOnscreen as String] as? Bool == true {
            onscreenSamples += 1
            if violations.count < 5 { violations.append(["pid": pid, "atMs": Int(Date().timeIntervalSince(started) * 1000)]) }
        }
    }
}

func finish() -> Never {
    let result: [String: Any] = ["bundle": target, "samples": samples,
        "durationMs": Int(Date().timeIntervalSince(started) * 1000), "systemWindowsMax": systemWindowsMax,
        "pids": pids.sorted(), "windowsOwned": windows.count, "onscreenSamples": onscreenSamples,
        "policySamplesByPid": policySamplesByPid, "policiesByPid": policiesByPid.mapValues { $0.sorted() },
        "regularPolicySamples": regularPolicySamples, "activeSamples": activeSamples, "violations": violations]
    FileHandle.standardOutput.write(try! JSONSerialization.data(withJSONObject: result, options: [.sortedKeys]))
    exit(0)
}

signal(SIGTERM, SIG_IGN)
signal(SIGINT, SIG_IGN)
let terminate = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
terminate.setEventHandler { finish() }
terminate.resume()
let interrupt = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
interrupt.setEventHandler { finish() }
interrupt.resume()
let timer = DispatchSource.makeTimerSource(queue: .main)
timer.schedule(deadline: .now(), repeating: .milliseconds(25))
timer.setEventHandler { sample() }
timer.resume()
DispatchQueue.main.async { sample(); FileHandle.standardError.write(Data("ready\n".utf8)) }
// NSWorkspace.runningApplications and NSRunningApplication properties refresh only
// when the main run loop runs in a common mode; dispatchMain alone leaves a stale list.
RunLoop.main.run()
