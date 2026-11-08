param(
    [string]$Executable,
    [string]$Profile,
    [switch]$SelfTest
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Test launcher only: a linked token can lower this same user's privileges, never raise them.
Add-Type -TypeDefinition @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

public static class CyberFiOwnedLaunch {
    public static string Stage = "initialize";
    public static string CreationApi = "none", TokenMode = "unknown";
    public static bool SelectedTokenVerified = false;
    const uint Query = 8, Suspended = 4, UnicodeEnvironment = 0x400, NoWindow = 0x08000000;
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct StartupInfo {
        public int cb; public string reserved, desktop, title;
        public int x, y, xSize, ySize, xChars, yChars, fill, flags;
        public short show, reservedBytes; public IntPtr reservedData, stdin, stdout, stderr;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct ProcessInfo { public IntPtr process, thread; public uint pid, tid; }
    [StructLayout(LayoutKind.Sequential)]
    struct SidAttributes { public IntPtr sid; public uint attributes; }
    public sealed class Result {
        public uint sourcePid; public bool sameSid, elevated, administrator, parentElevated, parentAdministrator, privilegeDropped; public uint exitCode;
        public string launchTokenMode;
    }
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr handle);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool GetTokenInformation(IntPtr token, int kind, IntPtr data, int bytes, out int required);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool SetTokenInformation(IntPtr token, int kind, IntPtr data, int bytes);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool DuplicateToken(IntPtr token, int level, out IntPtr duplicate);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool CheckTokenMembership(IntPtr token, IntPtr sid, out bool member);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CreateRestrictedToken(IntPtr token, uint flags, uint disableCount, [In] SidAttributes[] disable, uint deleteCount, IntPtr delete, uint restrictCount, IntPtr restrict, out IntPtr restricted);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CreateProcessWithTokenW(IntPtr token, uint logon, string app, StringBuilder command, uint flags, IntPtr env, string cwd, ref StartupInfo startup, out ProcessInfo process);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CreateProcessAsUserW(IntPtr token, string app, StringBuilder command, IntPtr processSecurity, IntPtr threadSecurity, bool inherit, uint flags, IntPtr env, string cwd, ref StartupInfo startup, out ProcessInfo process);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CreateProcessW(string app, StringBuilder command, IntPtr processSecurity, IntPtr threadSecurity, bool inherit, uint flags, IntPtr env, string cwd, ref StartupInfo startup, out ProcessInfo process);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool QueryFullProcessImageNameW(IntPtr process, uint flags, StringBuilder path, ref int length);
    [DllImport("kernel32.dll", SetLastError = true)] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError = true)] static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetExitCodeProcess(IntPtr process, out uint code);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool TerminateProcess(IntPtr process, uint code);
    [DllImport("advapi32.dll")] static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);
    [DllImport("advapi32.dll")] static extern IntPtr GetSidSubAuthority(IntPtr sid, uint index);

    static void Check(bool ok) { if (!ok) throw new Win32Exception(Marshal.GetLastWin32Error()); }
    static IntPtr Info(IntPtr token, int kind) {
        int length; GetTokenInformation(token, kind, IntPtr.Zero, 0, out length);
        if (length <= 0 || length > 65536) throw new InvalidOperationException("invalid-token-information");
        IntPtr buffer = Marshal.AllocHGlobal(length);
        try { Check(GetTokenInformation(token, kind, buffer, length, out length)); return buffer; }
        catch { Marshal.FreeHGlobal(buffer); throw; }
    }
    static int Number(IntPtr token, int kind) {
        IntPtr data = Info(token, kind);
        try { return Marshal.ReadInt32(data); } finally { Marshal.FreeHGlobal(data); }
    }
    static string Sid(IntPtr token) {
        IntPtr data = Info(token, 1);
        try { return new SecurityIdentifier(Marshal.ReadIntPtr(data)).Value; }
        finally { Marshal.FreeHGlobal(data); }
    }
    static bool IsAdministrator(IntPtr token) {
        byte[] sid = new byte[SecurityIdentifier.MaxBinaryLength];
        new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).GetBinaryForm(sid, 0);
        GCHandle pinned = GCHandle.Alloc(sid, GCHandleType.Pinned); IntPtr duplicate = IntPtr.Zero;
        try {
            Check(DuplicateToken(token, 2, out duplicate));
            bool member; Check(CheckTokenMembership(duplicate, pinned.AddrOfPinnedObject(), out member)); return member;
        } finally { if (duplicate != IntPtr.Zero) CloseHandle(duplicate); pinned.Free(); }
    }
    static void VerifyMedium(IntPtr token, string expectedSid) {
        if (Sid(token) != expectedSid || Number(token, 20) != 0 || Number(token, 8) != 1 || IsAdministrator(token))
            throw new InvalidOperationException("same-user-non-elevated-primary-token-required");
        IntPtr data = Info(token, 25);
        try {
            IntPtr sid = Marshal.ReadIntPtr(data);
            byte count = Marshal.ReadByte(GetSidSubAuthorityCount(sid));
            if (count == 0 || Marshal.ReadInt32(GetSidSubAuthority(sid, (uint)(count - 1))) != 0x2000)
                throw new InvalidOperationException("medium-integrity-token-required");
        } finally { Marshal.FreeHGlobal(data); }
    }
    static IntPtr RestrictedMedium(IntPtr current) {
        IntPtr groups = Info(current, 2), restricted = IntPtr.Zero;
        try {
            int count = Marshal.ReadInt32(groups), size = Marshal.SizeOf(typeof(SidAttributes));
            if (count < 1 || count > 1024) throw new InvalidOperationException("invalid-token-groups");
            var disabled = new List<SidAttributes>();
            for (int i = 0; i < count; i++) {
                var group = (SidAttributes)Marshal.PtrToStructure(IntPtr.Add(groups, IntPtr.Size + i * size), typeof(SidAttributes));
                string sid = new SecurityIdentifier(group.sid).Value;
                if (sid == "S-1-5-32-544" || sid == "S-1-5-114" ||
                    (sid.StartsWith("S-1-5-21-", StringComparison.Ordinal) &&
                     (sid.EndsWith("-512") || sid.EndsWith("-518") || sid.EndsWith("-519")))) disabled.Add(group);
            }
            if (disabled.Count == 0) throw new InvalidOperationException("administrative-group-required-for-privilege-drop");
            // DISABLE_MAX_PRIVILEGE disables privileges; administrative SIDs become deny-only.
            Check(CreateRestrictedToken(current, 1, (uint)disabled.Count, disabled.ToArray(), 0, IntPtr.Zero, 0, IntPtr.Zero, out restricted));
            var medium = new SecurityIdentifier("S-1-16-8192"); byte[] sidBytes = new byte[medium.BinaryLength]; medium.GetBinaryForm(sidBytes, 0);
            IntPtr label = Marshal.AllocHGlobal(size + sidBytes.Length);
            try {
                IntPtr sidPointer = IntPtr.Add(label, size); Marshal.Copy(sidBytes, 0, sidPointer, sidBytes.Length);
                Marshal.StructureToPtr(new SidAttributes { sid = sidPointer, attributes = 0x20 }, label, false);
                Check(SetTokenInformation(restricted, 25, label, size + sidBytes.Length));
            } finally { Marshal.FreeHGlobal(label); }
            IntPtr result = restricted; restricted = IntPtr.Zero; return result;
        } finally { if (restricted != IntPtr.Zero) CloseHandle(restricted); Marshal.FreeHGlobal(groups); }
    }
    static string Quote(string value) {
        if (String.IsNullOrEmpty(value) || value.IndexOfAny(new char[] {'"', '\0', '\r', '\n'}) >= 0 || value.EndsWith("\\"))
            throw new InvalidOperationException("invalid-fixed-launch-argument");
        return "\"" + value + "\"";
    }
    static IntPtr EnvironmentBlock() {
        var entries = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (DictionaryEntry item in Environment.GetEnvironmentVariables()) {
            string key = (string)item.Key, value = (string)item.Value;
            if (key.IndexOf('=') >= 0 || key.IndexOf('\0') >= 0 || value.IndexOf('\0') >= 0)
                throw new InvalidOperationException("invalid-environment-entry");
            entries.Add(key, value);
        }
        var block = new StringBuilder();
        foreach (var entry in entries) block.Append(entry.Key).Append('=').Append(entry.Value).Append('\0');
        block.Append('\0');
        return Marshal.StringToHGlobalUni(block.ToString());
    }
    public static Result Run(string executable, string[] arguments) {
        IntPtr current = IntPtr.Zero, linked = IntPtr.Zero, childToken = IntPtr.Zero, environment = IntPtr.Zero;
        ProcessInfo child = new ProcessInfo(); bool finished = false;
        try {
            Stage = "current-token"; Check(OpenProcessToken(GetCurrentProcess(), Query | 2 | 1 | 0x80, out current));
            string sid = Sid(current); bool elevated = Number(current, 20) != 0, parentAdministrator = IsAdministrator(current);
            string tokenMode = "current-medium";
            IntPtr launchToken = current;
            if (elevated) {
                if (Number(current, 18) == 1) {
                    Stage = "restrict-full-administrator-token";
                    linked = RestrictedMedium(current); tokenMode = "restricted-medium";
                } else {
                    Stage = "linked-medium-token";
                    IntPtr data = Info(current, 19);
                    try { linked = Marshal.ReadIntPtr(data); } finally { Marshal.FreeHGlobal(data); }
                    tokenMode = "linked-medium";
                }
                if (linked == IntPtr.Zero) throw new InvalidOperationException("linked-token-unavailable");
                launchToken = linked;
            }
            VerifyMedium(launchToken, sid); SelectedTokenVerified = true; TokenMode = tokenMode;
            var command = new StringBuilder(Quote(executable));
            foreach (string argument in arguments) command.Append(' ').Append(Quote(argument));
            environment = EnvironmentBlock();
            var startup = new StartupInfo(); startup.cb = Marshal.SizeOf(typeof(StartupInfo));
            startup.flags = 1; startup.show = 0;
            Stage = "create-suspended-owned-child";
            uint flags = Suspended | UnicodeEnvironment | NoWindow;
            if (tokenMode == "restricted-medium") {
                // Windows documents CreateProcessAsUser for a restricted version of the caller's own token.
                CreationApi = "CreateProcessAsUserW";
                Check(CreateProcessAsUserW(launchToken, executable, command, IntPtr.Zero, IntPtr.Zero, false, flags, environment, Path.GetDirectoryName(executable), ref startup, out child));
            } else if (elevated) {
                CreationApi = "CreateProcessWithTokenW";
                Check(CreateProcessWithTokenW(launchToken, 0, executable, command, flags, environment, Path.GetDirectoryName(executable), ref startup, out child));
            } else {
                CreationApi = "CreateProcessW";
                Check(CreateProcessW(executable, command, IntPtr.Zero, IntPtr.Zero, false, flags, environment, Path.GetDirectoryName(executable), ref startup, out child));
            }
            Stage = "verify-suspended-child-token";
            Check(OpenProcessToken(child.process, Query | 2, out childToken)); VerifyMedium(childToken, sid);
            var image = new StringBuilder(32768); int length = image.Capacity;
            Check(QueryFullProcessImageNameW(child.process, 0, image, ref length));
            if (!String.Equals(image.ToString(), executable, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("unexpected-child-image");
            Stage = "resume-verified-owned-child";
            if (ResumeThread(child.thread) != 1) throw new Win32Exception(Marshal.GetLastWin32Error());
            Stage = "wait-for-owned-child";
            if (WaitForSingleObject(child.process, 15 * 60 * 1000) != 0)
                throw new InvalidOperationException("owned-child-wait-failed");
            uint exit; Check(GetExitCodeProcess(child.process, out exit)); finished = true;
            Stage = "complete";
            return new Result { sourcePid = child.pid, sameSid = true, elevated = false, administrator = false, parentElevated = elevated,
                parentAdministrator = parentAdministrator, privilegeDropped = elevated, launchTokenMode = tokenMode, exitCode = exit };
        } finally {
            if (!finished && child.process != IntPtr.Zero) TerminateProcess(child.process, 1);
            if (childToken != IntPtr.Zero) CloseHandle(childToken);
            if (child.thread != IntPtr.Zero) CloseHandle(child.thread);
            if (child.process != IntPtr.Zero) CloseHandle(child.process);
            if (environment != IntPtr.Zero) Marshal.FreeHGlobal(environment);
            if (linked != IntPtr.Zero) CloseHandle(linked);
            if (current != IntPtr.Zero) CloseHandle(current);
        }
    }
}
'@

function Assert-NoReparsePoint([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    while ($null -ne $item) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse point refused.' }
        if ($item -is [IO.FileInfo]) { $item = $item.Directory } else { $item = $item.Parent }
    }
}

try {
    if ($SelfTest) {
        $probeRoot = Join-Path ([IO.Path]::GetTempPath()) ('cyberfi-owned-launch-' + [Guid]::NewGuid().ToString('N'))
        [void][IO.Directory]::CreateDirectory($probeRoot)
        $probeReport = Join-Path $probeRoot 'result.json'
        $probeValue = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('VMO8cmvDp2UgZGXEn2VyaTsgJVBBVEglICYgImFsxLFudMSxIgp5ZW5pIHNhdMSxcg=='))
        $env:CYBERFI_OWNED_LAUNCH_PROBE = $probeValue
        $env:CYBERFI_OWNED_LAUNCH_REPORT = $probeReport
        $probeCode = @'
$ErrorActionPreference='Stop'
$expected=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('VMO8cmvDp2UgZGXEn2VyaTsgJVBBVEglICYgImFsxLFudMSxIgp5ZW5pIHNhdMSxcg=='))
$match=([Environment]::GetEnvironmentVariable('CYBERFI_OWNED_LAUNCH_PROBE') -ceq $expected)
[IO.File]::WriteAllText($env:CYBERFI_OWNED_LAUNCH_REPORT,('{"environmentPreserved":'+$match.ToString().ToLowerInvariant()+'}'))
if(-not $match){exit 19}
exit 23
'@
        $probeExecutable = (Get-Process -Id $PID).Path
        try {
            $result = [CyberFiOwnedLaunch]::Run($probeExecutable, @('-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($probeCode))))
            $probe = Get-Content -LiteralPath $probeReport -Raw | ConvertFrom-Json
            if (-not $probe.environmentPreserved -or $result.exitCode -ne 23 -or -not $result.sameSid -or $result.elevated) { throw 'Owned launcher self-test failed.' }
            [pscustomobject]@{ success=$true; sameSid=$result.sameSid; elevated=$result.elevated; administrator=$result.administrator; parentElevated=$result.parentElevated; parentAdministrator=$result.parentAdministrator; privilegeDropped=$result.privilegeDropped; launchTokenMode=$result.launchTokenMode; creationApi=[CyberFiOwnedLaunch]::CreationApi; environmentPreserved=$true; exitCodePropagated=$true; guiLaunched=$false } | ConvertTo-Json -Compress
        } finally {
            Assert-NoReparsePoint $probeRoot
            if (Test-Path -LiteralPath $probeReport) {
                Assert-NoReparsePoint $probeReport
                [IO.File]::Delete($probeReport)
            }
            [IO.Directory]::Delete($probeRoot, $false)
        }
        exit 0
    }

    [CyberFiOwnedLaunch]::Stage = 'validate-owned-test-paths'
    if ([string]::IsNullOrEmpty($env:RUNNER_TEMP) -or [string]::IsNullOrEmpty($env:APPDATA)) { throw 'Hosted runner paths required.' }
    $expectedExecutable = [IO.Path]::GetFullPath((Join-Path $env:RUNNER_TEMP 'cyberfi-windows-auth-update\Applications\CyberFi\CyberFi.exe'))
    $expectedProfile = [IO.Path]::GetFullPath((Join-Path $env:APPDATA 'CyberFi'))
    if ([IO.Path]::GetFullPath($Executable) -ine $expectedExecutable -or [IO.Path]::GetFullPath($Profile) -ine $expectedProfile) { throw 'Exact owned test paths required.' }
    Assert-NoReparsePoint $expectedExecutable
    Assert-NoReparsePoint $expectedProfile
    if ($args.Count -ne 2 -or $args[0] -ine ('--user-data-dir=' + $expectedProfile) -or $args[1] -cne '--debug') { throw 'Exact existing owned Gym arguments required.' }
    [CyberFiOwnedLaunch]::Stage = 'validate-hidden-gym-environment'
    if ($env:HAPPY_DESKTOP_WINDOWS_HIDDEN -cne '1' -or $env:HAPPY_DESKTOP_DEBUG -cne '1' -or $env:HAPPY_DEBUG_RENDERER_PORT -cne '19486') { throw 'Existing hidden Gym environment required.' }
    $result = [CyberFiOwnedLaunch]::Run($expectedExecutable, [string[]]$args)
    $result | ConvertTo-Json -Compress
    exit ([int]$result.exitCode)
} catch {
    $nativeError = $null
    $cause = $_.Exception
    while ($null -ne $cause) {
        if ($cause -is [ComponentModel.Win32Exception]) { $nativeError = $cause.NativeErrorCode; break }
        $cause = $cause.InnerException
    }
    [Console]::Error.WriteLine(([pscustomobject]@{ success=$false; stage=[CyberFiOwnedLaunch]::Stage; nativeError=$nativeError; creationApi=[CyberFiOwnedLaunch]::CreationApi; launchTokenMode=[CyberFiOwnedLaunch]::TokenMode; selectedTokenVerified=[CyberFiOwnedLaunch]::SelectedTokenVerified } | ConvertTo-Json -Compress))
    exit 1
}
