param([switch]$SelfTest)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$report = [ordered]@{
    success = $false
    stage = 'hosted-runner-guard'
    nativeError = $null
    failureType = $null
    localAccountsError = $null
    accountCleanupError = $null
    fixtureSidVerified = $false
    elevated = $null
    administrator = $null
    mediumIntegrity = $null
    environmentPreserved = $false
    exitCodePropagated = $false
    guiLaunched = $false
    probeStarted = $false
    accountRemoved = $false
    fixtureRemoved = $false
}
$fixture = $null
$account = $null
$accountAttempted = $false
$nativeAttempted = $false
$password = $null

function Get-LocalAccountsFailure([Management.Automation.ErrorRecord]$Record) {
    $id = ([string]$Record.FullyQualifiedErrorId).Split(',')[0]
    $knownIds = @(
        'ParameterArgumentValidationError', 'ParameterArgumentTransformationError', 'NamedParameterNotFound',
        'UserExists', 'UserNotFound', 'GroupNotFound', 'MemberExists', 'AccessDenied', 'InvalidPassword', 'PasswordTooShort'
    )
    $category = [string]$Record.CategoryInfo.Category
    [ordered]@{
        id = if ($id -cin $knownIds) { $id } else { 'other' }
        type = if ($Record.Exception -is [Management.Automation.ParameterBindingException]) { 'parameter-binding' }
               elseif ($Record.Exception -is [ComponentModel.Win32Exception]) { 'win32' } else { 'other' }
        category = if ($category -cin @('InvalidArgument', 'InvalidData', 'InvalidOperation', 'ObjectNotFound', 'PermissionDenied', 'ResourceExists', 'SecurityError')) { $category } else { 'other' }
    }
}

function ConvertTo-NativeEnvironment([Collections.IDictionary]$Values) {
    $strings = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $Values.GetEnumerator()) {
        if ($entry.Key -isnot [string] -or $entry.Value -isnot [string]) {
            throw [ArgumentException]::new('The fixture environment requires string names and values.')
        }
        $strings.Add([string]$entry.Key, [string]$entry.Value)
    }
    return ,$strings
}

try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $SelfTest -or $env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_OS -cne 'Windows' -or
        $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:GITHUB_REPOSITORY -cne 'CyberfiTechh/CyberFi-Releases' -or
        $env:GITHUB_EVENT_NAME -cne 'workflow_dispatch' -or $env:GITHUB_RUN_ID -notmatch '^[1-9][0-9]*$' -or
        $identity.User.Value -notmatch '^S-1-5-21-([0-9]+-){3}500$' -or
        -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'An owned GitHub-hosted Windows preflight is required.'
    }
    $tempRoot = Get-Item -LiteralPath $env:RUNNER_TEMP
    if (-not $tempRoot.PSIsContainer -or $tempRoot.FullName -notmatch '^[A-Z]:\\a\\_temp$' -or
        ($tempRoot.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        [IO.Path]::GetDirectoryName($PSScriptRoot) -ine [IO.Path]::GetFullPath($env:GITHUB_WORKSPACE)) {
        throw 'The runner workspace or temporary directory is unexpected.'
    }

    $report.stage = 'compile-native-preflight'
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using System.Text;

public static class CyberFiStandardLaunch {
    public static string Stage = "initialize";
    public static bool TokenVerified, ImageVerified, ErrorModeRestored;
    public static uint? ResumeResult, WaitResult, ObservedExitCode, CleanupWaitResult;
    public static long? WaitElapsedMs;
    public static bool? TerminateSucceeded;
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct StartupInfo {
        public int size; public string reserved, desktop, title;
        public int x, y, width, height, columns, rows, fill, flags;
        public short show, reservedBytes; public IntPtr reservedData, stdin, stdout, stderr;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct ProcessInfo { public IntPtr process, thread; public uint pid, tid; }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CreateProcessWithLogonW(string user, string domain, IntPtr password, uint logonFlags,
        string application, StringBuilder command, uint creationFlags, IntPtr environment, string cwd,
        ref StartupInfo startup, out ProcessInfo process);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool GetTokenInformation(IntPtr token, int kind, IntPtr data, int bytes, out int required);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool QueryFullProcessImageNameW(IntPtr process, uint flags, StringBuilder path, ref int length);
    [DllImport("kernel32.dll", SetLastError = true)] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError = true)] static extern uint WaitForSingleObject(IntPtr process, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetExitCodeProcess(IntPtr process, out uint code);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")] static extern bool TerminateProcess(IntPtr process, uint code);
    [DllImport("kernel32.dll")] static extern uint GetErrorMode();
    [DllImport("kernel32.dll")] static extern uint SetErrorMode(uint mode);

    static void Check(bool ok) {
        if (!ok) throw new Win32Exception(Marshal.GetLastWin32Error());
    }
    static IntPtr TokenInfo(IntPtr token, int kind) {
        int bytes;
        GetTokenInformation(token, kind, IntPtr.Zero, 0, out bytes);
        if (bytes < 4 || bytes > 65536) throw new InvalidOperationException("unexpected-token-info-size");
        IntPtr data = Marshal.AllocHGlobal(bytes);
        try {
            Check(GetTokenInformation(token, kind, data, bytes, out bytes));
            return data;
        } catch {
            Marshal.FreeHGlobal(data);
            throw;
        }
    }
    static void VerifyStandardUser(IntPtr token, string expectedSid) {
        using (var identity = new WindowsIdentity(token)) {
            if (identity.User.Value != expectedSid ||
                new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator)) {
                throw new InvalidOperationException("owned-standard-user-required");
            }
        }
        IntPtr elevation = TokenInfo(token, 20);
        try {
            if (Marshal.ReadInt32(elevation) != 0) throw new InvalidOperationException("non-elevated-token-required");
        } finally { Marshal.FreeHGlobal(elevation); }

        IntPtr integrity = TokenInfo(token, 25);
        try {
            if (new SecurityIdentifier(Marshal.ReadIntPtr(integrity)).Value != "S-1-16-8192")
                throw new InvalidOperationException("medium-integrity-required");
        } finally { Marshal.FreeHGlobal(integrity); }
    }
    static IntPtr EnvironmentBlock(IDictionary<string, string> values) {
        var sorted = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in values) {
            string name = entry.Key, value = entry.Value;
            if (String.IsNullOrEmpty(name) || name.IndexOfAny(new char[] { '=', '\0' }) >= 0 || value == null || value.IndexOf('\0') >= 0)
                throw new InvalidOperationException("invalid-fixture-environment");
            sorted.Add(name, value);
        }
        var block = new StringBuilder();
        foreach (var entry in sorted) block.Append(entry.Key).Append('=').Append(entry.Value).Append('\0');
        return Marshal.StringToHGlobalUni(block.Append('\0').ToString());
    }
    public static uint Run(string user, SecureString password, string sid, string executable, string script, string cwd, IDictionary<string, string> values) {
        Stage = "validate-fixed-probe-paths";
        if (executable.IndexOf('"') >= 0 || script.IndexOf('"') >= 0)
            throw new InvalidOperationException("invalid-fixed-probe-path");
        Stage = "build-fixed-probe-command";
        var command = new StringBuilder("\"" + executable + "\" -NoLogo -NoProfile -NonInteractive -File \"" + script + "\"");
        if (command.Length >= 1024) throw new InvalidOperationException("probe-command-too-long");
        var startup = new StartupInfo { size = Marshal.SizeOf(typeof(StartupInfo)), flags = 1, show = 0 };
        ProcessInfo child = new ProcessInfo();
        IntPtr token = IntPtr.Zero, environment = IntPtr.Zero;
        bool exited = false;
        try {
            Stage = "allocate-unicode-environment";
            environment = EnvironmentBlock(values);
            Stage = "allocate-native-credential";
            IntPtr nativePassword = Marshal.SecureStringToGlobalAllocUnicode(password);
            try {
                Stage = "create-suspended-standard-user-probe";
                // The hosted runner experiment succeeded with logon flags zero and an unnamed desktop.
                const uint flags = 4 | 0x400 | 0x08000000; // Suspended, Unicode environment, no console window.
                const uint suppressErrorDialogs = 0x1 | 0x2;
                uint previousErrorMode = SetErrorMode(GetErrorMode() | suppressErrorDialogs);
                try {
                    Check(CreateProcessWithLogonW(user, ".", nativePassword, 0, executable, command, flags,
                        environment, cwd, ref startup, out child));
                } finally {
                    SetErrorMode(previousErrorMode);
                    ErrorModeRestored = GetErrorMode() == previousErrorMode;
                }
            } finally { Marshal.ZeroFreeGlobalAllocUnicode(nativePassword); }

            Stage = "verify-suspended-probe";
            Check(OpenProcessToken(child.process, 10, out token));
            VerifyStandardUser(token, sid);
            TokenVerified = true;
            var image = new StringBuilder(32768);
            int length = image.Capacity;
            Check(QueryFullProcessImageNameW(child.process, 0, image, ref length));
            if (!String.Equals(image.ToString(), executable, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("unexpected-probe-image");
            ImageVerified = true;
            if (!ErrorModeRestored) throw new InvalidOperationException("wrapper-error-mode-not-restored");

            Stage = "resume-verified-probe";
            ResumeResult = ResumeThread(child.thread);
            if (ResumeResult == UInt32.MaxValue) throw new Win32Exception(Marshal.GetLastWin32Error());
            if (ResumeResult != 1) throw new InvalidOperationException("unexpected-probe-suspend-count");

            Stage = "wait-for-verified-probe";
            var timer = Stopwatch.StartNew();
            WaitResult = WaitForSingleObject(child.process, 30000);
            int waitError = WaitResult == UInt32.MaxValue ? Marshal.GetLastWin32Error() : 0;
            WaitElapsedMs = timer.ElapsedMilliseconds;
            uint exitCode;
            bool observedExit = GetExitCodeProcess(child.process, out exitCode);
            if (observedExit) ObservedExitCode = exitCode;
            if (WaitResult == UInt32.MaxValue) throw new Win32Exception(waitError);
            if (WaitResult != 0) throw new InvalidOperationException("probe-wait-failed");
            exited = true;
            Check(observedExit);
            return exitCode;
        } finally {
            if (child.process != IntPtr.Zero && !exited) {
                if (WaitForSingleObject(child.process, 0) != 0) TerminateSucceeded = TerminateProcess(child.process, 1);
                CleanupWaitResult = WaitForSingleObject(child.process, 5000);
            }
            if (token != IntPtr.Zero) CloseHandle(token);
            if (child.thread != IntPtr.Zero) CloseHandle(child.thread);
            if (child.process != IntPtr.Zero) CloseHandle(child.process);
            if (environment != IntPtr.Zero) Marshal.FreeHGlobal(environment);
        }
    }
}
'@

    $report.stage = 'check-owned-account-name'
    $nonce = [Guid]::NewGuid().ToString('N')
    $accountName = 'cfprobe' + $nonce.Substring(0, 12)
    $description = 'cf-launch:' + $nonce
    if (Get-LocalUser -Name $accountName -ErrorAction SilentlyContinue) { throw 'The fixture account name already exists.' }
    $report.stage = 'generate-owned-account-credential'
    $random = [byte[]]::new(32)
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($random) } finally { $rng.Dispose() }
    $password = [Security.SecureString]::new()
    try {
        foreach ($character in ('Aa1!' + [Convert]::ToBase64String($random)).ToCharArray()) { $password.AppendChar($character) }
        $password.MakeReadOnly()
    } finally { [Array]::Clear($random, 0, $random.Length) }
    $accountAttempted = $true
    $report.stage = 'create-owned-standard-user'
    $account = New-LocalUser -Name $accountName -Password $password -Description $description -AccountExpires (Get-Date).AddMinutes(20)
    $report.stage = 'verify-owned-account-sid'
    $accountSid = [Security.Principal.SecurityIdentifier]::new([string]$account.SID)
    if ($accountSid.Value -ceq $identity.User.Value) { throw 'The fixture must have its own SID.' }
    $usersGroup = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
    $report.stage = 'read-standard-users-membership'
    if (-not (Get-LocalGroupMember -SID $usersGroup | Where-Object { [string]$_.SID -eq $accountSid.Value })) {
        $report.stage = 'add-standard-users-membership'
        Add-LocalGroupMember -SID $usersGroup -Member $accountSid.Value
    }

    $report.stage = 'prepare-owned-fixture'
    $fixture = New-Item -ItemType Directory -Path (Join-Path $tempRoot.FullName ('cyberfi-standard-launch-' + $nonce))
    $rule = [Security.AccessControl.FileSystemAccessRule]::new($accountSid, 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl = Get-Acl -LiteralPath $fixture.FullName
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $fixture.FullName -AclObject $acl
    $probe = Join-Path $fixture.FullName 'probe.ps1'
    $started = Join-Path $fixture.FullName 'started.flag'
    $receipt = Join-Path $fixture.FullName 'result.json'
    $probeSource = @'
$ErrorActionPreference = 'Stop'
[IO.File]::WriteAllText([IO.Path]::Combine($PSScriptRoot, 'started.flag'), '1')
$expected = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('VMO8cmvDp2UgZGXEn2VyaTsgJVBBVEglICYgImFsxLFudMSxIgp5ZW5pIHNhdMSxcg=='))
$preserved = [Environment]::GetEnvironmentVariable('CYBERFI_OWNED_LAUNCH_PROBE') -ceq $expected
$sidMatches = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ceq $env:CYBERFI_OWNED_LAUNCH_SID
$result = '{"environmentPreserved":' + $preserved.ToString().ToLowerInvariant() + ',"sidMatches":' + $sidMatches.ToString().ToLowerInvariant() + '}'
[IO.File]::WriteAllText((Join-Path $PSScriptRoot 'result.json'), $result)
if (-not $preserved -or -not $sidMatches) { exit 19 }
exit 23
'@
    [IO.File]::WriteAllText($probe, $probeSource)
    $systemDirectory = [Environment]::SystemDirectory
    $nativePowerShell = Join-Path $systemDirectory 'WindowsPowerShell\v1.0\powershell.exe'
    $windowsDirectory = [IO.Path]::GetDirectoryName($systemDirectory)
    $environment = @{
        SystemRoot = $windowsDirectory
        WINDIR = $windowsDirectory
        Path = $systemDirectory
        PSModulePath = Join-Path $systemDirectory 'WindowsPowerShell\v1.0\Modules'
        HOMEDRIVE = $fixture.FullName.Substring(0, 2)
        HOMEPATH = $fixture.FullName.Substring(2)
        USERPROFILE = $fixture.FullName
        TEMP = $fixture.FullName
        TMP = $fixture.FullName
        CYBERFI_OWNED_LAUNCH_SID = $accountSid.Value
        CYBERFI_OWNED_LAUNCH_PROBE = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('VMO8cmvDp2UgZGXEn2VyaTsgJVBBVEglICYgImFsxLFudMSxIgp5ZW5pIHNhdMSxcg=='))
    }

    $report.stage = 'normalize-probe-environment'
    $nativeEnvironment = ConvertTo-NativeEnvironment $environment
    $report.stage = 'native-launch'
    $nativeAttempted = $true
    $report.childExitCode = [CyberFiStandardLaunch]::Run($account.Name, $password, $accountSid.Value, $nativePowerShell, $probe, $fixture.FullName, $nativeEnvironment)
    $report.fixtureSidVerified = $true
    $report.elevated = $false
    $report.administrator = $false
    $report.mediumIntegrity = $true
    $report.stage = 'verify-probe-receipt'
    $report.receiptExists = [IO.File]::Exists($receipt)
    if (-not $report.receiptExists) { throw 'The child probe did not write its receipt.' }
    $receiptFile = Get-Item -LiteralPath $receipt
    if ($receiptFile.Length -gt 256 -or ($receiptFile.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'The child probe receipt is invalid.'
    }
    $result = Get-Content -LiteralPath $receipt -Raw | ConvertFrom-Json
    $report.environmentPreserved = $result.environmentPreserved -eq $true
    $report.exitCodePropagated = $report.childExitCode -eq 23
    $report.success = $report.environmentPreserved -and $report.exitCodePropagated -and $result.sidMatches -eq $true
} catch {
    if ($report.stage -eq 'native-launch' -and [CyberFiStandardLaunch]::Stage -ne 'initialize') { $report.stage = [CyberFiStandardLaunch]::Stage }
    if ($report.stage -in @('check-owned-account-name', 'create-owned-standard-user', 'read-standard-users-membership', 'add-standard-users-membership')) {
        $report.localAccountsError = Get-LocalAccountsFailure $_
    }
    for ($cause = $_.Exception; $null -ne $cause; $cause = $cause.InnerException) {
        $type = $cause.GetType().Name
        if ($type -cin @('ArgumentException', 'ArgumentNullException', 'InvalidCastException', 'InvalidOperationException', 'MethodException', 'MethodInvocationException', 'OutOfMemoryException', 'OverflowException', 'ParameterBindingException', 'ParameterBindingValidationException', 'Win32Exception')) {
            $report.failureType = $type
        }
        if ($cause -is [ComponentModel.Win32Exception]) { $report.nativeError = $cause.NativeErrorCode; break }
    }
} finally {
    if ($nativeAttempted) {
        $report.fixtureSidVerified = [CyberFiStandardLaunch]::TokenVerified
        if ($report.fixtureSidVerified) {
            $report.elevated = $false
            $report.administrator = $false
            $report.mediumIntegrity = $true
        }
        $report.imageVerified = [CyberFiStandardLaunch]::ImageVerified
        $report.errorModeRestored = [CyberFiStandardLaunch]::ErrorModeRestored
        $report.resumeResult = [CyberFiStandardLaunch]::ResumeResult
        $report.waitResult = [CyberFiStandardLaunch]::WaitResult
        $report.waitElapsedMs = [CyberFiStandardLaunch]::WaitElapsedMs
        $report.observedExitCode = [CyberFiStandardLaunch]::ObservedExitCode
        $report.terminateSucceeded = [CyberFiStandardLaunch]::TerminateSucceeded
        $report.cleanupWaitResult = [CyberFiStandardLaunch]::CleanupWaitResult
        $report.probeStarted = [IO.File]::Exists($started)
        $report.receiptExists = [IO.File]::Exists($receipt)
    }
    if ($accountAttempted) {
        try {
            $candidate = Get-LocalUser -Name $accountName -ErrorAction SilentlyContinue
            if ($candidate) {
                if ($candidate.Description -cne $description -or ($account -and $candidate.SID -ne $account.SID)) {
                    throw 'Fixture account identity changed.'
                }
                Remove-LocalUser -SID $candidate.SID
            }
            $report.accountRemoved = -not (Get-LocalUser -Name $accountName -ErrorAction SilentlyContinue)
        } catch {
            $report.accountRemoved = $false
            $report.accountCleanupError = Get-LocalAccountsFailure $_
        }
    }
    if ($fixture) {
        try {
            $directory = Get-Item -LiteralPath $fixture.FullName -Force
            if (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Fixture became a reparse point.' }
            foreach ($name in 'probe.ps1', 'started.flag', 'result.json') {
                $path = Join-Path $directory.FullName $name
                $item = Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
                if ($item) {
                    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Unexpected fixture entry.' }
                    [IO.File]::Delete($path)
                }
            }
            $report.remainingFixtureEntries = @(Get-ChildItem -LiteralPath $directory.FullName -Force | Select-Object -First 32).Count
            [IO.Directory]::Delete($directory.FullName, $false)
            $report.fixtureRemoved = $true
        } catch { $report.fixtureRemoved = $false }
    }
    if ($password) { $password.Dispose() }
    if ($identity) { $identity.Dispose() }
}
$report.success = $report.success -and $report.accountRemoved -and $report.fixtureRemoved
if ($report.success) { $report.stage = 'complete' }
[pscustomobject]$report | ConvertTo-Json -Compress
if ($report.success) { exit 0 }
exit 1
