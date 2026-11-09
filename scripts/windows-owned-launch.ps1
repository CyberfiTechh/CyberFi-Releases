param([switch]$SelfTest, [switch]$RunUpdate)
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
$profileHome = $null
$artifactRoot = $null
$portalEnvironment = @{}

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

function Get-OwnedEntry([string]$Path, [bool]$Directory) {
    $entry = Get-Item -LiteralPath $Path -Force
    if ($entry.FullName -ine [IO.Path]::GetFullPath($Path) -or $entry.PSIsContainer -ne $Directory -or
        ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Unexpected owned fixture entry.' }
    return $entry
}

function Get-FixtureEntries([IO.DirectoryInfo]$Directory) {
    foreach ($entry in Get-ChildItem -LiteralPath $Directory.FullName -Force) {
        $expected = Join-Path $Directory.FullName $entry.Name
        $checked = Get-OwnedEntry $expected $entry.PSIsContainer
        if ($checked.PSIsContainer) { Get-FixtureEntries $checked }
        $checked
    }
}

try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if ($SelfTest.IsPresent -eq $RunUpdate.IsPresent -or $env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_OS -cne 'Windows' -or
        $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:GITHUB_REPOSITORY -cne 'CyberfiTechh/CyberFi-Releases' -or
        $env:GITHUB_EVENT_NAME -cne 'workflow_dispatch' -or $env:GITHUB_RUN_ID -notmatch '^[1-9][0-9]*$' -or
        $identity.User.Value -notmatch '^S-1-5-21-([0-9]+-){3}500$' -or
        -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'An owned GitHub-hosted Windows preflight is required.'
    }
    $tempRoot = Get-OwnedEntry $env:RUNNER_TEMP $true
    $workspace = (Get-OwnedEntry $env:GITHUB_WORKSPACE $true).FullName
    $acceptance = if ($RunUpdate) { Join-Path $workspace 'acceptance' } else { $workspace }
    if ($tempRoot.FullName -notmatch '^[A-Z]:\\a\\_temp$' -or
        $PSScriptRoot -ine (Join-Path $acceptance 'scripts')) {
        throw 'The runner workspace or temporary directory is unexpected.'
    }
    if ($RunUpdate) {
        $report.mode = 'native-update'
        $report.Remove('guiLaunched')
        $report.stage = 'verify-update-ref'
        if ($env:GITHUB_REF -cne 'refs/heads/main' -or $env:GITHUB_SHA -cnotmatch '^[a-f0-9]{40}$') {
            throw 'The native update acceptance requires the reviewed Windows main workflow.'
        }
        $report.stage = 'verify-update-target'
        if ($env:ACCEPTANCE_SOURCE_SHA -cnotmatch '^[a-f0-9]{40}$' -or $env:TARGET -cne 'windows' -or $env:ARCH -cne 'x64') {
            throw 'Unexpected native update target or source revision.'
        }
        $report.stage = 'verify-update-credentials'
        foreach ($name in 'GH_TOKEN', 'CYBERAI_USERNAME', 'CYBERAI_PASSWORD') {
            $portalEnvironment[$name] = [Environment]::GetEnvironmentVariable($name)
            [Environment]::SetEnvironmentVariable($name, $null, 'Process')
        }
        if (-not $portalEnvironment.GH_TOKEN -or -not $portalEnvironment.CYBERAI_USERNAME -or
            $portalEnvironment.CYBERAI_USERNAME -ieq 'admin' -or $portalEnvironment.CYBERAI_PASSWORD.Length -lt 8) {
            throw 'The native update acceptance requires disposable portal credentials.'
        }
        $report.stage = 'verify-acceptance-checkout-path'
        $null = Get-OwnedEntry $acceptance $true
        $null = Get-OwnedEntry $PSScriptRoot $true
        $updateScript = (Get-OwnedEntry (Join-Path $PSScriptRoot 'verify-cyberai-windows-update.mjs') $false).FullName
        $report.stage = 'verify-upstream-checkout-path'
        $upstream = (Get-OwnedEntry (Join-Path $workspace 'upstream') $true).FullName
        $report.stage = 'resolve-update-git'
        # Get-Command with a type filter may return several PATH matches.
        $git = (Get-Command git.exe -CommandType Application | Select-Object -First 1).Source
        $report.stage = 'verify-acceptance-head'
        $acceptanceHead = & $git -C $acceptance rev-parse HEAD 2>$null
        $report.gitExitCode = $LASTEXITCODE
        if ($LASTEXITCODE -ne 0 -or $acceptanceHead -cne $env:GITHUB_SHA) { throw 'Unexpected acceptance revision.' }
        $report.stage = 'verify-acceptance-script-diff'
        & $git -C $acceptance diff --quiet HEAD -- scripts/windows-owned-launch.ps1 scripts/verify-cyberai-windows-update.mjs 2>$null
        $report.gitExitCode = $LASTEXITCODE
        if ($LASTEXITCODE -ne 0) { throw 'The reviewed acceptance scripts were modified.' }
        $report.stage = 'verify-upstream-head'
        $upstreamHead = & $git -C $upstream rev-parse HEAD 2>$null
        $report.gitExitCode = $LASTEXITCODE
        if ($LASTEXITCODE -ne 0 -or $upstreamHead -cne 'c9feffb54cdb3591220dafced4070e118e3d297a') { throw 'Unexpected upstream revision.' }
        $report.Remove('gitExitCode')
        $report.stage = 'resolve-update-node'
        $nodeCommand = Get-Command node.exe -CommandType Application | Select-Object -First 1
        $node = (Get-OwnedEntry $nodeCommand.Source $false).FullName
        $report.stage = 'verify-node-tool-cache-root'
        $toolRoot = (Get-OwnedEntry $env:RUNNER_TOOL_CACHE $true).FullName
        $report.stage = 'verify-node-tool-cache-entry'
        if ($node -notmatch ('^' + [regex]::Escape($toolRoot) + '\\node\\24\.\d+\.\d+\\x64\\node\.exe$')) { throw 'Unexpected Node tool cache entry.' }
        $report.stage = 'verify-update-ffmpeg-entry'
        $ffmpeg = (Get-OwnedEntry $env:HAPPY_DESKTOP_GYM_FFMPEG $false).FullName
        $report.stage = 'verify-update-ffmpeg-shared-path'
        if (-not ($ffmpeg.StartsWith($workspace + '\', [StringComparison]::OrdinalIgnoreCase) -or
                  $ffmpeg.StartsWith($tempRoot.FullName + '\', [StringComparison]::OrdinalIgnoreCase))) {
            throw 'The native recorder must be in a shared fixture path.'
        }
        $report.stage = 'create-update-artifact-root'
        $artifactPath = Join-Path $tempRoot.FullName 'cyberfi-windows-owned-evidence'
        $artifactRoot = New-Item -ItemType Directory -Path $artifactPath
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
    [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool GetProfilesDirectoryW(StringBuilder path, ref uint size);
    [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool DeleteProfileW(string sid, string profile, string computer);

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
    public static string ProfilesDirectory() {
        var path = new StringBuilder(32768);
        uint size = (uint)path.Capacity;
        Check(GetProfilesDirectoryW(path, ref size));
        return path.ToString();
    }
    public static void RemoveOwnedProfile(string sid, string path) {
        Check(DeleteProfileW(sid, path, null));
    }
    static IntPtr EnvironmentBlock(IDictionary<string, string> values, out int bytes) {
        var sorted = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in values) {
            string name = entry.Key, value = entry.Value;
            if (String.IsNullOrEmpty(name) || name.IndexOfAny(new char[] { '=', '\0' }) >= 0 || value == null || value.IndexOf('\0') >= 0)
                throw new InvalidOperationException("invalid-fixture-environment");
            sorted.Add(name, value);
        }
        var block = new StringBuilder();
        foreach (var entry in sorted) block.Append(entry.Key).Append('=').Append(entry.Value).Append('\0');
        block.Append('\0');
        bytes = checked((block.Length + 1) * 2);
        return Marshal.StringToHGlobalUni(block.ToString());
    }
    static string QuotePath(string path) {
        if (String.IsNullOrEmpty(path) || path.IndexOfAny(new char[] { '"', '\0' }) >= 0 || path.EndsWith("\\"))
            throw new InvalidOperationException("invalid-fixed-child-path");
        return "\"" + path + "\"";
    }
    public static uint RunProbe(string user, SecureString password, string sid, string executable, string script, string cwd,
        IDictionary<string, string> values, bool loadProfile) {
        return Run(user, password, sid, executable, QuotePath(executable) + " -NoLogo -NoProfile -NonInteractive -File " + QuotePath(script),
            cwd, values, loadProfile, loadProfile ? 120000u : 30000u);
    }
    public static uint RunUpdate(string user, SecureString password, string sid, string executable, string script, string cwd,
        IDictionary<string, string> values) {
        return Run(user, password, sid, executable, QuotePath(executable) + " --import tsx " + QuotePath(script) + " " + QuotePath(cwd),
            cwd, values, true, 27 * 60 * 1000);
    }
    static uint Run(string user, SecureString password, string sid, string executable, string commandLine, string cwd,
        IDictionary<string, string> values, bool loadProfile, uint timeout) {
        TokenVerified = ImageVerified = ErrorModeRestored = false;
        ResumeResult = WaitResult = ObservedExitCode = CleanupWaitResult = null;
        WaitElapsedMs = null;
        TerminateSucceeded = null;
        Stage = "build-fixed-child-command";
        var command = new StringBuilder(commandLine);
        if (command.Length >= 1024) throw new InvalidOperationException("child-command-too-long");
        var startup = new StartupInfo { size = Marshal.SizeOf(typeof(StartupInfo)), flags = 1, show = 0 };
        ProcessInfo child = new ProcessInfo();
        IntPtr token = IntPtr.Zero, environment = IntPtr.Zero;
        int environmentBytes = 0;
        bool exited = false;
        try {
            Stage = "allocate-unicode-environment";
            environment = EnvironmentBlock(values, out environmentBytes);
            Stage = "allocate-native-credential";
            IntPtr nativePassword = Marshal.SecureStringToGlobalAllocUnicode(password);
            try {
                Stage = "create-suspended-standard-user-child";
                const uint flags = 4 | 0x400 | 0x08000000; // Suspended, Unicode environment, no console window.
                const uint logonWithProfile = 1;
                const uint suppressErrorDialogs = 0x1 | 0x2;
                uint previousErrorMode = SetErrorMode(GetErrorMode() | suppressErrorDialogs);
                try {
                    Check(CreateProcessWithLogonW(user, ".", nativePassword, loadProfile ? logonWithProfile : 0, executable, command, flags,
                        environment, cwd, ref startup, out child));
                } finally {
                    SetErrorMode(previousErrorMode);
                    ErrorModeRestored = GetErrorMode() == previousErrorMode;
                }
            } finally {
                Marshal.ZeroFreeGlobalAllocUnicode(nativePassword);
                for (int offset = 0; offset < environmentBytes; offset += 2) Marshal.WriteInt16(environment, offset, 0);
                Marshal.FreeHGlobal(environment);
                environment = IntPtr.Zero;
            }

            Stage = "verify-suspended-child";
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

            Stage = "resume-verified-child";
            ResumeResult = ResumeThread(child.thread);
            if (ResumeResult == UInt32.MaxValue) throw new Win32Exception(Marshal.GetLastWin32Error());
            if (ResumeResult != 1) throw new InvalidOperationException("unexpected-probe-suspend-count");

            Stage = "wait-for-verified-child";
            var timer = Stopwatch.StartNew();
            WaitResult = WaitForSingleObject(child.process, timeout);
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
    $account = New-LocalUser -Name $accountName -Password $password -Description $description -AccountExpires (Get-Date).AddMinutes(45)
    $report.stage = 'verify-owned-account-sid'
    $accountSid = [Security.Principal.SecurityIdentifier]::new([string]$account.SID)
    if ($accountSid.Value -ceq $identity.User.Value) { throw 'The fixture must have its own SID.' }
    $usersGroup = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
    $report.stage = 'read-standard-users-membership'
    if (-not (Get-LocalGroupMember -SID $usersGroup | Where-Object { [string]$_.SID -eq $accountSid.Value })) {
        $report.stage = 'add-standard-users-membership'
        Add-LocalGroupMember -SID $usersGroup -Member $accountSid.Value
    }
    if ($RunUpdate) {
        $report.stage = 'verify-profile-initially-absent'
        $profiles = (Get-OwnedEntry ([CyberFiStandardLaunch]::ProfilesDirectory()) $true).FullName
        $expectedHome = Join-Path $profiles $account.Name
        if ((Test-Path -LiteralPath $expectedHome) -or (Get-CimInstance Win32_UserProfile -Filter "SID='$($accountSid.Value)'")) {
            throw 'The synthetic account must start without a profile.'
        }
        $profileHome = $expectedHome
    }

    $report.stage = 'prepare-owned-fixture'
    $fixture = New-Item -ItemType Directory -Path (Join-Path $tempRoot.FullName ('cyberfi-standard-launch-' + $nonce))
    $rule = [Security.AccessControl.FileSystemAccessRule]::new($accountSid, 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl = Get-Acl -LiteralPath $fixture.FullName
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $fixture.FullName -AclObject $acl
    $scratch = (New-Item -ItemType Directory -Path (Join-Path $fixture.FullName 'scratch')).FullName
    $runRoot = (New-Item -ItemType Directory -Path (Join-Path $fixture.FullName 'run')).FullName
    $probe = Join-Path $fixture.FullName 'probe.ps1'
    $started = Join-Path $fixture.FullName 'started.flag'
    $receipt = Join-Path $fixture.FullName 'result.json'
    $probeSource = @'
$ErrorActionPreference = 'Stop'
[IO.File]::WriteAllText([IO.Path]::Combine($PSScriptRoot, 'started.flag'), '1')
$expected = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('VMO8cmvDp2UgZGXEn2VyaTsgJVBBVEglICYgImFsxLFudMSxIgp5ZW5pIHNhdMSxcg=='))
$preserved = [Environment]::GetEnvironmentVariable('CYBERFI_OWNED_LAUNCH_PROBE') -ceq $expected
$sidMatches = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ceq $env:CYBERFI_OWNED_LAUNCH_SID
$result = @{ environmentPreserved = $preserved; sidMatches = $sidMatches }
if ($env:CYBERFI_OWNED_LAUNCH_PROFILE -ceq '1') {
    $result.home = [Environment]::GetFolderPath('UserProfile')
    $result.roaming = [Environment]::GetFolderPath('ApplicationData', 'Create')
    $result.local = [Environment]::GetFolderPath('LocalApplicationData', 'Create')
    Add-Type -AssemblyName System.Security
    $data = [Text.Encoding]::UTF8.GetBytes($expected)
    $scope = [Security.Cryptography.DataProtectionScope]::CurrentUser
    $encrypted = [Security.Cryptography.ProtectedData]::Protect($data, $null, $scope)
    $decoded = [Security.Cryptography.ProtectedData]::Unprotect($encrypted, $null, $scope)
    $result.dpapi = [Text.Encoding]::UTF8.GetString($decoded) -ceq $expected
}
[IO.File]::WriteAllText((Join-Path $PSScriptRoot 'result.json'), ($result | ConvertTo-Json -Compress))
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
        TEMP = $scratch
        TMP = $scratch
        CYBERFI_OWNED_LAUNCH_SID = $accountSid.Value
        CYBERFI_OWNED_LAUNCH_PROBE = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('VMO8cmvDp2UgZGXEn2VyaTsgJVBBVEglICYgImFsxLFudMSxIgp5ZW5pIHNhdMSxcg=='))
    }
    if ($RunUpdate) {
        $environment.CYBERFI_OWNED_LAUNCH_PROFILE = '1'
        $environment.USERPROFILE = $profileHome
        $environment.HOMEDRIVE = $profileHome.Substring(0, 2)
        $environment.HOMEPATH = $profileHome.Substring(2)
        $environment.APPDATA = Join-Path $profileHome 'AppData\Roaming'
        $environment.LOCALAPPDATA = Join-Path $profileHome 'AppData\Local'
    }

    $report.stage = 'normalize-probe-environment'
    $nativeEnvironment = ConvertTo-NativeEnvironment $environment
    $report.stage = 'native-launch'
    $nativeAttempted = $true
    $report.childExitCode = [CyberFiStandardLaunch]::RunProbe($account.Name, $password, $accountSid.Value, $nativePowerShell, $probe, $fixture.FullName, $nativeEnvironment, $RunUpdate.IsPresent)
    $report.fixtureSidVerified = $true
    $report.elevated = $false
    $report.administrator = $false
    $report.mediumIntegrity = $true
    $report.stage = 'verify-probe-receipt'
    $report.receiptExists = [IO.File]::Exists($receipt)
    if (-not $report.receiptExists) { throw 'The child probe did not write its receipt.' }
    $receiptFile = Get-Item -LiteralPath $receipt
    if ($receiptFile.Length -gt 4096 -or ($receiptFile.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'The child probe receipt is invalid.'
    }
    $result = Get-Content -LiteralPath $receipt -Raw | ConvertFrom-Json
    $report.environmentPreserved = $result.environmentPreserved -eq $true
    $report.exitCodePropagated = $report.childExitCode -eq 23
    $probePassed = $report.environmentPreserved -and $report.exitCodePropagated -and $result.sidMatches -eq $true
    if (-not $RunUpdate) {
        $report.success = $probePassed
    } else {
        $report.stage = 'verify-real-profile-and-dpapi'
        $actualProfile = Get-CimInstance Win32_UserProfile -Filter "SID='$($accountSid.Value)'"
        if (-not $probePassed -or $result.dpapi -ne $true -or $actualProfile.SID -cne $accountSid.Value -or $actualProfile.Special -ne $false -or
            $actualProfile.LocalPath -ine $profileHome -or $result.home -ine $profileHome -or
            $result.roaming -ine $environment.APPDATA -or $result.local -ine $environment.LOCALAPPDATA) {
            throw 'The standard user did not receive its own native profile.'
        }
        $null = Get-OwnedEntry $profileHome $true
        $null = Get-OwnedEntry (Join-Path $profileHome 'AppData') $true
        $null = Get-OwnedEntry $environment.APPDATA $true
        $null = Get-OwnedEntry $environment.LOCALAPPDATA $true
        $report.profileAndDpapiVerified = $true

        $report.stage = 'prepare-explicit-update-environment'
        $environment.Remove('CYBERFI_OWNED_LAUNCH_PROBE')
        $environment.Remove('CYBERFI_OWNED_LAUNCH_SID')
        $environment.Remove('CYBERFI_OWNED_LAUNCH_PROFILE')
        $environment.Path = @((Split-Path -Parent $node), (Split-Path -Parent $git), $systemDirectory, $windowsDirectory, (Split-Path -Parent $nativePowerShell)) -join ';'
        $environment.HOME = $profileHome
        $environment.RUNNER_TEMP = $runRoot
        $environment.USERNAME = $account.Name
        $environment.USERDOMAIN = $env:COMPUTERNAME
        $environment.CYBERFI_TEST_EXPECTED_SID = $accountSid.Value
        $environment.HAPPY_DESKTOP_GYM_FFMPEG = $ffmpeg
        foreach ($name in 'SystemDrive', 'ComSpec', 'PATHEXT', 'ProgramFiles', 'ProgramFiles(x86)', 'ProgramW6432', 'CommonProgramFiles',
            'CommonProgramFiles(x86)', 'CommonProgramW6432', 'ProgramData', 'ALLUSERSPROFILE', 'PUBLIC', 'COMPUTERNAME', 'OS',
            'PROCESSOR_ARCHITECTURE', 'PROCESSOR_IDENTIFIER', 'NUMBER_OF_PROCESSORS', 'SESSIONNAME', 'GITHUB_ACTIONS', 'GITHUB_REPOSITORY',
            'GITHUB_REF', 'GITHUB_WORKSPACE', 'RUNNER_ENVIRONMENT', 'TARGET', 'ARCH', 'ACCEPTANCE_SOURCE_SHA') {
            $value = [Environment]::GetEnvironmentVariable($name)
            if ($null -ne $value) { $environment[$name] = $value }
        }
        foreach ($entry in $portalEnvironment.GetEnumerator()) { $environment[$entry.Key] = $entry.Value }
        $portalEnvironment.Clear()
        $updateEnvironment = ConvertTo-NativeEnvironment $environment
        $report.stage = 'native-launch'
        try {
            $report.updateExitCode = [CyberFiStandardLaunch]::RunUpdate($account.Name, $password, $accountSid.Value, $node, $updateScript, $upstream, $updateEnvironment)
        } finally {
            $updateEnvironment.Clear()
            $environment.Clear()
        }
        $report.stage = 'verify-update-exit'
        $report.success = $report.updateExitCode -eq 0
    }
} catch {
    if ($report.stage -eq 'native-launch' -and [CyberFiStandardLaunch]::Stage -ne 'initialize') { $report.stage = [CyberFiStandardLaunch]::Stage }
    if ($report.stage -in @('check-owned-account-name', 'create-owned-standard-user', 'read-standard-users-membership', 'add-standard-users-membership')) {
        $report.localAccountsError = Get-LocalAccountsFailure $_
    }
    for ($cause = $_.Exception; $null -ne $cause; $cause = $cause.InnerException) {
        $type = $cause.GetType().Name
        if ($type -cin @('ArgumentException', 'ArgumentNullException', 'CommandNotFoundException', 'IOException', 'InvalidCastException', 'InvalidOperationException', 'ItemNotFoundException', 'MethodException', 'MethodInvocationException', 'OutOfMemoryException', 'OverflowException', 'ParameterBindingException', 'ParameterBindingValidationException', 'RuntimeException', 'UnauthorizedAccessException', 'Win32Exception')) {
            $report.failureType = $type
        }
        if ($cause -is [ComponentModel.Win32Exception]) { $report.nativeError = $cause.NativeErrorCode; break }
    }
} finally {
    $portalEnvironment.Clear()
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
    if ($RunUpdate -and $profileHome) {
        $report.profileRemoved = $false
        try {
            for ($attempt = 0; $attempt -lt 10; $attempt++) {
                $candidateProfile = Get-CimInstance Win32_UserProfile -Filter "SID='$($accountSid.Value)'"
                if (-not $candidateProfile -or -not $candidateProfile.Loaded) { break }
                Start-Sleep -Milliseconds 500
            }
            if ($candidateProfile) {
                if ($candidateProfile.SID -cne $accountSid.Value -or $candidateProfile.Special -ne $false -or
                    $candidateProfile.Loaded -ne $false -or $candidateProfile.LocalPath -ine $profileHome) {
                    throw 'The synthetic profile is not safe to remove.'
                }
                $null = Get-OwnedEntry $profileHome $true
                [CyberFiStandardLaunch]::RemoveOwnedProfile($accountSid.Value, $profileHome)
            }
            $report.profileRemoved = -not (Test-Path -LiteralPath $profileHome) -and
                -not (Get-CimInstance Win32_UserProfile -Filter "SID='$($accountSid.Value)'")
        } catch { $report.profileRemoved = $false }
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
            $ownedRoot = Join-Path $tempRoot.FullName ('cyberfi-standard-launch-' + $nonce)
            if ($nonce -cnotmatch '^[a-f0-9]{32}$' -or $fixture.FullName -ine $ownedRoot) { throw 'Unexpected fixture root.' }
            $directory = Get-OwnedEntry $ownedRoot $true
            if ($RunUpdate -and $artifactRoot) {
                $report.evidencePreserved = $false
                $runDirectory = Get-OwnedEntry (Join-Path $directory.FullName 'run') $true
                $testRoot = Join-Path $runDirectory.FullName 'cyberfi-windows-auth-update'
                if (Test-Path -LiteralPath $testRoot) {
                    $null = Get-OwnedEntry $testRoot $true
                    $sourceEvidence = Join-Path $testRoot 'evidence'
                    if (Test-Path -LiteralPath $sourceEvidence) {
                        $sourceEvidence = (Get-OwnedEntry $sourceEvidence $true).FullName
                        foreach ($name in 'automatic-update.json', 'actual-source-update.webm', 'actual-auto-reopened-target.webm', 'authenticated-target.png', 'failure.png') {
                            $path = Join-Path $sourceEvidence $name
                            if (Test-Path -LiteralPath $path) {
                                $item = Get-OwnedEntry $path $false
                                [IO.File]::Copy($item.FullName, (Join-Path $artifactRoot.FullName $name), $false)
                            }
                        }
                        $report.evidencePreserved = [IO.File]::Exists((Join-Path $artifactRoot.FullName 'automatic-update.json'))
                    }
                }
            }
            if (-not $report.accountRemoved -or ($RunUpdate -and -not $report.profileRemoved)) { throw 'The synthetic account or profile is still in use.' }
            # Validate the full tree before deletion and recheck each literal entry.
            # The walk emits children first and never follows reparse points.
            $entries = @(Get-FixtureEntries $directory)
            foreach ($entry in $entries) {
                $checked = Get-OwnedEntry $entry.FullName $entry.PSIsContainer
                if ($checked.PSIsContainer) { [IO.Directory]::Delete($checked.FullName, $false) }
                else { [IO.File]::Delete($checked.FullName) }
            }
            [IO.Directory]::Delete($directory.FullName, $false)
            $report.fixtureRemoved = $true
        } catch {
            $report.fixtureRemoved = $false
            $report.fixtureCleanupFailureType = $_.Exception.GetType().Name
        }
    }
    if ($password) { $password.Dispose() }
    if ($identity) { $identity.Dispose() }
}
$report.success = $report.success -and $report.accountRemoved -and $report.fixtureRemoved
if ($RunUpdate) { $report.success = $report.success -and $report.profileRemoved -and $report.evidencePreserved }
if ($report.success) { $report.stage = 'complete' }
$json = [pscustomobject]$report | ConvertTo-Json -Compress
if ($artifactRoot) { [IO.File]::WriteAllText((Join-Path $artifactRoot.FullName 'owned-launch.json'), $json) }
$json
if ($report.success) { exit 0 }
exit 1
