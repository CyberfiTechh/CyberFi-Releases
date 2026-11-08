param(
    [switch]$SelfCheck,
    [ValidateSet('preflight', 'failure')][string]$Phase = 'preflight',
    [string]$RunnerTemp = $env:RUNNER_TEMP
)
$ErrorActionPreference = 'Stop'

# Test infrastructure only: never seed the application's runtime, HOME, registry or MCP config.
function Assert-DiagnosticPath([string]$Root, [string]$Path) {
    $base = [IO.Path]::GetFullPath($Root).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $target = [IO.Path]::GetFullPath($Path)
    if (-not $target.StartsWith($base + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Diagnostic path escapes the owned temporary directory.'
    }
    $cursor = $target
    while ($cursor.Length -gt $base.Length) {
        if ((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Diagnostic path traverses a reparse point.'
        }
        $cursor = [IO.Path]::GetDirectoryName($cursor)
    }
}
function Safe-DiagnosticText([string]$Text) {
    # Exceptions can contain redirect URLs. Retain origin/path, never signed query strings.
    return [regex]::Replace($Text, 'https?://[^\s"''<>]+', {
        param($Match)
        try { return ([uri]$Match.Value).GetLeftPart([UriPartial]::Path) } catch { return '[URL omitted]' }
    })
}
function Assert-ArchiveEntries([string]$Listing) {
    if ([string]::IsNullOrWhiteSpace($Listing)) { throw 'Archive listing is empty.' }
    foreach ($entry in ($Listing -split '\r?\n' | Where-Object { $_ })) {
        $normalized = $entry.Replace('\', '/')
        if ($normalized.StartsWith('/') -or $normalized.Contains(':') -or ($normalized.Split('/') -contains '..')) {
            throw 'Archive contains an unsafe extraction path.'
        }
    }
}
function Invoke-DiagnosticCommand([string]$Command, [string[]]$Arguments, [string]$WorkingDirectory) {
    $start = [Diagnostics.ProcessStartInfo]::new($Command)
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.WorkingDirectory = $WorkingDirectory
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $process = [Diagnostics.Process]::Start($start)
    try {
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(120000)) {
            $process.Kill($true)
            throw 'Diagnostic command exceeded 120 seconds.'
        }
        return [ordered]@{ exitCode = $process.ExitCode; durationMs = $watch.ElapsedMilliseconds
            stdout = Safe-DiagnosticText $stdout.GetAwaiter().GetResult()
            stderr = Safe-DiagnosticText $stderr.GetAwaiter().GetResult() }
    } finally { $process.Dispose() }
}
function Invoke-ArchiveDownload($Archive, [string]$Destination, $Events, [scriptblock]$Request = {
    param($Url, $Output)
    Invoke-WebRequest -Uri $Url -Headers @{ accept = 'application/octet-stream' } -OutFile $Output -PassThru -TimeoutSec 120
}) {
    foreach ($url in @($Archive.url, $Archive.fallbackUrl)) {
        $address = [uri]$url
        if ($address.Scheme -ne 'https' -or $address.Host -notin @('github.com', 'api.github.com') -or $address.Query -or $address.UserInfo) {
            throw 'Untrusted diagnostic download URL.'
        }
        $watch = [Diagnostics.Stopwatch]::StartNew()
        $event = [ordered]@{ url = $address.GetLeftPart([UriPartial]::Path); status = $null; durationMs = 0 }
        $Events.Add($event)
        try {
            $response = & $Request $url $Destination
            $event.status = [int]$response.StatusCode
            $event.contentType = [string]$response.Headers['Content-Type']
            $event.contentLength = [string]$response.Headers['Content-Length']
            if ($event.status -ne 200) { throw 'Download did not return HTTP 200.' }
        } catch {
            if ($_.Exception.Response) { $event.status = [int]$_.Exception.Response.StatusCode }
            $event.error = Safe-DiagnosticText $_.Exception.Message
            if ($url -eq $Archive.fallbackUrl) { throw }
            continue
        } finally { $event.durationMs = $watch.ElapsedMilliseconds }
        $event.bytes = (Get-Item -LiteralPath $Destination).Length
        if ($event.bytes -gt 64MB) { throw 'Diagnostic dependency exceeds the 64 MiB size limit.' }
        $event.sha256 = (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($event.sha256 -cne $Archive.sha256) { throw 'Downloaded dependency failed the pinned SHA-256 check.' }
        return
    }
}
function Original-CacheInventory([string]$TemporaryRoot) {
    $records = [Collections.Generic.List[object]]::new()
    foreach ($run in (Get-ChildItem -LiteralPath $TemporaryRoot -Directory -Filter 'cyberfi-windows-mcp-*')) {
        Assert-DiagnosticPath $TemporaryRoot $run.FullName
        $runtime = Join-Path $run.FullName 'home/.pdr-kocum-agent/mcp-runtime/runtimes'
        $record = [ordered]@{ run = $run.Name; runtimeExists = Test-Path -LiteralPath $runtime; files = @() }
        if ($record.runtimeExists) {
            Assert-DiagnosticPath $TemporaryRoot $runtime
            $files = [Collections.Generic.List[object]]::new()
            foreach ($relative in @('uv-win32-x64/.cyberfi-runtime-sha256', 'python-win32-x64/.cyberfi-runtime-sha256', 'uv-win32-x64/uv.exe', 'python-win32-x64/python/python.exe')) {
                $path = Join-Path $runtime $relative
                Assert-DiagnosticPath $TemporaryRoot $path
                $item = [ordered]@{ relativePath = $relative; exists = Test-Path -LiteralPath $path }
                if ($item.exists) {
                    $item.bytes = (Get-Item -LiteralPath $path).Length
                    $item.sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
                    if ($relative.EndsWith('.cyberfi-runtime-sha256') -and $item.bytes -le 128) { $item.marker = [IO.File]::ReadAllText($path) }
                }
                $files.Add($item)
            }
            $downloads = Join-Path $runtime 'downloads'
            if (Test-Path -LiteralPath $downloads) {
                Assert-DiagnosticPath $TemporaryRoot $downloads
                foreach ($archive in (Get-ChildItem -LiteralPath $downloads -File | Where-Object { $_.Name -match '^(uv-|cpython-)' })) {
                    Assert-DiagnosticPath $TemporaryRoot $archive.FullName
                    $files.Add([ordered]@{ relativePath = 'downloads/' + $archive.Name; exists = $true; bytes = $archive.Length
                        sha256 = (Get-FileHash -LiteralPath $archive.FullName -Algorithm SHA256).Hash.ToLowerInvariant() })
                }
            }
            $record.files = $files.ToArray()
        }
        $records.Add($record)
    }
    return $records.ToArray()
}

if ($SelfCheck) {
    $testRoot = Join-Path ([IO.Path]::GetTempPath()) ('cyberfi-python-selfcheck-' + [guid]::NewGuid())
    New-Item -ItemType Directory -Path $testRoot | Out-Null
    Assert-DiagnosticPath $testRoot (Join-Path $testRoot 'safe/file')
    foreach ($bad in @('../escape', '/absolute', 'C:/absolute', 'a/../../escape', '\\host\share')) {
        $rejected = $false
        try { Assert-ArchiveEntries $bad } catch { $rejected = $true }
        if (-not $rejected) { throw "Unsafe archive path accepted: $bad" }
    }
    $rejected = $false
    try { Assert-DiagnosticPath $testRoot ($testRoot + '-neighbor/file') } catch { $rejected = $true }
    if (-not $rejected) { throw 'Sibling-prefix path accepted.' }
    $payload = [Text.Encoding]::UTF8.GetBytes('mock archive')
    $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($payload)).ToLowerInvariant()
    $archive = @{ url = 'https://github.com/astral-sh/uv/mock'; fallbackUrl = 'https://api.github.com/repos/astral-sh/uv/mock'; sha256 = $hash }
    $events = [Collections.Generic.List[object]]::new()
    $mock = { param($url, $path); if ($url.StartsWith('https://github.com/')) { return @{ StatusCode = 404; Headers = @{} } }; [IO.File]::WriteAllBytes($path, $payload); return @{ StatusCode = 200; Headers = @{} } }
    Invoke-ArchiveDownload $archive (Join-Path $testRoot 'mock.bin') $events $mock
    if ($events.Count -ne 2 -or $events[0].status -ne 404 -or $events[1].sha256 -cne $hash) { throw 'Mock HTTP fallback ledger failed.' }
    $archive.sha256 = '0' * 64
    $rejected = $false
    try { Invoke-ArchiveDownload $archive (Join-Path $testRoot 'bad.bin') ([Collections.Generic.List[object]]::new()) $mock } catch { $rejected = $true }
    if (-not $rejected) { throw 'Incorrect download digest accepted.' }
    if ((Safe-DiagnosticText 'https://example.com/asset?sig=secret') -match 'secret') { throw 'Signed URL query leaked.' }
    $fixtureRuntime = Join-Path $testRoot 'cyberfi-windows-mcp-test/home/.pdr-kocum-agent/mcp-runtime/runtimes'
    $fixtureUv = Join-Path $fixtureRuntime 'uv-win32-x64'
    New-Item -ItemType Directory -Path $fixtureUv -Force | Out-Null
    $fixtureMarker = Join-Path $fixtureUv '.cyberfi-runtime-sha256'
    [IO.File]::WriteAllText($fixtureMarker, $hash)
    $before = (Get-FileHash -LiteralPath $fixtureMarker -Algorithm SHA256).Hash
    $inventory = @(Original-CacheInventory $testRoot)
    if ($inventory.Count -ne 1 -or $inventory[0].files[0].marker -cne $hash -or
        (Get-FileHash -LiteralPath $fixtureMarker -Algorithm SHA256).Hash -cne $before) { throw 'Original cache inventory changed or omitted evidence.' }
    $valid = Join-Path $testRoot 'valid.txt'
    [IO.File]::WriteAllText($valid, 'safe extraction probe')
    $packed = Join-Path $testRoot 'valid.tar'
    $pack = Invoke-DiagnosticCommand 'tar' @('-cf', $packed, '-C', $testRoot, 'valid.txt') $testRoot
    $list = Invoke-DiagnosticCommand 'tar' @('-tf', $packed) $testRoot
    Assert-ArchiveEntries $list.stdout
    $extract = Join-Path $testRoot 'extracted'
    New-Item -ItemType Directory -Path $extract | Out-Null
    $unpack = Invoke-DiagnosticCommand 'tar' @('-xf', $packed, '-C', $extract) $testRoot
    if ($pack.exitCode -ne 0 -or $list.exitCode -ne 0 -or $unpack.exitCode -ne 0 -or [IO.File]::ReadAllText((Join-Path $extract 'valid.txt')) -cne 'safe extraction probe') { throw 'Real tar round trip failed.' }
    Write-Output 'PASS: mock HTTP fallback, pinned digest refusal, path containment, unsafe archive entries, URL redaction, immutable original-cache inventory and real tar round trip.'
    exit 0
}

if (-not $RunnerTemp -or -not $IsWindows) { throw 'A Windows runner temporary directory is required.' }
$RunnerTemp = (Resolve-Path -LiteralPath $RunnerTemp).Path
$reportRoot = Join-Path $RunnerTemp 'cyberfi-python-diagnostics'
Assert-DiagnosticPath $RunnerTemp $reportRoot
New-Item -ItemType Directory -Path $reportRoot -Force | Out-Null
$output = Join-Path $reportRoot ($Phase + '.json')
$report = [ordered]@{ phase = $Phase; startedAt = [DateTime]::UtcNow.ToString('o'); success = $false
    purpose = 'Isolated pinned dependency diagnostics; original MCP profiles and results are never changed'; originalCache = @(); probes = @() }
try {
    # Preserve original evidence before creating or downloading any probe runtime.
    $report.originalCache = @(Original-CacheInventory $RunnerTemp)
    [IO.File]::WriteAllText($output, ($report | ConvertTo-Json -Depth 12))
    $probeRoot = Join-Path $RunnerTemp ('cyberfi-python-probe-' + [guid]::NewGuid())
    Assert-DiagnosticPath $RunnerTemp $probeRoot
    New-Item -ItemType Directory -Path $probeRoot | Out-Null
    $report.probeRoot = $probeRoot
    $report.tar = Invoke-DiagnosticCommand 'tar' @('--version') $probeRoot
    $archives = @(
        @{ name = 'uv'; url = 'https://github.com/astral-sh/uv/releases/download/0.9.7/uv-x86_64-pc-windows-msvc.zip'; fallbackUrl = 'https://api.github.com/repos/astral-sh/uv/releases/assets/310707702'; sha256 = '5d250c32d3604e28dbe18dc65c668ff628c53e00dde2c642576e831e4a60da64'; executable = 'uv.exe' },
        @{ name = 'python'; url = 'https://github.com/astral-sh/python-build-standalone/releases/download/20251028/cpython-3.12.12%2B20251028-x86_64-pc-windows-msvc-install_only_stripped.tar.gz'; fallbackUrl = 'https://api.github.com/repos/astral-sh/python-build-standalone/releases/assets/309722214'; sha256 = 'b01ce5aed9bae58023ccfba76c9cf0e789aa2ca36057ee6e6af054da2a2d4eb1'; executable = 'python/python.exe' }
    )
    $probes = [Collections.Generic.List[object]]::new()
    foreach ($archive in $archives) {
        $probe = [ordered]@{ name = $archive.name; success = $false; requests = [Collections.Generic.List[object]]::new() }
        $probes.Add($probe)
        $report.probes = $probes.ToArray()
        try {
            $download = Join-Path $probeRoot ([IO.Path]::GetFileName(([uri]$archive.url).AbsolutePath))
            Invoke-ArchiveDownload $archive $download $probe.requests
            $probe.listing = Invoke-DiagnosticCommand 'tar' @('-tf', $download) $probeRoot
            if ($probe.listing.exitCode -ne 0) { throw 'Archive listing command failed.' }
            Assert-ArchiveEntries $probe.listing.stdout
            $probe.listing.stdout = '[Safe archive paths validated; listing omitted]'
            $destination = Join-Path $probeRoot $archive.name
            Assert-DiagnosticPath $probeRoot $destination
            New-Item -ItemType Directory -Path $destination | Out-Null
            $probe.extraction = Invoke-DiagnosticCommand 'tar' @('-xf', $download, '-C', $destination) $probeRoot
            if ($probe.extraction.exitCode -ne 0) { throw 'Archive extraction failed.' }
            $executable = Join-Path $destination $archive.executable
            Assert-DiagnosticPath $probeRoot $executable
            $probe.version = Invoke-DiagnosticCommand $executable @('--version') $probeRoot
            if ($probe.version.exitCode -ne 0) { throw 'Pinned dependency version command failed.' }
            $probe.success = $true
        } catch { $probe.error = Safe-DiagnosticText $_.Exception.Message }
        [IO.File]::WriteAllText($output, ($report | ConvertTo-Json -Depth 12))
    }
    $report.success = @($probes | Where-Object { -not $_.success }).Count -eq 0
} catch { $report.error = Safe-DiagnosticText $_.Exception.Message }
finally {
    $report.completedAt = [DateTime]::UtcNow.ToString('o')
    [IO.File]::WriteAllText($output, ($report | ConvertTo-Json -Depth 12))
    Write-Output ($report | ConvertTo-Json -Depth 12)
}
if (-not $report.success) { exit 1 }
