param(
    [Parameter(Mandatory=$true)][string]$Java,
    [Parameter(Mandatory=$true)][string]$Classes,
    [Parameter(Mandatory=$true)][string]$Cli,
    [string]$Instance
)
$ErrorActionPreference = 'Stop'
$root = Join-Path $env:LOCALAPPDATA ('bctl-' + [Guid]::NewGuid().ToString('N').Substring(0,8))
$identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)
$acl.SetOwner($identity)
$rule = New-Object Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
$acl.AddAccessRule($rule)
New-Item -ItemType Directory -Path $root | Out-Null
Set-Acl -LiteralPath $root -AclObject $acl
try {
    $native = Join-Path $root 'burpctl.exe'
    Copy-Item -LiteralPath $Cli -Destination $native
    $expected = & $Java -cp $Classes TrafficFixture hashes | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or $expected.Count -ne 100) { throw 'Cannot generate fixture digests' }
    $selection = if ($Instance) { @('--instance', $Instance) } else { @() }
    $status = & $native @selection status --format json | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or !$status.result.permissions.history_raw) { throw 'Raw fixture access is not enabled' }
    $instance = $status.result.instance_id
    $project = $status.result.project_id
    $common = @('--instance', $instance, '--format', 'json')
    $list = & $native @common history list --limit 100 --host 127.0.0.1 --path-contains /fixture/ --fields id,path,status | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or $list.result.items.Count -ne 100) { throw 'Expected 100 authorized fixture records' }
    $fixtureIndices = New-Object 'Collections.Generic.HashSet[int]'
    $historyIds = New-Object 'Collections.Generic.HashSet[int]'
    foreach ($row in $list.result.items) {
        if ($row.path -notmatch '^/fixture/(0|[1-9][0-9]?)$') { throw 'Unexpected fixture path' }
        $index = [int]$Matches[1]
        if (!$fixtureIndices.Add($index) -or !$historyIds.Add([int]$row.id)) { throw 'Duplicate fixture index or history ID; corpus coverage is incomplete' }
    }
    if ($fixtureIndices.Count -ne 100) { throw 'Corpus must cover every fixture index 0..99' }
    $latencies = New-Object Collections.Generic.List[double]
    $bytes = 0L
    foreach ($row in $list.result.items) {
        $index = [int]($row.path -replace '^/fixture/', '')
        if ($index -lt 0 -or $index -ge 100) { throw 'Unexpected fixture path' }
        $reference = @('history', 'get', [string]$row.id, '--project-id', $project)
        foreach ($part in @('request.body', 'response.body')) {
            $file = Join-Path $root 'body.bin'
            $watch = [Diagnostics.Stopwatch]::StartNew()
            $result = & $native @common @reference --part $part --raw --output $file | ConvertFrom-Json
            $watch.Stop()
            if ($LASTEXITCODE -ne 0 -or !$result.ok) { throw ('Raw failed: ' + $part + ' ' + $index) }
            $latencies.Add($watch.Elapsed.TotalMilliseconds)
            $actual = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($actual -ne $expected[$index].sha256 -or (Get-Item $file).Length -ne $expected[$index].size) { throw ('Byte mismatch: ' + $part + ' ' + $index) }
            $bytes += (Get-Item $file).Length
            Remove-Item -LiteralPath $file
        }
        $preview = & $native @common @reference --part response.body --base64 | ConvertFrom-Json
        if ($LASTEXITCODE -ne 0) { throw 'Base64 retrieval failed' }
        $decoded = [Convert]::FromBase64String($preview.result.item.data)
        $algorithm = [Security.Cryptography.SHA256]::Create()
        try { $hash = ([BitConverter]::ToString($algorithm.ComputeHash($decoded))).Replace('-', '').ToLowerInvariant() }
        finally { $algorithm.Dispose() }
        if ($hash -ne $expected[$index].prefix_sha256) { throw 'Base64 prefix mismatch' }
        if (($index % 10) -eq 0) { 'Verified fixture ' + $index }
    }
    $sorted = @($latencies | Sort-Object)
    'PASS: 100 metadata records, 200 raw byte/hash comparisons and 100 Base64 prefixes'
    'Raw retrieval: bytes=' + $bytes + ' p50_ms=' + $sorted[99] + ' p95_ms=' + $sorted[189]
    if (@(Get-ChildItem -LiteralPath $root -Filter '*.part' -Force).Count -ne 0) { throw 'Partial files left behind' }
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force
}
