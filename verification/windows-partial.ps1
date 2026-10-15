param(
    [Parameter(Mandatory=$true)][string]$Java,
    [Parameter(Mandatory=$true)][string]$Classpath,
    [Parameter(Mandatory=$true)][string]$Cli
)
$ErrorActionPreference = 'Stop'
$process = New-Object Diagnostics.Process
$process.StartInfo.FileName = $Java
$process.StartInfo.Arguments = '-cp "' + $Classpath + '" PartialSmokeServer'
$process.StartInfo.UseShellExecute = $false
$process.StartInfo.RedirectStandardInput = $true
$process.StartInfo.RedirectStandardOutput = $true
$process.StartInfo.RedirectStandardError = $true
$root = Join-Path $env:LOCALAPPDATA ('bctl-' + [Guid]::NewGuid().ToString('N').Substring(0,8))
[IO.Directory]::CreateDirectory($root) | Out-Null
try {
    if (!$process.Start()) { throw 'Cannot start fixture' }
    if ($process.StandardOutput.ReadLine() -ne 'ready') { throw ('Fixture startup failed: ' + $process.StandardError.ReadToEnd()) }
    $list = & $Cli instance list --format json | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw 'Discovery failed' }
    $instances = @($list.result.items | Where-Object { $_.project_id -eq 'fixture-project' })
    if ($instances.Count -ne 1) { throw 'Expected one fixture instance' }
    if ($list.result.items.Count -gt 1) {
        & $Cli status | Out-Null
        if ($LASTEXITCODE -ne 3) { throw 'Ambiguous selection did not fail' }
    }
    $output = Join-Path $root 'incomplete.bin'
    $export = New-Object Diagnostics.Process
    $export.StartInfo.FileName = $Cli
    $export.StartInfo.Arguments = '--instance ' + $instances[0].instance_id + ' history get 102 --project-id fixture-project --part request.body --raw --output "' + $output + '"'
    $export.StartInfo.UseShellExecute = $false
    $export.StartInfo.RedirectStandardError = $true
    $export.StartInfo.RedirectStandardOutput = $true
    try {
        if (!$export.Start()) { throw 'Cannot start export' }
        if (!$export.WaitForExit(35000)) { $export.Kill(); throw 'Export did not finish' }
        if ($export.ExitCode -ne 7 -or $export.StandardError.ReadToEnd() -notmatch '^PARTIAL_TRANSFER:') { throw 'Expected PARTIAL_TRANSFER after streaming began' }
    } finally { $export.Dispose() }
    $chunk = $process.StandardOutput.ReadLineAsync()
    if (!$chunk.Wait(2000) -or $chunk.Result -ne 'first chunk sent') { throw 'Fixture did not send the first chunk' }
    if (Test-Path -LiteralPath $output) { throw 'Incomplete destination published' }
    if (@(Get-ChildItem -LiteralPath $root -Force).Count -ne 0) { throw 'Temporary export not cleaned up' }
    $process.StandardInput.WriteLine('stop')
    if (!$process.WaitForExit(5000) -or $process.ExitCode -ne 0) { throw 'Fixture shutdown failed' }
    $after = & $Cli instance list --format json | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw 'Discovery after shutdown failed' }
    if (@($after.result.items | Where-Object { $_.project_id -eq 'fixture-project' }).Count -ne 0) { throw 'Fixture instance retained' }
    'PASS: authenticated multi-instance ambiguity, interrupted stream, no published/partial files, instance cleanup'
} finally {
    if ($process.Id -and !$process.HasExited) { $process.StandardInput.WriteLine('stop'); $process.WaitForExit(3000) | Out-Null }
    $process.Dispose()
    Remove-Item -LiteralPath $root -Recurse -Force
}
