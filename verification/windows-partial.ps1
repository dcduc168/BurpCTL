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
    & $Cli --instance $instances[0].instance_id history get 102 --project-id fixture-project --part request.body --raw --output $output | Out-Null
    if ($LASTEXITCODE -ne 7) { throw 'Incomplete transfer did not fail' }
    if (Test-Path -LiteralPath $output) { throw 'Incomplete destination published' }
    if (@(Get-ChildItem -LiteralPath $root -Force).Count -ne 0) { throw 'Temporary export not cleaned up' }
    $process.StandardInput.WriteLine('stop')
    if (!$process.WaitForExit(5000) -or $process.ExitCode -ne 0) { throw 'Fixture shutdown failed' }
    $after = & $Cli instance list --format json | ConvertFrom-Json
    if (@($after.result.items | Where-Object { $_.project_id -eq 'fixture-project' }).Count -ne 0) { throw 'Fixture instance retained' }
    'PASS: authenticated multi-instance ambiguity, interrupted stream, no published/partial files, instance cleanup'
} finally {
    if ($process.Id -and !$process.HasExited) { $process.StandardInput.WriteLine('stop'); $process.WaitForExit(3000) | Out-Null }
    $process.Dispose()
    Remove-Item -LiteralPath $root -Recurse -Force
}
