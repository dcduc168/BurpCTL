param(
    [Parameter(Mandatory=$true)][string]$Java,
    [Parameter(Mandatory=$true)][string]$Classes,
    [Parameter(Mandatory=$true)][string]$Cli
)
$ErrorActionPreference = 'Stop'
$root = Join-Path $env:LOCALAPPDATA ('bctl-' + [Guid]::NewGuid().ToString('N').Substring(0,8))
$socket = Join-Path $root 'e.sock'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)
$acl.SetOwner($identity)
$rule = New-Object Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
$acl.AddAccessRule($rule)
[IO.Directory]::CreateDirectory($root, $acl) | Out-Null
try {
    $cases = @('valid') * 20 + @('zero', 'oversized', 'tag', 'truncated')
    foreach ($case in $cases) {
        $proc = New-Object Diagnostics.Process
        $proc.StartInfo.FileName = $Java
        $proc.StartInfo.Arguments = '-cp "' + $Classes + '" UdsEcho "' + $socket + '"'
        $proc.StartInfo.UseShellExecute = $false
        if (!$proc.Start()) { throw 'Cannot start Java fixture' }
        try {
            $deadline = [DateTime]::UtcNow.AddSeconds(10)
            while (!(Test-Path -LiteralPath $socket)) {
                if ($proc.HasExited -or [DateTime]::UtcNow -gt $deadline) { throw 'Listener not ready' }
                Start-Sleep -Milliseconds 50
            }
            & $Cli transport-probe $socket --case $case
            if ($LASTEXITCODE -ne 0) { throw 'Rust echo failed' }
            if (!$proc.WaitForExit(5000)) { throw 'Java fixture did not exit' }
            $expectedExit = if ($case -eq 'valid') { 0 } else { 1 }
            if ($proc.ExitCode -ne $expectedExit) { throw ('Unexpected Java exit for ' + $case + ': ' + $proc.ExitCode) }
            if (Test-Path -LiteralPath $socket) { throw 'Socket cleanup failed' }
        } finally {
            if (!$proc.HasExited) { $proc.Kill(); $proc.WaitForExit() }
            $proc.Dispose()
        }
    }
    & $Cli --version
    if ($LASTEXITCODE -ne 0) { throw 'Version failed' }
    & $Cli --help
    if ($LASTEXITCODE -ne 0) { throw 'Help failed' }
    'PASS: Windows Rust/Java echo, fragmented UTF-8 frames, EOF and 20 rebind/cleanup cycles; zero/oversized/tag/truncated frames rejected'
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force
}
