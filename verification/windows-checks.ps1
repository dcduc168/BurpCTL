param(
    [Parameter(Mandatory=$true)][string]$Classes
)
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
$gradleHome = if ($env:GRADLE_USER_HOME) { $env:GRADLE_USER_HOME } else { Join-Path $env:USERPROFILE '.gradle' }
$montoya = @(Get-ChildItem -LiteralPath (Join-Path $gradleHome 'caches\modules-2\files-2.1\net.portswigger.burp.extensions\montoya-api\2026.7') -Recurse -Filter 'montoya-api-2026.7.jar')
if ($montoya.Count -ne 1) { throw 'Expected the locked Montoya API JAR' }
New-Item -ItemType Directory -Path $Classes -Force | Out-Null
$classpath = "$Classes;extension\build\libs\burpctl-extension.jar;$($montoya[0].FullName)"
javac --release 21 -cp $classpath -d $Classes verification\StatusSmoke.java verification\TrafficFixture.java verification\HistorySmoke.java verification\HistoryServer.java verification\PartialSmokeServer.java verification\SettingsSmoke.java verification\LifecycleSmoke.java
if ($LASTEXITCODE -ne 0) { throw 'Fixture compilation failed' }
foreach ($check in @('StatusSmoke', 'HistorySmoke', 'SettingsSmoke', 'LifecycleSmoke')) {
  java -cp $classpath $check
  if ($LASTEXITCODE -ne 0) { throw "$check failed" }
}
$fixture = New-Object Diagnostics.Process
$fixture.StartInfo.FileName = Join-Path $env:JAVA_HOME 'bin\java.exe'
$fixture.StartInfo.Arguments = '-cp "' + $classpath + '" HistoryServer'
$fixture.StartInfo.UseShellExecute = $false
$fixture.StartInfo.RedirectStandardInput = $true
$fixture.StartInfo.RedirectStandardOutput = $true
if (!$fixture.Start()) { throw 'Cannot start history fixture' }
try {
  $ready = $fixture.StandardOutput.ReadLineAsync()
  if (!$ready.Wait(10000) -or $ready.Result -ne 'ready') { throw 'History fixture startup failed' }
  $cli = 'cli\target\x86_64-pc-windows-msvc\release\burpctl.exe'
  $instances = (& $cli instance list --format json | ConvertFrom-Json).result.items
  $selectedFixture = @($instances | Where-Object { $_.project_id -eq 'fixture-project' })
  if ($selectedFixture.Count -ne 1) { throw 'Expected one history fixture instance' }
  .\verification\windows-history.ps1 -Java $fixture.StartInfo.FileName -Classes $classpath -Cli $cli -Instance $selectedFixture[0].instance_id
} finally {
  if (!$fixture.HasExited) {
    $fixture.StandardInput.WriteLine('stop')
    if (!$fixture.WaitForExit(5000)) { $fixture.Kill(); $fixture.WaitForExit() }
  }
  $fixture.Dispose()
}
# This fixture checks expected nonzero CLI exit codes itself.
$PSNativeCommandUseErrorActionPreference = $false
.\verification\windows-partial.ps1 -Java (Join-Path $env:JAVA_HOME 'bin\java.exe') -Classpath $classpath -Cli 'cli\target\x86_64-pc-windows-msvc\release\burpctl.exe'
