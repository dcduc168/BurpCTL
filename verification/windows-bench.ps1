param([Parameter(Mandatory=$true)][string]$Cli)
$ErrorActionPreference = 'Stop'
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class BurpCtlMemory {
    [StructLayout(LayoutKind.Sequential)]
    public struct Counters {
        public uint cb, faults;
        public UIntPtr peakWorkingSet, workingSet, peakPagedPool, pagedPool,
            peakNonPagedPool, nonPagedPool, pagefile, peakPagefile, privateUsage;
    }
    [DllImport("psapi.dll", SetLastError=true)]
    public static extern bool GetProcessMemoryInfo(IntPtr process, out Counters counters, uint size);
}
'@
$root = Join-Path $env:LOCALAPPDATA ('bctl-' + [Guid]::NewGuid().ToString('N').Substring(0,8))
[IO.Directory]::CreateDirectory($root) | Out-Null
try {
    $native = Join-Path $root 'burpctl.exe'
    Copy-Item -LiteralPath $Cli -Destination $native
    foreach ($command in @('--version', 'status --format json', 'history list --limit 10 --fields id,status --format json')) {
        $latencies = New-Object Collections.Generic.List[double]
        $peak = 0L
        $size = 0
        for ($index = 0; $index -lt 100; $index++) {
            $process = New-Object Diagnostics.Process
            $process.StartInfo.FileName = $native
            $process.StartInfo.Arguments = $command
            $process.StartInfo.UseShellExecute = $false
            $process.StartInfo.RedirectStandardOutput = $true
            $process.StartInfo.RedirectStandardError = $true
            $watch = [Diagnostics.Stopwatch]::StartNew()
            try {
                if (!$process.Start()) { throw 'Cannot start CLI' }
                $handle = $process.Handle
                $output = $process.StandardOutput.ReadToEnd()
                $diagnostic = $process.StandardError.ReadToEnd()
                $process.WaitForExit()
                $watch.Stop()
                if ($process.ExitCode -ne 0) { throw ('CLI failed: ' + $diagnostic) }
                $latencies.Add($watch.Elapsed.TotalMilliseconds)
                $size = [Text.Encoding]::UTF8.GetByteCount($output)
                $counters = New-Object BurpCtlMemory+Counters
                if ([BurpCtlMemory]::GetProcessMemoryInfo($handle, [ref]$counters, [Runtime.InteropServices.Marshal]::SizeOf($counters))) {
                    $peak = [Math]::Max($peak, [long]$counters.peakWorkingSet.ToUInt64())
                }
            } finally { $process.Dispose() }
        }
        $sorted = @($latencies | Sort-Object)
        [ordered]@{ command=$command; calls=100; p50_ms=$sorted[49]; p95_ms=$sorted[94]; peak_working_set_bytes=$peak; output_bytes=$size } | ConvertTo-Json -Compress
    }
} finally { Remove-Item -LiteralPath $root -Recurse -Force }
