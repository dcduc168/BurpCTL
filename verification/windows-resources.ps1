param(
    [Parameter(Mandatory=$true)][string]$Java,
    [Parameter(Mandatory=$true)][string]$Classes,
    [Parameter(Mandatory=$true)][int]$BurpPid,
    [int]$Samples = 30,
    [int]$IntervalSeconds = 10,
    [string]$Phase = 'idle'
)
$ErrorActionPreference = 'Stop'
for ($index = 0; $index -lt $Samples; $index++) {
    $heap = & $Java --add-exports jdk.internal.jvmstat/sun.jvmstat.monitor=ALL-UNNAMED -cp $Classes PerfSnapshot $BurpPid | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw 'Cannot read existing JVM performance counters' }
    $process = Get-Process -Id $BurpPid
    $io = Get-CimInstance Win32_Process -Filter "ProcessId = $BurpPid"
    if (!$io) { throw 'Cannot read Burp process IO counters' }
    [ordered]@{
        phase = $Phase
        sample = $index
        timestamp_utc = [DateTime]::UtcNow.ToString('o')
        heap_used_bytes = $heap.heap_used_bytes
        java_threads = $heap.live_threads
        gc_count = $heap.gc_count
        working_set_bytes = $process.WorkingSet64
        private_bytes = $process.PrivateMemorySize64
        handles = $process.HandleCount
        cpu_seconds = $process.TotalProcessorTime.TotalSeconds
        read_bytes = $io.ReadTransferCount
        write_bytes = $io.WriteTransferCount
    } | ConvertTo-Json -Compress
    if ($index -lt ($Samples - 1)) { Start-Sleep -Seconds $IntervalSeconds }
}
