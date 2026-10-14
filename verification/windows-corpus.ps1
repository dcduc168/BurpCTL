param(
    [Parameter(Mandatory=$true)][string]$Java,
    [Parameter(Mandatory=$true)][string]$Classes
)
$ErrorActionPreference = 'Stop'
$root = Join-Path $env:LOCALAPPDATA ('bctl-' + [Guid]::NewGuid().ToString('N').Substring(0,8))
[IO.Directory]::CreateDirectory($root) | Out-Null
$previousCase = $env:BURPCTL_CORPUS_CASE
try {
    $fixture = Join-Path $root 'fixture.exe'
    Add-Type -OutputAssembly $fixture -OutputType ConsoleApplication -TypeDefinition @'
using System;
using System.Text;
public class CorpusFixture {
    public static void Main(string[] args) {
        if (Array.IndexOf(args, "status") >= 0) {
            Console.WriteLine("{\"ok\":true,\"result\":{\"permissions\":{\"history_raw\":true},\"instance_id\":\"fixture\",\"project_id\":\"project\"}}");
        } else if (Array.IndexOf(args, "list") >= 0) {
            string mode = Environment.GetEnvironmentVariable("BURPCTL_CORPUS_CASE");
            var rows = new StringBuilder("{\"ok\":true,\"result\":{\"items\":[");
            for (int i = 0; i < 100; i++) {
                if (i != 0) rows.Append(',');
                int index = mode == "duplicate-index" ? 0 : i;
                int id = mode == "duplicate-id" ? 1000 : 1000 + i;
                rows.Append("{\"id\":").Append(id).Append(",\"path\":\"/fixture/").Append(index).Append("\",\"status\":200}");
            }
            Console.WriteLine(rows.Append("]}}").ToString());
        } else {
            // A complete corpus must reach byte checks; this fixture deliberately stops there.
            Console.WriteLine("{\"ok\":false}");
        }
    }
}
'@
    foreach ($case in @('duplicate-index', 'duplicate-id', 'complete')) {
        $env:BURPCTL_CORPUS_CASE = $case
        $message = $null
        try { & "$PSScriptRoot\windows-history.ps1" -Java $Java -Classes $Classes -Cli $fixture | Out-Null }
        catch { $message = $_.Exception.Message }
        $expected = if ($case -eq 'complete') { 'Raw failed:' } else { 'Duplicate fixture index or history ID' }
        if (!$message -or !$message.Contains($expected)) { throw ('Unexpected corpus gate result for ' + $case + ': ' + $message) }
    }
    'PASS: duplicate fixture/index denied; complete 0..99 corpus reaches byte verification'
} finally {
    $env:BURPCTL_CORPUS_CASE = $previousCase
    Remove-Item -LiteralPath $root -Recurse -Force
}
