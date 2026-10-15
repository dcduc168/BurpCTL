# Verification

Run these checks from a source checkout after building the Windows CLI and extension. Fixtures exercise production code with synthetic data; they do not establish Burp edition support or Montoya memory bounds.

## Choose the check

| Change | Check |
|---|---|
| Rust client, arguments or output | Cargo fmt/check/clippy and the focused IPC checks |
| Java dispatcher, authentication, policy or unload | Gradle build, `StatusSmoke`, `SettingsSmoke` and `LifecycleSmoke` |
| History filters, field selection or byte handling | `HistorySmoke`, then the native corpus check |
| Raw streaming or destination handling | Native corpus and `windows-partial.ps1` |
| Repeater screenshot | `ScreenshotSmoke`, native PNG export and live visible/offscreen Repeater capture |
| Protocol examples or release artifacts | `release-checks.py` |
| Performance claim | `windows-bench.ps1` and controlled Burp resource samples |

There is no unit-test framework. The Rust checks use Cargo's built-in runner; the Java checks are executable classes with assertions. The Rust export check rejects a completed stream with a wrong SHA-256 hash and requires cleanup of the destination and temporary file. The terminal-output check verifies buffer reuse for safe text and escaping of control and bidi characters.

## Build checks

```sh
cargo fmt --manifest-path cli/Cargo.toml -- --check
cargo check --manifest-path cli/Cargo.toml --locked
cargo clippy --manifest-path cli/Cargo.toml --locked --all-targets -- -D warnings
cargo test --manifest-path cli/Cargo.toml --locked
./extension/gradlew -p extension build --no-daemon
python3 verification/release-checks.py
```

On Windows, use `extension\gradlew.bat` for the Java build. Run Windows-target Rust checks on an MSVC development host or with the documented WSL cross-build tools. `release-checks.py` needs both built artifacts and Windows executable support; it checks golden frame bytes, raw-stream hashes, artifact versions and rejection of missing or stale binaries.

## Compile the Java fixtures

Use a JDK and the Montoya 2026.7 JAR from the build dependency cache. In PowerShell, set `$montoya` to that JAR's absolute path:

```powershell
$java = Join-Path $env:JAVA_HOME 'bin\java.exe'
$javac = Join-Path $env:JAVA_HOME 'bin\javac.exe'
$classes = Join-Path $env:TEMP 'burpctl-checks'
$extension = (Resolve-Path 'extension\build\libs\burpctl-extension.jar').Path
$montoya = 'C:\path\to\montoya-api-2026.7.jar'
$cli = (Resolve-Path 'cli\target\x86_64-pc-windows-msvc\release\burpctl.exe').Path
New-Item -ItemType Directory -Force $classes | Out-Null
$classpath = "$classes;$extension;$montoya"

& $javac --release 21 -cp "$extension;$montoya" -d $classes verification\StatusSmoke.java verification\TrafficFixture.java verification\HistorySmoke.java verification\HistoryServer.java verification\PartialSmokeServer.java verification\SettingsSmoke.java verification\LifecycleSmoke.java verification\ScreenshotSmoke.java
& $java -cp $classpath StatusSmoke
& $java -cp $classpath HistorySmoke
& $java -cp $classpath SettingsSmoke
& $java -cp $classpath LifecycleSmoke
& $java -cp $classpath ScreenshotSmoke
```

Check each native command's exit code before continuing. `StatusSmoke` covers a stalled partial-frame deadline, malformed frames, authentication/context/schema denial before Montoya, overload and cleanup. `HistorySmoke` covers scope, concurrent callback limits, projection without body reads, UTF-8 failures, missing responses and exact bytes. It also checks that host/method/path/status mismatches skip URL/scope work and that ID lookup retains scope checks before acceptance and output. `SettingsSmoke` checks lazy EDT construction, search keywords, keyboard/accessibility labels, metadata/raw dependency and permission revocation after unload.

`LifecycleSmoke` calls the production extension entry point for 20 initialized unload/reload cycles and 20 immediate-unload races. It checks fresh identities, permission reset, settings deregistration and socket/worker cleanup while a partial frame is waiting. These are synthetic-host checks, not 20 actual Burp reloads.

`ScreenshotSmoke` opens a temporary synthetic Swing window and checks permission denial before UI access, PNG pixels/dimensions, independent screenshot policy, one-operation concurrency, pixel-identical hidden capture without selecting Repeater, uninitialized/oversized views and queued EDT timeout cancellation. Its `serve` argument exposes that synthetic view through production IPC; select the `fixture-project` instance and run `repeater screenshot --output PATH`. Stop it with stdin after verification. No target traffic is sent.

## Native corpus and interrupted exports

`windows-checks.ps1 -Classes "$env:TEMP\burpctl-checks"` compiles the fixtures and runs the Java, lifecycle, native corpus and interrupted-export checks together. Run it from the repository root after building, with a JDK on PATH. It is also the entry point used by the release workflow.

Start the fixture in one terminal:

```powershell
& $java -cp $classpath HistoryServer
```

It prints `ready`, serves 100 in-memory records through the production IPC server and stops when it reads stdin. It enables metadata/raw permissions only for its synthetic records and sends no traffic.

In another terminal, define the same path variables, discover the fixture instance and run:

```powershell
& $cli instance list --format json
.\verification\windows-history.ps1 -Java $java -Classes $classpath -Cli $cli -Instance FIXTURE_INSTANCE
```

Select the instance whose project ID is `fixture-project`. The corpus check requires distinct history IDs and all fixture indices 0 through 99 before comparing 200 raw exports and 100 Base64 prefixes. It deletes its temporary exports. Stop `HistoryServer` before running the partial-transfer check:

```powershell
.\verification\windows-partial.ps1 -Java $java -Classpath $classpath -Cli $cli
```

This script starts and stops its own fixture. It requires `PARTIAL_TRANSFER`, confirms the fixture sent its first chunk, and checks that no destination or `.part` file remains. A connection error before streaming does not pass. If a real Burp instance is also running, it checks ambiguous selection.

## Live Burp

Load the JAR, confirm the settings panel appears in Burp Settings when searching for `BurpCTL` and that no suite tab is added. Check authenticated `status` and toggle metadata/raw independently; disabling metadata must revoke raw. Then unload and confirm discovery excludes that instance. Reload must produce a fresh instance ID with permissions disabled. Record Burp edition/version and its actual runtime; compiling Java 21 bytecode does not verify a Java 21 Burp installation.

Use existing authorized history for read checks. `TrafficFixture populate` is available for a real binary corpus, but it sends 100 POST requests through `127.0.0.1:8080` to its temporary server at `http://127.0.0.1:18123/fixture/0..99`. Run it only after explicit traffic authorization, operator scope setup and interception configuration. It adds project history and does not delete it. Its optional `populate 99` form sends only the last request and requires authorization for that retry.

## Resources

```powershell
.\verification\windows-bench.ps1 -Cli $cli
& $javac -source 21 -target 21 --add-exports jdk.internal.jvmstat/sun.jvmstat.monitor=ALL-UNNAMED -d $classes verification\PerfSnapshot.java
.\verification\windows-resources.ps1 -Java $java -Classes $classes -BurpPid BURP_PID -Samples 31 -IntervalSeconds 10 -Phase unloaded
```

`windows-bench.ps1` copies the CLI to temporary local NTFS, runs 100 calls per command and reports latency, output bytes and peak CLI working set. It needs a single live instance with metadata permission; it sends no traffic.

For idle comparison, stop scans, proxy use and Burp interaction, preserve the same project/history, and sample unloaded and loaded phases separately. Let workers expire before the loaded sample and make no CLI calls during it. Thirty-one samples ten seconds apart cover about five minutes. Record GC, CPU, threads, handles and process I/O alongside heap/RSS. I/O counters measure process transfers, not specifically disk writes. Avoid concurrent benchmark clients when measuring allocations or latency.

Heap includes uncollected garbage and Burp background allocations. Whole-process RSS also includes traffic retained by the project. Report workload, source version, sampling interval and uncertainty; output limits do not bound Montoya allocations.

Remove `$classes` when finished. Temporary fixture processes and profiling helpers are not part of the production deployment.
