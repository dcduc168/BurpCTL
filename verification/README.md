# Verification

Run these checks from a source checkout after building the native CLI and extension. Fixtures exercise production code with synthetic data; they do not establish Burp edition support or Montoya memory bounds.

## Choose the check

| Change | Check |
|---|---|
| Rust client, arguments or output | Cargo fmt/check/clippy and the focused IPC checks |
| Java dispatcher, authentication, policy or unload | Gradle build, `StatusSmoke`, `SettingsSmoke` and `LifecycleSmoke` |
| History filters, field selection or byte handling | `HistorySmoke`, then the native corpus check |
| Raw streaming or destination handling | `checks.py` native corpus and interrupted-export checks |
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

On Windows, use `extension\gradlew.bat` for the Java build. Build the native CLI with an explicit host target and `--release`, as the release workflow does. `release-checks.py --target HOST_TARGET` verifies golden frame bytes, raw-stream hashes, native executable format, artifact versions and rejection of missing or stale binaries. Its default target is the current host; a Windows cross-build from WSL needs `--target x86_64-pc-windows-msvc`.

## Native integration checks

Use Python 3.11+, a JDK on PATH and the built extension JAR. The script finds the locked Montoya API JAR in the Gradle cache, compiles the existing Java fixtures, then starts/stops only synthetic servers:

```sh
python3 verification/checks.py --cli cli/target/HOST_TARGET/release/burpctl
```

On Windows, append `.exe` to the CLI path and use `python`. No target traffic is sent. Temporary classes and exports are deleted on completion. The same entry point runs on all five release runners.

`StatusSmoke` covers private runtime creation, unsafe POSIX modes/symlinks/hard links, partial-frame deadlines, malformed frames, authentication/context/schema denial before Montoya, overload and cleanup. `HistorySmoke` checks scope, parallel callback caps, exact projection without implicit body reads, UTF-8 failures and raw bytes. `SettingsSmoke` checks lazy EDT construction, accessibility, permission dependencies and revocation after unload.

`LifecycleSmoke` invokes the production extension entry point for 20 initialized unload/reload cycles and 20 immediate-unload races. It checks fresh identities, reset permissions and settings/socket/worker cleanup. These are synthetic-host checks, not actual Burp reloads.

The native corpus covers all 100 distinct history IDs/fixture indices, compares 200 raw exports and 100 Base64 prefixes, and checks no-clobber/force. Two synthetic instances establish ambiguous selection denial and explicit selection. The interrupted-export fixture must send its first chunk before `PARTIAL_TRANSFER`; the check requires no destination or `.part` left behind, and no retained instance after unload.

For a synthetic Swing screenshot check on a desktop session, add `--screenshot`. It checks permission before UI access, PNG pixels/dimensions, independent policy, concurrency, pixel-identical hidden rendering without tab selection, size limits and timeout cancellation. This optional fixture is not part of headless release CI. Live Burp UI behavior on each OS still needs manual verification.

## Live Burp

Load the JAR, confirm the settings panel appears in Burp Settings when searching for `BurpCTL` and that no suite tab is added. Check authenticated `status` and toggle metadata/raw independently; disabling metadata must revoke raw. Then unload and confirm discovery excludes that instance. Reload must produce a fresh instance ID with permissions disabled. Record Burp edition/version and its actual runtime; compiling Java 21 bytecode does not verify a Java 21 Burp installation.

Use existing authorized history for read checks. `TrafficFixture populate` is available for a real binary corpus, but it sends 100 POST requests through `127.0.0.1:8080` to its temporary server at `http://127.0.0.1:18123/fixture/0..99`. Run it only after explicit traffic authorization, operator scope setup and interception configuration. It adds project history and does not delete it. Its optional `populate 99` form sends only the last request and requires authorization for that retry.

## Remaining integration gaps

Native fixtures passed on Windows x86_64, Linux x86_64/ARM64 and macOS Intel/Apple Silicon. Live Burp checks used Professional 2026.10 on Windows with bundled Java 26 running Java 21 bytecode. Fixtures do not establish live Linux/macOS Burp UI behavior, Community edition support or a real Burp installation running Java 21.

Other open checks include multiple real Burp windows, live HTTP/2/gzip, twenty actual Burp reloads, abrupt JVM crash recovery and adversarial filesystem path races. Retained extension memory and per-operation Burp peak memory have not been isolated by measurement.

## Windows cross-build from WSL

The previously verified cross-build uses cargo-xwin 0.23.1 and the MSVC target:

```sh
rustup target add x86_64-pc-windows-msvc
cargo xwin build --manifest-path cli/Cargo.toml --target x86_64-pc-windows-msvc --release --locked
python3 scripts/check-release.py --target x86_64-pc-windows-msvc
```

Windows executable checks require working WSL interop. Published release assets are built natively by GitHub runners; this cross-build is a development option.

## Resources

The retained process-resource helpers are Windows-specific. Set `JAVA_HOME` to the JDK, then:

```powershell
$cli = (Resolve-Path 'cli\target\x86_64-pc-windows-msvc\release\burpctl.exe').Path
$java = Join-Path $env:JAVA_HOME 'bin\java.exe'
$javac = Join-Path $env:JAVA_HOME 'bin\javac.exe'
$classes = Join-Path $env:TEMP 'burpctl-profiling'
New-Item -ItemType Directory -Force $classes | Out-Null
.\verification\windows-bench.ps1 -Cli $cli
& $javac -source 21 -target 21 --add-exports jdk.internal.jvmstat/sun.jvmstat.monitor=ALL-UNNAMED -d $classes verification\PerfSnapshot.java
.\verification\windows-resources.ps1 -Java $java -Classes $classes -BurpPid BURP_PID -Samples 31 -IntervalSeconds 10 -Phase unloaded
```

`windows-bench.ps1` copies the CLI to temporary local NTFS, runs 100 calls per command and reports latency, output bytes and peak CLI working set. It needs a single live instance with metadata permission; it sends no traffic.

For idle comparison, stop scans, proxy use and Burp interaction, preserve the same project/history, and sample unloaded and loaded phases separately. Let workers expire before the loaded sample and make no CLI calls during it. Thirty-one samples ten seconds apart cover about five minutes. Record GC, CPU, threads, handles and process I/O alongside heap/RSS. I/O counters measure process transfers, not specifically disk writes. Avoid concurrent benchmark clients when measuring allocations or latency.

Heap includes uncollected garbage and Burp background allocations. Whole-process RSS also includes traffic retained by the project. Report workload, source version, sampling interval and uncertainty; output limits do not bound Montoya allocations.

When compiling profiling helpers manually, remove their classes when finished. Temporary fixture processes and profiling helpers are not part of the production deployment.
