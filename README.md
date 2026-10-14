# BurpCTL

A short-lived native Windows CLI and a Java 21 Burp extension for authorized, on-demand reads. Implemented: `status`, `instance list`, `history list/get`, and `scope check`. No history mirror, index, database, CLI daemon, or automatic exports.

The read commands have been exercised on Windows with Burp Suite Professional 2026.10. Full release acceptance is **not yet established**: controlled idle/large-history memory profiling, Community edition, actual Windows Java 21 runtime, and additional host coverage remain unverified.

## Build

Use stable Rust and JDK 21 (verified with Temurin 21.0.12). Set `JAVA_HOME` to the JDK. The Gradle wrapper pins Gradle 9.2.1; dependencies are locked, and Gradle artifacts and the wrapper distribution have checksum verification. Personal tool configuration and agent instructions stay local and are ignored by Git.

```sh
./extension/gradlew -p extension build --no-daemon
cargo fmt --manifest-path cli/Cargo.toml -- --check
cargo check --manifest-path cli/Cargo.toml --locked
cargo clippy --manifest-path cli/Cargo.toml --locked -- -D warnings
```

On a Windows MSVC development host:

```powershell
.\extension\gradlew.bat -p extension build --no-daemon
cargo build --manifest-path cli/Cargo.toml --target x86_64-pc-windows-msvc --release --locked
```

From WSL, the verified alternative uses `cargo-xwin` 0.23.1 and the MSVC target:

```sh
rustup target add x86_64-pc-windows-msvc
cargo xwin build --manifest-path cli/Cargo.toml --target x86_64-pc-windows-msvc --release --locked
```

The CLI is `cli/target/x86_64-pc-windows-msvc/release/burpctl.exe`; the extension is `extension/build/libs/burpctl-extension.jar`. Package matching artifacts without publishing:

```sh
python3 scripts/package-release.py --output BurpCTL-0.1.0.zip
```

## Repository layout

| Directory | Purpose |
|---|---|
| `cli/` | Stateless Rust client, instance discovery, IPC and output |
| `extension/` | Montoya operations, policy, IPC server and lifecycle |
| `protocol/` | Wire contract and golden frame examples |
| `verification/` | Standalone integration fixtures and benchmark scripts |
| `skills/burpctl/` | Agent command discovery and authorized read workflow |
| `scripts/` | Explicit release packaging |

## Use

Copy `burpctl.exe` onto local NTFS and place it on Windows PATH. The current MSVC binary imports `VCRUNTIME140.dll`; the corresponding MSVC runtime must be available (it was present on the verified host). Loading it from a WSL UNC share was substantially slower in this session. Add the JAR as a Java extension in Burp; a supported Java 21+ runtime and Montoya 2026.7 APIs are required. The tested Burp bundle uses Java 26.0.2.

Status and scope membership checks are available after authentication. History permissions default to off: enable metadata and, separately, raw access in the **BurpCTL** tab only for data you authorize local tooling to read. History reads remain restricted to Burp scope. Permissions reset on reload; scope membership is not engagement authorization.

```powershell
burpctl.exe instance list --format json
burpctl.exe status
burpctl.exe --instance INSTANCE history list --limit 10 --fields id,method,path,status --format json
burpctl.exe --instance INSTANCE history list --host example.com --status 500 --fields id,path
burpctl.exe --instance INSTANCE scope check https://example.com/admin
```

Keep both identities from `meta.provenance` with history IDs. Numeric retrieval requires explicit source context:

```powershell
burpctl.exe --instance INSTANCE history get 123 --project-id PROJECT --fields id,status
burpctl.exe --instance INSTANCE history get 123 --project-id PROJECT --part response.body --base64 --body-max-bytes 4096 --format json
burpctl.exe --instance INSTANCE history get 123 --project-id PROJECT --part request.body --raw --output evidence.bin
```

UTF-8 previews reject invalid prefixes; use Base64 or raw export for arbitrary bytes. Preview truncation is explicit. Raw export verifies byte count and SHA-256 before publishing the destination; an existing destination requires `--force`. Exports inherit destination-directory permissions. Losslessness refers to Montoya bytes, not HTTP/2 network framing.

History ordering is unspecified, and queries may traverse all entries. Row limits cap accepted results; they do not bound Montoya's internal allocations or prove more matches exist. `path` omits query strings. Filtering and field projection run in Java before serialization. An empty list succeeds.

The private runtime root is `%LOCALAPPDATA%\burpctl\r`. Startup fails if private NTFS ACLs cannot be established or the socket path exceeds 100 UTF-8 bytes. Files belonging to other instances are never removed; stale entries are excluded after authenticated liveness checks. Reloads invalidate instance identity. If the project identity changes, reload the extension and obtain fresh references. ACLs and tokens do not isolate the service from malicious same-user processes.

Use the Windows executable from WSL, for example `/mnt/c/Tools/burpctl.exe status`. The Linux build is for development checks, not a client for Windows sockets. Stdout contains results; stderr contains diagnostics. JSON failures from a valid server response remain structured, with stable exit codes described in [the protocol](protocol/SPEC.md).

The repository [Agent Skill](skills/burpctl/SKILL.md) documents discovery and scoped evidence retrieval. The [protocol](protocol/SPEC.md) defines framing, permissions, fields, budgets and error codes.

## Verification

Checked on Windows 11 with Burp Professional 2026.10-54643 and its bundled Java 26.0.2, using Java 21 bytecode: native Rust/Java UDS, authentication and ACLs, denied permissions, scoped reads, projection, instance ambiguity, unload cleanup and incomplete-export cleanup. An authorized 100-message loopback corpus passed 200 exact request/response body comparisons and 100 Base64-prefix comparisons. Cargo fmt/check/clippy, including Windows-target clippy, and Gradle build passed. These checks preceded Git initialization.

Standalone Java and PowerShell checks live in `verification/`. Compile the Java fixtures against the extension JAR and Montoya 2026.7 JAR with `javac --release 21 -d CLASSES -cp CLASSPATH`; run `StatusSmoke` and `HistorySmoke` with both JARs and the compiled classes on the classpath. `PerfSnapshot` uses an internal JVM API and instead needs `-source 21 -target 21 --add-exports jdk.internal.jvmstat/sun.jvmstat.monitor=ALL-UNNAMED` at compilation and the same export at runtime. PowerShell scripts take explicit Java, classpath and CLI paths. Only run `TrafficFixture populate` with explicit traffic authorization and its loopback URL in Burp scope; the read CLI never sends fixture traffic or changes scope.

The tested history had only about 101 synthetic entries. A five-minute idle sample had uncontrolled ambient activity and GC, so no causal extension heap/RSS overhead or large-history allocation bound was established. Additional open checks include Community edition, Windows Java 21, multiple real Burp windows, live HTTP/2/gzip, repeated real extension reloads, abrupt JVM crash recovery and adversarial Windows path races. Fixture checks do not establish those integrations.
