# BurpCTL

Read Burp Suite status, scope and proxy history from a native Windows CLI. BurpCTL queries Montoya on demand and returns selected fields or exact message bytes. It keeps no history cache or index.

Version 0.1.0 implements `status`, `instance list`, `history list`, `history get` and `scope check`. It has been exercised with Burp Suite Professional 2026.10. Full v1 acceptance remains open; see [verification](#verification).

## Get started

Build the [CLI and extension](#build-from-source), then:

1. Copy `burpctl.exe` to local NTFS and add its directory to Windows PATH. The MSVC build requires `VCRUNTIME140.dll`; loading the executable from a WSL share was slower on the tested host.
2. Load `burpctl-extension.jar` as a Java extension in Burp. The extension needs Java 21 or later and Montoya 2026.7 APIs.
3. Open the BurpCTL tab. Enable metadata reads for history you authorize local tooling to access. Enable raw reads separately when you need message or body bytes.

History permissions start disabled and reset on reload. History reads require Burp scope membership as well as permission; scope membership alone does not establish engagement authorization.

```powershell
burpctl.exe instance list --format json
burpctl.exe status
burpctl.exe --instance INSTANCE history list --limit 10 --fields id,method,path,status --format json
burpctl.exe --instance INSTANCE history list --host example.com --status 500 --fields id,path
burpctl.exe --instance INSTANCE scope check https://example.com/admin
```

Replace `INSTANCE` with an ID from `instance list`. If several instances are running, select one explicitly. These commands send no target traffic.

From WSL, call the Windows executable: `/mnt/c/Tools/burpctl.exe status`. The Linux build is for development checks and cannot connect to Windows sockets. Use `--help` or `<command> --help` for the available options.

## Retrieve evidence

Keep each history ID with its `meta.provenance.instance_id` and `project_id`. Retrieval requires both source identities:

```powershell
burpctl.exe --instance INSTANCE history get 123 --project-id PROJECT --fields id,status
burpctl.exe --instance INSTANCE history get 123 --project-id PROJECT --part response.body --base64 --body-max-bytes 4096 --format json
burpctl.exe --instance INSTANCE history get 123 --project-id PROJECT --part request.body --raw --output evidence.bin
```

Replace `123`, `INSTANCE` and `PROJECT` with values from the same result. Reloading the extension invalidates its instance ID. If the project changes, reload and obtain fresh references.

UTF-8 previews reject invalid sequences, including a prefix cut within a character. Use Base64 or raw export for arbitrary bytes. Preview metadata reports truncation. Raw export verifies byte count and SHA-256 before publishing the file, cleans incomplete transfers and requires `--force` to replace an existing destination. Export files inherit the destination directory's permissions.

Exact bytes refer to Montoya's message representation. They do not preserve HTTP/2 network framing. Raw retrieval does not decompress bodies or normalize line endings.

## Output and limits

Filtering and field selection run in Java before serialization. `path` excludes the query string. Empty lists succeed. History ordering is unspecified; row limits cap returned matches, not traversal or Montoya allocations, and a limit hit does not prove that more matches exist.

Compact output is the default. Use `--format json` to retain the protocol envelope. Stdout carries results, stderr carries diagnostics, and exit codes distinguish denial, timeout and incomplete export. See the [protocol reference](protocol/SPEC.md) for fields, budgets and errors.

Each instance uses a token and current-user NTFS ACLs under `%LOCALAPPDATA%\burpctl\r`. Startup fails if ACL setup fails or the socket path exceeds 100 UTF-8 bytes. Discovery checks liveness through authenticated status calls; it excludes stale entries and leaves other instances' files alone. ACLs and tokens do not isolate BurpCTL from malicious processes running as the same user.

The [BurpCTL Agent Skill](skills/burpctl/SKILL.md) covers instance selection and authorized evidence retrieval.

## Build from source

Use stable Rust and JDK 21. Set `JAVA_HOME` to the JDK. Gradle 9.2.1 is pinned by the wrapper; dependencies are locked and Gradle artifacts have checksum verification.

On Windows with MSVC build tools:

```powershell
.\extension\gradlew.bat -p extension build --no-daemon
cargo build --manifest-path cli/Cargo.toml --target x86_64-pc-windows-msvc --release --locked
```

From WSL, the verified alternative uses cargo-xwin 0.23.1 and the MSVC target:

```sh
./extension/gradlew -p extension build --no-daemon
rustup target add x86_64-pc-windows-msvc
cargo xwin build --manifest-path cli/Cargo.toml --target x86_64-pc-windows-msvc --release --locked
```

Outputs:

- CLI: `cli/target/x86_64-pc-windows-msvc/release/burpctl.exe`
- Extension: `extension/build/libs/burpctl-extension.jar`

Package matching artifacts with Python 3.11 or later on Windows, or WSL with Windows interop:

```sh
python3 scripts/package-release.py --output BurpCTL-0.1.0.zip
```

Packaging checks artifact versions and Java 21 bytecode, excludes bundled Montoya classes, writes SHA-256 checksums and removes its archive if writing fails. It never replaces an existing output.

## Verification

Windows checks covered authenticated Rust/Java UDS, permissions, scope, field selection, instance ambiguity, lifecycle cleanup and incomplete exports. An actual Windows Temurin 21.0.12 runtime passed the production-server fixtures: 200 raw byte/hash comparisons and 100 Base64-prefix comparisons. A fix for intermittent EOF receive stalls passed 3,000 successive reads. Cargo fmt/check/clippy, two focused Rust checks on Linux and native Windows, Gradle build and release checks passed.

Controlled five-minute idle samples with and without the extension showed no increase in Burp process I/O transfer counters. Heap grew in both samples without GC, so retained extension RAM is not established. An authorized workload added 20,000 unique loopback POSTs. Before request reuse, a no-match query allocated about 170 MiB on the IPC worker; this measures allocation churn, not retained memory or peak heap. The request-reuse change still needs a live reload and measurement.

Other open checks: Community edition, real Burp running Java 21, multiple real Burp windows, live HTTP/2/gzip, twenty real reloads, abrupt JVM crash recovery and Windows path races. Fixture checks do not establish those integrations.

The [verification guide](verification/README.md) explains how to run the retained checks.

## Help and contributions

Report reproducible problems in [GitHub Issues](https://github.com/dcduc168/BurpCTL/issues). Include Burp edition/version, Java version, CLI/extension versions, the command and error code. Remove credentials, tokens and HTTP evidence before posting.

Keep changes focused. Run the relevant checks in the verification guide and update the protocol when behavior changes.
