# BurpCTL

Read Burp Suite status, scope and proxy history from a native Windows CLI. BurpCTL queries Montoya on demand and returns selected fields or exact message bytes. It keeps no history cache or index.

BurpCTL `0.1.0` is the first release. It supports `status`, `instance list`, `history list`, `history get`, `scope check` and `repeater screenshot`, and has been exercised with Burp Suite Professional 2026.10. Remaining acceptance checks are listed under [verification](#verification).

## Get started

Download `burpctl.exe` and `burpctl-extension.jar` from the [latest release](https://github.com/dcduc168/BurpCTL/releases/latest), or [build from source](#build-from-source), then:

1. Copy `burpctl.exe` to local NTFS and add its directory to Windows PATH. The MSVC build requires `VCRUNTIME140.dll`; loading the executable from a WSL share was slower on the tested host.
2. Load `burpctl-extension.jar` as a Java extension in Burp. The extension needs Java 21 or later and Montoya 2026.7 APIs.
3. Open Burp Settings and search for `BurpCTL`. Enable metadata reads for history you authorize local tooling to access. Enable raw reads separately when you need message or body bytes.

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

## Capture Repeater

Enable **Allow Repeater screenshots** in BurpCTL settings:

```powershell
burpctl.exe --instance INSTANCE repeater screenshot --output repeater.png
```

This saves a PNG of the main-window Repeater pane, including its current viewport and tab labels, even while another main tool is selected. Repeater must already have a usable layout; if it has not been initialized, open it once before capture. It does not switch tabs or send requests. Screenshot permission is separate from history permissions and allows sensitive content outside target scope; Montoya cannot verify the selected Repeater request's scope. Detached/minimized windows and unrecognized layouts are unsupported. Large panes above 4,194,304 pixels or PNGs above 8 MiB fail explicitly.

Exports verify size and SHA-256, clean incomplete files and require `--force` to replace an existing file. Rendering runs on the EDT; PNG encoding and transfer run on a worker. There is no screenshot cache or background capture. The approach uses Swing component rendering, as demonstrated by [BurpSuiteSharpenerEx](https://github.com/irsdl/BurpSuiteSharpenerEx/blob/main/src/main/java/ninja/burpsuite/extension/sharpener/uiControllers/subTabs/SubTabsActions.java).

## Output and limits

Filtering and field selection run in Java before serialization. `path` excludes the query string. Empty lists succeed. History ordering is unspecified; row limits cap returned matches, not traversal or Montoya allocations, and a limit hit does not prove that more matches exist.

Compact output is the default. Use `--format json` to retain the protocol envelope. Stdout carries results, stderr carries diagnostics, and exit codes distinguish denial, timeout and incomplete export. See the [protocol reference](protocol/SPEC.md) for fields, budgets and errors.

Each instance uses a token and current-user NTFS ACLs under `%LOCALAPPDATA%\burpctl\r`. Startup fails if ACL setup fails or the socket path exceeds 100 UTF-8 bytes. Discovery checks liveness through authenticated status calls; it excludes stale entries and leaves other instances' files alone. ACLs and tokens do not isolate BurpCTL from malicious processes running as the same user.

The [BurpCTL Agent Skill](skills/burpctl/SKILL.md) covers instance selection and authorized evidence retrieval.

## Build from source

Use stable Rust and JDK 21. Set `JAVA_HOME` to the JDK. Gradle 9.2.1 is pinned by the wrapper; dependencies are locked and Gradle artifacts have checksum verification.

The CLI release profile uses size optimization (`z`), ThinLTO and stripped symbols. On the tested Windows MSVC build, this reduced the executable from 986 to 665 KiB; 50 synthetic 8 MiB exports per profile had medians of 58.48 and 59.02 ms, with every SHA-256 verified. Sizes and timings depend on the compiler and host. Java remains a Java 21 JAR loaded by Burp's JVM.

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

Validate matching artifacts with Python 3.11 or later on Windows, or WSL with Windows interop:

```sh
python3 scripts/check-release.py
```

This checks CLI/JAR versions, Java 21 bytecode and that Montoya classes are not bundled.

## GitHub release builds

The [release workflow](.github/workflows/release.yml) builds on Windows Server 2025 with Rust 1.98.1, Temurin 21.0.12 and the pinned Gradle wrapper. It checks the CLI, Java fixtures, native raw/Base64 transfers, interrupted exports and release artifact validation. Live Burp and Repeater UI verification remain manual.

Push a tag matching the product version, such as `v0.1.0`, to build `burpctl.exe` and `burpctl-extension.jar` as separate release assets. The workflow creates a draft GitHub release after the checks pass; versions with a prerelease suffix are marked as prereleases. Release titles use only the version; notes contain the Full Changelog link. Review and publish the draft separately. Existing releases are never overwritten; a failed run that already created a draft needs that draft removed before retrying.

For a build without creating a release, select **Release build → Run workflow** in GitHub Actions. The two binaries are retained as workflow artifacts for 14 days. The workflow must first exist on the default branch to enable this control.

## Verification

Checks cover authenticated Rust/Java UDS, permissions, scope, field selection, instance ambiguity and incomplete exports. Production-server fixtures passed 200 raw byte/hash comparisons and 100 Base64-prefix comparisons on Windows Temurin 21.0.12. Cargo fmt/check/clippy, four focused Rust checks on Linux and native Windows, Gradle build and release artifact validation checks passed.

History uses filtered Montoya traversal. `--limit` bounds returned rows, not Burp's internal allocations. Retained extension RAM and per-operation Burp peak memory have not been isolated by measurement.

Production-entry-point fixtures passed 20 initialized unload/reload cycles and 20 immediate-unload races, including a socket waiting for a partial frame. These ran on the bundled Windows Java 26 runtime with Java 21 bytecode.

Other open checks: Community edition, real Burp running Java 21, multiple real Burp windows, live HTTP/2/gzip, twenty real reloads, abrupt JVM crash recovery and Windows path races. Fixture checks do not establish those integrations.

The [verification guide](verification/README.md) explains how to run the retained checks.

## Help and contributions

Report reproducible problems in [GitHub Issues](https://github.com/dcduc168/BurpCTL/issues). Include Burp edition/version, Java version, CLI/extension versions, the command and error code. Remove credentials, tokens and HTTP evidence before posting.

Keep changes focused. Run the relevant checks in the verification guide and update the protocol when behavior changes.
