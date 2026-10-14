# Phase 6 validation and release hardening

Phase 6 keeps the supported analysis surface at native PE32+ x86-64. ARM64, PE32/x86, CLR/.NET native decoding, unpacking and dynamic analysis remain separate or explicitly unsupported. All checked-in executable fixtures are consumed as bytes; none is executed.

## Reproduce build, tests and package

Follow the clean-machine steps in [`../README.md`](../README.md), then run:

```sh
cmake --build build --parallel 2
ctest --test-dir build --output-on-failure
cmake --build build --target package
```

The test suite covers parser/RVA boundary conditions, CLI help/version and report schema v6, the preserved v5 schema, deterministic output for fixed paths/options, structured JSONL diagnostics, unsupported-target reporting, malformed/mismatched PDB handling, an oversized sparse input, a process memory cap, cooperative deadlines and cancellation state. Every CLI rejection/stop test asserts that no new analysis artifact is emitted. Existing Phase 2/4 score thresholds and the hash-checked Gate 5 corpus baseline remain in force.

The CPack archive includes the executable, CMake-discovered runtime libraries, `LICENSE`, README, the current and v5 JSON schemas, the dependency/license inventory, and the exact vcpkg `copyright` text for every installed port under `share/nexusrev/licenses/<port>/copyright`. CI extracts the archive, compares each notice byte-for-byte with the resolved install tree, and runs its packaged `--version` and `--help` commands before uploading it.

## Fuzz harness

The `nexusrev_phase6_fuzz` libFuzzer harness exercises four surfaces with each input:

1. bounded PE parsing (including malformed headers and directory metadata);
2. RVA/file mapping and bounded read probes at input-derived values and section edges;
3. Capstone x86-64 instruction-stream decoding over at most 64 KiB / 128 decoded records;
4. analysis-report JSON serialization with arbitrary input bytes passed through escaped strings.

It processes at most 1 MiB per fuzz input and never executes the supplied bytes. Seed corpus files are copies of checked-in synthetic PE fixtures. The CI Linux smoke run is sanitizer-instrumented, bounded by run count, per-input timeout and RSS; minimized failures must be retained as regression seeds before release.

To build against the already-installed pinned Linux dependencies with Clang:

```sh
CC=clang CXX=clang++ cmake -S . -B build-fuzz \
  -DCMAKE_PREFIX_PATH="$PWD/build/vcpkg_installed/x64-linux" \
  -DNEXUSREV_BUILD_FUZZERS=ON \
  -DNEXUSREV_WARNINGS_AS_ERRORS=OFF
cmake --build build-fuzz --target nexusrev_phase6_fuzz --parallel 2
mkdir -p build-fuzz/corpus
cp tests/fuzz/corpus/* build-fuzz/corpus/
build-fuzz/nexusrev_phase6_fuzz -seed=20261015 -runs=2000 -max_len=4096 \
  -timeout=5 -rss_limit_mb=1024 build-fuzz/corpus
```

The fuzz target requires Clang with libFuzzer and AddressSanitizer/UndefinedBehaviorSanitizer support. The test harness is bounded and is not a claim of exhaustive fuzz coverage or a substitute for a security review.

## Resource and cancellation behavior

The command-line `--timeout-ms` deadline is **cooperative**, checked around bounded analysis work and at instruction decode checkpoints. It is not an OS-enforced hard kill; callers needing a strict service deadline should also use an external watchdog. On timeout, NexussREV returns 124; on Ctrl-C/Ctrl-Break/SIGTERM cancellation it returns 130. In either case it does not intentionally serialize a partial analysis result.

`--memory-limit-mib` applies a process memory limit where supported (POSIX `RLIMIT_AS`; Windows process-memory Job Object). A limit that the host cannot enforce fails explicitly as `RESOURCE_LIMIT_UNAVAILABLE`. Even without a caller-selected cap, input, decode work, record counts and artifact sizes have hard limits. Inputs over 256 MiB are rejected before full-file allocation.

Each artifact is flushed to a unique sibling staging directory and individually atomically renamed into place; POSIX files and containing directories are synced where available, and Windows uses write-through replacement. The pair of output and report cannot be made a single transaction across arbitrary directories/filesystems. If a process is interrupted between the two replacements, a previously completed artifact remains whole; consumers should verify the report's declared artifact paths and input hash.

## Determinism, schema, logs and inventory

For a fixed input byte sequence, invocation, dependency set and output paths, analysis and report content are deterministic. Reports include the input path and artifact paths, so comparing runs made with different paths naturally changes those fields. Staging names are not written into artifacts. SBOMs use the current UTC timestamp by default; pass `--timestamp` to make the generated SBOM byte-for-byte reproducible for the same installed package set. CPack archives include build-time filesystem metadata and are not claimed to be byte-for-byte identical across separate builds; their package contents, pinned dependency set and smoke-tested runtime are reproducible.

Schema v6 is the active contract at [`analysis-report.schema.json`](analysis-report.schema.json); the prior v5 schema is retained unchanged at [`analysis-report-v5.schema.json`](analysis-report-v5.schema.json). The schema contract version is independent of the analyzer configuration version used by the frozen Phase 5 metric projection.

Text diagnostics remain the default. `--log-format jsonl` emits machine-readable stderr objects with `level`, `code`, and `message` fields. `--help` and `--version` describe the supported target and dependency/schema versions.

The checked-in [`dependency/license inventory`](dependency-license-inventory.md) documents direct and resolved dependencies. CI generates a platform-specific CycloneDX 1.6 SBOM from the installed vcpkg database, verifies every component/version/PURL/license and dependency reference against that tree, and uploads the SBOM with release packages. The two SBOMs can differ in platform-specific components but name the same manifest baseline.

## Gate limits and release decision

CI supports Linux x64 and Windows x64 host builds; it does not establish support for binaries from every compiler, packer, architecture or operating-system version. The Phase 5 10-PE benchmark and Ghidra comparison remain corpus-scoped. CI sanitizer/fuzz smoke coverage and checked-in adversarial fixtures reduce risk but do not prove absence of all vulnerabilities.
