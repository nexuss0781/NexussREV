# NexussREV 0.1.0 — Phase 6 release notes

## Supported input and behavior

- The analysis engine supports native Windows PE32+ x86-64 (AMD64) EXE and DLL inputs.
- It emits bounded PE metadata, evidence-labelled function candidates, disassembly and a schema-v6 JSON report. The optional pseudocode view is a best-effort analysis representation, not recovered source and not guaranteed compilable.
- Inputs are treated as data only; NexussREV does not run, emulate or dynamically inspect samples.
- Matching PDB information is used only when the PE CodeView GUID and age match. Missing, corrupted or mismatched symbols are reported rather than silently trusted.
- Unsupported machine types (including PE32/x86 and ARM64) and CLR/.NET images are identified with an explicit `unsupported` status and are not decoded as x64.

## Limits and important constraints

- Input size: 256 MiB maximum.
- Executable decode work: 64 MiB; instruction records: 20,000; decode-gap records: 20,000.
- Each emitted artifact is limited to 64 MiB.
- Optional timeout is cooperative; optional process memory caps use platform facilities and fail plainly when unavailable.
- Each output file is staged, flushed and atomically replaced separately. The output/report pair is not an atomic multi-file transaction.
- No PE32/x86 or ARM64 analyzer, unpacker, dynamic-analysis feature, universal source-recovery claim, or arbitrary-sample execution is included.

## Validation and benchmark scope

Phase 6 CI runs the full existing Linux x64 and Windows x64 test suites, schema and CLI checks, static malformed-input/resource-bound tests, package extraction/runtime smoke tests and a bounded, fixed-seed Clang libFuzzer+ASan+UBSan smoke run on Linux. These tests reduce known risks but do not demonstrate absence of every high-severity defect.

The quality claims remain restricted to the checked-in Phase 5 corpus: 10 valid PE inputs and one malformed case. Its reported parse/decode/function-boundary/CFG/symbol/signature/type/reference measures are sample-scoped; the SQLite DLL's decode coverage is partial because of the byte-work limit, and the SQLite upstream package does not publish compiler identity/flags. The hash-pinned Ghidra 11.3.2 TSV is a comparison baseline, not ground truth. See [`phase5-validation.md`](phase5-validation.md) and [`phase6-validation.md`](phase6-validation.md).

## Packaging and dependencies

CMake/CPack creates a platform package with the executable, discoverable runtime dependencies, project license, README, release notes, active schema v6, preserved schema v5, dependency/license inventory, and every installed vcpkg port's upstream copyright text. The manifest pins LIEF 0.17.6, Capstone 5.0.9 and the vcpkg baseline. CI uploads platform-specific CycloneDX 1.6 SBOMs generated from the resolved install tree. Analysis artifacts are deterministic for fixed input bytes, options, toolchain/dependencies and paths; SBOM timestamps can be fixed explicitly, while CPack archive metadata varies with build-time filesystem timestamps and is not claimed to be byte-identical across builds.
