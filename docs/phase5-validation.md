# Phase 5 validation and quality reporting

Gate 5 turns the previous stage-specific checks into a reproducible, corpus-scoped quality report. It complements the Phase 2 boundary and Phase 4 signature/type benchmarks; it does not reinterpret their results as universal capability claims.

## Reproduce

From a configured build directory, run:

```sh
cmake --build build --parallel 2
ctest --test-dir build --output-on-failure
```

The `nexusrev_phase5_validation` CTest target writes `build/phase5-validation-results.json` (or the active CMake binary directory equivalent). It runs after `nexusrev_phase4_benchmark`; the Gate 2 and Gate 4 thresholds remain sourced from the checked-in v1 manifests. The JSON report includes per-input SHA-256, tool/dependency versions, source/compiler metadata where available, stage statuses, metric counts, the comparison baseline, and reproducible relative analyzer commands. CI uploads this report as `phase5-gate5-validation`.

The corpus manifest is [`../tests/benchmarks/v1/phase5-corpus.json`](../tests/benchmarks/v1/phase5-corpus.json). The eight source-labelled O0/O2 EXE/DLL/PDB/stripped cases come from the existing [`corpus.json`](../tests/benchmarks/v1/corpus.json); their source and compiler/link commands are recorded alongside the Phase 5 manifest. The Phase 4 hash-identified ground truth supplies held-out signature/type scoring. The synthetic malformed input tests the rejected-input path without requiring an output report.

## Metrics and exact denominator policies

| Metric | Numerator / denominator | Unknown and failure policy |
|---|---|---|
| Parse outcome | Valid corpus PEs with `parse=complete` / valid PE samples; separately, expected valid successes plus expected malformed rejections / all valid and negative cases | A missing report, timeout, unexpected status, wrong rejection diagnostic/exit code, or artifacts emitted for the malformed input fails the test. Zero valid samples is not measurable and cannot pass. |
| Executable-byte decode coverage | Sum of `decode.decoded_bytes` / sum of `decode.executable_file_backed_bytes` | A zero denominator is `not_measurable` with a null value, never `1.0`. Decode accounting also asserts `decoded + undecoded = processed` and `processed + limit-excluded = executable file-backed` per sample. Limit-excluded bytes are reported explicitly. |
| Candidate-boundary precision | Exact true-positive starts (or exact half-open ranges) / predicted starts (or ranges), grouped by PDB-present and PDB-stripped cases | Denominator zero is null/`not_measurable`; an empty prediction set is not treated as perfect precision. Exact start and range facts use the existing labelled Gate 2 truth sets. |
| Candidate-boundary recall | Exact true-positive starts (or ranges) / source-labelled starts (or ranges), grouped as above | Denominator zero is null/`not_measurable`; missing expected facts are false negatives. Existing Phase 2 floors are enforced without being raised. |
| CFG edge consistency | Edges whose source block/instruction and any declared in-function target block/RVA resolve consistently / all reported CFG edges | Zero edges is null/`not_measurable` and fails the nonempty Gate 5 evidence requirement. External call edges with no intra-function target block are valid when their source is consistent. |
| Unsupported semantic instructions | Instructions with status `unsupported` / all semantic instruction records; raw counts are also retained | Zero semantic instructions produces null, not a zero unsupported rate. Unsupported items remain visible rather than being excluded. |
| Unresolved flow instructions | Unknown-flow instructions and indirect branch/call instructions without a target / non-fallthrough semantic instructions | Zero flow-instruction denominator is null. Counts of unresolved control flow and unresolved CFG edges are also retained separately. |
| Symbol provenance completeness | Recovered known/candidate/fragment records with nonempty evidence and source / all recovered records | Zero records is null and cannot meet the positive provenance floor. Evidence is measured as provenance presence, not as proof that a label is correct. |
| Signature/type accuracy | Existing Gate 4 exact signature-location, parameter-type, and return-type TP/FP/FN metrics, with separate primary and held-out splits | `unknown` remains a missing ground-truth fact (false negative). Gate 4 confidence calibration is retained on the held-out split. These scores only describe the labelled Clang/LLD source fixture. |
| Reference-backend differences | Reported NexussREV/Ghidra fact differences / compared function/flow facts | The reference is accepted only after the input SHA-256 check. `not_configured`, `invalid`, or `divergent` is not a zero-difference match. Ghidra is a comparison source, not ground truth. |
| Output completeness | Reports conforming to `analysis-report.schema.json` with both declared output artifacts present at the declared paths / successfully analyzed valid samples | A missing or malformed report/artifact fails. A zero-sample denominator is null. The sample input is never overwritten. |

The JSON uses a shared ratio shape with `numerator`, `denominator`, `value`, and `status`; `value` is JSON `null` and `status` is `not_measurable` when the denominator is zero. A failed analysis never becomes a perfect score. Raw counts are preserved even where rates are also computed.

## Corpus and baseline

- **Real-world binary:** SQLite 3.54.0 official precompiled Windows x64 DLL, `sqlite3.dll`, distributed by SQLite under its public-domain dedication. The official archive's published SHA3-256 is verified before the DLL was checked in; the extracted DLL's SHA-256 is in the Phase 5 manifest. The upstream page does not publish the compiler identity or flags, so these are recorded as unknown rather than guessed. The DLL is parsed as data only.
- **Compiler-generated/reference fixture:** original NexussREV C test source compiled with the documented Clang/LLD flags. Its hash-pinned Ghidra 11.3.2 TSV reference currently compares with zero reported differences.
- **Boundary/signature fixtures:** eight existing, hash-pinned Clang/LLD O0/O2 EXE/DLL cases, both with matching PDBs and with export/CodeView directories stripped. Their compiler settings and ground truth remain recorded in the source manifests.
- **Malformed-input test:** a fixed byte string whose SHA-256, expected parse-failure exit code, diagnostic, and no-artifact expectation are pinned in the manifest.

`baseline_release_commit` records the Phase 4 baseline commit `2e52bd4`. [`phase5-baseline.json`](../tests/benchmarks/v1/phase5-baseline.json) pins stable per-sample input identities, stage/status results, decode accounting, recovery/provenance counts, semantic/CFG counts, reference state, and tool/dependency versions from that release. Gate 5 requires an exact match; changing an invariant therefore needs a reviewed baseline update. In addition, the run enforces the existing Phase 2 precision/recall floors and Phase 4 signature/type/calibration thresholds, adds initial decode/provenance/output floors, and checks the Ghidra reference. Changes to thresholds require reviewed corpus evidence; corpus results are not advertised as general binary performance.

The SQLite binary's executable section exceeds the analyzer's configured record budget. The current measured coverage is therefore partial; decoded and limit-excluded bytes are both included. Dynamic/compile-and-test validation is not applicable because emitted pseudocode is explicitly not a supported compilable subset. No PE fixture is executed.

The downloaded Antigravity file is a 32-bit Nullsoft installer wrapper, not the native PE32+ x86-64 application target. It is excluded from this corpus and was not run. No compatible Antigravity application binary is claimed to have been decompiled.
