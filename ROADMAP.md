# NexussREV Production Roadmap

**Purpose:** Replace the current “zero-loss source recovery” prototype claims with a testable, staged plan for a dependable Windows PE reverse-engineering and decompilation tool.

**Repository baseline inspected:** 2026-10-14. This roadmap defines target gates; completion and verification evidence are recorded with the corresponding phase.

## 1. Product target and non-negotiable truth

NexussREV should produce **evidence-backed, confidence-labelled C-like pseudocode and binary-analysis artifacts**. It must not promise to recreate an arbitrary executable’s exact original source or guarantee zero errors. Compilation is lossy and many-to-one: comments, macros, original names, source layout, intent, and sometimes type distinctions are absent from the binary; optimization, inlining, link-time optimization, stripping, packing, and obfuscation make reconstruction harder. A decompiler can estimate semantics and recover some source-level structure; it cannot generally invert compilation uniquely.

Use these terms consistently:

- **Disassembly:** decoded machine instructions, with invalid or undecoded byte ranges reported.
- **Decompilation:** a best-effort higher-level representation reconstructed from instructions and analysis.
- **Original-source recovery:** not a supported guarantee. When debug information or PDBs expose source names/types/lines, report their provenance and limits.
- **Correctness:** measured on a declared, versioned corpus using structural checks and (where feasible) differential or equivalence tests. A “100%” result may only refer to a clearly named corpus metric—not arbitrary binaries or exact source recovery.

## 2. Freeze now: stable boundaries, not incorrect behavior

Freeze the **product boundaries and data contracts** below so implementation can change without perpetuating false assumptions. “Freeze” does not mean preserving the current implementation or its metrics.

| NexussREV component / boundary | Inputs | Required outputs | Freeze / upgrade decision |
|---|---|---|---|
| CLI compatibility facade (`src/main.cpp`) | Existing `nexusrev <input.exe> <output>` invocation; later explicit options | Deterministic exit code, output artifact(s), machine-readable status/diagnostics | **Freeze the two-path invocation as a compatibility mode.** Add explicit format/report/backend flags. Do not freeze the current “finished / zero loss” console wording. |
| PE image adapter (current `load_binary`, LIEF) | File path or bounded byte stream | Validated PE image model: machine, PE32/PE32+, image base, sections, data directories, RVA↔file mapping, imports/exports, relocations, debug/exception metadata where available, and parse diagnostics | **Freeze an internal adapter contract only.** Keep LIEF behind it; remove `/usr/local` assumptions and never treat parse success as code recovery. LIEF parses/manipulates PE structures; it is not a decompiler. |
| Function-candidate discovery (current `recover_symbols`) | Parsed PE, entry point, exports, optional PDB/debug data, executable ranges, references | Candidate ranges with start/end, origin/provenance, confidence, ambiguity/overlap, and unresolved status | **Replace current behavior.** A PE symbol is not automatically a function; never invent a `0x100` size. Preserve a candidate-vs-confirmed distinction. |
| Decoder adapter (current Capstone calls) | Architecture/mode, address, executable bytes and decode options | Ordered instruction records (address, bytes, opcode/operands, flow effects where available) plus explicit gaps/errors | **Freeze a decoder interface, not x86-64-only behavior.** Capstone is a disassembly framework, not a source lifter. Make architecture and mode come from the PE header. |
| Analysis record/schema (current `Function`) | PE metadata, candidate range, decoded instructions, analysis results | Versioned records with VA, RVA, file offset, bytes, provenance, stage status, confidence and references to CFG/IR | **Do not freeze the current struct.** Its `size`, `pseudo_code` and `analysis_complete` conflate guesses with facts. Freeze a documented, versioned interchange schema before multiple backends depend on it. |
| CFG and type-analysis stages (current `analyze_control_flow`, `infer_types`) | Instructions/IR, call/reference facts, ABI and optional symbols | Basic blocks and typed edges; conservative type/variable annotations with evidence and confidence | **Keep the stage boundaries; replace the stubs.** Until implemented, report “not analyzed,” not an empty graph or successful inference. |
| “Deep recovery” fallback | Partial analysis and unresolved ranges | Additional evidence-backed candidates or explicit unresolved ranges | **Disable/retire the current implementation.** It fabricates sizes, retries the same bytes, and forces metrics to perfect values. No heuristic may convert failure into success. |
| Metrics and reconstruction validator | PE executable ranges and stage outputs | Per-stage coverage, decode gaps, function-candidate quality, unresolved/unsupported counts, provenance, warnings, and validation results | **Replace `LossMetrics` semantics.** Never equate symbol count, guessed function bytes, or emitted text with fidelity. No synthetic zero-loss scalar or forced “100%” flag. |
| Pseudocode emitter (current `disassemble_function` / `emit_code`) | CFG/IR and analysis annotations | Clearly labelled C-like pseudocode, address/source annotations, and separate JSON report; optionally raw disassembly | **Replace the current emitter.** Mnemonics inside C braces are not C source. Label output as pseudocode unless it passes a separate compilable-output contract. |
| Build/dependency/test boundary | Compiler, CMake, pinned dependency configuration | Reproducible configure/build/test result on declared platforms | **Freeze dependency policy, not local paths:** discover or fetch pinned dependencies through a supported package workflow; no hard-coded `/usr/local`. Add CI and tests before feature growth. |

### Frozen v1 scope

For the first production-minded release, constrain scope to **static analysis of native Windows PE32+ x86-64 EXEs and DLLs**. Support x86-64 Windows ABI assumptions explicitly. Report unsupported architectures and managed/.NET images rather than silently analyzing them as native x86-64. Defer ARM64, PE32/x86, kernel drivers, packed/self-modifying binaries, runtime unpacking, and exact source recovery until separate gates are approved. This is a scope-control decision, not a claim that other files cannot be parsed.

### Frozen result semantics

Every stage returns one of: `complete`, `partial`, `unsupported`, or `failed`, with structured diagnostics. “No function found” is not “all functions recovered.” “No decode error” is not proof of correct function boundaries. Missing symbols are not proof of missing code. Preserve original bytes and record address/RVA/file-offset mapping so every claim can be checked against the input.

## 3. Target component contracts (inputs and outputs)

Keep dependencies replaceable behind narrow contracts. This is the intended end-state data flow; each output should be persistable in a versioned JSON analysis bundle.

| Component | Inputs | Outputs |
|---|---|---|
| CLI / job manifest | Input PE path; output directory; selected architecture override only when justified; symbol paths; limits; requested artifact formats | Job manifest with input SHA-256, tool/config versions, start/end status, exit code, and artifact paths |
| PE loader / validator | PE file bytes, size and resource limits | Validated PE model; machine and image kind; section map; RVA/file-offset translation; entry point; imports/exports; relocation, exception, TLS, debug and CLR metadata where present; parse errors/warnings |
| Debug/symbol provider | PE debug directory and matching PDB (when available) | Symbol/type/source-line records with PDB identity (GUID/age), source, and confidence; explicit missing/mismatch status |
| Code-range discovery | PE model; entry point, exports, PDB function records, x64 exception/unwind ranges, relocations/references | Candidate code/function ranges with evidence, boundaries, confidence and unresolved/overlapping ranges |
| Instruction decoder | Machine/mode, VA, executable bytes, decode options | Instruction records and exact undecoded byte intervals; no assertion that an instruction stream is a function |
| CFG builder | Instruction records, branch/call targets, candidate ranges | Basic blocks and typed edges (fall-through, conditional, call, return, indirect/unknown), plus unresolved edges |
| IR lifter / ABI model | Instructions, target architecture, calling convention, imports and known prototypes | Architecture-neutral intermediate representation with register, flag, memory, call, branch and side-effect semantics; unsupported semantics marked explicitly |
| Dataflow / type recovery | IR, debug symbols, imports/prototypes, ABI rules, cross-references | Variables, stack slots, inferred types, function signatures and call relationships, each with evidence/confidence and “unknown” allowed |
| High-level structurer / emitter | CFG, IR and recovery results | C-like pseudocode (not guaranteed compilable or original), annotated disassembly, and optional compilable subset only under its own validation gate |
| Validator / report | Original PE plus all stage outputs and declared test evidence | Stage-by-stage coverage/quality, gaps, disagreements, invariants, benchmark results, provenance, and limitations; never a blanket “zero loss” assertion |

## 4. Gated implementation phases

A phase is complete only when its exit gate is satisfied in CI and its artifacts are reproducible. A failed gate blocks downstream feature claims; it does not trigger a forced-success fallback.

### Phase 0 — Correct the contract and make the project buildable

**Upgrade areas**

1. Remove or rewrite README and benchmark claims of “zero-loss,” 100% recovery, verified reconstruction, and broad C/C++/Rust capability. The current `benchmarks.md` is unsubstantiated and should be marked historical/unverified or removed from performance claims until regenerated.
2. Correct status behavior: `load_binary`, `analyze`, and emission must propagate real errors; output-write failures must fail the command. Remove forced `reconstruction_100_percent`, guessed byte totals, and `loss_ratio == 0` success logic.
3. Replace hard-coded LIEF paths and implicit library discovery with CMake package targets or a documented, pinned dependency manager. Pin versions/commits once selected; record versions in reports.
4. Add unit-test and CI skeletons (Windows x64 and Linux x64 build/test jobs; the analysis target remains Windows PE). Add warning-clean builds, sanitizers where available, and a small deterministic PE fixture corpus.
5. Specify the status model, artifact layout, error taxonomy and versioned interchange schema from Section 3.

**Gate 0**

- Clean configure, build and test on supported CI runners; no machine-local `/usr/local` dependency.
- Missing/malformed input and unwritable output produce non-zero exit codes and useful diagnostics; no success banner or artifact is emitted on failure.
- README, CLI help and reports make no exact-source or arbitrary zero-error promise.
- Every checked-in benchmark has a reproducible command, input identity/hash, tool version, and measured method—or is clearly marked unverified.

**Initial baseline blocker (addressed in Phase 0):** the review-time clean configure failed because Capstone was not discoverable and CMake hard-coded LIEF at `/usr/local`. The Phase 0 implementation replaces those assumptions with pinned vcpkg dependencies and CMake package targets; gate completion depends on the verification evidence for this phase.

**Owner-accepted README exception (2026-10-14):** At the project owner's direction, `README.md` remains byte-for-byte identical to its pre-Phase 0 version as the intended product vision. This explicitly waives the README-specific part of Upgrade Area 1 and Gate 0 item 3 for this phase; it does not assert that the current tool already achieves those README outcomes. CLI help, JSON reports, and the scoped status documentation remain accurate about the current partial static-analysis capability, while `benchmarks.md` remains historical/unverified.

**Gate 0 status: COMPLETE WITH ACCEPTED README EXCEPTION.** A clean Linux configure/build and both local CTest targets passed. GitHub Actions run [38458802467](https://github.com/nexuss0781/NexussREV/actions/runs/38458802467) for the README-restoration commit `ec603c6` passed Windows x64 and Linux x64 build/test jobs. The Phase 0 implementation commit `d2dcde9` also passed both jobs in [run 38457664855](https://github.com/nexuss0781/NexussREV/actions/runs/38457664855).

### Phase 1 — Correct PE ingestion and decode accounting

**Upgrade areas**

- Parse PE32+ x86-64 first; validate headers, section ranges, arithmetic overflow, data-directory counts, and RVA/file-offset mappings before reading content.
- Separate file offsets, RVAs, and VAs in types and reports. Handle section boundaries and virtual zero-fill correctly; do not request bytes through guessed ranges.
- Consume the PE entry point, executable section characteristics, imports/exports, base relocations, debug directory, TLS and x64 exception/unwind metadata where present. Distinguish native PE from CLR/.NET images.
- Make Capstone configuration derive from PE machine type; preserve full decoder detail and record invalid bytes, truncation and unsupported instructions rather than accepting a partial decode as complete.
- Bound input size, analysis work and output size. Treat samples as untrusted data; static analysis must never launch the input executable.

**Gate 1**

- Unit fixtures verify RVA/VA/file-offset conversion and section edge cases, PE32+ identity, imports/exports and truncated/malformed inputs.
- Decoder results match expected instruction bytes and addresses on checked-in compiler-generated fixtures; every undecoded interval is reported.
- No symbol count or heuristic byte estimate is presented as code coverage.

**Gate 1 status: COMPLETE.** The implementation is in commit `0abaa03`. The sanitizer-enabled, warnings-as-errors Linux build and both local CTest targets passed; schema v2 validates native, compiler-generated, CLR, and alternate-machine reports. GitHub Actions [run 38547827430](https://github.com/nexuss0781/NexussREV/actions/runs/38547827430) passed Linux x64 and Windows x64 build/test jobs. The compiler-generated fixture asserts exact instruction bytes/addresses and Capstone detail. No input executable was launched.

### Phase 2 — Evidence-based symbol and function-boundary recovery

**Upgrade areas**

- Add a debug-symbol provider for matching PDBs and record the PDB identity and source of every recovered label/type. Mismatched or unavailable symbols are a normal partial result.
- Combine PDB function records, PE exports/entry point, x64 exception/unwind ranges, code references and conservative recursive-descent analysis. Treat each source as evidence, not ground truth; account for thunks, tail calls, jump tables, cold fragments, inlining, overlapping code/data and indirect control flow.
- Preserve separate entities for known functions, candidate functions, fragments and unresolved executable ranges. Do not use “all PE symbols” as “all functions.”
- Establish a lawful, versioned benchmark set with PDB-present and PDB-stripped builds, MSVC/clang-cl/MinGW variants, EXEs and DLLs. Include optimized and unoptimized fixtures and cases with no useful symbols.

**Gate 2**

- On labelled fixtures, report precision and recall for function starts/ranges separately for symbol-backed and stripped cases. Set thresholds from the checked-in baseline and raise them only with reviewed benchmark evidence.
- Every discovered range has provenance; ambiguous boundaries remain explicitly ambiguous. No failed discovery is silently counted as a recovered function.

**Phase 2 implementation status (2026-10-15): IMPLEMENTED; the checked-in Clang/LLD v1 Gate 2 baseline passes.** Schema v3 and the optional MSF 7.0 PDB reader validate CodeView GUID/age before consuming procedure records. PDB labels/ranges, exports, entry point, x64 runtime-function ranges, and conservative direct-flow targets are kept as evidence; known functions, candidates, fragments, unresolved executable ranges, and unresolved control flow remain distinct. The fixed benchmark has eight labelled EXE/DLL cases (O0/O2, matching PDB/PDB-stripped) and records input/PDB/source hashes. The pinned Clang 18.1.3/LLD 18.1.3 baseline measures matching-PDB precision/recall of 1.000/1.000 for both starts and ranges; stripped precision/recall is 1.000/0.750 for starts and 1.000/0.625 for ranges. A separately versioned generated matrix now defines eight additional cases each for MSVC, clang-cl, and MinGW, with per-toolchain precision/recall floors and report artifacts. Locally, MinGW GCC 13 produced 1.000 precision/recall for starts and ranges in both DWARF-present/no-PDB and stripped groups; a clang-cl/LLD surrogate produced matching-PDB 1.000/1.000 and stripped 1.000/0.750 start and 1.000/0.625 range precision/recall. Sanitizer-enabled, warnings-as-errors Linux build and the unit, CLI, and fixed-baseline benchmark tests passed locally; input PE fixtures were not executed.

**Cross-toolchain validation status: COMPLETE.** Hosted run [38595104195](https://github.com/nexuss0781/NexussREV/actions/runs/38595104195) passed both Linux and Windows jobs and generated eight measured cases each for MSVC, clang-cl and MinGW. Matching-PDB MSVC and clang-cl cases each achieved 1.000 precision/recall for starts and ranges. Stripped MSVC achieved 1.000/0.750 start and 1.000/0.375 range precision/recall; stripped clang-cl achieved 1.000/0.750 and 1.000/0.625. MinGW achieved 1.000/1.000 for starts and ranges in both DWARF-present/no-PDB and stripped classes. The MSVC stripped-range recall sets the generated-matrix floor of 0.375; this lower recall is recorded explicitly rather than masked by other toolchains. The full per-case truths, ranges, hashes, compiler versions and thresholds are checked in at `tests/benchmarks/v1/toolchain-baseline.json` and retained as artifacts from the linked Actions run. The labeled PE fixtures were generated and analyzed statically; no fixture was executed.

### Phase 3 — Semantic lifting and control-flow foundation

**Upgrade areas**

- Use a mature decompiler as the correctness/reference baseline before attempting broad custom lifting. The recommended low-risk path is to automate Ghidra as an optional reference backend and compare NexussREV artifacts against it; if delivery speed is the priority, consider exposing Ghidra’s decompilation through an adapter rather than rebuilding its full engine.
- Retain Capstone for decoding only. A decoder’s instruction strings are not a semantic IR. Implement or adopt an architecture-specific lifter with explicit semantics for registers, flags, memory, calls, branches, stack effects and side effects; start with the declared x86-64 Windows ABI.
- Build basic blocks and control-flow edges from decoded instructions. Model unknown indirect destinations rather than inventing targets. Add call graph and cross-reference edges only with provenance.
- Keep backend-specific code outside the stable PE, candidate, CFG and output schema.

**Gate 3**

- Synthetic instruction tests cover each implemented instruction semantic and control-flow edge, including flags, signed/unsigned conditions, calls/returns, stack operations and indirect branches.
- Differential comparisons against the reference tool flag disagreements; any unsupported or divergent instruction is visible in the report. No function is marked semantically complete if it contains unmodelled instructions or unresolved control flow.

**Phase 3 / Gate 3 status (2026-10-15): COMPLETE.** Schema v4 adds a conservative x86-64 Microsoft-ABI semantic IR with explicit operands, register/RFLAGS/memory/stack effects and control-flow classification. The implemented subset covers common data movement, integer arithmetic/logic, condition-code operations, calls, branches, returns, stack actions, and `leave`; count-dependent shift instructions remain explicitly unsupported until their flag semantics can be represented precisely. Bounded function CFGs emit basic blocks, typed branch/fallthrough/call/unknown edges, and call-graph edges with provenance. Unbounded or ambiguous ranges, any intersecting decode gap, out-of-function targets, unsupported instructions, and indirect or unmodeled control transfers block semantic completion; unresolved direct calls remain distinct from indirect calls. The optional Ghidra headless exporter and hash-checked differential comparator are documented in `docs/phase3-semantic-analysis.md`. Synthetic tests cover modeled operations/edges, flag and condition effects, stack widths, unresolved/unknown flow, reference mismatches, and incomplete-function rules. A checksum-verified Ghidra 11.3.2 headless run on the checked-in compiler-generated fixture produced two function starts and two return-flow facts; the NexussREV comparator reported zero differences, and the generated report passed schema validation. Its versioned TSV is checked in and replayed by CLI tests in CI together with full report-schema validation. The Antigravity installer was not executed.

### Phase 4 — Dataflow, ABI, types and high-level structure

**Upgrade areas**

- Implement stack-frame and variable recovery, calling-convention/signature recovery, import prototypes, cross-function dataflow, and conservative type propagation. Use PDB/RTTI/vtable evidence where available; distinguish observed types from inferred types.
- Recover common control structures (conditions, loops, switches) only when CFG evidence supports them. Preserve irreducible or ambiguous flow in a lower-level representation rather than forcing misleading C syntax.
- Give every inferred type, name and prototype a confidence and evidence trail. Allow `unknown`, raw addresses and byte arrays as legitimate outputs.

**Gate 4**

- Type/signature metrics are evaluated only on fixtures with known ground truth and report precision as well as recall. Confidence calibration is measured against held-out samples.
- Pseudocode output is clearly labelled; no unsupported claim that it recompiles or equals original source. Unsupported cases remain inspectable through disassembly and IR.

**Phase 4 / Gate 4 status (2026-10-15): COMPLETE, corpus-scoped.** Schema v5 adds bounded stack-frame/slot analysis, Microsoft x64 ABI signatures, RIP-relative IAT call matching, a versioned import-prototype catalog, cross-function call-argument provenance and direct-callee type propagation, conservative CFG-backed conditional/natural-loop recovery, and a clearly labelled `--format pseudocode` view. The identity-checked MSF reader decodes bounded PDB TPI scalar, modifier, pointer, procedure/member-procedure, and argument-list records; a separate static-only MSVC x64 scanner validates self-relative RTTI locators, class hierarchy/type descriptors, vtable prefixes, and executable virtual-method RVAs. Other ABI/compiler RTTI formats, UDT field layouts, and aggregate types remain unknown. The hash-verified Gate 4 fixture records four source-known signatures with int parameter/return types in both Clang/LLD O0 primary and O2 held-out DLL fixtures. Current measured signature-location, parameter-type, and return-type precision/recall are each 1.000/1.000 in both splits; held-out confidence expected calibration error is 0.010 (four scored argument facts, mean confidence 0.990, empirical accuracy 1.000). These are deliberately corpus-limited results, not general-binary claims. CMake/CTest includes synthetic stack, ABI, import-dataflow, direct-call type-propagation, RTTI/vtable, structure, CLI, schema, and benchmark checks; the local warnings-as-errors build and all four CTest targets passed. Pseudocode retains unknowns and limitations; path-sensitive SSA, full switch recognition, broad aggregate inference, and non-MSVC RTTI recovery remain out of scope. PE fixtures are analyzed as data only, and the Antigravity installer sample was not executed.

### Phase 5 — Validation, corpus expansion and quality reporting

**Upgrade areas**

- Replace the single loss ratio with independent measures: PE parse status, executable-byte decode coverage, candidate-boundary precision/recall on labelled samples, CFG edge consistency, unresolved instructions/edges, symbol provenance, type/signature accuracy, and output completeness.
- Add regression tests from real-world but legally distributable binaries and synthetic compiler fixtures. Store hashes, compiler/tool versions, flags and expected invariants. Compare generated artifacts against the previous release and the reference backend.
- Where a compilable subset is explicitly supported, validate it separately with compile-and-test or differential execution in an isolated, disposable Windows environment. Never execute arbitrary user samples on the host; dynamic behavior is optional evidence, not a substitute for static analysis.

**Gate 5**

- Every metric has a documented numerator/denominator and unknown-state policy; no zero denominator or failed analysis defaults to a perfect score.
- CI fails on unexplained regressions; benchmark results include sample identity, compiler settings, reference versions and reproducible commands.
- A report distinguishes “measured on this corpus” from general capability. No universal no-error claim is made.

**Phase 5 / Gate 5 status (2026-10-15): COMPLETE; local and hosted gates pass.** The v1 corpus adds a hash-verified official SQLite 3.54.0 public-domain Windows x64 DLL plus the original Clang/LLD fixtures and the existing eight source-labelled O0/O2 EXE/DLL, PDB-present/stripped cases. Gate 5 now emits a schema-checked JSON quality report with independent parse outcome, executable-byte decode coverage, boundary precision/recall, CFG edge consistency, unresolved instruction/flow counts, symbol evidence provenance, Gate 4 signature/type/calibration results, hash-checked Ghidra 11.3.2 comparison, and output completeness. On the current Phase 4 build, the 10 valid corpus inputs parsed successfully (10/10); aggregate decode coverage was 35,099 / 2,904,782 executable file-backed bytes (1.208%, with record-budget-excluded bytes reported); CFG consistency was 26/26, recovered-function provenance 815/815, output completeness 10/10, and Ghidra reference differences 0. The checked-in Phase 4 release snapshot and existing Phase 2/4 floors are enforced. Hosted [CI run #38624967453](https://github.com/nexuss0781/NexussREV/actions/runs/38624967453) passed on both Linux and Windows and uploaded the Gate 5 report. The SQLite compiler identity/flags are explicitly unknown because the upstream package does not publish them. All fixtures are static-only. The downloaded Antigravity file was identified as a 32-bit Nullsoft installer wrapper, excluded as incompatible, and not executed; no compatible Antigravity application decompilation is claimed. See [`docs/phase5-validation.md`](docs/phase5-validation.md).

### Phase 6 — Hardened release and supported product surface
**Upgrade areas**

- Fuzz PE parsing, RVA mapping, instruction streams and artifact serialization; test timeouts, memory limits, cancellation, corrupted symbols and oversized inputs.
- Add reproducible packaging, dependency/license inventory, SBOM, versioned JSON schema, CLI help, structured logs, crash-safe output writes and clear unsupported-feature reporting.
- Add Windows ARM64 and PE32/x86 only as separate, tested architecture phases. Consider packing/unpacking or dynamic analysis only with a separate threat model and explicit isolated execution design.

**Gate 6 / release criteria**

- All supported-platform CI gates pass; fuzzing has no unresolved critical/high-severity parser or memory-safety issue in the release candidate.
- Install/build instructions work on a clean machine; dependency versions and licenses are auditable; outputs are deterministic for fixed inputs/configuration or document nondeterminism.
- Release notes state exact supported inputs, known limitations and benchmark scope. Unsupported inputs fail or return partial status plainly—never fabricate complete output.

**Phase 6 implementation status (2026-10-15): IMPLEMENTED; local gates pass, hosted Gate 6 pending.** The Linux sanitizer-enabled build passes all six CTest gates, including the frozen Phase 5 corpus baseline. The fixed-seed Clang libFuzzer+ASan+UBSan smoke completed 2,000 runs with no crash or sanitizer finding. The Linux CPack archive extracted and ran `--version`/`--help`; all 11 resolved vcpkg copyright notices matched the installed tree byte-for-byte. The CycloneDX 1.6 SBOM validator verified all 11 installed package versions, license declarations, encoded PURLs and dependency references. Hosted Linux/Windows CI remains required to validate the final release candidate and Windows package/DLL path. No Antigravity installer or checked-in sample was executed. See [`docs/phase6-validation.md`](docs/phase6-validation.md) and [`docs/phase6-release-notes.md`](docs/phase6-release-notes.md).

### Phase 7 — Unwind-driven coverage for large native engines

**Focus:** improve the static-analysis engine's use of PE exception metadata and its bounded coverage. This phase does not target the IDE/UI and does not claim exact-source recovery.

**Phase 7 status (2026-10-15): IN PROGRESS; first parser/recovery milestone locally verified.** AMD64 runtime-function tables now have a dedicated 200,000-record cap; synthetic tests accept 1,001 valid entries and reject declarations above the safe cap. On the inert Antigravity `language_server.exe` sample, NexussREV parsed 142,182 valid unwind entries; 137 overlap the current decoded slice and are admitted as exact, provenance-labelled candidates. Recovery reports 229 candidates, 0 known functions, and no matching PDB. The 20,000-instruction limit still covers only 67,394 of 50,134,887 executable file-backed bytes (0.134425%); its JSON report is already 57.76 MiB of the 64 MiB output ceiling. The report remains partial and every installer/application binary remains unexecuted. See [`docs/antigravity-engine-static-analysis.md`](docs/antigravity-engine-static-analysis.md) and [`docs/phase5-validation.md`](docs/phase5-validation.md).

**Static-engine semantic milestone (2026-10-15):** the bounded Antigravity slice contains 113 `MOVQ` instructions; all 113 now have exact legacy SSE2 semantics, reducing unsupported instructions from 395 to 282 without changing decode coverage, the 54 unresolved flow issues, or candidate/known-function counts. The updated report validates against schema v6 and remains below the 64 MiB limit. The installer and extracted engine remain unexecuted; this does not claim complete decompilation. See the Phase 10 entry in [`docs/antigravity-engine-static-analysis.md`](docs/antigravity-engine-static-analysis.md).

**Remaining Phase 7 gates:** (1) measure and validate worklist-selected coverage and recovery on representative large native inputs, refining section/function seeds only when evidence supports doing so while preserving exact decode accounting and explicit gaps; (2) continue measured SIMD semantics beyond the bounded MOVQ slice with focused regression/reference tests; and (3) keep unresolved control flow, absent symbols, and partial coverage visible. Streaming serialization is implemented under Phase 11; any future limit increase must retain its output bound and exact-parity regression.

**Phase 7 scheduler milestone (2026-10-15):** the CLI now offers an opt-in `function-ranges` strategy and an `auto` mode; callers may request `auto` with a bounded worker count. The scheduler stratifies up to 1,024 validated non-overlapping AMD64 `RUNTIME_FUNCTION` ranges, assigns deterministic per-range instruction/byte budgets, decodes with separate Capstone handles, and merges the results in RVA order before the existing PDB/function/semantic/CFG/dataflow stages. Unselected bytes and per-range tails remain explicit analysis-limit ranges; the 20,000-instruction, 64 MiB decode, 20,000-gap, and 64 MiB artifact limits remain in force. `linear` stays the CLI default. Worker-count determinism and byte-accounting invariants are covered on the checked-in compiler-generated PE fixture. This does not yet establish improved Antigravity coverage or accuracy; its executable remains static-only and was not analyzed or executed during this change.

**Phase 7 worklist milestone (2026-10-15):** each selected validated range is now traversed from its begin RVA with an ordered per-function worklist. The decoder follows in-range direct branch targets and reachable fallthrough, stops at returns and unconditional branches, and avoids overlapping instruction decodes; calls continue at fallthrough while selected validated ranges remain independent seeds. Bytes not reached by the bounded traversal are recorded as `analysis_limit` intervals, and worker-count parity plus exact byte accounting are checked. A synthetic branch fixture verifies that skipped bytes are not mislabeled as decoder failures and that direct/conditional targets remain in semantic output. This advances the scheduler gate locally but does not prove broader binary coverage or an Antigravity accuracy improvement; measurement on a representative large native engine, continued SIMD semantic coverage, and explicit unresolved-flow validation remain open.

### Phase 11 — Resource optimization with exact-output parity

**Upgrade areas**

- Remove duplicate ownership of the parsed PE model and release optional parser cross-check state immediately after parsing.
- Stream report JSON through a bounded writer rather than retaining a full report string and nested serializer strings; write ordinary string spans directly while preserving JSON escaping, output limits, and atomic staged publication.
- Reduce transient allocations and peak RAM without trimming report detail, instruction/semantic records, coverage, or validation quality.

**Gate 11**

- On the hash-pinned Antigravity sample, preserve the disassembly and JSON report byte-for-byte for identical options/paths; continue to pass the active schema and all golden/regression gates.
- Demonstrate a measurable peak-RSS reduction under the existing Release + ASan/UBSan build; maintain the 64 MiB report ceiling, cancellation/error handling, and staged-file publication behavior.
- Leave `README.md` byte-for-byte unchanged and never execute the installer or extracted engine.

**Phase 11 status (2026-10-15): IMPLEMENTED; all local gates pass.** PE metadata now has one owner; the LIEF cross-check object is local to parsing; JSON serialization streams through a fixed-size buffer bounded at 64 MiB with allocation-free escaping of ordinary spans. On the same Antigravity input (`ecc463b48ba0a6902fe0975d6ef357d504038a1b818387f0868348d92fcccfbe`), same output paths, and the Release build with ASan/UBSan, peak RSS changed from 939,400 KiB to 664,536 KiB (−274,864 KiB; −29.3%), while elapsed time changed from 9.762 s to 9.697 s. Both report and disassembly SHA-256 hashes match their pre-change artifacts exactly; schema v6 validates, all six CTest gates pass, and the fixed-seed 2,000-run ASan/UBSan fuzz smoke has no finding. The output remains 20,000 decoded instructions with 19,718 modeled semantics, 282 unsupported instructions, and 54 unresolved-flow issues; coverage remains partial. The README hash is unchanged. Hosted CI remains pending.

## 5. Library and tool selection

| Tool | Recommended role | Important boundary |
|---|---|---|
| [LIEF PE](https://lief.re/doc/latest/formats/pe/index.html) | PE parsing and structured metadata access behind NexussREV’s loader adapter | Parsing PE metadata does not identify all functions or reconstruct source. Keep all RVA and validity checks in NexussREV’s contract and tests. |
| [Capstone](https://www.capstone-engine.org/) | Multi-architecture instruction decoding for the decoder adapter | Its stated role is disassembly. It does not by itself provide a complete semantic lifter, CFG, type system or source decompiler. |
| [Ghidra](https://github.com/NationalSecurityAgency/ghidra) | First-choice automated reference/baseline; potentially an optional decompilation backend | The project describes disassembly, decompilation and automated modes. Treat its output as a comparison/reference, not proof of original-source identity. Pin and test the selected release. |
| [RetDec](https://github.com/avast/retdec) | Optional comparative benchmark if its supported target matches the test case | Its maintainers currently describe the project as in limited maintenance. Do not make it the sole critical-path dependency without a separate maintenance and support decision. |

The [Microsoft PE/COFF specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) is the format reference for headers, data directories, sections, imports, relocations, exception data and debug information. Respect the specification’s variable directory count and avoid assumptions that particular metadata always sits in a section with a conventional name.

## 6. First execution order

1. **Immediately:** correct README/benchmark claims; disable fabricated recovery and perfect-status paths.
2. **Next:** make CMake reproducible and add the minimal CI/test skeleton (Gate 0).
3. **Then:** implement the PE image model, address mapping and decode accounting (Gate 1).
4. **Then:** add PDB-aware symbols and evidence-backed range discovery (Gate 2).
5. **Decision at Gate 2:** choose whether NexussREV is primarily a Ghidra-backed workflow/product or a long-term independent decompiler engine. Do not begin broad type recovery before this decision and a passing semantic-lifting gate.
6. Proceed through Gates 3–6 in order. At every gate, preserve unresolved cases as explicit results rather than hiding them behind heuristics.
