# Status and artifact contract

This contract is implemented by the CLI and the active schema-v6 JSON Schema in [`analysis-report.schema.json`](analysis-report.schema.json). The prior v5 schema remains available at [`analysis-report-v5.schema.json`](analysis-report-v5.schema.json); report schema is versioned independently of the executable and analyzer configuration.

## Supported input and output

NexussREV performs bounded static parsing of PE32/PE32+ headers and metadata. Phase 1 instruction decoding is explicitly limited to **native PE32+ AMD64** executable sections. The CLI never launches the input. PE32, other machine types, and CLR/.NET images can be identified and reported, but are not decoded as x86-64. A PE parse and metadata report are not claims of source recovery or program correctness.

For `nexusrev <input> <output>`:

- `<output>` is UTF-8 annotated x86-64 disassembly with RVA, VA, file-offset, and byte information. It is not C/C++ source and is not guaranteed compilable.
- `<output>.report.json` is the schema-v6 machine-readable report; override the path with `--report-json <path>`.
- `--format pseudocode` selects the best-effort C-like pseudocode emitter. It is explicitly labelled as incomplete, not original source, and not guaranteed compilable. The default remains annotated disassembly.
- `--pdb <path>` selects an optional PDB. Without it, the CLI checks the PE's recorded CodeView path and same-directory filename. No remote symbol-server request is made.
- `--reference-report <ghidra.tsv>` optionally compares function starts and control-flow facts against the versioned TSV emitted by `tools/ghidra/ExportNexussREVReference.py`.

The report includes the input path, byte count and SHA-256, parsed PE identity and section layout, declared data directories, bounded import/export/relocation/debug/TLS/unwind/CLR metadata, per-instruction and decode-gap addresses/bytes, coverage totals, PDB identity and symbol-provider status, function evidence and unresolved ranges/control-flow, Phase 3 semantic instruction records, Phase 4 stack frames/signatures/import prototypes/call-argument flows/control-structure candidates, CFG blocks/typed edges, call-graph facts, optional reference differences, stages, diagnostics, dependency versions, and artifact paths. The security directory is represented as a file-offset-addressed directory, not an RVA.

Parsing is bounded to a 256 MiB input, 96 sections, 32 data directories, and bounded metadata/output record counts. Executable decode work is capped at 64 MiB; instruction and decode-gap records at 20,000 each; and each artifact at 64 MiB. Optional `--timeout-ms` and `--memory-limit-mib` controls provide cooperative deadline checks and a platform process-memory/address-space cap. PDB parsing is bounded to the same input ceiling, caps stream and procedure counts, validates MSF 7.0 block/stream ranges, and trusts records only after the PE CodeView GUID and age match. Header and section ranges are validated with overflow-safe arithmetic. RVA-to-file-offset conversion rejects virtual zero-fill and out-of-range reads. LIEF is used as a secondary parse over the same in-memory byte snapshot; the validated PE adapter is the source for emitted metadata and instruction bytes.

The CLI's default `--decode-strategy linear` preserves the original ordered section sweep. `--decode-strategy function-ranges` instead selects up to 1,024 stratified, validated, non-overlapping AMD64 `RUNTIME_FUNCTION` ranges and decodes their bounded windows with per-range Capstone handles; `--decode-workers` accepts 1–8, matching the implementation ceiling. `auto` selects this mode only when the PE has at least 8 MiB of executable file-backed data and 512 runtime-function records. In range mode, each selected range is traversed from its begin RVA using a bounded ordered worklist that follows in-range direct branch targets and reachable fallthrough; calls continue at fallthrough, returns and unconditional branches stop, and overlapping instructions are avoided. This is not proof of source-level function identity. It merges one deterministic RVA-sorted instruction stream for the existing semantic and dataflow stages. Unselected bytes and per-range tails remain `analysis_limit` gaps, and byte accounting still satisfies `processed_bytes + limited_bytes == executable_file_backed_bytes` and `decoded_bytes + undecoded_bytes == processed_bytes`.

The optional `image_discovery` report partitions the complete input file by file offset into `decoded_code`, `likely_code`, `likely_data`, or `unresolved`. Its four byte totals sum exactly to `input_file_bytes` and `accounted_file_bytes`; virtual zero-fill is reported separately because it has no file offset. Decoded instruction extents are evidence for decoded code. Bounded, validated PDB/unwind/function ranges and one-byte code-seed anchors from the entry point, exports, TLS callbacks, and direct control-flow references support likely code; no extent is invented for an unbounded candidate. Non-executable sections, PE headers/directories, debug payloads, and bounded RIP-relative memory references support likely data. Conflicting code/data evidence and bytes without support remain unresolved. Detailed ranges are capped at 20,000 records, while category totals stay exact and omitted detail is quantified. RIP-relative memory evidence is bounded to 20,000 references and reports if that limit is reached. This classification is evidence, not proof that a decoded instruction is source code or that likely data is never executable.

## Statuses and byte accounting

Each stage and the overall report uses exactly one of:

- `complete`: the stage completed according to its implemented contract. A complete parse or decode stage does not imply source reconstruction.
- `partial`: useful output exists but some bytes or metadata could not be completely analyzed, or bounded output limits were reached.
- `unsupported`: the parsed input/operation is outside the explicitly supported capability. Unsupported machine types and CLR images are reported without attempting x64 decoding.
- `failed`: the stage could not complete because of an error.

For executable file-backed bytes, the report distinguishes processed, decoded, undecoded, and limit-excluded bytes; `decoded_bytes + undecoded_bytes == processed_bytes`. Decoder-rejected bytes and terminal truncated-instruction bytes are preserved as exact gaps with section index, RVA, VA, file offset, bytes, size, and reason. Executable virtual zero-fill is reported separately and is never passed to Capstone as file data; its gap record has a null file offset instead of a guessed one. The `emission` stage being `complete` means only that the declared artifacts were published.

## Semantic lifting and CFG (Phase 3)

- Capstone remains a decoder; `semantic_analysis` is a separate, bounded x86-64 Microsoft-ABI semantic adapter. It records the exact operands, explicit register/flag/memory/stack effects, supported operation, condition predicate, flow class, direct target when established, and an explicit unsupported reason otherwise.
- The initial implementation intentionally models a subset. Unmodeled instruction semantics, unsupported addressing/control behavior, decode gaps, unbounded function candidates, and indirect destinations are visible in the report; unsupported control transfers emit explicit unknown-flow edges rather than being treated as no-ops or fallthrough.
- Per-function CFG blocks and typed edges plus call-graph edges preserve provenance. Direct calls whose targets cannot be mapped into the image remain distinct from unresolved indirect calls. A function is `semantic_complete` only when all instructions in its bounded range are modeled and its control flow has no unresolved edge or intersecting decode gap, including gaps after the last decoded instruction. A semantic stage may therefore be `partial` even when decoding completed.
- The optional Ghidra headless adapter compares function starts and direct call/branch/return facts after verifying the reference input SHA-256. The checked-in Ghidra 11.3.2 export is replayed by CLI tests. Status `not_configured` means no independent comparison ran; `divergent` lists every observed disagreement under `semantic_analysis.reference.differences`; a mismatch or malformed file is `invalid` and is never silently accepted as a match. Ghidra is a comparison source, not ground truth. See [`phase3-semantic-analysis.md`](phase3-semantic-analysis.md).

## Symbol and function-boundary semantics

- PDB records are considered only for a matching PE CodeView GUID/age. The report distinguishes `not_present`, `unverifiable`, `missing`, `matched`, `mismatched`, and `invalid`; mismatch or absence is a normal partial result and must not lend a label or range to another image.
- Matching PDB procedure records are reported as `known_functions` with provenance `pdb_procedure_record`. Their bounded procedure names/ranges and type indices are retained. The bounded TPI reader handles scalar, modifier, pointer, `LF_PROCEDURE`/`LF_MFUNCTION`, and `LF_ARGLIST` records; decoded signature facts have provenance `pdb_tpi_procedure_record` and are used only after the PE CodeView GUID/age match. Other CodeView type records remain `unknown`/`partial`, not guessed.
- Export targets, the entry point, x64 runtime-function/unwind records, and direct branch/call targets create evidence-labelled `candidate_functions`; none alone proves source-level function identity. Conflicting ranges are marked ambiguous. Possible thunks, tail calls, jump tables, cold fragments, inlining, code/data overlap, and indirect control flow may remain incomplete.
- `fragments`, `unresolved_ranges`, and `unresolved_control_flow` are separate from known/candidate functions. Confidence is evidence strength, not a probability of exactness. The annotated text and JSON report do not claim that all code has been found.
- Gate 2's versioned benchmark and exact-start/exact-range precision/recall thresholds are recorded in [`tests/benchmarks/v1`](../tests/benchmarks/v1/). Its checked-in numeric baseline is the stated Clang/LLD corpus only; it is not a claim about arbitrary binaries or untested compiler families.

## Dataflow, ABI, types, and structuring (Phase 4)

- `dataflow_analysis` is a separate bounded stage for native PE32+ AMD64 using Microsoft x64 ABI assumptions. Managed images and other architectures receive an `unsupported` stage result.
- Stack recovery tracks entry-relative RSP/RBP adjustments, observed stack slots, widths, and read/write counts. Dynamic alignment and unknown stack-pointer updates do not receive fabricated depths; partial reasons remain in `issues`.
- Register arguments use RCX/RDX/R8/R9 evidence (first read before local write); stack overflow arguments use entry-RSP offsets beginning at +40. An unconditional in-range tail branch can forward argument locations only when the caller did not write the relevant register. Linear register reaching-definitions are explicitly not path-sensitive.
- A matching, decoded PDB TPI procedure type can supply parameter count, scalar/pointer types, and return type with debug provenance. Otherwise inferred locations may be present but types and returns stay `unknown`. Import prototypes come from the finite `windows_sdk_prototype_catalog_v1` list; uncatalogued imports remain unknown. Direct-call parameter types propagate to caller-entry parameters only when the argument is proven to remain in the ABI register; propagated facts are labelled `inferred`. PDB class/UDT layouts and general aggregate type inference remain unsupported.
- RTTI/vtable recovery recognizes bounded MSVC x64 self-relative Complete Object Locator, TypeDescriptor, Class Hierarchy Descriptor, and aligned vftable-prefix patterns in non-executable file-backed data, and validates virtual-method RVAs against executable sections. Other ABI/compiler RTTI formats, full object layouts, and unresolved method slots remain unknown.
- Call-argument flows carry call-site RVA, ABI register, last observed local definition or entry-value source, expected/inferred argument type, evidence, and separate confidence. Values may be wrong at control-flow joins; no path-sensitive SSA claim is made.
- A conditional region is recovered only when two resolved CFG successors share a reachable join; a natural loop requires a backward edge whose target dominates its source. Switch tables, irreducible flow, and ambiguous structure stay in lower-level CFG/disassembly.
- Pseudocode retains instruction RVA comments and unknown/unsupported operations. It is a review aid, not original source, not guaranteed compilable, and not an equivalence claim.
- Gate 4 metrics use the hash-identified fixtures in [`phase4-ground-truth.json`](../tests/benchmarks/v1/phase4-ground-truth.json). `tests/phase4_benchmark.py` reports signature-location and type precision/recall; unknown types are false negatives. The O2 fixture is held out for expected-calibration-error scoring. CTest writes `build/phase4-benchmark-results.json`, uploaded by CI. Fixtures are parsed as data and never executed.

## Validation and quality reporting (Phase 5)

- `tests/phase5_validation.py` consumes the hash-pinned [`phase5-corpus.json`](../tests/benchmarks/v1/phase5-corpus.json), reuses Gate 2 boundary truths and the Gate 4 signature/type result, and validates each report against this schema. It emits `build/phase5-validation-results.json`; CI retains the file as a build artifact.
- Metrics are corpus-scoped and include parse-outcome conformance, executable-file-backed decode coverage, exact labelled boundary precision/recall, CFG edge consistency, unsupported/unresolved instructions and edges, recovered-function provenance, signature/type accuracy and calibration, Ghidra difference count, and output completeness. Their exact definitions, denominators, gates, and unknown-state policies are in [`phase5-validation.md`](phase5-validation.md).
- Each valid sample is also compared against the exact stable-invariant snapshot captured at Phase 4 commit `2e52bd4` in [`phase5-baseline.json`](../tests/benchmarks/v1/phase5-baseline.json); a changed invariant fails CI until reviewed and deliberately rebased.
- Zero denominators are represented as `value: null` with status `not_measurable`, never as a perfect score. Failed/unsupported analysis is not scored as successful; limit-excluded bytes and unresolved records remain explicit. The real-world SQLite 3.54.0 fixture is parsed as data only, and its upstream compiler settings are unknown rather than inferred.
- The Phase 5 result characterizes the checked-in fixture corpus only. It does not assert universal coverage or original-source recovery. The Antigravity Nullsoft installer wrapper is outside the PE32+ x86-64 application scope and was not executed or counted as an application decompilation sample.

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | Artifacts written; the report may be `partial` or `unsupported` and must be inspected. |
| `2` | Invalid command-line arguments or unsupported output format. |
| `3` | Input not found, unreadable, or rejected as malformed PE. |
| `5` | Analysis could not run. |
| `6` | Artifact write/publication failed. |
| `70` | Unexpected internal failure. |
| `124` | Cooperative analysis deadline expired. |
| `130` | Analysis was cancelled by Ctrl-C/Ctrl-Break or a termination signal. |

A successfully published report records exit code `0`. Expected input/analysis/write failures do not emit the success banner or a report artifact. Exit code `124` denotes a cooperative timeout; `130` denotes cancellation. `--log-format jsonl` emits stderr diagnostics as JSON Lines with `level`, `code`, and `message`. Each artifact is staged, flushed and atomically replaced individually; the output/report pair is not a single cross-file transaction. See [`phase6-validation.md`](phase6-validation.md) for release-boundary details.

## Important diagnostic families

Diagnostics use `code`, `severity` (`info`, `warning`, or `error`), and a human-readable `message`. Codes cover input/header/section/directory bounds, section overlap, PE address overflow, optional metadata truncation, decoder gaps/limits, PDB identity/missing/parse states, unsupported architectures or CLR, output errors, invalid arguments, resource-limit setup and internal failures. Metadata warnings do not turn an otherwise safe image parse into an unsafe read; unreadable or malformed records are reported and omitted as appropriate.

Exact file identity and universal correctness are never implied by a status value. The report's SHA-256 identifies the bytes analyzed by the adapter; no sample binary is executed during parsing or tests.
