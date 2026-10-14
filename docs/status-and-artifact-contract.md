# Phase 3 status and artifact contract

This contract is implemented by the Phase 1–3 CLI and the JSON Schema in [`analysis-report.schema.json`](analysis-report.schema.json). The report schema is versioned independently of the executable.

## Supported input and output

NexussREV performs bounded static parsing of PE32/PE32+ headers and metadata. Phase 1 instruction decoding is explicitly limited to **native PE32+ AMD64** executable sections. The CLI never launches the input. PE32, other machine types, and CLR/.NET images can be identified and reported, but are not decoded as x86-64. A PE parse and metadata report are not claims of source recovery or program correctness.

For `nexusrev <input> <output>`:

- `<output>` is UTF-8 annotated x86-64 disassembly with RVA, VA, file-offset, and byte information. It is not C/C++ source and is not guaranteed compilable.
- `<output>.report.json` is the schema-v4 machine-readable report; override the path with `--report-json <path>`.
- `--pdb <path>` selects an optional PDB. Without it, the CLI checks the PE's recorded CodeView path and same-directory filename. No remote symbol-server request is made.
- `--reference-report <ghidra.tsv>` optionally compares function starts and control-flow facts against the versioned TSV emitted by `tools/ghidra/ExportNexussREVReference.py`.

The report includes the input path, byte count and SHA-256, parsed PE identity and section layout, declared data directories, bounded import/export/relocation/debug/TLS/unwind/CLR metadata, per-instruction and decode-gap addresses/bytes, coverage totals, PDB identity and symbol-provider status, function evidence and unresolved ranges/control-flow, Phase 3 semantic instruction records, CFG blocks/typed edges, call-graph facts, optional reference differences, stages, diagnostics, dependency versions, and artifact paths. The security directory is represented as a file-offset-addressed directory, not an RVA.

Parsing is bounded to a 256 MiB input, 96 sections, 32 data directories, and bounded metadata/output record counts. PDB parsing is bounded to the same input ceiling, caps stream and procedure counts, validates MSF 7.0 block/stream ranges, and trusts records only after the PE CodeView GUID and age match. Header and section ranges are validated with overflow-safe arithmetic. RVA-to-file-offset conversion rejects virtual zero-fill and out-of-range reads. LIEF is used as a secondary parse over the same in-memory byte snapshot; the validated PE adapter is the source for emitted metadata and instruction bytes.

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
- Matching PDB procedure records are reported as `known_functions` with provenance `pdb_procedure_record`. Only their procedure names, section-relative start/end RVAs, and type-record indices are recovered; this release does **not** decode PDB type records into inferred signatures or source types.
- Export targets, the entry point, x64 runtime-function/unwind records, and direct branch/call targets create evidence-labelled `candidate_functions`; none alone proves source-level function identity. Conflicting ranges are marked ambiguous. Possible thunks, tail calls, jump tables, cold fragments, inlining, code/data overlap, and indirect control flow may remain incomplete.
- `fragments`, `unresolved_ranges`, and `unresolved_control_flow` are separate from known/candidate functions. Confidence is evidence strength, not a probability of exactness. The annotated text and JSON report do not claim that all code has been found.
- Gate 2's versioned benchmark and exact-start/exact-range precision/recall thresholds are recorded in [`tests/benchmarks/v1`](../tests/benchmarks/v1/). Its checked-in numeric baseline is the stated Clang/LLD corpus only; it is not a claim about arbitrary binaries or untested compiler families.

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | Artifacts written; the report may be `partial` or `unsupported` and must be inspected. |
| `2` | Invalid command-line arguments or unsupported output format. |
| `3` | Input not found, unreadable, or rejected as malformed PE. |
| `5` | Analysis could not run. |
| `6` | Artifact write/publication failed. |
| `70` | Unexpected internal failure. |

A successfully published report records exit code `0`. Expected input/analysis/write failures do not emit the success banner or a report artifact. Output files are staged before publication.

## Important diagnostic families

Diagnostics use `code`, `severity` (`info`, `warning`, or `error`), and a human-readable `message`. Codes cover input/header/section/directory bounds, section overlap, PE address overflow, optional metadata truncation, decoder gaps/limits, PDB identity/missing/parse states, unsupported architectures or CLR, output errors, invalid arguments, and internal failures. Metadata warnings do not turn an otherwise safe image parse into an unsafe read; unreadable or malformed records are reported and omitted as appropriate.

Exact file identity and universal correctness are never implied by a status value. The report's SHA-256 identifies the bytes analyzed by the adapter; no sample binary is executed during parsing or tests.
