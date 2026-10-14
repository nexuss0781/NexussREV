# Phase 1 status and artifact contract

This contract is implemented by the Phase 1 CLI and the JSON Schema in [`analysis-report.schema.json`](analysis-report.schema.json). The report schema is versioned independently of the executable.

## Supported input and output

NexussREV performs bounded static parsing of PE32/PE32+ headers and metadata. Phase 1 instruction decoding is explicitly limited to **native PE32+ AMD64** executable sections. The CLI never launches the input. PE32, other machine types, and CLR/.NET images can be identified and reported, but are not decoded as x86-64. A PE parse and metadata report are not claims of source recovery or program correctness.

For `nexusrev <input> <output>`:

- `<output>` is UTF-8 annotated x86-64 disassembly with RVA, VA, file-offset, and byte information. It is not C/C++ source and is not guaranteed compilable.
- `<output>.report.json` is the schema-v2 machine-readable report; override the path with `--report-json <path>`.

The report includes the input path, byte count and SHA-256, parsed PE identity and section layout, declared data directories, bounded import/export/relocation/debug/TLS/unwind/CLR metadata, per-instruction and decode-gap addresses/bytes, coverage totals, stages, diagnostics, dependency versions, and artifact paths. The security directory is represented as a file-offset-addressed directory, not an RVA.

Parsing is bounded to a 256 MiB input, 96 sections, 32 data directories, and bounded metadata/output record counts. Header and section ranges are validated with overflow-safe arithmetic. RVA-to-file-offset conversion rejects virtual zero-fill and out-of-range reads. LIEF is used as a secondary parse over the same in-memory byte snapshot; the validated PE adapter is the source for emitted metadata and instruction bytes.

## Statuses and byte accounting

Each stage and the overall report uses exactly one of:

- `complete`: the stage completed according to its implemented contract. A complete parse or decode stage does not imply source reconstruction.
- `partial`: useful output exists but some bytes or metadata could not be completely analyzed, or bounded output limits were reached.
- `unsupported`: the parsed input/operation is outside the explicitly supported capability. Unsupported machine types and CLR images are reported without attempting x64 decoding.
- `failed`: the stage could not complete because of an error.

An emitted native x64 listing remains an overall `partial` result because Phase 1 does not establish function boundaries or semantics. For executable file-backed bytes, the report distinguishes processed, decoded, undecoded, and limit-excluded bytes; `decoded_bytes + undecoded_bytes == processed_bytes`. Decoder-rejected bytes and terminal truncated-instruction bytes are preserved as exact gaps with section index, RVA, VA, file offset, bytes, size, and reason. Executable virtual zero-fill is reported separately and is never passed to Capstone as file data; its gap record has a null file offset instead of a guessed one. The `emission` stage being `complete` means only that the declared artifacts were published.

Phase 1 does not implement function-boundary recovery, CFG construction, semantic lifting, type inference, or source reconstruction. Instructions are linear disassembly of executable section bytes, not proof that every byte is reachable code. Symbol/debug metadata does not change these limits.

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

Diagnostics use `code`, `severity` (`info`, `warning`, or `error`), and a human-readable `message`. Codes cover input/header/section/directory bounds, section overlap, PE address overflow, optional metadata truncation, decoder gaps/limits, unsupported architectures or CLR, output errors, invalid arguments, and internal failures. Metadata warnings do not turn an otherwise safe image parse into an unsafe read; unreadable or malformed records are reported and omitted as appropriate.

Exact file identity and universal correctness are never implied by a status value. The report's SHA-256 identifies the bytes analyzed by the adapter; no sample binary is executed during parsing or tests.
