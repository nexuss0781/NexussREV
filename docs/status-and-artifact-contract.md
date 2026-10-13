# Phase 0 status and artifact contract

This contract is implemented by the Phase 0 CLI and the JSON schema in [`analysis-report.schema.json`](analysis-report.schema.json). The schema is versioned independently of the executable version.

## Result and stage statuses

Each stage and the overall report uses exactly one of:

- `complete`: the named stage completed according to its implemented contract; this does not imply source recovery.
- `partial`: some output/evidence is available, but known analysis work or coverage remains incomplete.
- `unsupported`: the requested input or operation is outside an explicitly supported capability.
- `failed`: the stage could not complete because of an error.

A valid PE parse followed by an emitted instruction listing is currently an overall `partial` result. Symbol records are candidates only. Function-boundary validation, CFG recovery, semantic lifting, type inference, and source reconstruction are not implemented. A lack of symbols or decode errors is not evidence of complete analysis. The `emission` stage being `complete` means only that the declared artifacts were written.

## Artifact layout

For `nexusrev <input> <output>`:

- `<output>`: UTF-8 annotated disassembly text. It is not C/C++ source and is not guaranteed compilable.
- `<output>.report.json`: machine-readable report; override the path with `--report-json <path>`.

The report contains schema and configuration versions, job start/end statuses and exit code, input path and SHA-256, tool and pinned dependency versions, per-stage statuses, diagnostics, and artifact paths. A successfully published report records exit code `0`; failures are reported on stderr and do not produce a success banner or a report artifact. Files are staged before publication; expected input/analysis/write failures do not emit an artifact.

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | Artifacts written; the report may be `partial` and must be inspected. |
| `2` | Invalid command-line arguments or unsupported output format. |
| `3` | Input not found, unreadable, or unparseable. |
| `5` | Analysis could not run. |
| `6` | Artifact write/publication failed. |
| `70` | Unexpected internal failure. |

## Diagnostic codes

| Code | Meaning |
|---|---|
| `INPUT_NOT_FOUND` | Input path does not exist or cannot be reached. |
| `INPUT_NOT_FILE` | Input is not a regular file. |
| `INPUT_READ_FAILED` | Input bytes could not be read for hashing. |
| `INPUT_PARSE_FAILED` | LIEF could not parse the input as a supported image. |
| `CANDIDATE_SIZE_UNKNOWN` | A symbol has no declared size; no guessed size is substituted. |
| `CANDIDATE_SIZE_UNSUPPORTED` | Declared size cannot be represented on this platform. |
| `CANDIDATE_CONTENT_UNAVAILABLE` | Candidate bytes could not be obtained. |
| `CANDIDATE_CONTENT_TRUNCATED` | Available bytes do not match the symbol's declared size. |
| `DECODE_INCOMPLETE` | The decoder did not decode every available byte. |
| `NO_SYMBOL_CANDIDATES` | No symbols were available; no function boundaries were inferred. |
| `SYMBOLS_ARE_CANDIDATES` | Reminder that symbols are not confirmed function boundaries. |
| `ANALYSIS_NOT_IMPLEMENTED` | Semantic lifting, CFG recovery, or type inference remains unavailable. |
| `OUTPUT_WRITE_FAILED` | Temporary artifact creation or publication failed. |
| `INVALID_ARGUMENT` | The CLI invocation is invalid. |
| `INTERNAL_ERROR` | An unexpected exception prevented a result. |

Diagnostics have `code`, `severity` (`info`, `warning`, or `error`), and a human-readable `message`. Exact source identity and universal correctness are never implied by a status value.
