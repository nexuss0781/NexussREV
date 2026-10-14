# Phase 3 — Semantic lifting and control-flow foundation

NexussREV retains Capstone as a decoder. The Phase 3 backend (`nexusrev-x64-windows-v1`) separately lifts a deliberately bounded x86-64 subset into instruction records with explicit operands, register and RFLAGS effects, memory effects, stack actions, flow kind, and direct target where established. The ABI label is **Microsoft x64**; this is not a full decompiler or a claim that arbitrary instructions have been interpreted.

## Lifted subset

The current explicit subset includes data movement (`mov`, `movabs`, `movzx`, `movsx`, `movsxd`, `lea`), integer arithmetic and logic (`add`, `sub`, `adc`, `sbb`, `inc`, `dec`, `neg`, `and`, `or`, `xor`, `not`, `cmp`, `test`, `imul`, `mul`, `div`, `idiv`, `xchg`), `nop`, 16-/64-bit `push`/`pop` with explicit stack deltas, 64-bit RFLAGS push/pop forms, `leave`, direct and indirect `call`/`jmp`, near `ret`, supported condition-code branches, and condition-code `cmov`/`set` forms. Variable-count shifts remain explicitly unsupported until their count-dependent flags can be represented without ambiguity. Conditions normalize to signed/unsigned predicates and list the RFLAGS inputs. The IR records exact decoded operands alongside the operation rather than pretending a mnemonic is source code.

Every other instruction is serialized with `status: unsupported` and an explicit reason. Operand detail missing from Capstone is also unsupported and receives an unknown-flow edge because its control behavior cannot be established. Unsupported control-transfer groups, loops, far transfers, interrupts, and terminal operations are represented as unknown CFG edges rather than false fallthrough. Arithmetic and logical flag outputs, preserved/undefined flags, stack deltas or actions, and implicit Windows x64 call clobbers are represented separately. Indirect calls and branches are never assigned invented destinations.

## CFG and completeness

CFGs are built for bounded known functions, candidates, and fragments. Blocks split at function starts, in-range branch targets, post-terminator instructions, and decode discontinuities. Edges distinguish direct branch, conditional true/false, fallthrough, call, indirect call/branch, and unknown flow; each carries decoder/fallthrough provenance. Call-graph entries preserve the call RVA and distinguish a resolved direct target, an unresolved direct target, and an unresolved indirect target. A bounded function is marked `semantic_complete` only if its boundary is unambiguous, every instruction in it has an implemented semantic, and the CFG has no unresolved edge, missing instruction boundary, decode gap intersecting its range, or boundary fallthrough. Unbounded and ambiguous function candidates remain partial. Whole-stage status is `partial` whenever any decoded instruction is unsupported, an unresolved range remains, or any function is incomplete; the stage does not equate absence of diagnostics with complete decompilation.

## Ghidra reference comparison

The optional `tools/ghidra/ExportNexussREVReference.py` Ghidra headless post-script exports function starts and direct control-flow facts as a bounded TSV v1 file. It hashes the imported PE and never executes it. Run it against the same file analyzed by NexussREV:

```text
mkdir -p <project-dir>
analyzeHeadless <project-dir> nexussrev -import sample.exe \
  -scriptPath tools/ghidra -postScript ExportNexussREVReference.py reference.tsv sample.exe
nexusrev --reference-report reference.tsv sample.exe analysis.disasm
```

The report validates the input SHA-256 before comparing function starts and call/branch/return facts. Invalid or mismatched reference reports are visible and ignored; disagreements are included under `semantic_analysis.reference.differences` and produce `GHIDRA_REFERENCE_DIVERGENCE`. A real Ghidra 11.3.2 headless export for `tests/fixtures/compiler-generated-x64.exe` is checked in as `tests/fixtures/compiler-generated-x64-ghidra-11.3.2.tsv`; CLI tests replay that file and assert the tool version, two function starts, two return facts, and zero differences. The reference was generated using the official `ghidra_11.3.2_PUBLIC_20250415.zip` release (SHA-256 `99d45035bdcc3d6627e7b1232b7b379905a9fad76c772c920602e2b5d8b2dac2`). Ghidra is an independent reference, not ground truth. Reference comparison is optional and the default status `not_configured` is explicit.

## Tests

Gate 3 synthetic tests use constructed x86-64 instruction records (no sample executable is launched) to assert every supported operation family, arithmetic/logical flag effects, signed and unsigned condition predicates, direct/indirect calls and branches, stack deltas/actions, CFG edge types, unmodeled-instruction visibility, incomplete-function rules, reference matches/divergences, and input-hash rejection. The real Ghidra-generated fixture is replayed in CI alongside full JSON Schema validation. CI also retains the Phase 1/2 PE and labelled benchmark regressions.
