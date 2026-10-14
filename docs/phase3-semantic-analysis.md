# Phase 3 — Semantic lifting and control-flow foundation

NexussREV retains Capstone as a decoder. The Phase 3 backend (`nexusrev-x64-windows-v1`) separately lifts a deliberately bounded x86-64 subset into instruction records with explicit operands, register and RFLAGS effects, memory effects, stack actions, flow kind, and direct target where established. The ABI label is **Microsoft x64**; this is not a full decompiler or a claim that arbitrary instructions have been interpreted.

## Lifted subset

The current explicit subset includes data movement (`mov`, `movabs`, `movzx`, `movsx`, `movsxd`, `lea`), integer arithmetic and logic (`add`, `sub`, `adc`, `sbb`, `inc`, `dec`, `neg`, `and`, `or`, `xor`, `not`, `cmp`, `test`, `imul`, `mul`, `div`, `idiv`, `xchg`), register-destination bit tests/modifiers (`bt`, `bts`, `btr`, `btc`), register-form bit scans (`bsf`, `bsr`), logical/arithmetic shifts (`shl`/`sal`, `shr`, `sar`) with immediate counts or masked `CL` counts on 32-/64-bit operands, `nop`, 16-/64-bit `push`/`pop` with explicit stack deltas, 64-bit RFLAGS push/pop forms, `leave`, direct and indirect `call`/`jmp`, near `ret`, supported condition-code branches, and condition-code `cmov`/`set` forms. Shift flag results model x86 count masking, zero-count preservation, count-one overflow behavior, and undefined AF/OF cases; bit operations record their CF/ZF effects and architecturally undefined flags. A zero-source bit scan records that its destination is undefined. Memory bit-test destinations, unsupported count sources, and out-of-width byte/word shift counts remain explicit. Conditions normalize to signed/unsigned predicates and list the RFLAGS inputs. The IR records exact decoded operands alongside the operation rather than pretending a mnemonic is source code.

Every other instruction is serialized with `status: unsupported` and an explicit reason. `INT3`, `UD2`, `UD2B`, `ICEBP`, and `INT1` are identified as trap operations, but their exception-handler destinations remain unknown CFG edges rather than false fallthrough. Operand detail missing from Capstone is also unsupported and receives an unknown-flow edge because its control behavior cannot be established. Unsupported control-transfer groups, loops, far transfers, other interrupts, and terminal operations are represented as unknown CFG edges rather than false fallthrough. Arithmetic and logical flag outputs, conditionally written/preserved/undefined flags, stack deltas or actions, and implicit Windows x64 call clobbers are represented separately. Indirect calls and branches are never assigned invented destinations.

## CFG and completeness

CFGs are built for bounded known functions, candidates, and fragments. Blocks split at function starts, in-range branch targets, post-terminator instructions, and decode discontinuities. Edges distinguish direct branch, conditional true/false, fallthrough, call, indirect call/branch, and unknown flow; each carries decoder/fallthrough provenance. Trap operations terminate their blocks and retain an unknown exceptional edge because the handler is outside the PE image. Call-graph entries preserve the call RVA and distinguish a resolved direct target, an unresolved direct target, and an unresolved indirect target. A bounded function is marked `semantic_complete` only if its boundary is unambiguous, every instruction in it has an implemented semantic, and the CFG has no unresolved edge, missing instruction boundary, decode gap intersecting its range, or boundary fallthrough. Unbounded and ambiguous function candidates remain partial. Whole-stage status is `partial` whenever any decoded instruction is unsupported, an unresolved range remains, or any function is incomplete; the stage does not equate absence of diagnostics with complete decompilation.

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

Gate 3 synthetic tests use constructed x86-64 instruction records (no sample executable is launched) to assert every supported operation family, bit-test/scan flag effects and operand limits, immediate and CL-count shift masking/flag effects, explicit trap classification and unresolved exceptional flow, arithmetic/logical flag effects, signed and unsigned condition predicates, direct/indirect calls and branches, stack deltas/actions, CFG edge types, unmodeled-instruction visibility, incomplete-function rules, reference matches/divergences, and input-hash rejection. The real Ghidra-generated fixture is replayed in CI alongside full JSON Schema validation. CI also retains the Phase 1/2 PE and labelled benchmark regressions.


## Scoped legacy SIMD addition (2026-10-15)

The x64 backend additionally models only the legacy 128-bit `MOVUPS` and `XORPS` forms. Their operand count and width are checked explicitly: `MOVUPS` requires XMM and/or 16-byte memory operands, and `XORPS` requires an XMM destination plus an XMM or 16-byte memory source. The IR operations are `vector_move_128` and `vector_xor_128`; operand records retain the exact register/memory operands and byte widths. Loads and stores report the corresponding memory effect. These legacy SSE operations preserve RFLAGS; `XORPS` is a bitwise operation over the 128-bit vector value, not floating-point arithmetic. Wider VEX/EVEX forms, other SIMD mnemonics, and mismatched operands remain unsupported. Synthetic unit tests exercise register moves, loads, stores, an XOR memory source, flag preservation, and rejection of a 256-bit XOR form. This addition does not imply that the full SIMD instruction set or AVX upper-lane semantics are implemented.

## Scoped legacy MOVQ addition (2026-10-15)

The backend models four exact legacy SSE2 MOVQ encoding families after checking opcode, mandatory prefix, REX.W where required, operand kinds, and byte widths: `66 REX.W 0F 6E` (r/m64 to XMM), `F3 0F 7E` (XMM/m64 to XMM), `66 REX.W 0F 7E` (XMM to r/m64), and `66 0F D6` (XMM to XMM/m64). Transfers into an XMM register are labelled `vector_move_low_64_to_xmm_zero_upper`, reflecting the architectural clearing of bits 127:64; transfers out are `vector_move_low_64_from_xmm`. Memory direction and address-register reads are recorded explicitly, and all these operations preserve RFLAGS. See the [MOVQ](https://www.felixcloutier.com/x86/movq) and [MOVD/MOVQ](https://www.felixcloutier.com/x86/movd:movq) instruction references, which reproduce Intel SDM operation details.

Synthetic regression tests cover register, memory, GPR and XMM forms; REX.W rejection for qword conversions; memory read/write direction; XMM upper-half behavior; address-register reads; and flag preservation. Unsupported MMX, MOVD, VEX/EVEX, malformed, and other unimplemented forms remain explicit. The change does not model AVX upper-vector state or establish source-level correctness.
