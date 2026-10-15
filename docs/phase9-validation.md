# Phase 9 — CFG and indirect-flow recovery

## Implemented milestone: bounded x64 absolute-VA switch tables

NexussREV now resolves one deliberately narrow switch-table form during bounded function CFG construction. It requires all of the following evidence:

- an indexed 8-byte indirect `jmp` with scale 8;
- an immediately preceding unsigned `cmp` and `ja`/`jnbe` or `jae`/`jnb`/`jnc` guard, with the compared register matching the index register after x86 GPR alias normalization;
- a nearby, non-clobbered `lea` from RIP-relative data to the table base (or a RIP-relative table operand);
- a bounded table of at most 256 absolute-VA entries that is wholly file-backed; and
- every entry resolving to an executable, already-decoded instruction boundary inside the same bounded function, with the guard's default target also decoded.

A table is accepted only as a whole. Validated case destinations are serialized using the existing schema-v6 `indirect_branch` CFG edge kind, one edge per distinct target, with `bounded_va64_jump_table` provenance and a concrete `target_rva`/`to_block`. No schema or report-version change was needed. Once all entries pass validation, only the matching Phase 2 unresolved-jump-table record is removed. The Ghidra comparator translates these multi-target CFG edges into branch facts so the existing reference format can compare them.

If an entry, guard, table bound, mapping, or instruction boundary is missing or inconsistent, NexussREV emits one unresolved indirect edge with no target and keeps the function partial. It does not publish a partial case list or guess a destination. Duplicate table entries are deduplicated as CFG destinations after each individual entry has been validated.

## Validation

The focused unit fixture labels a two-case x64 switch, checks that both edges land on matching block starts, checks that no resolved-flow marker remains, and compares all six flow facts (guard, two switch cases, and three returns) against a Ghidra-format reference. A companion fixture corrupts one table target and verifies that the entire switch remains one unresolved indirect edge and the function remains partial. The final Release build had AddressSanitizer/UndefinedBehaviorSanitizer enabled and warnings treated as errors; the full build passed, and all seven configured CTest gates passed, including unit, CLI/schema, daemon, hardening, Phase 2/4 benchmarks, and Phase 5 corpus validation. The existing checked-in Ghidra 11.3.2 comparison also passed with zero differences.

## Limitations and remaining Phase 9 work

This milestone is not general indirect-flow recovery. It does not yet resolve 32-bit relative-offset tables, tables with bounds derived through more complex dataflow, indirect calls, indirect tail calls, import thunks, cold fragments, or exception-handler edges. Targets must already be decoded and lie inside the same bounded function; the `function-ranges` decoder does not yet schedule targets discovered by this semantic pass. No broader coverage or universal correctness claim follows from the synthetic fixture. These cases remain explicit unresolved flow until separately implemented and measured.
