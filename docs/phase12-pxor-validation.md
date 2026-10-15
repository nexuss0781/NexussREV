# Phase 12 — Bounded legacy SSE2 `PXOR` semantics

**Status:** implemented as one narrowly validated instruction-family slice in the production native C++ semantic path (`src/phase3.cpp`). This is not a claim of general SSE, AVX, or VAES completeness.

## Modeled form

Only the legacy SSE2 encoding `66 0F EF /r` with exactly two 128-bit operands is modeled: an XMM destination and an XMM or 128-bit memory source. The semantic operation is `vector_xor_128_preserve_upper_lanes`: the destination's 128 bits are XORed with the source, and the upper vector-register bits are unchanged. The destination is read and written; a register source is read; a memory source is read (with its addressing registers read) and never written. No arithmetic flags are read, changed, or undefined; the six tracked arithmetic flags are preserved.

The analyzer validates the mandatory legacy prefix, opcode, operand count, width, and direction/form before setting `status: modeled`. It preserves `unsupported` for the MMX form, non-128-bit operands, malformed/other prefix forms, memory destinations, and VEX/EVEX mnemonic families such as `VPXOR*`. It does not claim support for every legacy SIMD encoding or for AVX/VAES.

## Focused regression coverage

`legacy_pxor_semantics_tests` checks register/register and register/memory forms, zero/unspecified decoder access metadata, exact register and memory effects, flag preservation, and explicit rejection of wider, MMX, invalid-encoding, memory-destination, and VEX cases. The tests are additive and leave the existing tests intact.

## References

- [Intel 64 and IA-32 Architectures Software Developer's Manual, Volume 2](https://cdrdv2-public.intel.com/825760/325383-sdm-vol-2abcd.pdf) — instruction-set reference.
- [PXOR instruction entry](https://www.felixcloutier.com/x86/pxor) — convenient transcription of the encoding, operation, legacy upper-bit behavior, and flags-affected entry; the Intel manual is authoritative.
