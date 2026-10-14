

## Phase 9 — bounded legacy SIMD semantics

The x64 semantic backend now models legacy 128-bit `MOVUPS` and `XORPS` only, with operand-width/form validation, explicit memory effects, and RFLAGS preservation. Wider and otherwise mismatched forms remain unsupported. Synthetic tests cover XMM register moves, 16-byte loads/stores, a memory-source XOR, flag preservation, and rejection of a 256-bit `XORPS` form.

The same verified engine file (`ecc463b48ba0a6902fe0975d6ef357d504038a1b818387f0868348d92fcccfbe`) and the same first 20,000 decoded instructions were analyzed before and after this change:

| Measurement | Before | Phase 9 |
|---|---:|---:|
| Modeled instructions | 19,459 (97.295%) | 19,605 (98.025%) |
| Unsupported instructions | 541 | 395 |
| Decoded bytes | 67,394 | 67,394 |
| Executable file-backed bytes | 50,134,887 | 50,134,887 |
| Executable-byte coverage | 0.134425% | 0.134425% |
| Unresolved control-flow issues | 54 | 54 |

This adds 146 explicitly modeled instructions in the decoded slice; it does not increase decode coverage or establish function/source correctness. The Phase-9 JSON report is 60,568,231 bytes, below the 64 MiB cap by 6,540,633 bytes. Recovery remains partial with 229 candidates and no confirmed functions. The largest unsupported families in the Phase-9 sampled slice were `MOVQ` (113), `PMOVMSKB` (60), `PCMPEQB` (35), `VAESENC` (27), `MOVSD` (25), `PUNPCKLBW` (23), `PSHUFLW` (23), and `VXORPS` (12); their then-current semantics were not implemented.

All six CTest gates passed, including the new synthetic SIMD regression. The installer and extracted app were not executed; the analyzer processed the engine as inert PE data.

- Phase-9 disassembly: `/workspace/downloads/antigravity/static-inspection/results/language-server-phase9b.disasm`
- Phase-9 JSON report: `/workspace/downloads/antigravity/static-inspection/results/language-server-phase9b.disasm.report.json`

## Phase 10 — bounded legacy MOVQ semantics

Only four verified legacy SSE2 MOVQ encoding families are modeled, with exact opcode/prefix/REX.W, operand-kind, and width checks. XMM destinations copy the low 64 bits and clear their upper 64 bits; memory reads/stores and address-register reads are explicit; RFLAGS are preserved. MMX, MOVD, VEX/EVEX, and mismatched forms remain unsupported. The Intel instruction references used for the semantic contract are [MOVQ](https://www.felixcloutier.com/x86/movq) and [MOVD/MOVQ](https://www.felixcloutier.com/x86/movd:movq).

The same SHA-256-verified input (`ecc463b48ba0a6902fe0975d6ef357d504038a1b818387f0868348d92fcccfbe`) and identical first 20,000 decoded instructions were analyzed before and after the change:

| Measurement | Phase 9 | Phase 10 |
|---|---:|---:|
| Modeled instructions | 19,605 (98.025%) | 19,718 (98.590%) |
| Unsupported instructions | 395 | 282 |
| MOVQ instructions modeled | 0 / 113 | 113 / 113 |
| Decoded bytes | 67,394 | 67,394 |
| Executable file-backed bytes | 50,134,887 | 50,134,887 |
| Executable-byte coverage | 0.134425% | 0.134425% |
| Unresolved control-flow issues | 54 | 54 |
| JSON report bytes | 60,568,231 | 60,570,765 |

The 113 newly modeled records reduce the unsupported semantic count by 113; they do not increase decode or function-boundary coverage. The Phase-10 report is below the 64 MiB artifact cap by 6,538,099 bytes. Recovery remains partial with 229 candidates, zero confirmed functions, and no matching PDB. Remaining largest unsupported families in the bounded slice are `PMOVMSKB` (60), `PCMPEQB` (35), `VAESENC` (27), `MOVSD` (25), `PUNPCKLBW` (23), `PSHUFLW` (23), `VXORPS` (12), `MOVD` (10), `MOVSS` (10), and `VMOVQ` (9).

All six CTest gates pass; the Phase-10 report validates against the active JSON schema. The installer and extracted engine were not executed; the analyzer processed the engine as inert PE data only. This remains a bounded semantic milestone, not a complete decompilation or original-source recovery.

- Phase-10 disassembly: `/workspace/downloads/antigravity/static-inspection/results/language-server-phase10.disasm`
- Phase-10 JSON report: `/workspace/downloads/antigravity/static-inspection/results/language-server-phase10.disasm.report.json`
