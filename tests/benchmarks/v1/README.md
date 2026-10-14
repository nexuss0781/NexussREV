# Phase 2 boundary benchmark v1

This is the checked-in Gate 2 numeric baseline. [`corpus.json`](corpus.json) pins source by SHA-256 after canonicalizing CRLF to LF (so Windows checkout settings do not affect identity), and pins every PE/PDB by exact-byte SHA-256. It stores human-readable function labels and half-open `[start_rva, end_rva)` truth ranges and specifies the expected symbol-provider state. [`baseline.json`](baseline.json) pins the minimum precision/recall floors and the review policy. The fixtures are original test code and their binaries are analyzed as data only; no PE is executed.

The eight cases cover **O0 and O2**, **EXE and DLL**, with a matching PDB and with both the export directory and CodeView/debug directory removed. The stripped files retain the code and x64 exception/unwind tables. The O2 stripped cases intentionally expose missed leaf/helper functions where no unwind range or reachable direct target remains; those misses count against recall instead of being waived.

## Reproduction

From the repository root, after building `nexusrev`:

```sh
python3 tests/phase2_benchmark.py \
  --program build/nexusrev \
  --manifest tests/benchmarks/v1/corpus.json \
  --baseline tests/benchmarks/v1/baseline.json \
  --output build/phase2-benchmark-results.json
```

CTest runs the same command as `nexusrev_phase2_benchmark`. The report contains per-case and grouped exact-start/exact-range counts and precision/recall, input and PDB hashes, symbol state, binary kind, optimization setting, and tool version.

## Measured reference

On the pinned LLVM Clang 18.1.3 / LLD 18.1.3 COFF artifacts:

| Case class | Start precision | Start recall | Range precision | Range recall |
|---|---:|---:|---:|---:|
| Matching PDB | 1.000 (16/16) | 1.000 (16/16) | 1.000 (16/16) | 1.000 (16/16) |
| PDB stripped | 1.000 (12/12) | 0.750 (12/16) | 1.000 (10/10) | 0.625 (10/16) |

The acceptance floors in `baseline.json` are set from this checked-in reference. Changes to the corpus, compiler/linker versions, ground truth, or floors require review and new reproducible evidence. Do not raise a threshold merely because code changed.

## Coverage boundary

V1 is a **Clang/LLD COFF** corpus that includes the requested PE kinds, optimization profiles, symbol-backed inputs, and no-useful-symbols inputs. This environment cannot execute the proprietary MSVC toolchain and does not currently have MSVC, clang-cl, or MinGW fixture artifacts. Therefore the v1 numeric results must not be described as cross-toolchain measurements; compiler-family expansion remains a documented follow-up before claiming broader benchmark coverage.
