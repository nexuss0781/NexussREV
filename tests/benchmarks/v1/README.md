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

The checked-in numeric baseline above remains **Clang/LLD COFF**. The supplemental [`toolchain-matrix.json`](toolchain-matrix.json) and [`phase2_toolchain_benchmark.py`](../../phase2_toolchain_benchmark.py) define a second, generated matrix: eight cases per toolchain (O0/O2 × EXE/DLL × debug/stripped), original fixture source only, SHA-256 identities, exact compiler/linker versions, per-case truth, and grouped start/range precision and recall. Its thresholds are in the manifest and are checked by the runner.

MSVC and clang-cl cases use each generated image's matching PDB as labeled function-boundary truth, then analyze a copy with export and debug-directory entries cleared. MinGW GCC does not produce PDBs; its debug-enabled companion uses DWARF `low_pc`/`high_pc` labels for the independent truth ranges, and its stripped copy removes debug data and export/debug directory entries. Reports mark these as `dwarf_present_no_pdb` or `stripped`; they must not be described as PDB-backed results.

CI generates these binaries from `corpus.c`, analyzes them strictly as data (never executing them), and uploads per-toolchain JSON reports as workflow artifacts. The output records the actual runner compiler versions and hashes, making a run auditable even when hosted toolchain versions advance. The command forms are:

```sh
python3 tests/phase2_toolchain_benchmark.py \
  --mode mingw --program build/nexusrev \
  --compiler x86_64-w64-mingw32-gcc \
  --objdump x86_64-w64-mingw32-objdump \
  --strip x86_64-w64-mingw32-objcopy \
  --matrix tests/benchmarks/v1/toolchain-matrix.json \
  --output build/phase2-toolchain-matrix/mingw.json
```

On Windows CI, the same runner uses `--mode msvc --compiler cl.exe --linker link.exe` and `--mode clang-cl --compiler clang-cl.exe --linker lld-link.exe` with `build/Release/nexusrev.exe` and the same matrix manifest. Thus the static v1 Clang/LLD baseline and generated cross-toolchain measurements remain distinct and are not silently mixed.
