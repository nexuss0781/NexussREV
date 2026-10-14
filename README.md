# NexussREV

NexussREV is a **static PE analysis prototype**. It parses PE metadata and performs bounded, evidence-labelled analysis; it does not reconstruct original source code. Inputs are treated as data and are never executed.

## Supported surface and limitations

- **Analyzed target:** native Windows PE32+ x86-64 (AMD64) executables and DLLs.
- **Parse/identify only:** PE32/x86, ARM64 and other machine types. CLR/.NET images are identified but not analyzed as native code. These inputs receive an explicit `unsupported` status and are not decoded as x64.
- **PDB symbols:** accepted only when the PDB GUID and age match the PE CodeView identity. Mismatched, missing and malformed symbol data is reported and ignored.
- **Outputs:** annotated disassembly or a best-effort C-like pseudocode view, plus a versioned JSON analysis report. Pseudocode is not original source and is not guaranteed to compile.
- **Not included:** execution or emulation of samples, unpacking, dynamic analysis, ARM64 decoding, or PE32/x86 decoding.

Analysis is bounded to 256 MiB per input, 64 MiB of executable-byte decode work, 20,000 instruction records, 20,000 decode-gap records and 64 MiB per emitted artifact. `--timeout-ms` adds a cooperative wall-clock deadline; `--memory-limit-mib` applies a process address-space cap on POSIX or a Windows process-memory limit. Operating-system watchdogs remain useful for strict external deadlines.

## Clean-machine build

Requirements: CMake 3.24+, a C++17 compiler, Git, Python 3.10+, and the platform's native build tools. The dependency versions are resolved from the checked-in vcpkg manifest and baseline.

### Linux (x64)

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --requirement requirements-test.txt

export VCPKG_ROOT="$HOME/vcpkg"
git clone https://github.com/microsoft/vcpkg.git "$VCPKG_ROOT"
git -C "$VCPKG_ROOT" checkout e456309491fd875487bf02b8a0dca76c1b1b00cc
"$VCPKG_ROOT/bootstrap-vcpkg.sh" -disableMetrics

cmake -S . -B build \
  -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" \
  -DCMAKE_BUILD_TYPE=Release \
  -DNEXUSREV_WARNINGS_AS_ERRORS=ON
cmake --build build --parallel 2
ctest --test-dir build --output-on-failure
cmake --build build --target package
```

### Windows (x64, PowerShell)

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --requirement requirements-test.txt

$env:VCPKG_ROOT = "$HOME\vcpkg"
git clone https://github.com/microsoft/vcpkg.git $env:VCPKG_ROOT
git -C $env:VCPKG_ROOT checkout e456309491fd875487bf02b8a0dca76c1b1b00cc
& "$env:VCPKG_ROOT\bootstrap-vcpkg.bat" -disableMetrics

cmake -S . -B build -A x64 `
  "-DCMAKE_TOOLCHAIN_FILE=$env:VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" `
  -DCMAKE_BUILD_TYPE=Release -DNEXUSREV_WARNINGS_AS_ERRORS=ON
cmake --build build --config Release --parallel 2
ctest --test-dir build -C Release --output-on-failure
cmake --build build --config Release --target package
```

The CPack package contains the executable, runtime dependencies discoverable by CMake, the active and previous report schemas, README, project license, dependency-license inventory and each installed vcpkg port's upstream copyright text. Build dependencies and exact license expressions are summarized in [`docs/dependency-license-inventory.md`](docs/dependency-license-inventory.md); CI generates and validates a platform-specific CycloneDX 1.6 SBOM against the resolved installed package database.

## Usage

```sh
build/nexusrev --help
build/nexusrev --version
build/nexusrev --format disassembly --log-format jsonl \
  --timeout-ms 30000 --memory-limit-mib 1024 \
  input.exe analysis.txt
build/nexusrev --format pseudocode --pdb matching.pdb input.exe pseudocode.c
```

On Windows, run `build\Release\nexusrev.exe` instead of `build/nexusrev`. By default the report is written to `<output>.report.json`; `--report-json path` changes that location. Schema v6 is active at [`docs/analysis-report.schema.json`](docs/analysis-report.schema.json), and the v5 contract is retained at [`docs/analysis-report-v5.schema.json`](docs/analysis-report-v5.schema.json).

`--log-format jsonl` emits one JSON object per diagnostic line on stderr. Each artifact is written to a private same-directory staging area, flushed, then atomically replaced. The disassembly and JSON report are individually atomic, but the two-file publication is not a single cross-file transaction.

## Tests and measured scope

`ctest` runs parser/RVA and semantic unit tests, CLI/schema checks, bounded resource/cancellation tests, and the Phase 2, 4 and 5 corpus gates. The Phase 6 libFuzzer target is optional and requires Clang; the bounded CI smoke run is documented in [`docs/phase6-validation.md`](docs/phase6-validation.md).

The Phase 5 corpus currently contains 10 valid PE inputs and one malformed-input case. Its reported decode, CFG, symbol, signature/type and Ghidra comparison metrics apply **only to that checked-in corpus**; they are not general performance or universal accuracy claims. See [`docs/phase5-validation.md`](docs/phase5-validation.md) and [`docs/phase6-release-notes.md`](docs/phase6-release-notes.md).

## License

NexussREV is licensed under the MIT License; see [`LICENSE`](LICENSE). Third-party dependencies retain their own licenses, listed in the dependency inventory and SBOM.
