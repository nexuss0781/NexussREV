# Phase 10 — Optional independent decoder cross-check

**Status:** implemented as an opt-in test target. Capstone remains the production decoder and the default build has no Zydis dependency.

## Design

The optional `nexusrev_decoder_crosscheck` target compares Capstone 5.0.9 with the independently maintained Zydis 4.1.1 decoder. It is deliberately isolated from the production executable and is disabled by default (`NEXUSREV_ENABLE_ZYDIS_CROSSCHECK=OFF`). The vcpkg `decoder-crosscheck` feature adds Zydis only when requested; the existing vcpkg baseline already pins Zydis 4.1.1 (port-version 1) and Zycore-C 1.5.2.

The test compares decode acceptance and instruction lengths, normalized mnemonics (including `JNZ`/`JNE` aliases), visible operand counts and types, register/memory widths and read/write accesses, register identities, memory base/index/scale/displacement, relative branch/call destinations, AVX vector-length metadata against vector-register width, and EVEX zero-mask metadata. Immediate values and relative targets are compared directly; the harness does not treat the libraries' different immediate-width/access representations as equivalent fields. LEA address-generation operands are compared by addressing expression rather than data width/read access. When Capstone leaves a non-immediate operand's access field unset while Zydis supplies one, the test reports that metadata as unavailable rather than calling it a decoder disagreement. Curated cases cover integer/register/memory instructions, relative control flow, and VEX 128/256-bit and EVEX 512-bit `VADDPS`, including an EVEX zero-masked form. Truncated `MOVABS` and EVEX byte sequences are checked for consistent rejection. The test statically parses the checked-in compiler-generated x86-64 PE and compares code from the function starts through their reference return instructions in the existing SHA-256-verified Ghidra 11.3.2 TSV, bounded to file-backed executable bytes. The fixture has no unwind table, so it does not invent runtime-function bounds or compare alignment padding after a function's known return. It never executes the PE fixture.

Any disagreement is printed with its address and fact and fails the test; unavailable Capstone access metadata is separately reported and counted. The comparator does not silently prefer either decoder or suppress disagreements. This is a decoder cross-check, not semantic equivalence, a function-discovery test, or proof of correctness for all x86 encodings. Its curated cases and the single checked-in fixture are a small sample.

## License review

The exact pinned upstream license files identify both Zydis 4.1.1 and Zycore-C 1.5.2 as MIT-licensed: [Zydis LICENSE](https://github.com/zyantific/zydis/blob/v4.1.1/LICENSE) and [Zycore-C LICENSE](https://github.com/zyantific/zycore-c/blob/v1.5.2/LICENSE). The matching vcpkg ports also declare `MIT` and install each upstream `LICENSE` as the package copyright notice. The default production build does not install either package. The optional feature and packaging preserve their separate notices; neither dependency is vendored or copied into project source. See [`dependency-license-inventory.md`](dependency-license-inventory.md).

## Local validation

With the repository's pinned vcpkg checkout available:

```sh
cmake -S . -B build-zydis \
  -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" \
  -DVCPKG_MANIFEST_FEATURES=decoder-crosscheck \
  -DNEXUSREV_ENABLE_ZYDIS_CROSSCHECK=ON \
  -DCMAKE_BUILD_TYPE=Release \
  -DNEXUSREV_WARNINGS_AS_ERRORS=ON
cmake --build build-zydis --target nexusrev_decoder_crosscheck --parallel 2
ctest --test-dir build-zydis -R '^nexusrev_decoder_crosscheck$' --output-on-failure
```

The feature is also exercised in Linux x64 and Windows x64 CI in a separate build directory after the normal release package and SBOM are produced. The normal package and SBOM therefore retain the default production dependency graph.
