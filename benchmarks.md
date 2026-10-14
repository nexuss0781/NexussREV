# Benchmark status

**Historical claims remain withdrawn.** Earlier narrative claims of zero loss, 100% recovery, or broad binary coverage were not supported by hashes, tool versions, reproducible commands, or a measured method; they must not be cited as project results.

The current reproducible validation baseline is **Phase 5 / Gate 5**, scoped strictly to the hash-identified corpus in [`tests/benchmarks/v1/phase5-corpus.json`](tests/benchmarks/v1/phase5-corpus.json). It combines one legally distributable real-world SQLite x64 DLL, compiler-generated NexussREV fixtures, eight labelled Phase 2 cases, Phase 4 source-known type/signature facts, a hash-checked Ghidra 11.3.2 comparison, and an expected malformed-input rejection. Detailed metric definitions, exact denominators, unknown-state behavior, thresholds, and limitations are in [`docs/phase5-validation.md`](docs/phase5-validation.md).

Build and run the checked-in gates with:

```sh
cmake --build build --parallel 2
ctest --test-dir build --output-on-failure
```

Gate 5 writes `build/phase5-validation-results.json`; CI publishes it as a build artifact. Every result identifies sample hashes and tool/dependency versions. PE/PDB fixtures are always analyzed as data and never executed. The measured results describe only this corpus and do not establish accuracy or completeness for arbitrary binaries, applications, compilers, or ABIs.
