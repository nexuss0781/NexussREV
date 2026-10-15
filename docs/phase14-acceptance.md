# Phase 14 — Cross-engine acceptance and release evidence

Phase 14 adds one deterministic, platform-specific acceptance manifest that brings together existing CI evidence; it does not replace or duplicate the analyzer, corpus, packaging, license, or cross-engine checks.

## CI artifact

After the existing platform build, CTest, package/SBOM smoke checks, optional Zydis cross-check, and platform toolchain checks pass, CI runs:

```sh
python3 tools/generate_acceptance_manifest.py \
  --platform linux-x64 \
  --commit "$GITHUB_SHA" \
  --phase4-report build/phase4-benchmark-results.json \
  --phase5-report build/phase5-validation-results.json \
  --sbom build/sbom.cdx.json \
  --package build/NexussREV-0.1.0-Linux-x86_64.tar.gz \
  --ctest-results build/ctest-results.xml \
  --zydis-ctest-results build-zydis/ctest-results.xml \
  --optional-installed-root build/vcpkg_installed \
  --license-inventory docs/dependency-license-inventory.md \
  --vcpkg-manifest vcpkg.json \
  --output build/phase14-acceptance-manifest.json
```

Windows CI supplies `--platform windows-x64` and the produced ZIP package. The manifest records the full commit SHA, platform, required CTest names/results, exact resolved optional Zydis/Zycore versions, Ghidra version and corpus comparison counts, the vcpkg baseline, and the package/SBOM/corpus/license-inventory/JUnit evidence file names, sizes, and SHA-256 hashes. It also carries compact corpus metrics and the report's explicit limitations. No wall-clock timestamp or machine-specific absolute path is written, so the manifest bytes are stable for identical commit and evidence inputs.

The existing acceptance evidence remains the source of truth:

- [Phase 3 Ghidra comparator](phase3-semantic-analysis.md) and the checked-in, SHA-256-pinned Ghidra 11.3.2 fixture provide a reference comparison, not ground truth.
- [Phase 5 corpus validation](phase5-validation.md) defines the named corpus, score denominators, unknown-state policy, baseline, and explicit coverage gaps.
- [Phase 6 release validation](phase6-validation.md) checks deterministic output, packaging, licenses/notices, and the SBOM.
- [Phase 10 decoder cross-check](phase10-decoder-crosscheck.md) keeps Zydis opt-in and test-only; Capstone remains the production decoder.
- [Dependency/license inventory](dependency-license-inventory.md) documents direct, transitive, and optional dependency licensing. The production SBOM is generated before the optional decoder feature is enabled and must not include Zydis or Zycore.

## Scope and limits

The manifest is a hash-linked CI summary, **not a signed attestation**. A passed Ghidra comparison applies only to the specific pinned fixture(s) named in the corpus report; a Zydis pass is a small decoder cross-check, not semantic equivalence. Corpus metrics do not generalize to arbitrary binaries, compiler families, or source recovery. All sample binaries remain static data and are never executed. The package hash identifies the exact uploaded archive; package archive bytes are not claimed to be identical across independent builds because filesystem metadata may vary. The reference engine is not a production dependency or part of the release package.
