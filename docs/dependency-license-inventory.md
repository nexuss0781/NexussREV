# Dependency and license inventory

NexussREV's vcpkg dependency resolution is anchored by `builtin-baseline` `e456309491fd875487bf02b8a0dca76c1b1b00cc` in [`../vcpkg.json`](../vcpkg.json). The direct versions are also constrained by the manifest overrides and CMake package requirements. Re-resolve only by reviewing the baseline/override changes and the updated platform SBOM.

## Direct linked dependencies

| Component | Pinned version | SPDX license expression | Role |
|---|---:|---|---|
| LIEF | 0.17.6 | `Apache-2.0` | PE-format cross-check behind NexussREV's bounded loader |
| Capstone | 5.0.9 | `BSD-3-Clause` | x86-64 instruction decoding |

## Transitive vcpkg components in the supported x64 builds

The following licenses appear in the resolved vcpkg graph used by this repository. The exact component versions, target architecture, package relationships and declared license expressions are recorded from each build's installed vcpkg status database in its CycloneDX 1.6 SBOM.

| Component | Resolved version in current baseline | SPDX license expression | Role / note |
|---|---:|---|---|
| frozen | 1.2.0 | `Apache-2.0` | LIEF dependency |
| fmt | 12.2.0 | `MIT` | LIEF/spdlog formatting dependency |
| mbedtls | 3.6.5 | `Apache-2.0 OR GPL-2.0-or-later` | LIEF crypto dependency; package offers either license choice |
| spdlog | 1.17.0 | `MIT` | LIEF logging dependency |
| tcb-span | 2022-06-15 | `BSL-1.0` | LIEF support dependency |
| tl-expected | 1.3.1 | `CC0-1.0` | LIEF support dependency |
| utfcpp | 4.2.1 | `BSL-1.0` | LIEF Unicode support dependency |

Versions above describe the current vcpkg baseline and may differ only after a reviewed baseline update. vcpkg's CMake helper ports are build tooling, not linked runtime components. Python `jsonschema` (`4.26.0`, MIT) is used only by test validators and is not part of the runtime package.

## SBOM generation

After a successful manifest-mode build, CI generates `build/sbom.cdx.json` from the actual installed package database and the same pinned vcpkg ports tree, separately for Linux x64 and Windows x64. The file uses CycloneDX 1.6, carries a generation timestamp and the manifest baseline, and includes direct and installed transitive package components with their port-declared SPDX expressions. CI uploads the platform-specific SBOM with the package artifacts.

To generate locally:

```sh
python3 tools/generate_sbom.py \
  --installed-root build/vcpkg_installed \
  --ports-root "$VCPKG_ROOT/ports" \
  --platform linux-x64 \
  --output build/sbom.cdx.json
```

Use `--timestamp 2026-10-15T00:00:00Z` when a fixed timestamp is needed to compare generated SBOM content reproducibly. CPack includes each installed port's exact `copyright` text under `share/nexusrev/licenses/<port>/copyright`, and the package smoke test checks the notices against the installed tree. NexussREV does not relicense third-party components.
