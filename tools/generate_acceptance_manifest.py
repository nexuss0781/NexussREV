#!/usr/bin/env python3
"""Create a deterministic, hash-linked per-platform release acceptance manifest."""

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import xml.etree.ElementTree as ET


REQUIRED_CTESTS = {
    "nexusrev_unit_tests",
    "nexusrev_cli_tests",
    "nexusrev_phase6_hardening",
    "nexusrev_phase2_benchmark",
    "nexusrev_phase4_benchmark",
    "nexusrev_phase5_validation",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load_json(path, description):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read {description} at {path}: {error}") from error


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def artifact_record(path):
    require(path.is_file(), f"required evidence file is missing: {path}")
    return {"file": path.name, "size_bytes": path.stat().st_size, "sha256": sha256(path)}


def parse_ctest_junit(path, required_names, description, exact_names=False):
    require(path.is_file(), f"{description} JUnit result is missing: {path}")
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as error:
        raise ValueError(f"cannot parse {description} JUnit result {path}: {error}") from error
    cases = [root] if root.tag == "testcase" else root.findall(".//testcase")
    require(cases, f"{description} JUnit result contains no test cases")
    names = [case.get("name", "") for case in cases]
    require(all(names), f"{description} JUnit result contains an unnamed test case")
    missing = sorted(required_names - set(names))
    require(not missing, f"{description} JUnit result omits required tests: {missing}")
    if exact_names:
        require(set(names) == required_names and len(names) == len(required_names),
                f"{description} JUnit result must contain exactly {sorted(required_names)}, got {names}")
    failed = sum(len(case.findall("failure")) + len(case.findall("error")) for case in cases)
    skipped = sum(len(case.findall("skipped")) for case in cases)
    require(failed == 0, f"{description} JUnit result reports {failed} failed/error test cases")
    require(skipped == 0, f"{description} JUnit result reports {skipped} skipped test cases")
    return {
        "status": "passed",
        "test_count": len(cases),
        "failed_count": failed,
        "skipped_count": skipped,
        "test_names": sorted(names),
    }


def parse_vcpkg_status(installed_root):
    status_path = installed_root / "vcpkg" / "status"
    require(status_path.is_file(), f"vcpkg installed status is missing: {status_path}")
    packages = {}
    for block in re.split(r"\n\s*\n", status_path.read_text(encoding="utf-8").strip()):
        fields = {}
        for line in block.splitlines():
            if ": " in line and not line.startswith(" "):
                key, value = line.split(": ", 1)
                fields[key] = value
        if fields.get("Package") and fields.get("Version") and fields.get("Status", "install ok installed") == "install ok installed":
            packages[fields["Package"]] = fields
    return packages


def property_map(items):
    return {item.get("name"): item.get("value") for item in items if isinstance(item, dict)}


def compact_metric(metrics, key):
    entry = metrics.get(key)
    require(isinstance(entry, dict) and isinstance(entry.get("metric"), dict),
            f"Phase 5 report is missing the {key} metric")
    metric = entry["metric"]
    return {field: metric.get(field) for field in ("numerator", "denominator", "value", "status")}


def git_commit():
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True,
            check=True, timeout=5,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError("--commit is required when git metadata is unavailable") from error


def build_manifest(args):
    for path, label in (
        (args.phase4_report, "Phase 4 report"),
        (args.phase5_report, "Phase 5 report"),
        (args.sbom, "CycloneDX SBOM"),
        (args.package, "release package"),
        (args.license_inventory, "license inventory"),
        (args.vcpkg_manifest, "vcpkg manifest"),
    ):
        require(path.is_file(), f"{label} is missing: {path}")

    commit = args.commit or git_commit()
    require(re.fullmatch(r"[0-9a-fA-F]{40}", commit) is not None,
            f"commit must be a full 40-character Git SHA, got {commit!r}")
    commit = commit.lower()

    phase4 = load_json(args.phase4_report, "Phase 4 benchmark report")
    require(phase4.get("gate") == "Phase 4 / Gate 4" and phase4.get("format_version") == 1,
            "Phase 4 benchmark report has an unexpected gate or format version")

    phase5 = load_json(args.phase5_report, "Phase 5 validation report")
    require(phase5.get("format_version") == 1, "Phase 5 report format_version must be 1")
    samples = phase5.get("samples")
    require(isinstance(samples, list) and samples, "Phase 5 report has no corpus samples")
    require(phase5.get("fixture_count") == len(samples),
            "Phase 5 fixture_count does not match its sample list")
    require(phase5.get("negative_case_count", 0) >= 1,
            "Phase 5 report does not include a negative input case")
    require(phase5.get("static_only") is True,
            "Phase 5 report must explicitly state that corpus files were static-only")
    previous_release = phase5.get("previous_release_comparison", {})
    require(previous_release.get("status") == "matched",
            "Phase 5 previous-release comparison did not match")

    metrics = phase5.get("metrics", {})
    reference = metrics.get("reference_backend", {})
    compared = [sample for sample in reference.get("samples", [])
                if sample.get("status") == "compared" and sample.get("tool") == "Ghidra"]
    require(compared, "Phase 5 report contains no compared Ghidra reference sample")
    require(all(sample.get("version") for sample in compared),
            "a compared Ghidra reference sample has no recorded version")
    reference_differences = sum(sample.get("difference_count", 0) for sample in compared)
    require(reference_differences == reference.get("total_difference_count"),
            "Phase 5 Ghidra difference total does not match its per-sample results")
    require(reference_differences == 0,
            f"Phase 5 Ghidra comparison has {reference_differences} differences")

    build_config = phase5.get("reproducibility", {}).get("build_configuration", {})
    project = build_config.get("nexusrev", {})
    dependencies = build_config.get("dependencies", {})
    require(project.get("name") == "NexussREV" and project.get("version"),
            "Phase 5 report is missing NexussREV build identity")
    require(dependencies.get("capstone") and dependencies.get("lief"),
            "Phase 5 report is missing pinned production dependency versions")

    vcpkg = load_json(args.vcpkg_manifest, "vcpkg manifest")
    baseline = vcpkg.get("builtin-baseline")
    require(isinstance(baseline, str) and baseline,
            "vcpkg manifest has no builtin-baseline")
    default_dependencies = vcpkg.get("dependencies", [])
    default_names = {
        item if isinstance(item, str) else item.get("name")
        for item in default_dependencies
    }
    require("zydis" not in default_names,
            "Zydis must remain outside the default production dependency graph")
    feature_dependencies = vcpkg.get("features", {}).get("decoder-crosscheck", {}).get("dependencies", [])
    feature_names = {
        item if isinstance(item, str) else item.get("name")
        for item in feature_dependencies
    }
    require("zydis" in feature_names,
            "the optional decoder-crosscheck feature does not declare Zydis")
    zydis_override = next((item for item in vcpkg.get("overrides", [])
                           if item.get("name") == "zydis"), None)
    expected_zydis_version = zydis_override.get("version-semver") if zydis_override else None
    require(expected_zydis_version, "vcpkg manifest does not pin the optional Zydis version")

    sbom = load_json(args.sbom, "CycloneDX SBOM")
    require(sbom.get("bomFormat") == "CycloneDX" and sbom.get("specVersion") == "1.6",
            "release SBOM must use CycloneDX 1.6")
    sbom_metadata = sbom.get("metadata", {})
    sbom_properties = property_map(sbom_metadata.get("properties", []))
    require(sbom_properties.get("nexussrev:platform") == args.platform,
            "SBOM platform does not match the requested acceptance platform")
    require(sbom_properties.get("nexussrev:vcpkg-baseline") == baseline,
            "SBOM vcpkg baseline does not match vcpkg.json")
    root_component = sbom_metadata.get("component", {})
    require(root_component.get("name") == "NexussREV" and
            root_component.get("version") == project["version"],
            "SBOM project identity does not match the Phase 5 report")
    components = sbom.get("components", [])
    component_names = [component.get("name") for component in components]
    require(len(component_names) == len(set(component_names)), "SBOM has duplicate component names")
    require("zydis" not in component_names and "zycore" not in component_names,
            "default production SBOM unexpectedly includes optional Zydis dependencies")
    require(all(component.get("licenses") for component in components),
            "release SBOM has a component without license information")

    optional_packages = parse_vcpkg_status(args.optional_installed_root)
    zydis_record = optional_packages.get("zydis")
    zycore_record = optional_packages.get("zycore")
    require(zydis_record is not None and zycore_record is not None,
            "optional test install tree does not contain both Zydis and Zycore")
    require(zydis_record["Version"].split("#", 1)[0] == expected_zydis_version,
            "resolved Zydis version does not match the vcpkg pin")

    main_ctest = parse_ctest_junit(args.ctest_results, REQUIRED_CTESTS,
                                   "main CTest suite")
    crosscheck_name = "nexusrev_decoder_crosscheck"
    crosscheck_ctest = parse_ctest_junit(args.zydis_ctest_results, {crosscheck_name},
                                         "optional Zydis cross-check", exact_names=True)

    ghidra_versions = sorted({sample["version"] for sample in compared})
    optional_versions = {
        "zydis": {
            "version": zydis_record["Version"],
            "port_version": zydis_record.get("Port-Version"),
        },
        "zycore": {
            "version": zycore_record["Version"],
            "port_version": zycore_record.get("Port-Version"),
        },
    }
    sbom_components = []
    for component in sorted(components, key=lambda item: item["name"]):
        sbom_components.append({
            "name": component["name"],
            "version": component["version"],
            "licenses": component["licenses"],
        })

    reference_flow_count = sum(sample.get("compared_flow_count", 0) for sample in compared)
    corpus = {
        "name": phase5.get("corpus"),
        "scope": phase5.get("scope"),
        "static_only": phase5["static_only"],
        "positive_fixture_count": phase5["fixture_count"],
        "negative_case_count": phase5["negative_case_count"],
        "previous_release_comparison": previous_release.get("status"),
        "ghidra_reference": {
            "versions": ghidra_versions,
            "compared_sample_count": len(compared),
            "compared_flow_count": reference_flow_count,
            "difference_count": reference_differences,
            "role": "hash-pinned comparison baseline, not ground truth",
        },
        "summary_metrics": {
            "executable_byte_decode_coverage": compact_metric(metrics, "executable_byte_decode_coverage"),
            "cfg_edge_consistency": compact_metric(metrics, "cfg_edge_consistency"),
            "output_completeness": compact_metric(metrics, "output_completeness"),
        },
        "limitations": phase5.get("limitations", []),
    }

    return {
        "format": "nexusrev-release-acceptance",
        "format_version": 1,
        "project": {
            "name": project["name"],
            "version": project["version"],
            "commit": commit,
        },
        "platform": args.platform,
        "analysis_scope": "Native Windows PE32+ AMD64; static-only; corpus-scoped measurements; no product-wide correctness claim.",
        "engines": {
            "production_parser": {"name": "LIEF", "version": dependencies["lief"]},
            "production_decoder": {"name": "Capstone", "version": dependencies["capstone"]},
            "reference_backend": {
                "name": "Ghidra",
                "versions": ghidra_versions,
                "status": "passed on the hash-pinned corpus sample(s) only",
                "redistributed": False,
            },
            "optional_decoder_crosscheck": {
                "primary": "Capstone",
                "secondary": "Zydis",
                "status": "passed",
                "resolved_packages": optional_versions,
                "production_dependency": False,
            },
        },
        "validation": {
            "main_ctest": main_ctest,
            "optional_zydis_ctest": crosscheck_ctest,
            "deterministic_output_gate": "passed via nexusrev_phase6_hardening",
            "release_package_smoke": "passed before acceptance-manifest generation in CI",
            "sbom_smoke": "passed before acceptance-manifest generation in CI",
            "corpus": corpus,
        },
        "license_provenance": {
            "vcpkg_baseline": baseline,
            "default_production_sbom_components": sbom_components,
            "optional_decoder_packages_are_not_in_release_sbom": True,
            "inventory_file": artifact_record(args.license_inventory),
        },
        "evidence": {
            "phase4_benchmark": artifact_record(args.phase4_report),
            "phase5_validation": artifact_record(args.phase5_report),
            "release_sbom": artifact_record(args.sbom),
            "release_package": artifact_record(args.package),
            "main_ctest_junit": artifact_record(args.ctest_results),
            "optional_zydis_ctest_junit": artifact_record(args.zydis_ctest_results),
            "vcpkg_manifest": artifact_record(args.vcpkg_manifest),
        },
        "reproducibility": {
            "manifest_has_timestamp": False,
            "same_commit_and_evidence_produce_same_manifest_bytes": True,
            "package_archive_byte_identity_across_builds_claimed": False,
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", required=True, choices=("linux-x64", "windows-x64"))
    parser.add_argument("--commit", help="full commit SHA (defaults to git rev-parse HEAD)")
    parser.add_argument("--phase4-report", required=True, type=pathlib.Path)
    parser.add_argument("--phase5-report", required=True, type=pathlib.Path)
    parser.add_argument("--sbom", required=True, type=pathlib.Path)
    parser.add_argument("--package", required=True, type=pathlib.Path)
    parser.add_argument("--ctest-results", required=True, type=pathlib.Path)
    parser.add_argument("--zydis-ctest-results", required=True, type=pathlib.Path)
    parser.add_argument("--optional-installed-root", required=True, type=pathlib.Path)
    parser.add_argument("--license-inventory", required=True, type=pathlib.Path)
    parser.add_argument("--vcpkg-manifest", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()

    try:
        manifest = build_manifest(args)
        encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(encoded)
    except (OSError, UnicodeError, ValueError, KeyError, TypeError, ET.ParseError) as error:
        print(f"acceptance manifest generation failed: {error}", file=sys.stderr)
        return 2
    print(f"Phase 14 acceptance manifest written: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
