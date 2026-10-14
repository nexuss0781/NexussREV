#!/usr/bin/env python3
"""Validate a generated CycloneDX SBOM against the resolved vcpkg install tree."""

import argparse
import json
import pathlib
import re
import uuid
from urllib.parse import unquote


def installed_packages(installed_root):
    status_path = installed_root / "vcpkg" / "status"
    if not status_path.is_file():
        raise AssertionError(f"vcpkg status file is missing: {status_path}")
    packages = {}
    for block in re.split(r"\n\s*\n", status_path.read_text(encoding="utf-8").strip()):
        fields = {}
        for line in block.splitlines():
            if ": " in line and not line.startswith(" "):
                key, value = line.split(": ", 1)
                fields[key] = value
        if fields.get("Package") and fields.get("Version") and fields.get("Status", "install ok installed") == "install ok installed":
            packages[fields["Package"]] = fields["Version"]
    return packages


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sbom", required=True, type=pathlib.Path)
    parser.add_argument("--installed-root", required=True, type=pathlib.Path)
    args = parser.parse_args()

    bom = json.loads(args.sbom.read_text(encoding="utf-8"))
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.6"
    uuid.UUID(bom["serialNumber"].removeprefix("urn:uuid:"))
    components = bom["components"]
    by_name = {component["name"]: component for component in components}
    assert len(by_name) == len(components), "duplicate SBOM component names"
    expected = installed_packages(args.installed_root)
    assert set(by_name) == set(expected), (
        f"SBOM components differ from installed packages: missing={sorted(set(expected) - set(by_name))}, "
        f"extra={sorted(set(by_name) - set(expected))}"
    )

    refs = {bom["metadata"]["component"]["bom-ref"]}
    for name, component in by_name.items():
        assert component["version"] == expected[name], f"incorrect installed version for {name}"
        assert component["bom-ref"] == component["purl"]
        assert component["purl"].startswith("pkg:vcpkg/")
        encoded_version = component["purl"].rsplit("@", 1)[1]
        assert "#" not in encoded_version and "?" not in encoded_version, f"unescaped PURL delimiter: {name}"
        assert unquote(encoded_version) == component["version"], f"PURL version mismatch for {name}"
        assert component.get("licenses"), f"license declaration missing for {name}"
        refs.add(component["bom-ref"])

    assert bom["metadata"]["component"].get("licenses"), "project license missing from SBOM root"
    for edge in bom["dependencies"]:
        assert edge["ref"] in refs, f"dependency edge references an unknown component: {edge['ref']}"
        assert set(edge.get("dependsOn", [])) <= refs, f"dependency edge has an unknown target: {edge['ref']}"

    print(f"CycloneDX 1.6 SBOM validated: {len(components)} installed packages, PURLs and licenses verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
