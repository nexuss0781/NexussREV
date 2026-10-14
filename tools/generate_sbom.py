#!/usr/bin/env python3
"""Generate a CycloneDX 1.6 SBOM from a vcpkg installed status database."""

import argparse
import datetime as dt
import json
import pathlib
import re
import sys
import uuid
from urllib.parse import quote, unquote


def paragraphs(text):
    for block in re.split(r"\n\s*\n", text.strip()):
        entry = {}
        for line in block.splitlines():
            if ": " in line and not line.startswith(" "):
                key, value = line.split(": ", 1)
                entry[key] = value
        if entry:
            yield entry


def port_manifest(ports_root, name):
    path = ports_root / name / "vcpkg.json"
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"cannot read vcpkg port manifest {path}: {error}") from error


def purl(name, version, ecosystem="vcpkg"):
    encoded_name = quote(name, safe="._-~")
    encoded_version = quote(version, safe="._-~")
    if unquote(encoded_name) != name or unquote(encoded_version) != version:
        raise RuntimeError(f"could not encode PURL identity for {name}@{version}")
    result = f"pkg:{ecosystem}/{encoded_name}@{encoded_version}"
    if "#" in encoded_version or "?" in encoded_version:
        raise RuntimeError(f"reserved delimiter was not encoded in PURL version {version!r}")
    return result


def dependency_names(manifest):
    result = []
    for item in manifest.get("dependencies", []):
        if isinstance(item, str):
            result.append(item)
        elif isinstance(item, dict) and isinstance(item.get("name"), str):
            result.append(item["name"])
    return sorted(set(result))


def parse_timestamp(value):
    if value:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("timestamp must include a timezone, e.g. 2026-10-15T00:00:00Z")
        return parsed.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installed-root", required=True, type=pathlib.Path,
                        help="vcpkg installed tree (the directory containing vcpkg/status)")
    parser.add_argument("--ports-root", required=True, type=pathlib.Path,
                        help="pinned vcpkg ports directory")
    parser.add_argument("--version", default="0.1.0")
    parser.add_argument("--platform", required=True, help="release target label, e.g. linux-x64")
    parser.add_argument("--timestamp", help="UTC timestamp override for reproducible generation")
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()

    status_path = args.installed_root / "vcpkg" / "status"
    if not status_path.is_file():
        parser.error(f"vcpkg status file not found: {status_path}")
    try:
        records = list(paragraphs(status_path.read_text(encoding="utf-8")))
        timestamp = parse_timestamp(args.timestamp)
    except (OSError, UnicodeError, ValueError) as error:
        parser.error(str(error))

    packages = {}
    for record in records:
        name = record.get("Package")
        version = record.get("Version")
        if not name or not version or record.get("Status", "install ok installed") != "install ok installed":
            continue
        manifest = port_manifest(args.ports_root, name)
        package = packages.setdefault(name, {
            "name": name,
            "version": version,
            "architecture": record.get("Architecture", "unknown"),
            "manifest": manifest,
        })
        if package["version"] != version:
            raise RuntimeError(f"multiple installed versions of {name}: {package['version']} and {version}")

    if not packages:
        parser.error(f"no installed packages found in {status_path}")

    build_tools = {"vcpkg-cmake", "vcpkg-cmake-config"}
    components = []
    refs = {name: purl(name, package["version"]) for name, package in packages.items()}
    for name in sorted(packages):
        package = packages[name]
        manifest = package["manifest"]
        license_expression = manifest.get("license")
        licenses = ([{"expression": license_expression}] if license_expression else
                    [{"license": {"name": "NOASSERTION"}}])
        component = {
            "type": "library",
            "bom-ref": refs[name],
            "name": name,
            "version": package["version"],
            "purl": refs[name],
            "scope": "excluded" if name in build_tools else "required",
            "licenses": licenses,
            "properties": [
                {"name": "nexussrev:platform", "value": args.platform},
                {"name": "vcpkg:architecture", "value": package["architecture"]},
                {"name": "nexussrev:license-source", "value": f"vcpkg ports/{name}/vcpkg.json"},
            ],
        }
        if manifest.get("description"):
            description = manifest["description"]
            if isinstance(description, dict):
                description = description.get("en", "")
            if isinstance(description, str) and description:
                component["description"] = description
        components.append(component)

    root_ref = purl("nexussrev", args.version, ecosystem="generic")
    root = {
        "type": "application",
        "bom-ref": root_ref,
        "name": "NexussREV",
        "version": args.version,
        "purl": root_ref,
        "licenses": [{"expression": "MIT"}],
        "properties": [
            {"name": "nexussrev:platform", "value": args.platform},
            {"name": "nexussrev:analysis-target", "value": "native PE32+ x86-64; static-only"},
            {"name": "nexussrev:vcpkg-installed-root", "value": "build-time inventory; see vcpkg manifest baseline"},
        ],
    }

    project_manifest = json.loads(pathlib.Path("vcpkg.json").read_text(encoding="utf-8"))
    direct_names = []
    for item in project_manifest.get("dependencies", []):
        if isinstance(item, str):
            direct_names.append(item)
        elif isinstance(item, dict) and item.get("name"):
            direct_names.append(item["name"])
    direct_refs = sorted(refs[name] for name in set(direct_names) if name in refs)
    dependency_edges = [{"ref": root_ref, "dependsOn": direct_refs}]
    for name in sorted(packages):
        children = sorted(refs[child] for child in dependency_names(packages[name]["manifest"])
                          if child in refs and child != name)
        if children:
            dependency_edges.append({"ref": refs[name], "dependsOn": children})
    dependency_edges.sort(key=lambda edge: edge["ref"])

    component_keys = "\n".join(component["bom-ref"] for component in components)
    deterministic_uuid = uuid.uuid5(uuid.NAMESPACE_URL, f"{args.platform}\n{component_keys}")
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{deterministic_uuid}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "component": root,
            "properties": [
                {"name": "nexussrev:platform", "value": args.platform},
                {"name": "nexussrev:vcpkg-baseline", "value": project_manifest["builtin-baseline"]},
            ],
            "tools": {"components": [{"type": "application", "name": "vcpkg", "version": "pinned by builtin-baseline"}]},
        },
        "components": components,
        "dependencies": dependency_edges,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(bom, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote CycloneDX 1.6 SBOM with {len(components)} installed vcpkg components to {args.output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as error:
        print(f"SBOM generation failed: {error}", file=sys.stderr)
        raise SystemExit(2)
