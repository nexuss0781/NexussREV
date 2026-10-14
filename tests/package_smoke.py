#!/usr/bin/env python3
"""Extract and execute only the packaged NexussREV CLI smoke checks."""

import argparse
import json
import os
import pathlib
import subprocess
import tarfile
import tempfile
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=pathlib.Path)
    parser.add_argument("--installed-root", required=True, type=pathlib.Path,
                        help="vcpkg installed tree used to verify packaged third-party notices")
    parser.add_argument("--format", required=True, choices=("zip", "tgz"))
    parser.add_argument("--platform", required=True, choices=("linux-x64", "windows-x64"))
    args = parser.parse_args()
    assert args.archive.is_file(), f"package archive is missing: {args.archive}"

    with tempfile.TemporaryDirectory(prefix="nexusrev-package-smoke-") as temporary:
        root = pathlib.Path(temporary)
        if args.format == "zip":
            with zipfile.ZipFile(args.archive) as package:
                package.extractall(root)
        else:
            with tarfile.open(args.archive, "r:gz") as package:
                package.extractall(root)

        binary_names = {"nexusrev.exe", "nexusrev"} if args.platform == "windows-x64" else {"nexusrev"}
        binaries = [path for path in root.rglob("*") if path.is_file() and path.name.lower() in binary_names]
        assert len(binaries) == 1, f"expected one packaged CLI, found {binaries}"
        executable = binaries[0]
        environment = os.environ.copy()
        library_dirs = [str(path) for path in root.rglob("lib") if path.is_dir()]
        bin_dirs = [str(path) for path in root.rglob("bin") if path.is_dir()]
        if args.platform == "windows-x64":
            environment["PATH"] = os.pathsep.join(bin_dirs + library_dirs + [environment.get("PATH", "")])
        else:
            environment["LD_LIBRARY_PATH"] = os.pathsep.join(library_dirs + [environment.get("LD_LIBRARY_PATH", "")])

        version = subprocess.run([str(executable), "--version"], capture_output=True,
                                  text=True, check=False, timeout=20, env=environment)
        assert version.returncode == 0, f"packaged --version failed: {version.stderr}"
        assert "NexussREV" in version.stdout and "schema 6" in version.stdout
        help_result = subprocess.run([str(executable), "--help"], capture_output=True,
                                     text=True, check=False, timeout=20, env=environment)
        assert help_result.returncode == 0, f"packaged --help failed: {help_result.stderr}"
        assert "PE32+ x86-64" in help_result.stdout and "--timeout-ms" in help_result.stdout

        schema_files = list(root.rglob("analysis-report.schema.json"))
        prior_schema_files = list(root.rglob("analysis-report-v5.schema.json"))
        assert len(schema_files) == 1 and len(prior_schema_files) == 1
        current_schema = json.loads(schema_files[0].read_text(encoding="utf-8"))
        old_schema = json.loads(prior_schema_files[0].read_text(encoding="utf-8"))
        assert current_schema["properties"]["schema_version"]["const"] == 6
        assert old_schema["properties"]["schema_version"]["const"] == 5
        assert list(root.rglob("LICENSE")), "package omitted the project license"
        assert list(root.rglob("dependency-license-inventory.md")), "package omitted dependency license inventory"
        assert list(root.rglob("phase6-release-notes.md")), "package omitted release notes"
        expected_notices = {
            path.parent.name: path.read_bytes()
            for path in args.installed_root.glob("*/share/*/copyright")
        }
        packaged_notices = {
            path.parent.name: path.read_bytes()
            for path in root.rglob("copyright")
            if path.parent.parent.name == "licenses"
        }
        assert expected_notices, "no vcpkg port copyright files were available to compare"
        assert packaged_notices.keys() == expected_notices.keys(), (
            f"package third-party notices differ from installed ports: expected {sorted(expected_notices)}, "
            f"found {sorted(packaged_notices)}"
        )
        assert packaged_notices == expected_notices, "packaged third-party copyright text differs from vcpkg"

    print(f"{args.platform} package extraction, runtime and metadata smoke passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
