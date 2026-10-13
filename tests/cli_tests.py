#!/usr/bin/env python3
"""Phase 0 CLI acceptance tests; only a checked-in synthetic PE fixture is analyzed."""

import argparse
import hashlib
import json
import pathlib
import subprocess
import tempfile


def run(program, *arguments):
    return subprocess.run(
        [str(program), *map(str, arguments)],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--program", required=True, type=pathlib.Path)
    parser.add_argument("--fixture", required=True, type=pathlib.Path)
    args = parser.parse_args()

    help_result = run(args.program, "--help")
    assert help_result.returncode == 0, help_result.stderr
    assert "not original source code" in help_result.stdout
    fixture_hash = hashlib.sha256(args.fixture.read_bytes()).hexdigest()
    overwrite_result = run(args.program, args.fixture, args.fixture)
    assert overwrite_result.returncode == 2
    assert "INVALID_ARGUMENT" in overwrite_result.stderr
    assert hashlib.sha256(args.fixture.read_bytes()).hexdigest() == fixture_hash

    with tempfile.TemporaryDirectory(prefix="nexusrev-phase0-") as directory:
        root = pathlib.Path(directory)
        missing = root / "missing.exe"
        missing_output = root / "missing-output.txt"
        missing_result = run(args.program, missing, missing_output)
        assert missing_result.returncode != 0
        assert "INPUT_NOT_FOUND" in missing_result.stderr
        assert "Wrote annotated" not in missing_result.stdout
        assert not missing_output.exists()
        assert not pathlib.Path(str(missing_output) + ".report.json").exists()

        malformed = root / "malformed.exe"
        malformed.write_bytes(b"not a PE image\x00\x01")
        malformed_output = root / "malformed-output.txt"
        malformed_result = run(args.program, malformed, malformed_output)
        assert malformed_result.returncode != 0
        assert "INPUT_PARSE_FAILED" in malformed_result.stderr
        assert "Wrote annotated" not in malformed_result.stdout
        assert not malformed_output.exists()
        assert not pathlib.Path(str(malformed_output) + ".report.json").exists()

        valid_output = root / "fixture.disasm"
        valid_result = run(args.program, args.fixture, valid_output)
        assert valid_result.returncode == 0, valid_result.stderr
        assert "[partial]" in valid_result.stdout
        assert valid_output.is_file()
        report_path = pathlib.Path(str(valid_output) + ".report.json")
        assert report_path.is_file()
        report = json.loads(report_path.read_text(encoding="utf-8"))
        assert report["schema_version"] == 1
        assert report["status"] == "partial"
        assert report["run"] == {
            "start_status": "running",
            "end_status": "partial",
            "exit_code": 0,
        }
        assert report["tool"]["configuration_version"] == 1
        assert report["input"]["sha256"] == fixture_hash
        assert [stage["name"] for stage in report["stages"]] == [
            "parse", "analysis", "emission"
        ]
        assert all(
            stage["status"] in {"complete", "partial", "unsupported", "failed"}
            for stage in report["stages"]
        )
        output_text = valid_output.read_text(encoding="utf-8")
        assert "not original source code" in output_text
        assert "candidate" in output_text.lower()

        blocked_output = root / "absent-parent" / "out.disasm"
        blocked_result = run(args.program, args.fixture, blocked_output)
        assert blocked_result.returncode != 0
        assert "OUTPUT_WRITE_FAILED" in blocked_result.stderr
        assert "Wrote annotated" not in blocked_result.stdout
        assert not blocked_output.exists()
        assert not pathlib.Path(str(blocked_output) + ".report.json").exists()

    print("CLI acceptance tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
