#!/usr/bin/env python3
"""Bounded Phase 6 CLI release-hardening checks; fixture bytes are never executed."""

import argparse
import hashlib
import json
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import time

import jsonschema


def run(program, *arguments, timeout=30):
    return subprocess.run(
        [str(program), *map(str, arguments)],
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )


def require_no_artifacts(output):
    assert not output.exists(), f"unexpected partial output artifact: {output}"
    assert not pathlib.Path(str(output) + ".report.json").exists(), "unexpected JSON report artifact"


def make_large_pe(source, destination, size_bytes):
    data = bytearray(source.read_bytes())
    pe_offset = int.from_bytes(data[0x3C:0x40], "little")
    coff = pe_offset + 4
    optional = coff + 20
    section_count = int.from_bytes(data[coff + 2:coff + 4], "little")
    optional_size = int.from_bytes(data[coff + 16:coff + 18], "little")
    section_table = optional + optional_size
    text_section = None
    for index in range(section_count):
        section = section_table + index * 40
        characteristics = int.from_bytes(data[section + 36:section + 40], "little")
        if characteristics & 0x20000000:
            text_section = section
            break
    assert text_section is not None
    raw_offset = int.from_bytes(data[text_section + 20:text_section + 24], "little")
    virtual_address = int.from_bytes(data[text_section + 12:text_section + 16], "little")
    alignment = int.from_bytes(data[optional + 32:optional + 36], "little")
    assert size_bytes % 0x200 == 0 and alignment > 0
    data[coff + 2:coff + 4] = (1).to_bytes(2, "little")
    data[optional + 4:optional + 8] = size_bytes.to_bytes(4, "little")
    image_size = ((virtual_address + size_bytes + alignment - 1) // alignment) * alignment
    data[optional + 56:optional + 60] = image_size.to_bytes(4, "little")
    data[optional + 108:optional + 112] = (0).to_bytes(4, "little")
    data[text_section + 8:text_section + 12] = size_bytes.to_bytes(4, "little")
    data[text_section + 16:text_section + 20] = size_bytes.to_bytes(4, "little")
    with destination.open("wb") as stream:
        stream.write(data)
        stream.truncate(raw_offset + size_bytes)
        stream.seek(raw_offset + len(data[raw_offset:]))
        remaining = raw_offset + size_bytes - stream.tell()
        fill = b"\x90" * min(1024 * 1024, remaining)
        while remaining:
            chunk = fill[:min(len(fill), remaining)]
            stream.write(chunk)
            remaining -= len(chunk)
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--program", required=True, type=pathlib.Path)
    parser.add_argument("--fixture", required=True, type=pathlib.Path)
    parser.add_argument("--generator", required=True, type=pathlib.Path)
    parser.add_argument("--schema-v5", required=True, type=pathlib.Path)
    parser.add_argument("--schema-v6", required=True, type=pathlib.Path)
    args = parser.parse_args()

    schema_v5 = json.loads(args.schema_v5.read_text(encoding="utf-8"))
    schema_v6 = json.loads(args.schema_v6.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema_v5)
    jsonschema.Draft202012Validator.check_schema(schema_v6)
    assert schema_v5["properties"]["schema_version"]["const"] == 5
    assert schema_v6["properties"]["schema_version"]["const"] == 6
    assert schema_v5["$id"] != schema_v6["$id"]

    help_result = run(args.program, "--help")
    assert help_result.returncode == 0, help_result.stderr
    for option in ("--version", "--log-format", "--timeout-ms", "--memory-limit-mib", "PE32+ x86-64"):
        assert option in help_result.stdout, f"--help omits {option}"
    version_result = run(args.program, "--version")
    assert version_result.returncode == 0, version_result.stderr
    assert "NexussREV" in version_result.stdout and "schema 6" in version_result.stdout

    with tempfile.TemporaryDirectory(prefix="nexusrev-phase6-") as temporary:
        root = pathlib.Path(temporary)
        output = root / "stable.disasm"
        first = run(args.program, args.fixture, output)
        assert first.returncode == 0, first.stderr
        report_path = pathlib.Path(str(output) + ".report.json")
        first_disassembly = output.read_bytes()
        first_report = report_path.read_bytes()
        report = json.loads(first_report.decode("utf-8"))
        jsonschema.Draft202012Validator(schema_v6).validate(report)
        assert report["schema_version"] == 6
        assert report["input"]["sha256"] == hashlib.sha256(args.fixture.read_bytes()).hexdigest()
        assert "ANALYSIS_TIMEOUT" not in first.stderr

        second = run(args.program, args.fixture, output)
        assert second.returncode == 0, second.stderr
        assert output.read_bytes() == first_disassembly, "fixed-input output was not deterministic"
        assert report_path.read_bytes() == first_report, "fixed-input JSON report was not deterministic"
        assert not list(root.glob(".nexusrev-stage-*")), "successful run left staging directories behind"

        malformed_log = run(args.program, "--log-format", "jsonl", "--bad-option")
        assert malformed_log.returncode == 2
        log_records = [json.loads(line) for line in malformed_log.stderr.splitlines() if line.strip()]
        assert log_records and log_records[0]["code"] == "INVALID_ARGUMENT"
        assert all(set(record) == {"level", "code", "message"} for record in log_records)

        aliased_target = root / "aliased-output.txt"
        relative_alias = os.path.relpath(aliased_target, pathlib.Path.cwd())
        alias_result = run(args.program, "--report-json", aliased_target, args.fixture, relative_alias)
        assert alias_result.returncode == 2 and "paths must be different" in alias_result.stderr
        assert not aliased_target.exists()
        if os.name == "nt":
            case_target = root / "Case-aliased-output.txt"
            case_alias = root / "case-aliased-output.txt"
            case_result = run(args.program, "--report-json", case_alias, args.fixture, case_target)
            assert case_result.returncode == 2 and "paths must be different" in case_result.stderr
            assert not case_target.exists() and not case_alias.exists()

        bad_pdb = root / "not-a-pdb.pdb"
        bad_pdb.write_bytes(b"not an MSF/PDB\x00")
        log_output = root / "jsonl.disasm"
        logged = run(args.program, "--log-format", "jsonl", "--pdb", bad_pdb, args.fixture, log_output)
        assert logged.returncode == 0, logged.stderr
        pdb_records = [json.loads(line) for line in logged.stderr.splitlines() if line.strip()]
        assert pdb_records, "malformed PDB did not emit a structured diagnostic"
        assert all(set(record) == {"level", "code", "message"} for record in pdb_records)

        timeout_output = root / "timed-out.disasm"
        timed = run(args.program, "--timeout-ms", "1", args.fixture, timeout_output)
        assert timed.returncode == 124, f"expected cooperative timeout 124, got {timed.returncode}: {timed.stderr}"
        assert "ANALYSIS_TIMEOUT" in timed.stderr
        require_no_artifacts(timeout_output)

        cancellation_input = make_large_pe(args.fixture, root / "cancellation.exe", 64 * 1024 * 1024)
        cancellation_output = root / "cancelled.disasm"
        creation_flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        process = subprocess.Popen(
            [str(args.program), "--timeout-ms", "60000", str(cancellation_input), str(cancellation_output)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            creationflags=creation_flags,
        )
        if os.name == "nt":
            time.sleep(0.1)
        else:
            handler_ready = False
            deadline = time.monotonic() + 5.0
            status_path = pathlib.Path(f"/proc/{process.pid}/status")
            while time.monotonic() < deadline and process.poll() is None:
                try:
                    for line in status_path.read_text(encoding="ascii").splitlines():
                        if line.startswith("SigCgt:"):
                            caught = int(line.split()[1], 16)
                            handler_ready = bool(caught & (1 << (signal.SIGINT - 1)))
                            break
                except (FileNotFoundError, PermissionError):
                    pass
                if handler_ready:
                    break
                time.sleep(0.005)
            assert handler_ready, "CLI did not install its SIGINT cancellation handler"
        assert process.poll() is None, "large bounded analysis completed before cancellation delivery"
        if os.name == "nt":
            process.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            process.send_signal(signal.SIGINT)
        stdout, stderr = process.communicate(timeout=30)
        assert process.returncode == 130, f"expected cancellation exit 130, got {process.returncode}: {stdout} {stderr}"
        assert "ANALYSIS_CANCELLED" in stderr
        require_no_artifacts(cancellation_output)

        oversized = root / "oversized.exe"
        with oversized.open("wb") as stream:
            stream.truncate(256 * 1024 * 1024 + 1)
        oversized_output = root / "oversized.disasm"
        rejected = run(args.program, oversized, oversized_output)
        assert rejected.returncode != 0
        assert "INPUT_TOO_LARGE" in rejected.stderr or "INPUT_SIZE_LIMIT" in rejected.stderr
        require_no_artifacts(oversized_output)

        capped_input = root / "memory-capped.exe"
        with capped_input.open("wb") as stream:
            stream.truncate(96 * 1024 * 1024)
        capped_output = root / "memory-capped.disasm"
        capped = run(args.program, "--memory-limit-mib", "64", capped_input, capped_output)
        assert capped.returncode != 0, "process-memory cap did not constrain a 96 MiB input allocation"
        require_no_artifacts(capped_output)

        preserved_output = root / "preserved.disasm"
        preserved_output.write_bytes(b"prior complete output\n")
        invalid_report_destination = root / "report-is-a-directory"
        invalid_report_destination.mkdir()
        failed = run(args.program, "--report-json", invalid_report_destination, args.fixture, preserved_output)
        assert failed.returncode == 6, failed.stderr
        assert preserved_output.read_bytes() == b"prior complete output\n"
        assert not list(root.glob(".nexusrev-stage-*")), "failed preflight left staging directories behind"

        unsupported_input = root / "unsupported-arm64.exe"
        generated = subprocess.run(
            [sys.executable, str(args.generator), "--output", str(unsupported_input), "--machine", "0xaa64"],
            capture_output=True, text=True, check=False, timeout=10,
        )
        assert generated.returncode == 0, generated.stderr
        unsupported_output = root / "unsupported.disasm"
        unsupported = run(args.program, unsupported_input, unsupported_output)
        assert unsupported.returncode == 0, unsupported.stderr
        unsupported_report = json.loads(pathlib.Path(str(unsupported_output) + ".report.json").read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator(schema_v6).validate(unsupported_report)
        assert unsupported_report["status"] == "unsupported"
        assert unsupported_report["pe"]["supported_x64_native"] is False
        assert "no x64 instruction decoding was performed" in unsupported_output.read_text(encoding="utf-8")

    print("Phase 6 schema, CLI, determinism, resource-bound and artifact-publication tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
