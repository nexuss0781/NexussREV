#!/usr/bin/env python3
"""Phase 1 CLI acceptance tests over deterministic synthetic and compiler-built PE fixtures."""

import argparse
import hashlib
import json
import pathlib
import subprocess
import sys
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
    parser.add_argument("--generator", required=True, type=pathlib.Path)
    parser.add_argument("--compiler-fixture", required=True, type=pathlib.Path)
    args = parser.parse_args()

    help_result = run(args.program, "--help")
    assert help_result.returncode == 0, help_result.stderr
    assert "not original source code" in help_result.stdout
    assert "PE32+ x86-64" in help_result.stdout
    fixture_hash = hashlib.sha256(args.fixture.read_bytes()).hexdigest()
    overwrite_result = run(args.program, args.fixture, args.fixture)
    assert overwrite_result.returncode == 2
    assert "INVALID_ARGUMENT" in overwrite_result.stderr
    assert hashlib.sha256(args.fixture.read_bytes()).hexdigest() == fixture_hash

    with tempfile.TemporaryDirectory(prefix="nexusrev-phase1-") as directory:
        root = pathlib.Path(directory)

        def generate(filename, *extra):
            path = root / filename
            generated = subprocess.run(
                [sys.executable, str(args.generator), "--output", str(path), *extra],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            assert generated.returncode == 0, generated.stderr
            return path

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
        assert report["schema_version"] == 2
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
        assert report["pe"]["machine_name"] == "AMD64"
        assert report["pe"]["supported_x64_native"] is True
        assert report["pe"]["entry_point"] == {
            "rva": 0x1000, "va": 0x140001000, "file_offset": 0x200
        }
        assert report["decode"]["decoded_bytes"] == report["decode"]["executable_file_backed_bytes"]
        assert report["decode"]["instructions"]
        output_text = valid_output.read_text(encoding="utf-8")
        assert "not original source code" in output_text
        assert "RVA=0x" in output_text and "FILE=0x" in output_text

        rich = generate("metadata-x64.exe")
        rich_output = root / "metadata.disasm"
        rich_result = run(args.program, rich, rich_output)
        assert rich_result.returncode == 0, rich_result.stderr
        rich_report = json.loads(pathlib.Path(str(rich_output) + ".report.json").read_text(encoding="utf-8"))
        pe = rich_report["pe"]
        assert pe["imports"] == [{
            "library": "KERNEL32.dll", "name": "ExitProcess", "by_ordinal": False,
            "ordinal": 0, "iat_rva": 0x20D0
        }]
        assert pe["exports"][0]["name"] == "exported_func"
        assert pe["exports"][0]["rva"] == 0x1000
        assert {item["type"] for item in pe["base_relocations"]} == {0, 10}
        assert pe["debug_entries"][0]["codeview_age"] == 1
        assert pe["debug_entries"][0]["pdb_path"] == "fixture.pdb"
        assert pe["tls"]["present"] is True
        assert pe["tls"]["callbacks"] == [0x140001000]
        assert pe["runtime_functions"][0]["begin_rva"] == 0x1000
        assert pe["runtime_functions"][0]["unwind_info_available"] is True
        assert rich_report["decode"]["executable_file_backed_bytes"] == 8
        assert rich_report["decode"]["decoded_bytes"] == 5
        assert rich_report["decode"]["undecoded_bytes"] == 3
        assert any(gap["reason"] == "decoder_rejected" and gap["bytes"] == "06"
                   for gap in rich_report["decode"]["gaps"])
        assert any(gap["reason"] == "truncated_instruction" and gap["bytes"] == "e8 01"
                   for gap in rich_report["decode"]["gaps"])
        zero_fill_gap = next(gap for gap in rich_report["decode"]["gaps"]
                             if gap["reason"] == "virtual_zero_fill_not_file_backed")
        assert zero_fill_gap["file_offset"] is None and zero_fill_gap["bytes"] == ""
        first = rich_report["decode"]["instructions"][0]
        assert (first["rva"], first["va"], first["file_offset"], first["bytes"]) == (
            0x1000, 0x140001000, 0x200, "48 89 d8"
        )

        compiler_output = root / "compiler-generated.disasm"
        compiler_result = run(args.program, args.compiler_fixture, compiler_output)
        assert compiler_result.returncode == 0, compiler_result.stderr
        compiler_report = json.loads(pathlib.Path(str(compiler_output) + ".report.json").read_text(encoding="utf-8"))
        compiled_pe = compiler_report["pe"]
        assert compiled_pe["machine_name"] == "AMD64"
        assert compiled_pe["entry_point"]["rva"] == 0x1010
        assert compiled_pe["exports"][0]["name"] == "Add"
        compiled_instructions = compiler_report["decode"]["instructions"]
        assert [(item["rva"], item["file_offset"], item["bytes"]) for item in compiled_instructions] == [
            (0x1000, 0x400, "8d 04 11"), (0x1003, 0x403, "c3"),
            (0x1004, 0x404, "66 66 66 2e 0f 1f 84 00 00 00 00 00"),
            (0x1010, 0x410, "50"), (0x1011, 0x411, "c7 44 24 04 2a 00 00 00"),
            (0x1019, 0x419, "8b 44 24 04"), (0x101d, 0x41d, "58"), (0x101e, 0x41e, "c3")
        ]
        assert compiler_report["decode"]["decoded_bytes"] == 31
        assert compiler_report["decode"]["undecoded_bytes"] == 0
        first_detail = compiled_instructions[0]["detail"]
        assert first_detail["available"] is True
        assert first_detail["instruction_name"] == "lea"
        assert first_detail["opcodes"][0] == 0x8D
        assert "rcx" in first_detail["registers_read"] and "rdx" in first_detail["registers_read"]
        assert "eax" in first_detail["registers_written"]
        assert first_detail["operands"][0]["register"] == "eax"
        assert first_detail["operands"][1]["type"] == "memory"
        assert first_detail["operands"][1]["base"] == "rcx"
        assert first_detail["operands"][1]["index"] == "rdx"

        clr = generate("managed-x64.exe", "--clr")
        clr_output = root / "managed.disasm"
        clr_result = run(args.program, clr, clr_output)
        assert clr_result.returncode == 0, clr_result.stderr
        clr_report = json.loads(pathlib.Path(str(clr_output) + ".report.json").read_text(encoding="utf-8"))
        assert clr_report["status"] == "unsupported"
        assert clr_report["pe"]["clr"]["present"] is True
        assert clr_report["decode"]["instructions"] == []
        assert any(item["code"] == "MANAGED_CLR_UNSUPPORTED" for item in clr_report["diagnostics"])

        arm64 = generate("arm64.exe", "--machine", "0xaa64")
        arm_output = root / "arm64.disasm"
        arm_result = run(args.program, arm64, arm_output)
        assert arm_result.returncode == 0, arm_result.stderr
        arm_report = json.loads(pathlib.Path(str(arm_output) + ".report.json").read_text(encoding="utf-8"))
        assert arm_report["status"] == "unsupported"
        assert arm_report["pe"]["machine_name"] == "ARM64"
        assert arm_report["decode"]["instructions"] == []

        blocked_output = root / "absent-parent" / "out.disasm"
        blocked_result = run(args.program, args.fixture, blocked_output)
        assert blocked_result.returncode != 0
        assert "OUTPUT_WRITE_FAILED" in blocked_result.stderr
        assert "Wrote annotated" not in blocked_result.stdout
        assert not blocked_output.exists()
        assert not pathlib.Path(str(blocked_output) + ".report.json").exists()

    print("Phase 1 CLI acceptance tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
