#!/usr/bin/env python3
"""CLI acceptance tests over deterministic PE and PDB fixtures."""

import argparse
import hashlib
import json
import jsonschema
import pathlib
import struct
import subprocess
import sys
import tempfile


def run(program, *arguments):
    return subprocess.run(
        [str(program), *map(str, arguments)],
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )


def validate_report(report, validator):
    errors = list(validator.iter_errors(report))
    if errors:
        details = "\n".join(
            f"{'/'.join(map(str, error.absolute_path))}: {error.message}"
            for error in errors[:10]
        )
        raise AssertionError(f"analysis report does not conform to schema:\n{details}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--program", required=True, type=pathlib.Path)
    parser.add_argument("--fixture", required=True, type=pathlib.Path)
    parser.add_argument("--generator", required=True, type=pathlib.Path)
    parser.add_argument("--compiler-fixture", required=True, type=pathlib.Path)
    parser.add_argument("--phase2-fixtures", required=True, type=pathlib.Path)
    parser.add_argument("--schema", required=True, type=pathlib.Path)
    args = parser.parse_args()

    schema = json.loads(args.schema.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    report_validator = jsonschema.Draft202012Validator(schema)
    assert schema["properties"]["schema_version"]["const"] == 6
    help_result = run(args.program, "--help")
    assert help_result.returncode == 0, help_result.stderr
    assert "not original source" in help_result.stdout
    assert "pseudocode" in help_result.stdout
    assert "PE32+ x86-64" in help_result.stdout
    assert "--pdb" in help_result.stdout
    assert "--decode-strategy" in help_result.stdout
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
        validate_report(report, report_validator)
        assert report["schema_version"] == 6
        assert report["status"] == "partial"
        assert report["run"] == {
            "start_status": "running",
            "end_status": "partial",
            "exit_code": 0,
        }
        assert report["tool"]["configuration_version"] == 4
        assert report["input"]["sha256"] == fixture_hash
        assert [stage["name"] for stage in report["stages"]] == [
            "parse", "analysis", "symbol_provider", "function_recovery", "semantic_analysis", "dataflow_analysis", "emission"
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
        assert report["symbols"]["status"] == "not_present"
        assert report["function_recovery"]["candidate_functions"]
        assert report["semantic_analysis"]["status"] in {"partial", "complete"}
        assert report["semantic_analysis"]["instructions"]
        assert report["semantic_analysis"]["reference"]["status"] == "not_configured"
        assert report["dataflow_analysis"]["status"] in {"partial", "complete"}
        assert report["dataflow_analysis"]["abi"] == "Microsoft x64"
        assert report["dataflow_analysis"]["signatures"]
        ghidra_tsv = root / "ghidra-reference.tsv"
        with ghidra_tsv.open("w", encoding="utf-8") as reference:
            reference.write(f"NEXUSREV_GHIDRA_REFERENCE\t1\t{report['input']['sha256']}\tunit-test\n")
            for group in ("known_functions", "candidate_functions", "fragments"):
                for function in report["function_recovery"][group]:
                    reference.write(f"F\t{function['start_rva']}\n")
            flow_kinds = {
                "direct_call": "call", "conditional_branch": "conditional_branch",
                "direct_branch": "branch", "indirect_branch": "indirect_branch", "return": "return",
            }
            for instruction in report["semantic_analysis"]["instructions"]:
                kind = flow_kinds.get(instruction["control_flow"])
                if kind:
                    target = instruction["target_rva"]
                    reference.write(f"E\t{instruction['rva']}\t{kind}\t{target if target is not None else '-'}\n")
        referenced_output = root / "referenced.disasm"
        referenced_result = run(args.program, "--reference-report", ghidra_tsv, args.fixture, referenced_output)
        assert referenced_result.returncode == 0, referenced_result.stderr
        referenced_report = json.loads(pathlib.Path(str(referenced_output) + ".report.json").read_text(encoding="utf-8"))
        assert referenced_report["semantic_analysis"]["reference"]["status"] == "compared"
        assert referenced_report["semantic_analysis"]["reference"]["difference_count"] == 0

        mismatched_tsv = root / "ghidra-mismatched.tsv"
        mismatched_tsv.write_text("NEXUSREV_GHIDRA_REFERENCE\t1\t" + "0" * 64 + "\tunit-test\n", encoding="utf-8")
        mismatched_output = root / "reference-mismatch.disasm"
        mismatched_result = run(args.program, "--reference-report", mismatched_tsv, args.fixture, mismatched_output)
        assert mismatched_result.returncode == 0, mismatched_result.stderr
        mismatched_report = json.loads(pathlib.Path(str(mismatched_output) + ".report.json").read_text(encoding="utf-8"))
        assert mismatched_report["semantic_analysis"]["reference"]["status"] == "invalid"
        assert any(item["code"] == "GHIDRA_REFERENCE_INPUT_MISMATCH" for item in mismatched_report["diagnostics"])
        output_text = valid_output.read_text(encoding="utf-8")
        assert "not original source code" in output_text
        assert "RVA=0x" in output_text and "FILE=0x" in output_text

        pseudocode_output = root / "fixture.pseudo.c"
        pseudocode_result = run(args.program, "--format", "pseudocode", args.fixture, pseudocode_output)
        assert pseudocode_result.returncode == 0, pseudocode_result.stderr
        pseudocode_text = pseudocode_output.read_text(encoding="utf-8")
        assert "best-effort C-like pseudocode" in pseudocode_text
        assert "not original source" in pseudocode_text
        assert "not guaranteed compilable" in pseudocode_text
        pseudocode_report = json.loads(pathlib.Path(str(pseudocode_output) + ".report.json").read_text(encoding="utf-8"))
        validate_report(pseudocode_report, report_validator)

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

        range_fixture = root / "two-function-ranges.exe"
        range_image = bytearray(rich.read_bytes())
        struct.pack_into("<I", range_image, 0x704, 0x1004)
        struct.pack_into("<III", range_image, 0x70C, 0x1004, 0x1008, 0x3020)
        struct.pack_into("<I", range_image, 0x124, 24)
        range_image[0x720:0x724] = bytes((1, 1, 0, 0))
        range_fixture.write_bytes(range_image)
        range_outputs = []
        for worker_count in (1, 2):
            range_output = root / f"function-ranges-{worker_count}.disasm"
            range_result = run(args.program, "--decode-strategy", "function-ranges",
                               "--decode-workers", str(worker_count), range_fixture, range_output)
            assert range_result.returncode == 0, range_result.stderr
            range_report = json.loads(pathlib.Path(str(range_output) + ".report.json").read_text(encoding="utf-8"))
            validate_report(range_report, report_validator)
            assert len(range_report["pe"]["runtime_functions"]) == 2
            assert any(item["code"] == "FUNCTION_RANGE_DECODE_USED"
                       for item in range_report["diagnostics"])
            assert any(item["code"] == "FUNCTION_RANGE_WORKLIST_USED"
                       for item in range_report["diagnostics"])
            range_decode = range_report["decode"]
            assert range_decode["decoded_bytes"] + range_decode["undecoded_bytes"] == range_decode["processed_bytes"]
            assert range_decode["processed_bytes"] + range_decode["limited_bytes"] == \
                range_decode["executable_file_backed_bytes"]
            range_rvas = [item["rva"] for item in range_decode["instructions"]]
            assert range_rvas == sorted(set(range_rvas))
            range_outputs.append((range_decode, range_report["semantic_analysis"]))
        assert range_outputs[0] == range_outputs[1], "function-range results changed with worker count"

        worklist_fixture = root / "branch-worklist.exe"
        worklist_image = bytearray(rich.read_bytes())
        worklist_image[0x200:0x209] = bytes.fromhex("eb 02 06 06 75 02 c3 06 c3")
        struct.pack_into("<I", worklist_image, 0x190, 9)
        struct.pack_into("<I", worklist_image, 0x198, 9)
        struct.pack_into("<I", worklist_image, 0x704, 0x1009)
        worklist_fixture.write_bytes(worklist_image)
        worklist_output = root / "branch-worklist.disasm"
        worklist_result = run(args.program, "--decode-strategy", "function-ranges",
                              worklist_fixture, worklist_output)
        assert worklist_result.returncode == 0, worklist_result.stderr
        worklist_report = json.loads(
            pathlib.Path(str(worklist_output) + ".report.json").read_text(encoding="utf-8"))
        validate_report(worklist_report, report_validator)
        worklist_decode = worklist_report["decode"]
        assert [item["rva"] for item in worklist_decode["instructions"]] == [
            0x1000, 0x1004, 0x1006, 0x1008
        ]
        assert worklist_decode["processed_bytes"] == 6
        assert worklist_decode["limited_bytes"] == 3
        assert worklist_decode["decoded_bytes"] == 6
        limit_ranges = sorted((item["rva"], item["size"])
                              for item in worklist_decode["gaps"]
                              if item["reason"] == "analysis_limit")
        assert limit_ranges == [(0x1002, 2), (0x1007, 1)]
        assert not any(item["reason"] == "decoder_rejected"
                       for item in worklist_decode["gaps"])
        branch_semantics = {item["rva"]: item
                            for item in worklist_report["semantic_analysis"]["instructions"]}
        assert branch_semantics[0x1000]["control_flow"] == "direct_branch"
        assert branch_semantics[0x1000]["target_rva"] == 0x1004
        assert branch_semantics[0x1004]["control_flow"] == "conditional_branch"
        assert branch_semantics[0x1004]["target_rva"] == 0x1008

        auto_range_fixture = generate("auto-function-ranges.exe", "--auto-function-ranges")
        auto_range_output = root / "auto-function-ranges.disasm"
        auto_range_result = run(args.program, "--decode-strategy", "auto", "--decode-workers", "2",
                                auto_range_fixture, auto_range_output)
        assert auto_range_result.returncode == 0, auto_range_result.stderr
        auto_range_report = json.loads(
            pathlib.Path(str(auto_range_output) + ".report.json").read_text(encoding="utf-8"))
        validate_report(auto_range_report, report_validator)
        assert len(auto_range_report["pe"]["runtime_functions"]) == 512
        assert any(item["code"] == "FUNCTION_RANGE_DECODE_USED"
                   for item in auto_range_report["diagnostics"])
        auto_decode = auto_range_report["decode"]
        assert auto_decode["instruction_count"] == 8192
        assert auto_decode["processed_bytes"] + auto_decode["limited_bytes"] == \
            auto_decode["executable_file_backed_bytes"]
        assert auto_decode["decoded_bytes"] + auto_decode["undecoded_bytes"] == auto_decode["processed_bytes"]

        compiler_output = root / "compiler-generated.disasm"
        compiler_result = run(args.program, args.compiler_fixture, compiler_output)
        assert compiler_result.returncode == 0, compiler_result.stderr
        compiler_report = json.loads(pathlib.Path(str(compiler_output) + ".report.json").read_text(encoding="utf-8"))
        validate_report(compiler_report, report_validator)
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

        ghidra_reference = args.compiler_fixture.with_name("compiler-generated-x64-ghidra-11.3.2.tsv")
        assert ghidra_reference.is_file()
        ghidra_output = root / "ghidra-reference.disasm"
        ghidra_result = run(args.program, "--reference-report", ghidra_reference,
                            args.compiler_fixture, ghidra_output)
        assert ghidra_result.returncode == 0, ghidra_result.stderr
        ghidra_report = json.loads(pathlib.Path(str(ghidra_output) + ".report.json").read_text(encoding="utf-8"))
        validate_report(ghidra_report, report_validator)
        ghidra_comparison = ghidra_report["semantic_analysis"]["reference"]
        assert ghidra_comparison["status"] == "compared"
        assert ghidra_comparison["tool"] == "Ghidra"
        assert ghidra_comparison["version"] == "11.3.2"
        assert ghidra_comparison["reference_function_count"] == 2
        assert ghidra_comparison["compared_flow_count"] == 2
        assert ghidra_comparison["difference_count"] == 0

        pdb_dll = args.phase2_fixtures / "pdb-sample.dll"
        pdb_output = root / "pdb-backed.disasm"
        pdb_result = run(args.program, pdb_dll, pdb_output)
        assert pdb_result.returncode == 0, pdb_result.stderr
        pdb_report = json.loads(pathlib.Path(str(pdb_output) + ".report.json").read_text(encoding="utf-8"))
        assert pdb_report["symbols"]["status"] == "matched"
        assert pdb_report["symbols"]["expected_identity"] == pdb_report["symbols"]["observed_identity"]
        assert {item["name"] for item in pdb_report["symbols"]["functions"]} == {
            "add_one", "call_add", "call_helper", "private_helper"
        }
        assert all(item["provenance"] == "pdb_procedure_record" and item["type_index"] is not None
                   for item in pdb_report["symbols"]["functions"])
        assert all(item["type_status"] == "decoded" and item["return_type"] == "int" and
                   item["parameter_types"] == ["int"] and item["type_provenance"] == "pdb_tpi_procedure_record"
                   for item in pdb_report["symbols"]["functions"])
        assert all(item["return_type"] == "int" and item["return_type_status"] == "observed" and
                   item["parameters"][0]["type"] == "int" and item["parameters"][0]["type_status"] == "observed"
                   for item in pdb_report["dataflow_analysis"]["signatures"])
        known = pdb_report["function_recovery"]["known_functions"]
        assert len(known) == 4
        assert all(any(evidence["source"] == "pdb_procedure_record" for evidence in item["evidence"])
                   for item in known)
        assert not pdb_report["function_recovery"]["candidate_functions"]
        pdb_text = pdb_output.read_text(encoding="utf-8")
        assert "Symbol provider: matched (4 procedure records)" in pdb_text
        assert "Known functions:" in pdb_text and "pdb_procedure_record" in pdb_text
        pseudocode_pdb = root / "pdb-backed.pseudocode"
        pseudocode_pdb_result = run(args.program, "--format", "pseudocode", pdb_dll, pseudocode_pdb)
        assert pseudocode_pdb_result.returncode == 0, pseudocode_pdb_result.stderr
        assert "int add_one(int arg0" in pseudocode_pdb.read_text(encoding="utf-8")

        mismatch_output = root / "pdb-mismatch.disasm"
        mismatch_result = run(args.program, "--pdb", args.phase2_fixtures / "pdb-sample-o2.pdb",
                              pdb_dll, mismatch_output)
        assert mismatch_result.returncode == 0, mismatch_result.stderr
        mismatch_report = json.loads(pathlib.Path(str(mismatch_output) + ".report.json").read_text(encoding="utf-8"))
        assert mismatch_report["symbols"]["status"] == "mismatched"
        assert mismatch_report["symbols"]["functions"] == []
        assert not mismatch_report["function_recovery"]["known_functions"]
        assert any(item["code"] == "PDB_IDENTITY_MISMATCH" for item in mismatch_report["diagnostics"])

        stripped_dll = args.phase2_fixtures / "stripped" / "pdb-sample-stripped.dll"
        stripped_output = root / "stripped.disasm"
        stripped_result = run(args.program, stripped_dll, stripped_output)
        assert stripped_result.returncode == 0, stripped_result.stderr
        stripped_report = json.loads(pathlib.Path(str(stripped_output) + ".report.json").read_text(encoding="utf-8"))
        assert stripped_report["symbols"]["status"] == "not_present"
        assert not stripped_report["function_recovery"]["known_functions"]
        stripped_candidates = stripped_report["function_recovery"]["candidate_functions"]
        assert len(stripped_candidates) == 4
        assert all(any(evidence["source"] == "x64_unwind_range" for evidence in item["evidence"])
                   for item in stripped_candidates)
        assert all(item["end_rva"] is not None for item in stripped_candidates)
        stripped_text = stripped_output.read_text(encoding="utf-8")
        assert "Candidate functions:" in stripped_text and "x64_unwind_range" in stripped_text

        missing_pdb_output = root / "pdb-missing.disasm"
        missing_pdb = run(args.program, "--pdb", root / "absent.pdb", pdb_dll, missing_pdb_output)
        assert missing_pdb.returncode == 0
        missing_pdb_report = json.loads(pathlib.Path(str(missing_pdb_output) + ".report.json").read_text(encoding="utf-8"))
        assert missing_pdb_report["symbols"]["status"] == "missing"
        bad_pdb = root / "bad.pdb"
        bad_pdb.write_bytes(b"not a PDB")
        bad_pdb_output = root / "pdb-invalid.disasm"
        invalid_pdb = run(args.program, "--pdb", bad_pdb, pdb_dll, bad_pdb_output)
        assert invalid_pdb.returncode == 0
        invalid_pdb_report = json.loads(pathlib.Path(str(bad_pdb_output) + ".report.json").read_text(encoding="utf-8"))
        assert invalid_pdb_report["symbols"]["status"] == "invalid"
        protected = run(args.program, "--pdb", args.phase2_fixtures / "pdb-sample.pdb",
                        pdb_dll, args.phase2_fixtures / "pdb-sample.pdb")
        assert protected.returncode == 2

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
