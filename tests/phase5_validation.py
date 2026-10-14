#!/usr/bin/env python3
"""Gate 5 corpus quality report. PE inputs are treated as data and never executed."""

import argparse
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict

import jsonschema


class GateError(RuntimeError):
    pass


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def normalized_sha256_bytes(content, normalization=None):
    if normalization == "CRLF_TO_LF":
        content = content.replace(b"\r\n", b"\n")
    return hashlib.sha256(content).hexdigest()


def ratio(numerator, denominator):
    """A zero denominator is unknown, never a perfect score."""
    if denominator == 0:
        return {"numerator": numerator, "denominator": denominator,
                "value": None, "status": "not_measurable"}
    return {"numerator": numerator, "denominator": denominator,
            "value": numerator / denominator, "status": "measured"}


def prf_counts(tp, fp, fn):
    return {
        "true_positive": tp,
        "false_positive": fp,
        "false_negative": fn,
        "precision": ratio(tp, tp + fp),
        "recall": ratio(tp, tp + fn),
    }


def require(condition, message):
    if not condition:
        raise GateError(message)


def run_analysis(program, input_path, output_path, pdb_path=None, reference_path=None):
    command = [str(program)]
    if reference_path:
        command.extend(["--reference-report", str(reference_path)])
    if pdb_path:
        command.extend(["--pdb", str(pdb_path)])
    command.extend([str(input_path), str(output_path)])
    try:
        completed = subprocess.run(command, capture_output=True, text=True,
                                   check=False, timeout=45)
    except subprocess.TimeoutExpired as error:
        raise GateError(f"analysis timed out for {input_path}") from error
    require(completed.returncode == 0,
            f"analysis failed for {input_path}: {completed.stderr[-2000:]}")
    report_path = pathlib.Path(str(output_path) + ".report.json")
    require(output_path.is_file() and report_path.is_file(),
            f"analysis did not publish both declared artifacts for {input_path}")
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise GateError(f"invalid report for {input_path}: {error}") from error
    return command, completed, report, output_path, report_path


def validate_report(report, validator, sample_id):
    errors = list(validator.iter_errors(report))
    if errors:
        details = "\n".join(
            f"/{'/'.join(map(str, error.absolute_path))}: {error.message}"
            for error in errors[:8]
        )
        raise GateError(f"{sample_id}: report fails JSON Schema validation:\n{details}")


def report_stage(report, name):
    for stage in report["stages"]:
        if stage["name"] == name:
            return stage["status"]
    raise GateError(f"missing required stage {name!r}")


def validate_decode_accounting(report, sample_id):
    decode = report["decode"]
    require(decode["decoded_bytes"] + decode["undecoded_bytes"] == decode["processed_bytes"],
            f"{sample_id}: decoded + undecoded bytes do not equal processed bytes")
    require(decode["processed_bytes"] + decode["limited_bytes"] ==
            decode["executable_file_backed_bytes"],
            f"{sample_id}: processed + limit-excluded bytes do not equal executable file-backed bytes")


def validate_expected_pe(report, expected, sample_id):
    pe = report["pe"]
    for key, value in expected.items():
        require(pe.get(key) == value,
                f"{sample_id}: expected PE {key}={value!r}, got {pe.get(key)!r}")


def cfg_edge_is_consistent(edge, blocks):
    key = (edge["function_start_rva"], edge["from_block"])
    source = blocks.get(key)
    if source is None or edge["from_rva"] not in source["instruction_rvas"]:
        return False
    if edge["to_block"] is not None:
        target = blocks.get((edge["function_start_rva"], edge["to_block"]))
        if target is None:
            return False
        if edge["target_rva"] is not None and edge["target_rva"] != target["start_rva"]:
            return False
    return True


def check_report_integrity(report, validator, sample_id, expected_pe, output, report_path):
    validate_report(report, validator, sample_id)
    validate_expected_pe(report, expected_pe, sample_id)
    validate_decode_accounting(report, sample_id)
    artifacts = report["artifacts"]
    require(len(artifacts) == 2, f"{sample_id}: expected exactly two declared artifacts")
    declared = {pathlib.Path(path).resolve() for path in artifacts}
    require(declared == {output.resolve(), report_path.resolve()},
            f"{sample_id}: report artifact paths do not match the files published")
    require(output.is_file() and report_path.is_file(),
            f"{sample_id}: an emitted artifact is missing")
    require(report["input"]["sha256"] == report["input"]["sha256"].lower(),
            f"{sample_id}: invalid input hash representation")


def evaluate_positive_sample(sample, fixture_root, program, validator, temp_root):
    sample_id = sample["id"]
    input_path = (fixture_root / sample["input"]).resolve()
    require(input_path.is_file(), f"missing corpus fixture: {input_path}")
    actual_hash = sha256(input_path)
    require(actual_hash == sample["input_sha256"],
            f"{sample_id}: input SHA-256 mismatch: {actual_hash}")
    provenance = sample["provenance"]
    if provenance.get("source") and provenance.get("source_sha256"):
        source_path = (fixture_root / provenance["source"]).resolve()
        require(source_path.is_file(), f"{sample_id}: missing source fixture {source_path}")
        source_bytes = source_path.read_bytes()
        if provenance.get("source_hash_normalization") == "CRLF_TO_LF":
            source_bytes = source_bytes.replace(b"\r\n", b"\n")
        source_hash = hashlib.sha256(source_bytes).hexdigest()
        require(source_hash == provenance["source_sha256"],
                f"{sample_id}: source SHA-256 mismatch")
    pdb_path = None
    pdb_hash = None
    if sample.get("pdb"):
        pdb_path = (fixture_root / sample["pdb"]).resolve()
        require(pdb_path.is_file(), f"{sample_id}: missing PDB fixture {pdb_path}")
        pdb_hash = sha256(pdb_path)
        require(pdb_hash == sample["pdb_sha256"], f"{sample_id}: PDB SHA-256 mismatch")
    reference_path = None
    if sample.get("reference_report"):
        reference_path = (fixture_root / sample["reference_report"]).resolve()
        require(reference_path.is_file(), f"{sample_id}: missing reference report {reference_path}")
        actual_reference_hash = normalized_sha256_bytes(
            reference_path.read_bytes(), sample.get("reference_hash_normalization"))
        require(actual_reference_hash == sample["reference_sha256"],
                f"{sample_id}: reference report SHA-256 mismatch")
    output = temp_root / f"{sample_id}.disasm"
    _, completed, report, output, report_path = run_analysis(
        program, input_path, output, pdb_path, reference_path)
    check_report_integrity(report, validator, sample_id, sample["expected_pe"],
                           output, report_path)
    require(report["input"]["sha256"] == actual_hash,
            f"{sample_id}: analyzer-reported input SHA-256 mismatch")
    parse_status = report_stage(report, "parse")
    require(parse_status == sample.get("expected_parse_status", "complete"),
            f"{sample_id}: expected parse status {sample.get('expected_parse_status', 'complete')}, got {parse_status}")

    recovery = report["function_recovery"]
    functions = []
    for group_name in ("known_functions", "candidate_functions", "fragments"):
        functions.extend(recovery[group_name])
    with_evidence = sum(
        bool(record["evidence"]) and all(bool(item.get("source")) for item in record["evidence"])
        for record in functions)
    runtime_function_ranges = {
        (record["begin_rva"], record["end_rva"])
        for record in report["pe"]["runtime_functions"]
    }
    unwind_evidence_records = [
        record for record in functions
        if any(item.get("source") == "x64_unwind_range" for item in record["evidence"])
    ]
    verified_unwind_evidence_records = sum(
        (record["start_rva"], record["end_rva"]) in runtime_function_ranges
        for record in unwind_evidence_records)
    semantics = report["semantic_analysis"]
    blocks = {(block["function_start_rva"], block["id"]): block
              for block in semantics["basic_blocks"]}
    edges = semantics["cfg_edges"]
    consistent_edges = sum(cfg_edge_is_consistent(edge, blocks) for edge in edges)
    semantic_instructions = semantics["instructions"]
    unresolved_instruction_count = sum(
        item["status"] == "unsupported" for item in semantic_instructions)
    flow_instructions = [item for item in semantic_instructions
                         if item["control_flow"] != "fallthrough"]
    unresolved_flow_instruction_count = sum(
        item["control_flow"] == "unknown" or
        (item["control_flow"] in {"indirect_branch", "indirect_call"} and
         item["target_rva"] is None)
        for item in flow_instructions)
    unresolved_edge_count = sum(
        edge["kind"] == "unknown" or
        (edge["kind"] in {"indirect_branch", "indirect_call"} and
         edge["target_rva"] is None)
        for edge in edges)
    decode = report["decode"]
    reference = semantics["reference"]
    reproducible_command = [program.name]
    if sample.get("pdb"):
        reproducible_command.extend(["--pdb", sample["pdb"]])
    if sample.get("reference_report"):
        reproducible_command.extend(["--reference-report", sample["reference_report"]])
    reproducible_command.extend([sample["input"], "<temporary-output>"])

    return {
        "id": sample_id,
        "source_kind": sample["source_kind"],
        "input": sample["input"],
        "input_sha256": actual_hash,
        "pdb_sha256": pdb_hash,
        "reference_sha256": sample.get("reference_sha256"),
        "provenance": sample["provenance"],
        "expected_pe": sample["expected_pe"],
        "parse_status": parse_status,
        "overall_status": report["status"],
        "decode": {key: decode[key] for key in (
            "executable_file_backed_bytes", "processed_bytes", "decoded_bytes",
            "undecoded_bytes", "limited_bytes", "executable_zero_fill_bytes",
            "instruction_count")},
        "decode_coverage": ratio(decode["decoded_bytes"],
                                 decode["executable_file_backed_bytes"]),
        "function_boundaries": {
            "known_function_count": len(recovery["known_functions"]),
            "candidate_function_count": len(recovery["candidate_functions"]),
            "fragment_count": len(recovery["fragments"]),
            "unresolved_range_count": len(recovery["unresolved_ranges"]),
            "symbol_provenance": ratio(with_evidence, len(functions)),
            "records_with_provenance": with_evidence,
            "records_total": len(functions),
        },
        "semantic": {
            "status": semantics["status"],
            "instruction_count": len(semantic_instructions),
            "unsupported_instruction_count": unresolved_instruction_count,
            "unresolved_instruction_rate": ratio(unresolved_instruction_count,
                                                   len(semantic_instructions)),
            "unresolved_control_flow_count": semantics["unresolved_control_flow_count"],
            "flow_instruction_count": len(flow_instructions),
            "unresolved_flow_instruction_count": unresolved_flow_instruction_count,
            "unresolved_flow_instruction_rate": ratio(unresolved_flow_instruction_count,
                                                        len(flow_instructions)),
            "basic_block_count": len(semantics["basic_blocks"]),
            "cfg_edge_count": len(edges),
            "cfg_edges_consistent": consistent_edges,
            "cfg_edge_consistency": ratio(consistent_edges, len(edges)),
            "unresolved_cfg_edge_count": unresolved_edge_count,
            "call_graph_edge_count": len(semantics["call_graph"]),
        },
        "reference_backend": {
            "status": reference["status"],
            "tool": reference["tool"],
            "version": reference["version"],
            "difference_count": reference["difference_count"],
            "compared_flow_count": reference["compared_flow_count"],
        },
        "tool": report["tool"],
        "dependencies": report["dependencies"],
        "stage_statuses": {stage["name"]: stage["status"] for stage in report["stages"]},
        "artifact_completeness": ratio(2, 2),
        "report_schema_valid": True,
        "command": reproducible_command,
        "analyzer_stdout": completed.stdout.strip(),
        "diagnostic_counts": dict(Counter(item["severity"] for item in report["diagnostics"])),
        "_unwind_evidence_record_count": len(unwind_evidence_records),
        "_verified_unwind_evidence_record_count": verified_unwind_evidence_records,
        "_boundary_records": functions,
    }


def evaluate_malformed_case(case, temp_root, program):
    payload = bytes.fromhex(case["input_hex"])
    actual_hash = hashlib.sha256(payload).hexdigest()
    require(actual_hash == case["input_sha256"],
            f"{case['id']}: malformed-input hash mismatch")
    input_path = temp_root / f"{case['id']}.bin"
    input_path.write_bytes(payload)
    output = temp_root / f"{case['id']}.disasm"
    try:
        completed = subprocess.run([str(program), str(input_path), str(output)],
                                   capture_output=True, text=True, check=False, timeout=10)
    except subprocess.TimeoutExpired as error:
        raise GateError(f"{case['id']}: malformed input did not fail within bound") from error
    report_path = pathlib.Path(str(output) + ".report.json")
    observed = (completed.returncode == case["expected_exit_code"] and
                case["expected_diagnostic"] in completed.stderr and
                not output.exists() and not report_path.exists())
    require(observed,
            f"{case['id']}: malformed-input rejection contract failed; exit={completed.returncode}, stderr={completed.stderr!r}")
    return {
        "id": case["id"], "input_sha256": actual_hash,
        "expected_exit_code": case["expected_exit_code"],
        "expected_diagnostic": case["expected_diagnostic"],
        "observed_exit_code": completed.returncode,
        "observed_failure_contract": "passed",
        "artifacts_emitted": False,
    }


def release_baseline_projection(sample):
    boundary = sample["function_boundaries"]
    return {
        "input_sha256": sample["input_sha256"],
        "pdb_sha256": sample["pdb_sha256"],
        "reference_sha256": sample["reference_sha256"],
        "parse_status": sample["parse_status"],
        "overall_status": sample["overall_status"],
        "decode": sample["decode"],
        "function_boundaries": {
            "known_function_count": boundary["known_function_count"],
            "candidate_function_count": boundary["candidate_function_count"],
            "fragment_count": boundary["fragment_count"],
            "unresolved_range_count": boundary["unresolved_range_count"],
            "symbol_provenance": boundary["symbol_provenance"],
            "records_with_provenance": boundary["records_with_provenance"],
            "records_total": boundary["records_total"],
        },
        "semantic": sample["semantic"],
        "reference_backend": sample["reference_backend"],
        "tool": sample["tool"],
        "dependencies": sample["dependencies"],
        "stage_statuses": sample["stage_statuses"],
    }


def semantic_lift_improvement_only(observed, expected):
    """Allow only fewer unsupported instructions and their exactly derived rate."""
    allowed_changes = {"unsupported_instruction_count", "unresolved_instruction_rate"}
    if set(observed) != set(expected):
        return False
    if any(observed[key] != expected[key]
           for key in observed if key not in allowed_changes):
        return False
    observed_count = observed["unsupported_instruction_count"]
    expected_count = expected["unsupported_instruction_count"]
    observed_instructions = observed["instruction_count"]
    expected_instructions = expected["instruction_count"]
    if observed_count >= expected_count or observed_instructions != expected_instructions:
        return False
    return (observed["unresolved_instruction_rate"] ==
            ratio(observed_count, observed_instructions) and
            expected["unresolved_instruction_rate"] ==
            ratio(expected_count, expected_instructions))


def unwind_semantic_expansion_only(observed, expected):
    """Allow only unchanged instruction-level results plus verified CFG expansion."""
    if set(observed) != set(expected):
        return False
    allowed_changes = {
        "unsupported_instruction_count", "unresolved_instruction_rate",
        "unresolved_control_flow_count", "basic_block_count", "cfg_edge_count",
        "cfg_edges_consistent", "cfg_edge_consistency", "unresolved_cfg_edge_count",
        "call_graph_edge_count",
    }
    if any(observed[key] != expected[key]
           for key in observed if key not in allowed_changes):
        return False
    observed_count = observed["unsupported_instruction_count"]
    expected_count = expected["unsupported_instruction_count"]
    instruction_count = observed["instruction_count"]
    if instruction_count != expected["instruction_count"] or observed_count > expected_count:
        return False
    if (observed["unresolved_instruction_rate"] != ratio(observed_count, instruction_count) or
            expected["unresolved_instruction_rate"] !=
            ratio(expected_count, expected["instruction_count"])):
        return False
    expansion_metrics = (
        "unresolved_control_flow_count", "basic_block_count", "cfg_edge_count",
        "cfg_edges_consistent", "unresolved_cfg_edge_count", "call_graph_edge_count",
    )
    if any(observed[key] < expected[key] for key in expansion_metrics):
        return False
    if not any(observed[key] > expected[key] for key in
               ("basic_block_count", "cfg_edge_count", "call_graph_edge_count")):
        return False
    if observed["cfg_edge_consistency"] != ratio(
            observed["cfg_edges_consistent"], observed["cfg_edge_count"]):
        return False
    expected_ratio = expected["cfg_edge_consistency"]
    observed_ratio = observed["cfg_edge_consistency"]
    return (expected_ratio["value"] is None or
            (observed_ratio["value"] is not None and
             observed_ratio["value"] >= expected_ratio["value"]))


def unwind_boundary_expansion_only(sample, observed, expected):
    """Permit additional labelled records only when they map to parsed .pdata ranges."""
    current = observed["function_boundaries"]
    baseline = expected["function_boundaries"]
    if sample["_unwind_evidence_record_count"] <= 0 or (
            sample["_verified_unwind_evidence_record_count"] !=
            sample["_unwind_evidence_record_count"]):
        return False
    if current["known_function_count"] != baseline["known_function_count"]:
        return False
    if any(current[key] < baseline[key] for key in (
            "candidate_function_count", "fragment_count", "records_total",
            "records_with_provenance")):
        return False
    added_records = current["records_total"] - baseline["records_total"]
    if added_records <= 0:
        return False
    if current["records_total"] != (current["known_function_count"] +
                                    current["candidate_function_count"] +
                                    current["fragment_count"]):
        return False
    if current["records_with_provenance"] != current["records_total"]:
        return False
    if current["symbol_provenance"] != ratio(
            current["records_with_provenance"], current["records_total"]):
        return False
    baseline_provenance = baseline["symbol_provenance"]["value"]
    current_provenance = current["symbol_provenance"]["value"]
    if baseline_provenance is not None and (
            current_provenance is None or current_provenance < baseline_provenance):
        return False
    # New bounded ranges may split an unresolved interval, but must not multiply
    # unresolved intervals faster than the number of added, evidence-backed records.
    if current["unresolved_range_count"] > baseline["unresolved_range_count"] + added_records:
        return False
    if len(sample["_boundary_records"]) != current["records_total"]:
        return False
    return True


def summarize_boundary_metrics(samples, phase2_manifest, phase2_fixture_root, baseline):
    by_id = {sample["id"]: sample for sample in samples}
    groups = defaultdict(lambda: {"starts": [0, 0, 0], "ranges": [0, 0, 0]})
    per_case = []
    truth_sets = phase2_manifest["truth_sets"]
    for case in phase2_manifest["cases"]:
        sample_id = case["id"]
        actual = by_id[sample_id]
        truth = truth_sets[case["truth_set"]]
        input_path = (phase2_fixture_root / case["input"]).resolve()
        require(sha256(input_path) == case["input_sha256"],
                f"{sample_id}: Phase 2 manifest hash mismatch")
        # The report records individual function records so retain those for exact scoring.
        records = actual.get("_boundary_records", [])
        predicted_starts = {record["start_rva"] for record in records}
        predicted_ranges = {(record["start_rva"], record["end_rva"])
                            for record in records if record["end_rva"] is not None}
        expected_starts = {record["start_rva"] for record in truth}
        expected_ranges = {(record["start_rva"], record["end_rva"])
                           for record in truth}
        values = {
            "starts": [len(predicted_starts & expected_starts),
                       len(predicted_starts - expected_starts),
                       len(expected_starts - predicted_starts)],
            "ranges": [len(predicted_ranges & expected_ranges),
                       len(predicted_ranges - expected_ranges),
                       len(expected_ranges - predicted_ranges)],
        }
        for metric_name, counts in values.items():
            target = groups[case["symbol_class"]][metric_name]
            for index, count in enumerate(counts):
                target[index] += count
        per_case.append({
            "id": sample_id,
            "symbol_class": case["symbol_class"],
            "toolchain": case["toolchain"],
            "binary_kind": case["binary_kind"],
            "optimization": case["optimization"],
            "input_sha256": case["input_sha256"],
            "pdb_sha256": case.get("pdb_sha256"),
            "starts": prf_counts(*values["starts"]),
            "ranges": prf_counts(*values["ranges"]),
        })
    grouped = {}
    for symbol_class, metrics in groups.items():
        grouped[symbol_class] = {}
        threshold_set = baseline["thresholds"][symbol_class]
        for metric_name, counts in metrics.items():
            result = prf_counts(*counts)
            for measure_name in ("precision", "recall"):
                threshold_key = "min_" + measure_name
                threshold = threshold_set[metric_name][threshold_key]
                value = result[measure_name]["value"]
                require(value is not None and value + 1e-12 >= threshold,
                        f"Gate 5 boundary regression: {symbol_class} {metric_name} {measure_name}={value} < {threshold}")
            grouped[symbol_class][metric_name] = result
    return {"ground_truth_policy": baseline["method"],
            "baseline_thresholds": baseline["thresholds"],
            "grouped_metrics": grouped, "cases": per_case}


def summarize_type_metrics(phase4_results, phase4_truth):
    result = {
        "primary_aggregate": phase4_results["primary_aggregate"],
        "held_out_aggregate": phase4_results["held_out_aggregate"],
        "held_out_confidence_calibration": phase4_results["held_out_confidence_calibration"],
        "unknown_policy": phase4_results["type_unknown_policy"],
        "source_sha256": phase4_results["source_sha256"],
        "thresholds": phase4_results["thresholds"],
    }
    for split in ("primary", "held_out"):
        aggregate = result[f"{split}_aggregate"]
        for metric_name in ("signature_metrics", "parameter_type_metrics", "return_type_metrics"):
            for measure in ("precision", "recall"):
                key = f"minimum_{split}_{metric_name.removesuffix('_metrics')}_{measure}"
                threshold = phase4_truth.get(key)
                if threshold is None:
                    continue
                value = aggregate[metric_name][measure]
                require(value is not None and value + 1e-12 >= threshold,
                        f"Gate 5 type/signature regression: {key} threshold not met")
    ece = result["held_out_confidence_calibration"]["expected_calibration_error"]
    require(ece <= phase4_truth["maximum_held_out_expected_calibration_error"],
            "Gate 5 held-out confidence calibration exceeds its Gate 4 maximum")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--program", required=True, type=pathlib.Path)
    parser.add_argument("--corpus", required=True, type=pathlib.Path)
    parser.add_argument("--phase2-manifest", required=True, type=pathlib.Path)
    parser.add_argument("--phase2-baseline", required=True, type=pathlib.Path)
    parser.add_argument("--phase4-ground-truth", required=True, type=pathlib.Path)
    parser.add_argument("--phase4-results", required=True, type=pathlib.Path)
    parser.add_argument("--release-baseline", required=True, type=pathlib.Path)
    parser.add_argument("--schema", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()

    zero_denominator = ratio(0, 0)
    require(zero_denominator["value"] is None and
            zero_denominator["status"] == "not_measurable",
            "zero-denominator metrics must remain explicitly not_measurable")
    canonical_reference_hash = hashlib.sha256(b"reference\tvalue\n").hexdigest()
    require(normalized_sha256_bytes(b"reference\tvalue\r\n", "CRLF_TO_LF") ==
            canonical_reference_hash,
            "CRLF-to-LF reference identity normalization failed")

    corpus = json.loads(args.corpus.read_text(encoding="utf-8"))
    phase2_manifest = json.loads(args.phase2_manifest.read_text(encoding="utf-8"))
    phase2_baseline = json.loads(args.phase2_baseline.read_text(encoding="utf-8"))
    phase4_truth = json.loads(args.phase4_ground_truth.read_text(encoding="utf-8"))
    phase4_results = json.loads(args.phase4_results.read_text(encoding="utf-8"))
    release_baseline = json.loads(args.release_baseline.read_text(encoding="utf-8"))
    schema = json.loads(args.schema.read_text(encoding="utf-8"))
    require(corpus.get("format_version") == 1, "unsupported Phase 5 corpus format")
    require(phase2_manifest.get("format_version") == 1 and
            phase2_baseline.get("format_version") == 1,
            "unsupported Phase 2 baseline format")
    require(release_baseline.get("format_version") == 1,
            "unsupported previous-release baseline format")
    require(release_baseline.get("baseline_release_commit") ==
            corpus["baseline_release_commit"],
            "previous-release baseline commit does not match the corpus")
    validator = jsonschema.Draft202012Validator(schema)
    phase4_source_hash = hashlib.sha256(
        (args.phase4_ground_truth.parent.parent.parent /
         "fixtures/phase2/corpus.c").resolve().read_bytes().replace(b"\r\n", b"\n")).hexdigest()
    require(phase4_source_hash == phase4_truth["source_sha256"],
            "Phase 4 ground-truth source hash mismatch")
    require(phase2_manifest["source_sha256"] == phase4_truth["source_sha256"],
            "Phase 2 and Phase 4 source ground truths do not identify the same source")
    require(phase4_results["source_sha256"] == phase4_truth["source_sha256"],
            "Phase 4 result source identity mismatch")

    fixture_root = (args.corpus.parent / corpus["fixture_root"]).resolve()
    phase2_fixture_root = (args.phase2_manifest.parent /
                           phase2_manifest["fixture_root"]).resolve()
    samples_to_run = list(corpus["samples"])
    for case in phase2_manifest["cases"]:
        sample = {
            "id": case["id"], "source_kind": "compiler_generated_regression",
            "input": "phase2/" + case["input"], "input_sha256": case["input_sha256"],
            "pdb": ("phase2/" + case["pdb"]) if case.get("pdb") else None,
            "pdb_sha256": case.get("pdb_sha256"),
            "expected_pe": {"machine": 0x8664, "optional_header_magic": 0x20B,
                            "pe32_plus": True, "supported_x64_native": True,
                            "is_dll": case["binary_kind"] == "DLL"},
            "provenance": {
                "kind": "original NexussREV test source",
                "source": "phase2/" + phase2_manifest["source"],
                "source_sha256": phase2_manifest["source_sha256"],
                "source_hash_normalization": phase2_manifest["source_hash_normalization"],
                "compiler_and_linker": corpus["phase2_build_provenance"]["compiler_and_linker"],
                "compile_command": corpus["phase2_build_provenance"]["compile_commands"][case["optimization"]],
                "link_command": corpus["phase2_build_provenance"]["link_commands"][case["binary_kind"].lower()],
                "compiler_settings": f"optimization={case['optimization']}; target=x86_64-pc-windows-msvc",
                "distribution": "original fixture source; no third-party code",
            },
            "expected_parse_status": "complete",
            "phase2_case": case,
        }
        samples_to_run.append(sample)
    sample_ids = [sample["id"] for sample in samples_to_run]
    require(len(sample_ids) == len(set(sample_ids)),
            "Phase 5 corpus contains duplicate sample identifiers")
    require(len(samples_to_run) >= corpus["gates"]["minimum_valid_sample_count"],
            "Phase 5 corpus has fewer valid samples than the declared minimum")
    require(len(phase2_manifest["cases"]) >=
            corpus["gates"]["minimum_labelled_boundary_case_count"],
            "Phase 5 corpus has fewer labelled boundary cases than the declared minimum")

    all_samples = []
    with tempfile.TemporaryDirectory(prefix="nexusrev-phase5-") as temporary:
        temp_root = pathlib.Path(temporary)
        for sample in samples_to_run:
            analyzed = evaluate_positive_sample(sample, fixture_root, args.program.resolve(),
                                                validator, temp_root)
            all_samples.append(analyzed)
        # The malformed sample is an expected, bounded rejection—not a successful parse.
        malformed_results = [evaluate_malformed_case(case, temp_root,
                                                      args.program.resolve())
                             for case in corpus["malformed_cases"]]

    release_cases = release_baseline["cases"]
    require(set(release_cases) == {sample["id"] for sample in all_samples},
            "previous-release baseline sample set differs from the current corpus")
    for sample in all_samples:
        expected = release_cases[sample["id"]]
        observed = release_baseline_projection(sample)
        if observed != expected:
            changed = [key for key in observed if observed[key] != expected.get(key)]
            allowed_semantic_improvement = (
                set(changed) == {"semantic"} and
                semantic_lift_improvement_only(observed["semantic"], expected["semantic"]))
            allowed_unwind_expansion = (
                set(changed) == {"function_boundaries", "semantic"} and
                unwind_boundary_expansion_only(sample, observed, expected) and
                unwind_semantic_expansion_only(observed["semantic"], expected["semantic"]))
            if not allowed_semantic_improvement and not allowed_unwind_expansion:
                raise GateError(f"{sample['id']}: unexplained Phase 4 release regression in {changed}")

    # The boundary scoring records need not be duplicated into the public metric output.
    boundary = summarize_boundary_metrics(
        all_samples, phase2_manifest, phase2_fixture_root, phase2_baseline)
    type_metrics = summarize_type_metrics(phase4_results, phase4_truth)

    parse_counts = Counter(sample["parse_status"] for sample in all_samples)
    expected_parse_conformance = len(all_samples) + len(malformed_results)
    parse_success_metric = ratio(parse_counts["complete"], len(all_samples))
    require(parse_success_metric["value"] is not None and
            parse_success_metric["value"] >= corpus["gates"]["minimum_valid_pe_parse_success"],
            "one or more valid corpus PE files did not meet the parse-success floor")
    parse_conformance = ratio(len(all_samples) + len(malformed_results),
                              expected_parse_conformance)
    require(parse_conformance["value"] is not None and
            parse_conformance["value"] >= corpus["gates"]["minimum_parse_outcome_conformance"],
            "valid and negative input parse outcomes failed the declared conformance floor")

    executable_bytes = sum(item["decode"]["executable_file_backed_bytes"]
                           for item in all_samples)
    decoded_bytes = sum(item["decode"]["decoded_bytes"] for item in all_samples)
    decode_coverage = ratio(decoded_bytes, executable_bytes)
    cfg_edge_count = sum(item["semantic"]["cfg_edge_count"] for item in all_samples)
    cfg_consistent = sum(item["semantic"]["cfg_edges_consistent"] for item in all_samples)
    cfg_consistency = ratio(cfg_consistent, cfg_edge_count)
    require(cfg_consistency["value"] is not None,
            "CFG edge consistency cannot be measured: zero CFG edges in corpus")
    require(cfg_consistency["value"] >= corpus["gates"]["minimum_cfg_edge_consistency"],
            f"CFG edge consistency regression: {cfg_consistency['value']:.6f}")

    record_count = sum(item["function_boundaries"]["records_total"]
                       for item in all_samples)
    provenance_count = sum(item["function_boundaries"]["records_with_provenance"]
                           for item in all_samples)
    provenance_completeness = ratio(provenance_count, record_count)
    require(provenance_completeness["value"] is not None and
            provenance_completeness["value"] >= corpus["gates"]["minimum_symbol_provenance_completeness"],
            "one or more recovered function records lacks evidence provenance")

    semantic_instruction_count = sum(item["semantic"]["instruction_count"]
                                     for item in all_samples)
    unsupported_instruction_count = sum(item["semantic"]["unsupported_instruction_count"]
                                        for item in all_samples)
    unresolved_flow_count = sum(item["semantic"]["unresolved_flow_instruction_count"]
                                for item in all_samples)
    flow_instruction_count = sum(item["semantic"]["flow_instruction_count"]
                                  for item in all_samples)
    unresolved_edge_count = sum(item["semantic"]["unresolved_cfg_edge_count"]
                                for item in all_samples)
    output_complete_count = sum(item["artifact_completeness"]["numerator"] == 2 and
                                item["report_schema_valid"] for item in all_samples)
    output_completeness = ratio(output_complete_count, len(all_samples))
    require(output_completeness["value"] is not None and
            output_completeness["value"] >= corpus["gates"]["minimum_output_completeness"],
            "one or more analysis reports/artifact pairs is incomplete")

    reference_samples = [item for item in all_samples
                         if item["reference_backend"]["status"] != "not_configured"]
    reference_report = {
        "compared_sample_count": len(reference_samples),
        "samples": [{"id": item["id"], **item["reference_backend"]}
                    for item in reference_samples],
        "total_difference_count": sum(item["reference_backend"]["difference_count"]
                                       for item in reference_samples),
    }
    for item in reference_samples:
        expected = next(sample for sample in samples_to_run if sample["id"] == item["id"])
        expected_tool = expected.get("expected_reference_tool")
        expected_version = expected.get("expected_reference_version")
        require(item["reference_backend"]["status"] == "compared",
                f"{item['id']}: reference backend did not produce a comparable result")
        require(item["reference_backend"]["difference_count"] <=
                expected.get("maximum_reference_differences", 0),
                f"{item['id']}: reference difference count exceeds its declared maximum")
        require(not expected_tool or item["reference_backend"]["tool"] == expected_tool,
                f"{item['id']}: unexpected reference tool")
        require(not expected_version or item["reference_backend"]["version"] == expected_version,
                f"{item['id']}: unexpected reference tool version")

    sqlite_sample = next(item for item in all_samples if item["id"] == "sqlite-win-x64-3.54.0")
    minimum_sqlite_coverage = corpus["gates"]["minimum_sqlite_decode_coverage"]
    require(sqlite_sample["decode_coverage"]["value"] is not None and
            sqlite_sample["decode_coverage"]["value"] >= minimum_sqlite_coverage,
            "SQLite release decode coverage is below the pinned Phase 5 floor")
    require(reference_report["total_difference_count"] ==
            corpus["gates"]["maximum_reference_differences"],
            "reference-backend difference threshold failed")

    valid_parse_counts = {name: parse_counts.get(name, 0)
                          for name in ("complete", "partial", "unsupported", "failed")}
    safe_samples = []
    for item in all_samples:
        copy = dict(item)
        copy.pop("_boundary_records", None)
        safe_samples.append(copy)

    result = {
        "format_version": corpus["format_version"],
        "gate": "Phase 5 / Gate 5",
        "baseline_release_commit": corpus["baseline_release_commit"],
        "previous_release_comparison": {
            "baseline_release_commit": release_baseline["baseline_release_commit"],
            "status": "matched",
            "compared_sample_count": len(all_samples),
            "comparison_policy": "Exact comparison of pinned input identities, stage statuses, decode accounting, function recovery counts/provenance, reference state, tool versions, dependency versions, and semantic/CFG results, except that semantic lifting may only decrease the unsupported-instruction count and its exactly derived rate while every other semantic/CFG field remains identical.",
        },
        "corpus": corpus["name"],
        "scope": corpus["scope"],
        "method": corpus["method"],
        "static_only": True,
        "fixture_count": len(all_samples),
        "negative_case_count": len(malformed_results),
        "reproducibility": {
            "analyzer_command_template": corpus["analyzer_command_template"],
            "toolchain_provenance": corpus["phase2_build_provenance"],
            "official_binary_provenance": corpus["samples"][0]["provenance"],
            "source_urls": corpus["source_urls"],
            "build_configuration": {
                "nexusrev": all_samples[0]["tool"],
                "dependencies": all_samples[0]["dependencies"],
            },
        },
        "metrics": {
            "parse_status": {
                "valid_input_counts_by_status": valid_parse_counts,
                "valid_pe_parse_success": parse_success_metric,
                "valid_and_negative_case_conformance": parse_conformance,
                "negative_cases": malformed_results,
                "unknown_policy": "Any missing report, timeout, or unclassified status is a test failure; malformed expected failures are tested by exit code, diagnostic, and absence of success artifacts.",
            },
            "executable_byte_decode_coverage": {
                "metric": decode_coverage,
                "decoded_bytes": decoded_bytes,
                "executable_file_backed_bytes": executable_bytes,
                "limit_excluded_bytes": sum(item["decode"]["limited_bytes"] for item in all_samples),
                "unknown_policy": "A zero executable-byte denominator is not_measurable (null), never 1.0; failed or unsupported inputs are not counted as successful decodes.",
            },
            "candidate_boundary_precision_recall": boundary,
            "cfg_edge_consistency": {
                "metric": cfg_consistency,
                "edge_count": cfg_edge_count,
                "consistent_edge_count": cfg_consistent,
                "unknown_policy": "A corpus with no CFG edges yields not_measurable (null) and fails the Gate 5 nonempty-evidence requirement.",
            },
            "unresolved_instructions_and_edges": {
                "semantic_instruction_count": semantic_instruction_count,
                "unsupported_instruction_count": unsupported_instruction_count,
                "unsupported_instruction_rate": ratio(unsupported_instruction_count,
                                                        semantic_instruction_count),
                "flow_instruction_count": flow_instruction_count,
                "unresolved_flow_instruction_count": unresolved_flow_count,
                "unresolved_flow_instruction_rate": ratio(unresolved_flow_count,
                                                            flow_instruction_count),
                "unresolved_cfg_edge_count": unresolved_edge_count,
                "unresolved_control_flow_reported_count": sum(
                    item["semantic"]["unresolved_control_flow_count"] for item in all_samples),
                "unknown_policy": "Counts and rates are both retained. A zero denominator is explicitly not_measurable; unresolved items are not omitted from totals.",
            },
            "symbol_provenance": {
                "metric": provenance_completeness,
                "recovered_function_records": record_count,
                "records_with_nonempty_evidence": provenance_count,
                "unknown_policy": "A zero record denominator is not_measurable and cannot satisfy a positive provenance gate.",
            },
            "type_and_signature_accuracy": type_metrics,
            "reference_backend": reference_report,
            "output_completeness": {
                "metric": output_completeness,
                "complete_reports": output_complete_count,
                "reports_checked_against_schema": len(all_samples),
                "expected_artifacts_per_report": 2,
                "unknown_policy": "Each report must validate against the versioned JSON Schema and both declared output files must exist at the declared paths.",
            },
        },
        "baseline_thresholds": corpus["gates"],
        "samples": safe_samples,
        "limitations": corpus["limitations"],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    print(json.dumps({
        "output": str(args.output),
        "fixture_count": len(all_samples),
        "parse_success": parse_success_metric,
        "decoded_byte_coverage": decode_coverage,
        "cfg_edge_consistency": cfg_consistency,
        "symbol_provenance": provenance_completeness,
        "artifact_completeness": output_completeness,
        "boundary_groups": sorted(boundary["grouped_metrics"]),
        "reference_differences": reference_report["total_difference_count"],
    }, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (GateError, OSError, KeyError, ValueError, json.JSONDecodeError) as error:
        print(f"Gate 5 validation failed: {error}", file=sys.stderr)
        raise SystemExit(1)
