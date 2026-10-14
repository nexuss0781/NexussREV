#!/usr/bin/env python3
"""Compute Gate 2 exact-start and exact-range metrics over the checked-in corpus."""
import argparse
import hashlib
import json
import pathlib
import subprocess
import tempfile


def prf(predictions, truth):
    predictions = set(predictions)
    truth = set(truth)
    true_positive = len(predictions & truth)
    false_positive = len(predictions - truth)
    false_negative = len(truth - predictions)
    precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 0.0
    recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else 0.0
    return {
        "true_positive": true_positive,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "precision": precision,
        "recall": recall,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--program", required=True, type=pathlib.Path)
    parser.add_argument("--manifest", required=True, type=pathlib.Path)
    parser.add_argument("--baseline", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
    if manifest.get("format_version") != 1 or baseline.get("format_version") != 1:
        raise SystemExit("unsupported benchmark corpus/baseline format")
    fixture_root = (args.manifest.parent / manifest["fixture_root"]).resolve()
    source_path = fixture_root / manifest["source"]
    source_sha256 = hashlib.sha256(source_path.read_bytes()).hexdigest()
    if source_sha256 != manifest["source_sha256"]:
        raise SystemExit(f"source hash mismatch: expected {manifest['source_sha256']}, got {source_sha256}")
    results = []
    for case in manifest["cases"]:
        truth = manifest["truth_sets"][case["truth_set"]]
        input_path = fixture_root / case["input"]
        if not input_path.is_file():
            raise SystemExit(f"missing fixture {input_path}")
        input_sha256 = hashlib.sha256(input_path.read_bytes()).hexdigest()
        if input_sha256 != case["input_sha256"]:
            raise SystemExit(f"{case['id']}: input SHA-256 mismatch")
        with tempfile.TemporaryDirectory(prefix="nexusrev-gate2-") as temporary:
            output = pathlib.Path(temporary) / "analysis.disasm"
            command = [str(args.program), str(input_path)]
            if case.get("pdb"):
                pdb_path = fixture_root / case["pdb"]
                if not pdb_path.is_file():
                    raise SystemExit(f"missing PDB fixture {pdb_path}")
                pdb_sha256 = hashlib.sha256(pdb_path.read_bytes()).hexdigest()
                if pdb_sha256 != case["pdb_sha256"]:
                    raise SystemExit(f"{case['id']}: PDB SHA-256 mismatch")
                command.extend(["--pdb", str(pdb_path)])
            else:
                pdb_sha256 = None
            command.append(str(output))
            completed = subprocess.run(command, capture_output=True, text=True, check=False, timeout=25)
            if completed.returncode != 0:
                raise SystemExit(f"analysis failed for {case['id']}: {completed.stderr}")
            report = json.loads(pathlib.Path(str(output) + ".report.json").read_text(encoding="utf-8"))
        expected_symbol_status = case["expected_symbols"]
        if report["symbols"]["status"] != expected_symbol_status:
            raise SystemExit(f"{case['id']}: expected symbol state {expected_symbol_status}, got {report['symbols']['status']}")
        records = []
        recovery = report["function_recovery"]
        for name in ("known_functions", "candidate_functions", "fragments"):
            records.extend(recovery[name])
        starts = {record["start_rva"] for record in records}
        ranges = {(record["start_rva"], record["end_rva"]) for record in records if record["end_rva"] is not None}
        truth_starts = {record["start_rva"] for record in truth}
        truth_ranges = {(record["start_rva"], record["end_rva"]) for record in truth}
        results.append({
            "id": case["id"],
            "symbol_class": case["symbol_class"],
            "toolchain": case["toolchain"],
            "binary_kind": case["binary_kind"],
            "optimization": case["optimization"],
            "symbol_status": report["symbols"]["status"],
            "input_sha256": input_sha256,
            "pdb_sha256": pdb_sha256,
            "tool_version": report["tool"]["version"],
            "function_starts": prf(starts, truth_starts),
            "function_ranges": prf(ranges, truth_ranges),
        })
    grouped = {}
    for symbol_class in sorted({case["symbol_class"] for case in results}):
        selected = [item for item in results if item["symbol_class"] == symbol_class]
        for item in selected:
            # Add per-case counts so equal RVAs from separate binaries never collapse together.
            st = item["function_starts"]
            rg = item["function_ranges"]
            grouped.setdefault(symbol_class, {"starts": [0, 0, 0], "ranges": [0, 0, 0]})
            grouped[symbol_class]["starts"][0] += st["true_positive"]
            grouped[symbol_class]["starts"][1] += st["false_positive"]
            grouped[symbol_class]["starts"][2] += st["false_negative"]
            grouped[symbol_class]["ranges"][0] += rg["true_positive"]
            grouped[symbol_class]["ranges"][1] += rg["false_positive"]
            grouped[symbol_class]["ranges"][2] += rg["false_negative"]
    grouped_metrics = {}
    for symbol_class, totals in grouped.items():
        grouped_metrics[symbol_class] = {}
        for metric_name in ("starts", "ranges"):
            tp, fp, fn = totals[metric_name]
            grouped_metrics[symbol_class][metric_name] = {
                "true_positive": tp,
                "false_positive": fp,
                "false_negative": fn,
                "precision": tp / (tp + fp) if tp + fp else 0.0,
                "recall": tp / (tp + fn) if tp + fn else 0.0,
            }
    for symbol_class, threshold_set in baseline["thresholds"].items():
        if symbol_class not in grouped_metrics:
            raise SystemExit(f"baseline category {symbol_class} has no corpus cases")
        for metric_name in ("starts", "ranges"):
            actual = grouped_metrics[symbol_class][metric_name]
            threshold = threshold_set[metric_name]
            for key in ("min_precision", "min_recall"):
                value_name = key.removeprefix("min_")
                if actual[value_name] + 1e-12 < threshold[key]:
                    raise SystemExit(
                        f"Gate 2 threshold failed: {symbol_class} {metric_name} {value_name}="
                        f"{actual[value_name]:.3f} < {threshold[key]:.3f}"
                    )
    result = {
        "benchmark_version": manifest["format_version"],
        "baseline_version": baseline["format_version"],
        "tool_version": baseline["tool_version"],
        "source_sha256": source_sha256,
        "corpus": manifest["name"],
        "case_count": len(results),
        "grouped_metrics": grouped_metrics,
        "cases": results,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for symbol_class, metrics in grouped_metrics.items():
        print(f"{symbol_class}: starts precision={metrics['starts']['precision']:.3f} "
              f"recall={metrics['starts']['recall']:.3f}; ranges precision={metrics['ranges']['precision']:.3f} "
              f"recall={metrics['ranges']['recall']:.3f}")
    print(f"Gate 2 benchmark passed: {len(results)} labelled cases; report={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
