#!/usr/bin/env python3
"""Gate 4 metrics over hash-identified PE fixtures; samples are analyzed, never executed."""

import argparse
import hashlib
import json
import pathlib
import subprocess
import tempfile


def metric(tp, fp, fn):
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {"true_positive": tp, "false_positive": fp, "false_negative": fn,
            "precision": precision, "recall": recall}


def location_key(function_name, parameter):
    if parameter.get("location") == "register":
        return (function_name, int(parameter["index"]), "register", parameter.get("register", ""))
    return (function_name, int(parameter["index"]), "stack", parameter.get("stack_offset"))


def evaluate_sample(program, fixture_root, sample, temp_root):
    sample_path = (fixture_root / sample["input"]).resolve()
    actual_hash = hashlib.sha256(sample_path.read_bytes()).hexdigest()
    if actual_hash != sample["input_sha256"]:
        raise AssertionError(f"fixture identity mismatch for {sample['id']}: {actual_hash}")
    output = temp_root / f"{sample['id']}.txt"
    completed = subprocess.run([str(program), str(sample_path), str(output)], capture_output=True,
                           text=True, check=False, timeout=30)
    if completed.returncode != 0:
        raise AssertionError(f"analysis failed for {sample['id']}: {completed.stderr}")
    report_path = pathlib.Path(str(output) + ".report.json")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if report["input"]["sha256"] != sample["input_sha256"]:
        raise AssertionError(f"analyzer input hash mismatch for {sample['id']}")
    signatures = report["dataflow_analysis"]["signatures"]
    predicted_by_name = {item["label"]: item for item in signatures if item["label"]}
    expected_locations = set()
    predicted_locations = set()
    expected_types = set()
    predicted_types = set()
    expected_returns = set()
    predicted_returns = set()
    calibration_predictions = []
    expected_names = {item["name"] for item in sample["functions"]}
    for function in sample["functions"]:
        name = function["name"]
        expected_signature = {location_key(name, parameter) for parameter in function["parameters"]}
        expected_locations.update(expected_signature)
        for parameter in function["parameters"]:
            expected_types.add((name, int(parameter["index"]), parameter["type"]))
        expected_returns.add((name, function["return_type"]))
        prediction = predicted_by_name.get(name)
        if prediction is None:
            continue
        for parameter in prediction["parameters"]:
            key = location_key(name, parameter)
            predicted_locations.add(key)
            if parameter.get("type") not in (None, "", "unknown"):
                predicted_types.add((name, int(parameter["index"]), parameter["type"]))
            if sample["held_out"]:
                calibration_predictions.append({
                    "confidence": float(parameter["confidence"]),
                    "correct": key in expected_signature,
                    "fact": f"{name}:arg{parameter['index']}:{parameter.get('register') or parameter.get('stack_offset')}"
                })
        if prediction.get("return_type") not in (None, "", "unknown"):
            predicted_returns.add((name, prediction["return_type"]))
    for name, prediction in predicted_by_name.items():
        if name in expected_names:
            continue
        for parameter in prediction["parameters"]:
            predicted_locations.add(location_key(name, parameter))
            if parameter.get("type") not in (None, "", "unknown"):
                predicted_types.add((name, int(parameter["index"]), parameter["type"]))
        if prediction.get("return_type") not in (None, "", "unknown"):
            predicted_returns.add((name, prediction["return_type"]))
    return {
        "id": sample["id"], "input_sha256": actual_hash, "held_out": sample["held_out"],
        "signature_metrics": metric(len(expected_locations & predicted_locations),
                                     len(predicted_locations - expected_locations),
                                     len(expected_locations - predicted_locations)),
        "parameter_type_metrics": metric(len(expected_types & predicted_types),
                                          len(predicted_types - expected_types),
                                          len(expected_types - predicted_types)),
        "return_type_metrics": metric(len(expected_returns & predicted_returns),
                                       len(predicted_returns - expected_returns),
                                       len(expected_returns - predicted_returns)),
        "ground_truth_signature_facts": len(expected_locations),
        "predicted_signature_facts": len(predicted_locations),
        "ground_truth_parameter_type_facts": len(expected_types),
        "predicted_parameter_type_facts": len(predicted_types),
        "held_out_predictions": calibration_predictions,
    }


def aggregate(sample_results, metric_name):
    fields = ("true_positive", "false_positive", "false_negative")
    values = {field: sum(item[metric_name][field] for item in sample_results) for field in fields}
    return metric(values["true_positive"], values["false_positive"], values["false_negative"])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--program", required=True, type=pathlib.Path)
    parser.add_argument("--ground-truth", required=True, type=pathlib.Path)
    parser.add_argument("--fixtures", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    ground_truth = json.loads(args.ground_truth.read_text(encoding="utf-8"))
    primary = []
    held_out = []
    with tempfile.TemporaryDirectory(prefix="nexusrev-phase4-") as temp:
        temp_root = pathlib.Path(temp)
        for sample in ground_truth["samples"]:
            result = evaluate_sample(args.program.resolve(), args.fixtures.resolve(), sample, temp_root)
            (held_out if sample["held_out"] else primary).append(result)
        # Validate that the new CLI mode publishes a labelled pseudocode artifact.
        sample = ground_truth["samples"][0]
        sample_path = (args.fixtures / sample["input"]).resolve()
        pseudocode_path = temp_root / "phase4-pseudocode.txt"
        pseudocode = subprocess.run([str(args.program.resolve()), "--format", "pseudocode",
                                     str(sample_path), str(pseudocode_path)], capture_output=True,
                                    text=True, check=False, timeout=30)
        if pseudocode.returncode != 0:
            raise AssertionError(f"pseudocode output failed: {pseudocode.stderr}")
        pseudocode_text = pseudocode_path.read_text(encoding="utf-8")
        required_disclaimers = ("best-effort C-like pseudocode", "not original source", "not guaranteed compilable")
        if not all(text in pseudocode_text for text in required_disclaimers):
            raise AssertionError("pseudocode output is missing a required limitation label")

    predictions = [prediction for item in held_out for prediction in item["held_out_predictions"]]
    if predictions:
        brier = sum((item["confidence"] - float(item["correct"])) ** 2 for item in predictions) / len(predictions)
        bins = []
        edges = (0.0, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0000001)
        for low, high in zip(edges, edges[1:]):
            values = [item for item in predictions if low <= item["confidence"] < high]
            if not values:
                continue
            bins.append({"lower_bound": low, "upper_bound": high,
                         "count": len(values),
                         "mean_confidence": sum(item["confidence"] for item in values) / len(values),
                         "empirical_accuracy": sum(item["correct"] for item in values) / len(values)})
        ece = sum(item["count"] / len(predictions) * abs(item["mean_confidence"] - item["empirical_accuracy"])
                  for item in bins)
    else:
        brier = 0.0
        bins = []
        ece = 0.0
    result = {
        "format_version": 1,
        "gate": "Phase 4 / Gate 4",
        "method": "Analyze hash-verified PE/PDB fixtures as data; compare emitted ABI/type facts to source-derived truth; calibrate signature confidence on the held-out optimized fixture.",
        "source_sha256": ground_truth["source_sha256"],
        "primary_samples": primary,
        "primary_aggregate": {
            "signature_metrics": aggregate(primary, "signature_metrics"),
            "parameter_type_metrics": aggregate(primary, "parameter_type_metrics"),
            "return_type_metrics": aggregate(primary, "return_type_metrics"),
        },
        "held_out_samples": held_out,
        "held_out_aggregate": {
            "signature_metrics": aggregate(held_out, "signature_metrics"),
            "parameter_type_metrics": aggregate(held_out, "parameter_type_metrics"),
            "return_type_metrics": aggregate(held_out, "return_type_metrics"),
        },
        "held_out_confidence_calibration": {
            "prediction_count": len(predictions),
            "mean_confidence": sum(item["confidence"] for item in predictions) / len(predictions) if predictions else 0.0,
            "empirical_accuracy": sum(item["correct"] for item in predictions) / len(predictions) if predictions else 0.0,
            "brier_score": brier,
            "expected_calibration_error": ece,
            "bins": bins,
            "maximum_expected_calibration_error": ground_truth["maximum_held_out_expected_calibration_error"],
        },
        "type_unknown_policy": ground_truth["metric_policy"]["unknown_policy"],
        "pseudocode_label_validation": "passed",
        "limitations": [
            "Type precision/recall is scored only for the source-labelled PDB fixture; unknown predictions remain false negatives.",
            "The held-out set contains one optimized compiler fixture family and is a calibration check, not a broad generalization claim.",
            "No fixture executable was launched."
        ]
    }
    threshold_keys = [key for key in ground_truth if key.startswith("minimum_") or key == "maximum_held_out_expected_calibration_error"]
    result["thresholds"] = {key: ground_truth[key] for key in threshold_keys}
    for split_name, metrics in (("primary", result["primary_aggregate"]), ("held_out", result["held_out_aggregate"])):
        for metric_name, metric_result in metrics.items():
            for measure in ("precision", "recall"):
                threshold_key = f"minimum_{split_name}_{metric_name.removesuffix('_metrics')}_{measure}"
                threshold = ground_truth.get(threshold_key)
                if threshold is not None and metric_result[measure] < threshold:
                    raise AssertionError(f"{split_name} {metric_name} {measure} {metric_result[measure]:.3f} is below {threshold_key}={threshold}")
    if result["held_out_confidence_calibration"]["expected_calibration_error"] > ground_truth["maximum_held_out_expected_calibration_error"]:
        raise AssertionError("held-out confidence calibration error exceeds the declared Gate 4 maximum")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output),
                      "primary_signature": result["primary_aggregate"]["signature_metrics"],
                      "primary_parameter_type": result["primary_aggregate"]["parameter_type_metrics"],
                      "held_out_signature": result["held_out_aggregate"]["signature_metrics"],
                      "confidence_ece": result["held_out_confidence_calibration"]["expected_calibration_error"]}, indent=2))


if __name__ == "__main__":
    main()
