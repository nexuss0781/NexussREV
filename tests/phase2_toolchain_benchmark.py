#!/usr/bin/env python3
"""Build and measure Phase 2 fixtures with MSVC, clang-cl, or MinGW.

PE inputs are only written and parsed as data; this script never launches them.
"""
import argparse
import hashlib
import json
import pathlib
import re
import shutil
import struct
import subprocess
import tempfile


def run(command, *, cwd=None, check=True):
    completed = subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=False)
    if check and completed.returncode:
        details = (completed.stdout + "\n" + completed.stderr).strip()
        raise SystemExit(f"command failed ({completed.returncode}): {command!r}\n{details[-5000:]}")
    return completed


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_sha256(path):
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def get_version(command):
    for flag in ("--version", "/Bv", "/?"):
        result = run([command, flag], check=False)
        text = (result.stdout + "\n" + result.stderr).strip()
        if text:
            return text.splitlines()[0].strip()
    return "version unavailable"


def parse_dwarf_functions(objdump, image, image_base, source_functions):
    text = run([objdump, "--dwarf=info", "--wide", str(image)]).stdout
    functions = {}
    current = None

    def finish():
        if not current or not current.get("name") or "low_pc" not in current or "high_pc" not in current:
            return
        name = current["name"]
        if name not in source_functions:
            return
        low = current["low_pc"]
        high = current["high_pc"]
        # GCC emits DW_AT_high_pc as a constant size (DWARF 4/5); tolerate
        # producers that emit an absolute address as well.
        end = high if high > low else low + high
        if low < image_base or end <= low:
            return
        functions[name] = {"name": name, "start_rva": low - image_base, "end_rva": end - image_base}

    for line in text.splitlines():
        if "DW_TAG_subprogram" in line:
            finish()
            current = {}
            continue
        if current is None:
            continue
        if "DW_AT_name" in line and "name" not in current:
            value = line.split(":", 1)[-1].strip()
            # Objdump may include a string-table annotation before the name.
            pattern = r"\b(" + "|".join(map(re.escape, sorted(source_functions))) + r")\b"
            match = re.search(pattern, value)
            if match:
                current["name"] = match.group(1)
        for attribute, field in (("DW_AT_low_pc", "low_pc"), ("DW_AT_high_pc", "high_pc")):
            if attribute in line:
                match = re.search(r"0x([0-9a-fA-F]+)", line.split(":", 1)[-1])
                if match:
                    current[field] = int(match.group(1), 16)
    finish()
    if set(functions) != source_functions:
        raise SystemExit(f"MinGW DWARF labels are incomplete in {image}: {sorted(functions)}")
    return sorted(functions.values(), key=lambda item: item["start_rva"])


def records_from_report(report):
    records = []
    recovery = report["function_recovery"]
    for group in ("known_functions", "candidate_functions", "fragments"):
        records.extend(recovery[group])
    starts = {record["start_rva"] for record in records}
    ranges = {(record["start_rva"], record["end_rva"]) for record in records if record["end_rva"] is not None}
    return starts, ranges


def metrics(predictions, truth):
    predicted = set(predictions)
    expected = set(truth)
    tp, fp, fn = len(predicted & expected), len(predicted - expected), len(expected - predicted)
    return {
        "true_positive": tp,
        "false_positive": fp,
        "false_negative": fn,
        "precision": tp / (tp + fp) if tp + fp else 0.0,
        "recall": tp / (tp + fn) if tp + fn else 0.0,
    }


def strip_pe_directories(source, destination):
    data = bytearray(source.read_bytes())
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise SystemExit(f"not an MZ PE: {source}")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise SystemExit(f"truncated PE header: {source}")
    optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    optional = pe_offset + 24
    if optional + optional_size > len(data) or struct.unpack_from("<H", data, optional)[0] != 0x20B:
        raise SystemExit(f"expected a complete PE32+ optional header: {source}")
    directory_count = struct.unpack_from("<I", data, optional + 108)[0]
    directories = optional + 112
    for index in (0, 6):  # export and debug/CodeView
        offset = directories + index * 8
        if index < directory_count and offset + 8 <= optional + optional_size:
            struct.pack_into("<II", data, offset, 0, 0)
    destination.write_bytes(data)


def analyze(program, image, output_dir, pdb=None):
    output = output_dir / (image.stem + ".disasm")
    command = [str(program)]
    if pdb is not None:
        command.extend(["--pdb", str(pdb)])
    command.extend([str(image), str(output)])
    completed = run(command, check=False)
    if completed.returncode:
        raise SystemExit(f"analysis failed for {image}: {completed.stderr[-4000:]}")
    report_path = pathlib.Path(str(output) + ".report.json")
    return json.loads(report_path.read_text(encoding="utf-8"))


def build_msvc_fixture(compiler, linker, source, work, profile, binary_kind):
    optimization = "/Od" if profile == "O0" else "/O2"
    obj = work / f"msvc-{profile}.obj"
    compile_pdb = work / f"msvc-{profile}-compile.pdb"
    run([compiler, "/nologo", "/TC", "/c", "/Zi", optimization, "/Ob0",
         f"/Fo{obj}", f"/Fd{compile_pdb}", str(source)])
    stem = f"msvc-{profile}-{binary_kind.lower()}"
    suffix = ".dll" if binary_kind == "DLL" else ".exe"
    image, pdb = work / f"{stem}{suffix}", work / f"{stem}.pdb"
    common = [linker, "/NOLOGO", "/DEBUG:FULL", f"/PDB:{pdb}", f"/OUT:{image}",
              "/INCREMENTAL:NO", "/OPT:NOREF", "/OPT:NOICF", "/NODEFAULTLIB"]
    if binary_kind == "DLL":
        common.extend(["/DLL", "/NOENTRY"])
    else:
        common.extend(["/ENTRY:add_one", "/NODEFAULTLIB", "/SUBSYSTEM:CONSOLE"])
    run(common + [str(obj)])
    return image, pdb


def build_clang_cl_fixture(compiler, linker, source, work, profile, binary_kind):
    optimization = "/Od" if profile == "O0" else "/O2"
    obj = work / f"clang-cl-{profile}.obj"
    compile_pdb = work / f"clang-cl-{profile}-compile.pdb"
    run([compiler, "/nologo", "/TC", "/c", "/Zi", optimization, "/Ob0",
         f"/Fo{obj}", f"/Fd{compile_pdb}", str(source)])
    stem = f"clang-cl-{profile}-{binary_kind.lower()}"
    suffix = ".dll" if binary_kind == "DLL" else ".exe"
    image, pdb = work / f"{stem}{suffix}", work / f"{stem}.pdb"
    common = [linker, "/NOLOGO", "/DEBUG", f"/PDB:{pdb}", f"/OUT:{image}",
              "/INCREMENTAL:NO", "/OPT:NOREF", "/OPT:NOICF", "/NODEFAULTLIB"]
    if binary_kind == "DLL":
        common.extend(["/DLL", "/NOENTRY"])
    else:
        common.extend(["/ENTRY:add_one", "/NODEFAULTLIB", "/SUBSYSTEM:CONSOLE"])
    run(common + [str(obj)])
    return image, pdb


def build_mingw_fixture(compiler, source, work, profile, binary_kind):
    optimization = "-O0" if profile == "O0" else "-O2"
    obj = work / f"mingw-{profile}.o"
    run([compiler, "-fms-extensions", "-ffunction-sections", "-fno-inline", "-g",
         optimization, "-c", str(source), "-o", str(obj)])
    stem = f"mingw-{profile}-{binary_kind.lower()}"
    image = work / (stem + (".dll" if binary_kind == "DLL" else ".exe"))
    map_file = work / (stem + ".map")
    if binary_kind == "DLL":
        command = [compiler, "-nostdlib", "-shared", "-Wl,--entry,0", f"-Wl,-Map,{map_file}",
                   "-o", str(image), str(obj)]
    else:
        command = [compiler, "-nostdlib", "-Wl,--entry,add_one", "-Wl,--subsystem,console",
                   f"-Wl,-Map,{map_file}", "-o", str(image), str(obj)]
    run(command)
    return image, None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("msvc", "clang-cl", "mingw"), required=True)
    parser.add_argument("--program", type=pathlib.Path, required=True)
    parser.add_argument("--compiler", required=True)
    parser.add_argument("--linker", default="")
    parser.add_argument("--objdump", default="")
    parser.add_argument("--strip", default="")
    parser.add_argument("--matrix", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    program = args.program.resolve()
    output = args.output.resolve()
    matrix_path = args.matrix.resolve()
    matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
    if matrix.get("format_version") != 1:
        raise SystemExit("unsupported toolchain-matrix format")
    if args.mode not in matrix.get("toolchains", {}):
        raise SystemExit(f"toolchain mode {args.mode} is not declared in the matrix")
    if matrix.get("source_hash_normalization") != "CRLF_TO_LF":
        raise SystemExit("unsupported toolchain source-hash normalization policy")
    source = (matrix_path.parent / matrix["source"]).resolve()
    source_functions = set(matrix["source_functions"])
    if not source.is_file() or not program.is_file():
        raise SystemExit("source fixture or analyzer executable is missing")
    observed_source_hash = source_sha256(source)
    if observed_source_hash != matrix["source_sha256"]:
        raise SystemExit(f"source hash mismatch: expected {matrix['source_sha256']}, got {observed_source_hash}")
    output.parent.mkdir(parents=True, exist_ok=True)
    if args.mode in ("msvc", "clang-cl") and not args.linker:
        raise SystemExit("Windows compiler modes require --linker")
    if args.mode == "mingw" and (not args.objdump or not args.strip):
        raise SystemExit("MinGW mode requires --objdump and --strip")
    compiler_version = get_version(args.compiler)
    linker_version = get_version(args.linker) if args.linker else run([args.compiler, "-dumpversion"]).stdout.strip()
    results = []
    toolchain = matrix["toolchains"][args.mode]
    expected_symbols = {"msvc": "matched", "clang-cl": "matched", "mingw": "not_present"}[args.mode]
    with tempfile.TemporaryDirectory(prefix=f"nexusrev-{args.mode}-") as temporary:
        work = pathlib.Path(temporary)
        for profile in matrix["profiles"]:
            for binary_kind in matrix["binary_kinds"]:
                if args.mode == "msvc":
                    image, pdb = build_msvc_fixture(args.compiler, args.linker, source, work, profile, binary_kind)
                elif args.mode == "clang-cl":
                    image, pdb = build_clang_cl_fixture(args.compiler, args.linker, source, work, profile, binary_kind)
                else:
                    image, pdb = build_mingw_fixture(args.compiler, source, work, profile, binary_kind)
                if args.mode == "mingw":
                    truth_report = analyze(program, image, work)
                    truth = parse_dwarf_functions(args.objdump, image, truth_report["pe"]["image_base"], source_functions)
                else:
                    truth_report = analyze(program, image, work, pdb)
                    if truth_report["symbols"]["status"] != "matched":
                        raise SystemExit(f"{args.mode} {image.name}: matching PDB was not accepted")
                    truth = truth_report["symbols"]["functions"]
                    if not truth:
                        raise SystemExit(f"{args.mode} {image.name}: matching PDB has no supported procedure records")
                    if not source_functions.issubset({item["name"] for item in truth}):
                        raise SystemExit(f"{args.mode} {image.name}: PDB procedure labels do not cover the declared source functions")
                if args.mode == "mingw" and truth_report["symbols"]["status"] != "not_present":
                    raise SystemExit(f"MinGW {image.name}: unexpected PDB state {truth_report['symbols']['status']}")
                truth_starts = {item["start_rva"] for item in truth}
                truth_ranges = {(item["start_rva"], item["end_rva"]) for item in truth if item.get("end_rva") is not None}
                if not truth_starts or not truth_ranges:
                    raise SystemExit(f"{args.mode} {image.name}: ground truth has no bounded procedure ranges")
                variants = [("debug", image, expected_symbols)]
                stripped = work / (image.stem + "-stripped" + image.suffix)
                if args.mode == "mingw":
                    run([args.strip, "--strip-all", str(image), str(stripped)])
                else:
                    shutil.copyfile(image, stripped)
                strip_pe_directories(stripped, stripped)
                variants.append(("stripped", stripped, "not_present"))
                for variant_name, variant_image, symbol_status in variants:
                    report = truth_report if variant_name == "debug" else analyze(program, variant_image, work)
                    if report["symbols"]["status"] != symbol_status:
                        raise SystemExit(f"{args.mode} {variant_image.name}: expected symbol status {symbol_status}, got {report['symbols']['status']}")
                    starts, ranges = records_from_report(report)
                    result = {
                        "id": f"{args.mode}-{profile.lower()}-{binary_kind.lower()}-{variant_name}",
                        "compiler_mode": args.mode,
                        "compiler_version": compiler_version,
                        "linker_version": linker_version,
                        "binary_kind": binary_kind,
                        "optimization": profile,
                        "evidence_class": "pdb_present" if args.mode in ("msvc", "clang-cl") and variant_name == "debug" else ("dwarf_present_no_pdb" if args.mode == "mingw" and variant_name == "debug" else "stripped"),
                        "symbol_status": report["symbols"]["status"],
                        "input_sha256": sha256(variant_image),
                        "pdb_sha256": sha256(pdb) if pdb is not None and variant_name == "debug" else None,
                        "truth": truth,
                        "function_starts": metrics(starts, truth_starts),
                        "function_ranges": metrics(ranges, truth_ranges),
                    }
                    results.append(result)
    grouped = {}
    for item in results:
        category = item["evidence_class"]
        bucket = grouped.setdefault(category, {"starts": [0, 0, 0], "ranges": [0, 0, 0]})
        for metric_name, metric_result in (("starts", item["function_starts"]), ("ranges", item["function_ranges"])):
            for index, key in enumerate(("true_positive", "false_positive", "false_negative")):
                bucket[metric_name][index] += metric_result[key]
    grouped_metrics = {}
    for category, values in grouped.items():
        grouped_metrics[category] = {}
        for metric_name, counts in values.items():
            tp, fp, fn = counts
            grouped_metrics[category][metric_name] = {
                "true_positive": tp, "false_positive": fp, "false_negative": fn,
                "precision": tp / (tp + fp) if tp + fp else 0.0,
                "recall": tp / (tp + fn) if tp + fn else 0.0,
            }
    if len(results) != matrix["expected_cases_per_toolchain"]:
        raise SystemExit(f"matrix emitted {len(results)} cases, expected {matrix['expected_cases_per_toolchain']}")
    for category, threshold_set in matrix["thresholds"].items():
        if category not in grouped_metrics:
            continue
        for metric_name in ("starts", "ranges"):
            actual = grouped_metrics[category][metric_name]
            for threshold_name, threshold in threshold_set[metric_name].items():
                value_name = threshold_name.removeprefix("min_")
                if actual[value_name] + 1e-12 < threshold:
                    raise SystemExit(f"{args.mode} {category} {metric_name} {value_name}={actual[value_name]:.3f} < {threshold:.3f}")
    report = {
        "matrix_version": matrix["format_version"],
        "compiler_mode": args.mode,
        "compiler": toolchain["compiler"],
        "linker": toolchain["linker"],
        "truth_source": toolchain["truth_source"],
        "compiler_version": compiler_version,
        "linker_version": linker_version,
        "source_sha256": observed_source_hash,
        "fixture_source": matrix["source"],
        "case_count": len(results),
        "grouped_metrics": grouped_metrics,
        "cases": results,
    }
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for category, values in grouped_metrics.items():
        print(f"{args.mode}/{category}: starts P/R={values['starts']['precision']:.3f}/{values['starts']['recall']:.3f}; "
              f"ranges P/R={values['ranges']['precision']:.3f}/{values['ranges']['recall']:.3f}")
    print(f"Toolchain matrix complete: {len(results)} cases; report={output}")


if __name__ == "__main__":
    main()
