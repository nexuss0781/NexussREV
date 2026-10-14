#include "nexusrev.hpp"
#include "phase3.hpp"
#include "phase4.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <system_error>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace {

constexpr int kInvalidArguments = 2;
constexpr int kInputFailure = 3;
constexpr int kAnalysisFailure = 5;
constexpr int kOutputFailure = 6;
constexpr int kInternalFailure = 70;

struct CliOptions {
    std::string input_path;
    std::string output_path;
    std::string report_path;
    std::string pdb_path;
    std::string reference_report_path;
    std::string format = "disassembly";
};

void print_usage(std::ostream& output, const char* executable) {
    output << "Usage: " << executable
           << " [--format disassembly|pseudocode] [--report-json <path>] [--pdb <matching.pdb>] [--reference-report <ghidra.tsv>] <input.exe> <output>\n"
           << "       " << executable << " --help\n\n"
           << "The two-path form is the compatibility mode. Native PE32+ x86-64 receives bounded decode and function-boundary analysis.\n"
           << "A PDB is used only when its GUID and age match the PE CodeView identity; otherwise it is reported and ignored.\n"
           << "An optional Ghidra headless reference TSV can be supplied with --reference-report for differential checks.\n"
           << "Disassembly is the default; pseudocode is an incomplete C-like analysis view, not original source or guaranteed compilable.\n"
           << "Unsupported architectures and CLR/.NET images are identified, not decoded as x64. A JSON report is\n"
           << "written to <output>.report.json unless --report-json is specified.\n";
}

std::filesystem::path normalized_absolute_path(const std::string& value) {
    std::error_code filesystem_error;
    const std::filesystem::path absolute = std::filesystem::absolute(value, filesystem_error);
    return (filesystem_error ? std::filesystem::path(value) : absolute).lexically_normal();
}

bool parse_arguments(int argc, char** argv, CliOptions& options, bool& show_help,
                     std::string& error) {
    show_help = false;
    std::vector<std::string> positional;
    for (int index = 1; index < argc; ++index) {
        const std::string argument = argv[index];
        if (argument == "--help" || argument == "-h") {
            show_help = true;
            return true;
        }
        if (argument == "--format") {
            if (index + 1 >= argc) {
                error = "--format requires a value";
                return false;
            }
            options.format = argv[++index];
            if (options.format != "disassembly" && options.format != "pseudocode") {
                error = "unsupported format; choose 'disassembly' or 'pseudocode'";
                return false;
            }
            continue;
        }
        if (argument == "--report-json") {
            if (index + 1 >= argc) {
                error = "--report-json requires a path";
                return false;
            }
            options.report_path = argv[++index];
            continue;
        }
        if (argument == "--pdb") {
            if (index + 1 >= argc) {
                error = "--pdb requires a path";
                return false;
            }
            options.pdb_path = argv[++index];
            continue;
        }
        if (argument == "--reference-report") {
            if (index + 1 >= argc) {
                error = "--reference-report requires a path";
                return false;
            }
            options.reference_report_path = argv[++index];
            continue;
        }
        if (argument.rfind("--", 0) == 0) {
            error = "unknown option: " + argument;
            return false;
        }
        positional.push_back(argument);
    }

    if (positional.size() != 2U) {
        error = "expected an input path and an output path";
        return false;
    }
    options.input_path = positional[0];
    options.output_path = positional[1];
    if (options.report_path.empty()) {
        options.report_path = options.output_path + ".report.json";
    }
    if (std::filesystem::path(options.output_path).lexically_normal() ==
        std::filesystem::path(options.report_path).lexically_normal()) {
        error = "the disassembly and JSON report paths must be different";
        return false;
    }
    const auto normalized_input = normalized_absolute_path(options.input_path);
    if (normalized_absolute_path(options.output_path) == normalized_input ||
        normalized_absolute_path(options.report_path) == normalized_input) {
        error = "output and report paths must not overwrite the input file";
        return false;
    }
    if (!options.pdb_path.empty() &&
        (normalized_absolute_path(options.output_path) == normalized_absolute_path(options.pdb_path) ||
         normalized_absolute_path(options.report_path) == normalized_absolute_path(options.pdb_path))) {
        error = "output and report paths must not overwrite the supplied PDB";
        return false;
    }
    if (!options.reference_report_path.empty() &&
        (normalized_absolute_path(options.output_path) == normalized_absolute_path(options.reference_report_path) ||
         normalized_absolute_path(options.report_path) == normalized_absolute_path(options.reference_report_path))) {
        error = "output paths must not overwrite the supplied Ghidra reference report";
        return false;
    }
    return true;
}

std::filesystem::path temporary_path_for(const std::filesystem::path& destination,
                                         unsigned int ordinal) {
    const auto tick = std::chrono::steady_clock::now().time_since_epoch().count();
    std::filesystem::path temporary = destination;
    temporary += ".tmp." + std::to_string(tick) + "." + std::to_string(ordinal);
    return temporary;
}

bool write_temporary(const std::filesystem::path& path, const std::string& content,
                     std::string& error) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) {
        error = "cannot create temporary output file: " + path.string();
        return false;
    }
    output.write(content.data(), static_cast<std::streamsize>(content.size()));
    output.close();
    if (!output) {
        std::error_code ignored;
        std::filesystem::remove(path, ignored);
        error = "failed while writing temporary output file: " + path.string();
        return false;
    }
    return true;
}

bool replace_file(const std::filesystem::path& source,
                  const std::filesystem::path& destination, std::string& error) {
#ifdef _WIN32
    if (MoveFileExW(source.c_str(), destination.c_str(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == 0) {
        error = "unable to publish output file: " + destination.string();
        return false;
    }
#else
    std::error_code filesystem_error;
    std::filesystem::rename(source, destination, filesystem_error);
    if (filesystem_error) {
        error = "unable to publish output file '" + destination.string() + "': " +
                filesystem_error.message();
        return false;
    }
#endif
    return true;
}

bool write_artifacts(const CliOptions& options, const std::string& disassembly,
                     const std::string& report_json, std::string& error) {
    const std::filesystem::path output_path(options.output_path);
    const std::filesystem::path report_path(options.report_path);
    const auto output_temporary = temporary_path_for(output_path, 1U);
    const auto report_temporary = temporary_path_for(report_path, 2U);

    if (!write_temporary(output_temporary, disassembly, error)) {
        return false;
    }
    if (!write_temporary(report_temporary, report_json, error)) {
        std::error_code ignored;
        std::filesystem::remove(output_temporary, ignored);
        return false;
    }
    if (!replace_file(output_temporary, output_path, error)) {
        std::error_code ignored;
        std::filesystem::remove(output_temporary, ignored);
        std::filesystem::remove(report_temporary, ignored);
        return false;
    }
    if (!replace_file(report_temporary, report_path, error)) {
        std::error_code ignored;
        std::filesystem::remove(output_path, ignored);
        std::filesystem::remove(report_temporary, ignored);
        return false;
    }
    return true;
}

void print_diagnostics(const nexusrev::AnalysisReport& report) {
    for (const auto& diagnostic : report.diagnostics) {
        std::cerr << '[' << diagnostic.severity << "] " << diagnostic.code << ": "
                  << diagnostic.message << '\n';
    }
}

} // namespace

int main(int argc, char** argv) {
    CliOptions options;
    bool show_help = false;
    std::string argument_error;
    if (!parse_arguments(argc, argv, options, show_help, argument_error)) {
        std::cerr << "INVALID_ARGUMENT: " << argument_error << '\n';
        print_usage(std::cerr, argv[0]);
        return kInvalidArguments;
    }
    if (show_help) {
        print_usage(std::cout, argv[0]);
        return 0;
    }

    nexusrev::AnalysisReport report;
    try {
        nexusrev::Decompiler decompiler;
        if (!decompiler.load_binary(options.input_path, report)) {
            print_diagnostics(report);
            return kInputFailure;
        }
        if (!decompiler.analyze(report, options.pdb_path)) {
            print_diagnostics(report);
            return kAnalysisFailure;
        }
        if (!options.reference_report_path.empty())
            nexusrev::compare_ghidra_reference(report, options.reference_report_path);

        report.stages.push_back({"emission", "complete"});
        report.artifacts = {options.output_path, options.report_path};
        report.exit_code = 0;
        const std::string output_text = options.format == "pseudocode" ?
            nexusrev::emit_pseudocode(report) : decompiler.emit_annotated_disassembly(report);
        const std::string report_json = nexusrev::report_to_json(report);

        std::string write_error;
        if (!write_artifacts(options, output_text, report_json, write_error)) {
            std::cerr << "OUTPUT_WRITE_FAILED: " << write_error << '\n';
            return kOutputFailure;
        }
        print_diagnostics(report);
        std::cout << '[' << report.status << "] Wrote " << options.format << " and analysis report.\n";
        return 0;
    } catch (const std::exception& exception) {
        std::cerr << "INTERNAL_ERROR: " << exception.what() << '\n';
        return kInternalFailure;
    } catch (...) {
        std::cerr << "INTERNAL_ERROR: unknown failure\n";
        return kInternalFailure;
    }
}
