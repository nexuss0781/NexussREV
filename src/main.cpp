#include "nexusrev.hpp"
#include "phase3.hpp"
#include "phase4.hpp"

#include <algorithm>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <random>
#include <sstream>
#include <string>
#include <system_error>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <sys/resource.h>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace {

constexpr int kInvalidArguments = 2;
constexpr int kInputFailure = 3;
constexpr int kAnalysisFailure = 5;
constexpr int kOutputFailure = 6;
constexpr int kInternalFailure = 70;
constexpr int kTimeoutExit = 124;
constexpr int kCancelledExit = 130;

struct CliOptions {
    std::string input_path;
    std::string output_path;
    std::string report_path;
    std::string pdb_path;
    std::string reference_report_path;
    std::string format = "disassembly";
    std::string log_format = "text";
    std::uint64_t timeout_ms = 0;
    std::uint64_t memory_limit_mib = 0;
};

void print_usage(std::ostream& output, const char* executable) {
    output << "Usage: " << executable
           << " [--format disassembly|pseudocode] [--report-json <path>] [--pdb <matching.pdb>]\n"
           << " [--reference-report <ghidra.tsv>] [--log-format text|jsonl]\n"
           << " [--timeout-ms <n>] [--memory-limit-mib <n>] <input.exe> <output>\n"
           << "       " << executable << " --help | --version\n\n"
           << "The supported analysis target is native PE32+ x86-64, treated as data only.\n"
           << "ARM64, PE32/x86, CLR/.NET and other architectures are identified and reported as unsupported; they are not decoded as x64.\n"
           << "A PDB is used only when its GUID and age match the PE CodeView identity; otherwise it is reported and ignored.\n"
           << "An optional Ghidra headless reference TSV can be supplied with --reference-report for differential checks.\n"
           << "Disassembly is the default; pseudocode is an incomplete C-like analysis view, not original source or guaranteed compilable.\n"
           << "A JSON report is written to <output>.report.json unless --report-json is specified (schema v6; v5 is retained).\n"
           << "Hard analysis bounds: 256 MiB input, 64 MiB decode work/output, 20,000 instruction records;\n"
           << "--timeout-ms sets a cooperative wall-clock deadline and --memory-limit-mib sets a process memory cap.\n"
           << "Each artifact is staged and atomically replaced; the two-file publication is not a cross-file transaction.\n"
           << "Use --log-format jsonl for one structured diagnostic object per stderr line.\n";
}

std::filesystem::path normalized_absolute_path(const std::filesystem::path& value) {
    std::error_code filesystem_error;
    const std::filesystem::path absolute = std::filesystem::absolute(value, filesystem_error);
    const std::filesystem::path normalized =
        (filesystem_error ? value : absolute).lexically_normal();
    filesystem_error.clear();
    const std::filesystem::path canonical = std::filesystem::weakly_canonical(normalized, filesystem_error);
    return filesystem_error ? normalized : canonical.lexically_normal();
}

bool same_path_identity(const std::filesystem::path& left, const std::filesystem::path& right) {
    const auto normalized_left = normalized_absolute_path(left);
    const auto normalized_right = normalized_absolute_path(right);
    if (normalized_left == normalized_right) return true;
#ifdef _WIN32
    if (CompareStringOrdinal(normalized_left.c_str(), -1, normalized_right.c_str(), -1, TRUE) == CSTR_EQUAL)
        return true;
#endif
    std::error_code error;
    if (!std::filesystem::exists(normalized_left, error) || error) return false;
    error.clear();
    if (!std::filesystem::exists(normalized_right, error) || error) return false;
    error.clear();
    return std::filesystem::equivalent(normalized_left, normalized_right, error) && !error;
}

void signal_handler(int) { nexusrev::request_cancellation(); }

#ifdef _WIN32
BOOL WINAPI console_control_handler(DWORD event) {
    if (event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT || event == CTRL_CLOSE_EVENT) {
        nexusrev::request_cancellation();
        return TRUE;
    }
    return FALSE;
}
#endif

bool apply_memory_limit(std::uint64_t memory_limit_mib, std::string& error) {
    if (memory_limit_mib == 0U) return true;
    const std::uint64_t bytes = memory_limit_mib * 1024U * 1024U;
#ifdef _WIN32
    HANDLE job = CreateJobObjectW(nullptr, nullptr);
    if (job == nullptr) {
        error = "unable to create a Windows job object for the requested memory cap";
        return false;
    }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    limits.ProcessMemoryLimit = static_cast<SIZE_T>(bytes);
    const bool configured = SetInformationJobObject(job, JobObjectExtendedLimitInformation,
        &limits, sizeof(limits)) != 0;
    const bool assigned = configured && AssignProcessToJobObject(job, GetCurrentProcess()) != 0;
    if (!assigned) {
        CloseHandle(job);
        error = "unable to enforce the requested Windows process memory cap";
        return false;
    }
    // Keep the job handle alive for the process lifetime so its limit remains active.
    static HANDLE process_job = job;
    (void)process_job;
#else
    struct rlimit limits {};
    if (getrlimit(RLIMIT_AS, &limits) != 0) {
        error = "unable to query the process address-space limit";
        return false;
    }
    const rlim_t requested = bytes > static_cast<std::uint64_t>(std::numeric_limits<rlim_t>::max())
        ? std::numeric_limits<rlim_t>::max() : static_cast<rlim_t>(bytes);
    limits.rlim_cur = limits.rlim_max == RLIM_INFINITY ? requested : std::min(requested, limits.rlim_max);
    if (setrlimit(RLIMIT_AS, &limits) != 0) {
        error = "unable to enforce the requested process address-space limit";
        return false;
    }
#endif
    return true;
}

std::string json_quote(const std::string& value) {
    std::ostringstream result;
    constexpr char hex[] = "0123456789abcdef";
    result << '"';
    std::size_t index = 0U;
    while (index < value.size()) {
        const auto character = static_cast<unsigned char>(value[index]);
        switch (character) {
        case '"': result << "\\\""; ++index; continue;
        case '\\': result << "\\\\"; ++index; continue;
        case '\b': result << "\\b"; ++index; continue;
        case '\f': result << "\\f"; ++index; continue;
        case '\n': result << "\\n"; ++index; continue;
        case '\r': result << "\\r"; ++index; continue;
        case '\t': result << "\\t"; ++index; continue;
        default:
            if (character < 0x20U) {
                result << "\\u00" << hex[(character >> 4U) & 15U] << hex[character & 15U];
                ++index;
                continue;
            }
            if (character < 0x80U) {
                result << static_cast<char>(character);
                ++index;
                continue;
            }
            const std::size_t length = character >= 0xc2U && character <= 0xdfU ? 2U :
                character >= 0xe0U && character <= 0xefU ? 3U :
                character >= 0xf0U && character <= 0xf4U ? 4U : 0U;
            bool valid = length != 0U && index + length <= value.size();
            for (std::size_t i = 1U; valid && i < length; ++i) {
                const auto continuation = static_cast<unsigned char>(value[index + i]);
                valid = continuation >= 0x80U && continuation <= 0xbfU;
            }
            if (valid && length == 3U) {
                const auto second = static_cast<unsigned char>(value[index + 1U]);
                valid = (character != 0xe0U || second >= 0xa0U) &&
                        (character != 0xedU || second <= 0x9fU);
            }
            if (valid && length == 4U) {
                const auto second = static_cast<unsigned char>(value[index + 1U]);
                valid = (character != 0xf0U || second >= 0x90U) &&
                        (character != 0xf4U || second <= 0x8fU);
            }
            if (valid) {
                result.write(value.data() + static_cast<std::ptrdiff_t>(index),
                             static_cast<std::streamsize>(length));
                index += length;
            } else {
                result << "\\u00" << hex[(character >> 4U) & 15U] << hex[character & 15U];
                ++index;
            }
            continue;
        }
    }
    result << '"';
    return result.str();
}

bool parse_arguments(int argc, char** argv, CliOptions& options, bool& show_help,
                     bool& show_version, std::string& error) {
    show_help = false;
    show_version = false;
    std::vector<std::string> positional;
    for (int index = 1; index < argc; ++index) {
        const std::string argument = argv[index];
        if (argument == "--help" || argument == "-h") {
            show_help = true;
            return true;
        }
        if (argument == "--version") {
            show_version = true;
            continue;
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
        if (argument == "--log-format") {
            if (index + 1 >= argc) {
                error = "--log-format requires a value";
                return false;
            }
            options.log_format = argv[++index];
            if (options.log_format != "text" && options.log_format != "jsonl") {
                error = "unsupported log format; choose 'text' or 'jsonl'";
                return false;
            }
            continue;
        }
        if (argument == "--timeout-ms" || argument == "--memory-limit-mib") {
            if (index + 1 >= argc) {
                error = argument + " requires a positive integer";
                return false;
            }
            const std::string value = argv[++index];
            std::uint64_t parsed = 0;
            try {
                std::size_t consumed = 0;
                parsed = std::stoull(value, &consumed, 10);
                if (consumed != value.size() || parsed == 0U) throw std::invalid_argument("invalid");
            } catch (...) {
                error = argument + " requires a positive integer";
                return false;
            }
            if (argument == "--timeout-ms") {
                if (parsed > 3600000U) {
                    error = "--timeout-ms must not exceed 3600000";
                    return false;
                }
                options.timeout_ms = parsed;
            } else {
                if (parsed > 65536U) {
                    error = "--memory-limit-mib must not exceed 65536";
                    return false;
                }
                options.memory_limit_mib = parsed;
            }
            continue;
        }
        if (argument.rfind("--", 0) == 0) {
            error = "unknown option: " + argument;
            return false;
        }
        positional.push_back(argument);
    }

    if (show_version) {
        if (positional.empty()) return true;
        error = "--version cannot be combined with input/output paths";
        return false;
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
    if (same_path_identity(options.output_path, options.report_path)) {
        error = "the disassembly and JSON report paths must be different";
        return false;
    }
    if (same_path_identity(options.output_path, options.input_path) ||
        same_path_identity(options.report_path, options.input_path)) {
        error = "output and report paths must not overwrite the input file";
        return false;
    }
    if (!options.pdb_path.empty() &&
        (same_path_identity(options.output_path, options.pdb_path) ||
         same_path_identity(options.report_path, options.pdb_path))) {
        error = "output and report paths must not overwrite the supplied PDB";
        return false;
    }
    if (!options.reference_report_path.empty() &&
        (same_path_identity(options.output_path, options.reference_report_path) ||
         same_path_identity(options.report_path, options.reference_report_path))) {
        error = "output paths must not overwrite the supplied Ghidra reference report";
        return false;
    }
    return true;
}

struct StagedArtifact {
    std::filesystem::path destination;
    std::filesystem::path directory;
    std::filesystem::path temporary;
};

bool destination_is_replaceable(const std::filesystem::path& path, std::string& error) {
    std::error_code ec;
    const bool exists = std::filesystem::exists(path, ec);
    if (ec) {
        error = "cannot inspect output destination '" + path.string() + "': " + ec.message();
        return false;
    }
    if (exists && !std::filesystem::is_regular_file(path, ec)) {
        error = "output destination exists but is not a regular file: " + path.string();
        return false;
    }
    if (ec) {
        error = "cannot inspect output destination '" + path.string() + "': " + ec.message();
        return false;
    }
    return true;
}

bool create_stage(const std::filesystem::path& destination, unsigned int ordinal,
                  StagedArtifact& staged, std::string& error) {
    std::filesystem::path parent = destination.parent_path();
    if (parent.empty()) parent = ".";
    std::error_code ec;
    if (!std::filesystem::is_directory(parent, ec) || ec) {
        error = "output parent directory is unavailable: " + parent.string();
        return false;
    }
    std::random_device random;
    const auto tick = std::chrono::steady_clock::now().time_since_epoch().count();
    for (unsigned int attempt = 0; attempt < 32U; ++attempt) {
        const auto token = std::to_string(tick) + "." + std::to_string(random()) +
                           "." + std::to_string(ordinal) + "." + std::to_string(attempt);
        auto directory = parent / (".nexusrev-stage-" + token);
        ec.clear();
        if (std::filesystem::create_directory(directory, ec)) {
            staged.destination = destination;
            staged.directory = std::move(directory);
            staged.temporary = staged.directory / destination.filename();
            return true;
        }
        if (ec && ec != std::errc::file_exists) {
            error = "cannot create an output staging directory beside '" + destination.string() +
                    "': " + ec.message();
            return false;
        }
    }
    error = "unable to reserve a unique output staging directory beside '" + destination.string() + "'";
    return false;
}

bool sync_staged_file(const std::filesystem::path& path, std::string& error) {
#ifdef _WIN32
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        error = "cannot reopen staged output for durable flush: " + path.string();
        return false;
    }
    const bool flushed = FlushFileBuffers(file) != 0;
    CloseHandle(file);
    if (!flushed) {
        error = "cannot flush staged output to disk: " + path.string();
        return false;
    }
#else
    const int fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        error = "cannot reopen staged output for durable flush: " + path.string();
        return false;
    }
    const bool flushed = ::fsync(fd) == 0;
    ::close(fd);
    if (!flushed) {
        error = "cannot flush staged output to disk: " + path.string();
        return false;
    }
#endif
    return true;
}

bool write_temporary(const std::filesystem::path& path, const std::string& content,
                     std::string& error) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) {
        error = "cannot create temporary output file: " + path.string();
        return false;
    }
    output.write(content.data(), static_cast<std::streamsize>(content.size()));
    output.flush();
    output.close();
    if (!output || !sync_staged_file(path, error)) {
        std::error_code ignored;
        std::filesystem::remove(path, ignored);
        if (error.empty()) error = "failed while writing temporary output file: " + path.string();
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
    std::filesystem::path parent = destination.parent_path();
    if (parent.empty()) parent = ".";
    const int directory_fd = ::open(parent.c_str(), O_RDONLY | O_DIRECTORY);
    if (directory_fd >= 0) {
        (void)::fsync(directory_fd);
        ::close(directory_fd);
    }
#endif
    return true;
}

bool write_artifacts(const CliOptions& options, const std::string& disassembly,
                     const std::string& report_json, std::string& error) {
    const std::filesystem::path output_path(options.output_path);
    const std::filesystem::path report_path(options.report_path);
    if (!destination_is_replaceable(output_path, error) ||
        !destination_is_replaceable(report_path, error)) return false;

    StagedArtifact output_stage;
    StagedArtifact report_stage;
    if (!create_stage(output_path, 1U, output_stage, error)) return false;
    if (!create_stage(report_path, 2U, report_stage, error)) {
        std::error_code ignored;
        std::filesystem::remove_all(output_stage.directory, ignored);
        return false;
    }
    const auto cleanup = [&]() {
        std::error_code ignored;
        std::filesystem::remove_all(output_stage.directory, ignored);
        std::filesystem::remove_all(report_stage.directory, ignored);
    };
    if (!write_temporary(output_stage.temporary, disassembly, error) ||
        !write_temporary(report_stage.temporary, report_json, error)) {
        cleanup();
        return false;
    }
    if (nexusrev::analysis_stop_reason() != nexusrev::StopReason::none) {
        error = "analysis was stopped before output publication";
        cleanup();
        return false;
    }
    if (!replace_file(output_stage.temporary, output_path, error)) {
        cleanup();
        return false;
    }
    if (nexusrev::analysis_stop_reason() != nexusrev::StopReason::none) {
        error = "analysis was stopped between output and report publication";
        cleanup();
        return false;
    }
    if (!replace_file(report_stage.temporary, report_path, error)) {
        error += " (the disassembly artifact may already have been atomically published)";
        cleanup();
        return false;
    }
    if (nexusrev::analysis_stop_reason() != nexusrev::StopReason::none) {
        error = "analysis was stopped after both artifacts were atomically published";
        cleanup();
        return false;
    }
    cleanup();
    return true;
}

void print_diagnostics(const nexusrev::AnalysisReport& report, const std::string& format) {
    for (const auto& diagnostic : report.diagnostics) {
        if (format == "jsonl") {
            std::cerr << "{\"level\":" << json_quote(diagnostic.severity)
                      << ",\"code\":" << json_quote(diagnostic.code)
                      << ",\"message\":" << json_quote(diagnostic.message) << "}\n";
        } else {
            std::cerr << '[' << diagnostic.severity << "] " << diagnostic.code << ": "
                      << diagnostic.message << '\n';
        }
    }
}

int stop_exit_code(nexusrev::StopReason reason) {
    if (reason == nexusrev::StopReason::timed_out) return kTimeoutExit;
    if (reason == nexusrev::StopReason::cancelled) return kCancelledExit;
    return 0;
}

void report_stop(nexusrev::StopReason reason, const std::string& format) {
    const std::string code = reason == nexusrev::StopReason::timed_out ?
        "ANALYSIS_TIMEOUT" : "ANALYSIS_CANCELLED";
    const std::string message = reason == nexusrev::StopReason::timed_out ?
        "analysis exceeded its cooperative wall-clock deadline; any published artifact remains whole" :
        "analysis was cancelled; any published artifact remains whole";
    if (format == "jsonl") {
        std::cerr << "{\"level\":\"error\",\"code\":" << json_quote(code)
                  << ",\"message\":" << json_quote(message) << "}\n";
    } else {
        std::cerr << "[error] " << code << ": " << message << '\n';
    }
}

} // namespace

int main(int argc, char** argv) {
#ifdef _WIN32
    SetConsoleCtrlHandler(console_control_handler, TRUE);
#else
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);
#endif
    CliOptions options;
    bool show_help = false;
    bool show_version = false;
    std::string argument_error;
    if (!parse_arguments(argc, argv, options, show_help, show_version, argument_error)) {
        if (options.log_format == "jsonl") {
            std::cerr << "{\"level\":\"error\",\"code\":\"INVALID_ARGUMENT\",\"message\":"
                      << json_quote(argument_error) << "}\n";
        } else {
            std::cerr << "INVALID_ARGUMENT: " << argument_error << '\n';
            print_usage(std::cerr, argv[0]);
        }
        return kInvalidArguments;
    }
    if (show_help) {
        print_usage(std::cout, argv[0]);
        return 0;
    }
    if (show_version) {
        std::cout << "NexussREV " << NEXUSREV_VERSION
                  << " (report schema 6; LIEF " << NEXUSREV_LIEF_VERSION
                  << "; Capstone " << NEXUSREV_CAPSTONE_VERSION << ")\n";
        return 0;
    }
    std::string resource_error;
    if (!apply_memory_limit(options.memory_limit_mib, resource_error)) {
        if (options.log_format == "jsonl") {
            std::cerr << "{\"level\":\"error\",\"code\":\"RESOURCE_LIMIT_UNAVAILABLE\",\"message\":"
                      << json_quote(resource_error) << "}\n";
        } else {
            std::cerr << "RESOURCE_LIMIT_UNAVAILABLE: " << resource_error << '\n';
        }
        return kInternalFailure;
    }
    nexusrev::set_analysis_timeout_ms(options.timeout_ms);

    nexusrev::AnalysisReport report;
    try {
        nexusrev::Decompiler decompiler;
        if (!decompiler.load_binary(options.input_path, report)) {
            print_diagnostics(report, options.log_format);
            const auto reason = nexusrev::analysis_stop_reason();
            const std::string stop_code = reason == nexusrev::StopReason::timed_out ?
                "ANALYSIS_TIMEOUT" : "ANALYSIS_CANCELLED";
            if (reason != nexusrev::StopReason::none &&
                std::none_of(report.diagnostics.begin(), report.diagnostics.end(),
                    [&stop_code](const auto& item) { return item.code == stop_code; }))
                report_stop(reason, options.log_format);
            if (reason != nexusrev::StopReason::none) return stop_exit_code(reason);
            return kInputFailure;
        }
        if (!decompiler.analyze(report, options.pdb_path)) {
            print_diagnostics(report, options.log_format);
            const auto reason = nexusrev::analysis_stop_reason();
            const std::string stop_code = reason == nexusrev::StopReason::timed_out ?
                "ANALYSIS_TIMEOUT" : "ANALYSIS_CANCELLED";
            if (reason != nexusrev::StopReason::none &&
                std::none_of(report.diagnostics.begin(), report.diagnostics.end(),
                    [&stop_code](const auto& item) { return item.code == stop_code; }))
                report_stop(reason, options.log_format);
            if (reason != nexusrev::StopReason::none) return stop_exit_code(reason);
            return kAnalysisFailure;
        }
        const auto stop_reason = nexusrev::analysis_stop_reason();
        if (stop_reason != nexusrev::StopReason::none) {
            print_diagnostics(report, options.log_format);
            report_stop(stop_reason, options.log_format);
            return stop_exit_code(stop_reason);
        }
        if (!options.reference_report_path.empty())
            nexusrev::compare_ghidra_reference(report, options.reference_report_path);

        report.stages.push_back({"emission", "complete"});
        report.artifacts = {options.output_path, options.report_path};
        report.exit_code = 0;
        const std::string output_text = options.format == "pseudocode" ?
            nexusrev::emit_pseudocode(report) : decompiler.emit_annotated_disassembly(report);
        const std::string report_json = nexusrev::report_to_json(report);
        const auto after_serialization = nexusrev::analysis_stop_reason();
        if (after_serialization != nexusrev::StopReason::none) {
            report_stop(after_serialization, options.log_format);
            return stop_exit_code(after_serialization);
        }

        std::string write_error;
        if (!write_artifacts(options, output_text, report_json, write_error)) {
            const auto reason = nexusrev::analysis_stop_reason();
            if (reason != nexusrev::StopReason::none) {
                report_stop(reason, options.log_format);
                return stop_exit_code(reason);
            }
            if (options.log_format == "jsonl") {
                std::cerr << "{\"level\":\"error\",\"code\":\"OUTPUT_WRITE_FAILED\",\"message\":"
                          << json_quote(write_error) << "}\n";
            } else {
                std::cerr << "OUTPUT_WRITE_FAILED: " << write_error << '\n';
            }
            return kOutputFailure;
        }
        print_diagnostics(report, options.log_format);
        std::cout << '[' << report.status << "] Wrote " << options.format << " and analysis report.\n";
        return 0;
    } catch (const std::exception& exception) {
        if (options.log_format == "jsonl") {
            std::cerr << "{\"level\":\"error\",\"code\":\"INTERNAL_ERROR\",\"message\":"
                      << json_quote(exception.what()) << "}\n";
        } else {
            std::cerr << "INTERNAL_ERROR: " << exception.what() << '\n';
        }
        return kInternalFailure;
    } catch (...) {
        if (options.log_format == "jsonl")
            std::cerr << "{\"level\":\"error\",\"code\":\"INTERNAL_ERROR\",\"message\":\"unknown failure\"}\n";
        else
            std::cerr << "INTERNAL_ERROR: unknown failure\n";
        return kInternalFailure;
    }
}
