#include "nexusrev.hpp"

#include <LIEF/LIEF.hpp>

#include <filesystem>
#include <iomanip>
#include <limits>
#include <sstream>
#include <system_error>
#include <utility>

#include "sha256.hpp"

#ifndef NEXUSREV_VERSION
#define NEXUSREV_VERSION "0.1.0"
#endif
#ifndef NEXUSREV_LIEF_VERSION
#define NEXUSREV_LIEF_VERSION "unknown"
#endif
#ifndef NEXUSREV_CAPSTONE_VERSION
#define NEXUSREV_CAPSTONE_VERSION "unknown"
#endif

namespace nexusrev {
namespace {

void add_diagnostic(AnalysisReport& report, std::string code, std::string severity,
                    std::string message) {
    report.diagnostics.push_back({std::move(code), std::move(severity), std::move(message)});
}

std::string json_escape(const std::string& value) {
    std::ostringstream escaped;
    for (const unsigned char character : value) {
        switch (character) {
        case '"': escaped << "\\\""; break;
        case '\\': escaped << "\\\\"; break;
        case '\b': escaped << "\\b"; break;
        case '\f': escaped << "\\f"; break;
        case '\n': escaped << "\\n"; break;
        case '\r': escaped << "\\r"; break;
        case '\t': escaped << "\\t"; break;
        default:
            if (character < 0x20U) {
                constexpr char hex[] = "0123456789abcdef";
                escaped << "\\u00" << hex[(character >> 4U) & 0x0fU]
                        << hex[character & 0x0fU];
            } else {
                escaped << static_cast<char>(character);
            }
        }
    }
    return escaped.str();
}

} // namespace

Decompiler::Decompiler() {
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &capstone_handle_) != CS_ERR_OK) {
        throw std::runtime_error("unable to initialize Capstone x86-64 decoder");
    }
    if (cs_option(capstone_handle_, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
        cs_close(&capstone_handle_);
        throw std::runtime_error("unable to enable Capstone instruction details");
    }
}

Decompiler::~Decompiler() {
    if (capstone_handle_ != 0) {
        cs_close(&capstone_handle_);
    }
}

bool Decompiler::load_binary(const std::string& path, AnalysisReport& report) {
    report.input_path = path;
    report.tool_version = NEXUSREV_VERSION;
    report.lief_version = NEXUSREV_LIEF_VERSION;
    report.capstone_version = NEXUSREV_CAPSTONE_VERSION;
    report.stages.push_back({"parse", "failed"});

    std::error_code filesystem_error;
    const std::filesystem::path input_path(path);
    if (!std::filesystem::exists(input_path, filesystem_error)) {
        const std::string reason = filesystem_error ? filesystem_error.message() : "file does not exist";
        add_diagnostic(report, "INPUT_NOT_FOUND", "error", "cannot open input '" + path + "': " + reason);
        return false;
    }
    if (!std::filesystem::is_regular_file(input_path, filesystem_error) || filesystem_error) {
        add_diagnostic(report, "INPUT_NOT_FILE", "error", "input is not a readable regular file: " + path);
        return false;
    }

    std::string hash_error;
    if (!sha256_file(path, report.input_sha256, hash_error)) {
        add_diagnostic(report, "INPUT_READ_FAILED", "error", "cannot read input '" + path + "': " + hash_error);
        return false;
    }

    try {
        binary_ = LIEF::Parser::parse(path);
        if (!binary_) {
            add_diagnostic(report, "INPUT_PARSE_FAILED", "error",
                           "LIEF did not recognize a supported executable image: " + path);
            return false;
        }
    } catch (const std::exception& exception) {
        add_diagnostic(report, "INPUT_PARSE_FAILED", "error",
                       "failed to parse input '" + path + "': " + exception.what());
        return false;
    } catch (...) {
        add_diagnostic(report, "INPUT_PARSE_FAILED", "error",
                       "failed to parse input '" + path + "' due to an unknown parser error");
        return false;
    }

    report.stages.back().status = "complete";
    return true;
}

bool Decompiler::analyze(AnalysisReport& report) {
    if (!binary_) {
        add_diagnostic(report, "ANALYSIS_WITHOUT_INPUT", "error", "analysis requires a successfully parsed input");
        report.stages.push_back({"analysis", "failed"});
        return false;
    }

    report.stages.push_back({"analysis", "partial"});
    candidates_.clear();
    const auto symbols = binary_->symbols();
    std::size_t candidates_with_sizes = 0;

    for (const auto& symbol : symbols) {
        SymbolCandidate candidate;
        candidate.name = symbol.name().empty() ? "<unnamed>" : symbol.name();
        candidate.address = static_cast<std::uint64_t>(symbol.value());
        candidate.declared_size = static_cast<std::uint64_t>(symbol.size());

        if (candidate.declared_size == 0U) {
            add_diagnostic(report, "CANDIDATE_SIZE_UNKNOWN", "warning",
                           "symbol '" + candidate.name + "' has no declared size; it was not decoded");
            candidates_.push_back(std::move(candidate));
            continue;
        }
        if (candidate.declared_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
            add_diagnostic(report, "CANDIDATE_SIZE_UNSUPPORTED", "warning",
                           "symbol '" + candidate.name + "' is too large for this platform and was not decoded");
            candidates_.push_back(std::move(candidate));
            continue;
        }

        ++candidates_with_sizes;
        std::vector<std::uint8_t> content;
        try {
            const auto content_span = binary_->get_content_from_virtual_address(
                candidate.address, static_cast<std::size_t>(candidate.declared_size));
            if (!content_span.empty()) {
                content.assign(content_span.begin(), content_span.end());
            }
        } catch (const std::exception& exception) {
            add_diagnostic(report, "CANDIDATE_CONTENT_UNAVAILABLE", "warning",
                           "could not read bytes for symbol '" + candidate.name + "': " + exception.what());
            candidates_.push_back(std::move(candidate));
            continue;
        }

        if (content.size() != static_cast<std::size_t>(candidate.declared_size)) {
            add_diagnostic(report, "CANDIDATE_CONTENT_TRUNCATED", "warning",
                           "available bytes do not cover the declared size of symbol '" + candidate.name + "'");
        }
        if (content.empty()) {
            candidates_.push_back(std::move(candidate));
            continue;
        }

        cs_insn* instructions = nullptr;
        const std::size_t instruction_count = cs_disasm(
            capstone_handle_, content.data(), content.size(), candidate.address, 0, &instructions);
        std::size_t decoded_bytes = 0;
        for (std::size_t index = 0; index < instruction_count; ++index) {
            std::ostringstream line;
            line << "0x" << std::hex << std::setw(16) << std::setfill('0')
                 << instructions[index].address << "  " << instructions[index].mnemonic;
            if (instructions[index].op_str[0] != '\0') {
                line << " " << instructions[index].op_str;
            }
            candidate.instructions.push_back(line.str());
            decoded_bytes += instructions[index].size;
        }
        if (instructions != nullptr) {
            cs_free(instructions, instruction_count);
        }
        candidate.decode_complete = instruction_count > 0U && decoded_bytes == content.size();
        if (!candidate.decode_complete) {
            add_diagnostic(report, "DECODE_INCOMPLETE", "warning",
                           "Capstone did not decode every available byte for symbol candidate '" + candidate.name + "'");
        }
        candidates_.push_back(std::move(candidate));
    }

    if (symbols.empty()) {
        add_diagnostic(report, "NO_SYMBOL_CANDIDATES", "info",
                       "the parsed image contains no symbols; no function boundaries were inferred");
    } else {
        add_diagnostic(report, "SYMBOLS_ARE_CANDIDATES", "info",
                       "PE symbols are evidence only and are not treated as confirmed function boundaries");
    }
    if (candidates_with_sizes > 0U) {
        add_diagnostic(report, "ANALYSIS_NOT_IMPLEMENTED", "info",
                       "control-flow recovery, semantic lifting, and type inference are not implemented; output is disassembly only");
    }
    return true;
}

std::string Decompiler::emit_annotated_disassembly(const AnalysisReport& report) const {
    std::ostringstream output;
    output << "NexussREV annotated disassembly\n"
           << "Tool version: " << report.tool_version << "\n"
           << "Input SHA-256: " << report.input_sha256 << "\n"
           << "\nNOTICE: This is a best-effort instruction listing, not original source code,\n"
           << "not guaranteed compilable C/C++, and not a claim of complete recovery.\n"
           << "Symbols below are candidates, not confirmed function boundaries.\n\n";

    for (const auto& candidate : candidates_) {
        output << "Symbol candidate: " << candidate.name << " @ 0x" << std::hex
               << candidate.address << std::dec << " (declared size: "
               << candidate.declared_size << ", decode: "
               << (candidate.decode_complete ? "all available bytes decoded" : "partial or unavailable")
               << ")\n";
        for (const auto& instruction : candidate.instructions) {
            output << "  " << instruction << '\n';
        }
        if (candidate.instructions.empty()) {
            output << "  [no instruction bytes emitted]\n";
        }
        output << '\n';
    }
    return output.str();
}

std::string report_to_json(const AnalysisReport& report) {
    std::ostringstream output;
    output << "{\n"
           << "  \"schema_version\": " << report.schema_version << ",\n"
           << "  \"status\": \"" << json_escape(report.status) << "\",\n"
           << "  \"run\": {\n"
           << "    \"start_status\": \"" << json_escape(report.start_status) << "\",\n"
           << "    \"end_status\": \"" << json_escape(report.status) << "\",\n"
           << "    \"exit_code\": " << report.exit_code << "\n"
           << "  },\n"
           << "  \"input\": {\n"
           << "    \"path\": \"" << json_escape(report.input_path) << "\",\n"
           << "    \"sha256\": \"" << json_escape(report.input_sha256) << "\"\n"
           << "  },\n"
           << "  \"tool\": {\n"
           << "    \"name\": \"NexussREV\",\n"
           << "    \"version\": \"" << json_escape(report.tool_version) << "\",\n"
           << "    \"configuration_version\": " << report.configuration_version << "\n"
           << "  },\n"
           << "  \"dependencies\": {\n"
           << "    \"lief\": \"" << json_escape(report.lief_version) << "\",\n"
           << "    \"capstone\": \"" << json_escape(report.capstone_version) << "\"\n"
           << "  },\n"
           << "  \"stages\": [";
    for (std::size_t index = 0; index < report.stages.size(); ++index) {
        const auto& stage = report.stages[index];
        output << (index == 0U ? "\n" : ",\n")
               << "    {\"name\": \"" << json_escape(stage.name)
               << "\", \"status\": \"" << json_escape(stage.status) << "\"}";
    }
    if (!report.stages.empty()) {
        output << '\n';
    }
    output << "  ],\n  \"diagnostics\": [";
    for (std::size_t index = 0; index < report.diagnostics.size(); ++index) {
        const auto& diagnostic = report.diagnostics[index];
        output << (index == 0U ? "\n" : ",\n")
               << "    {\"code\": \"" << json_escape(diagnostic.code)
               << "\", \"severity\": \"" << json_escape(diagnostic.severity)
               << "\", \"message\": \"" << json_escape(diagnostic.message) << "\"}";
    }
    if (!report.diagnostics.empty()) {
        output << '\n';
    }
    output << "  ],\n  \"artifacts\": [";
    for (std::size_t index = 0; index < report.artifacts.size(); ++index) {
        output << (index == 0U ? "\n" : ",\n")
               << "    \"" << json_escape(report.artifacts[index]) << "\"";
    }
    if (!report.artifacts.empty()) {
        output << '\n';
    }
    output << "  ]\n}\n";
    return output.str();
}

} // namespace nexusrev
