#pragma once

#include <capstone/capstone.h>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace LIEF {
class Binary;
}

namespace nexusrev {

struct Diagnostic {
    std::string code;
    std::string severity;
    std::string message;
};

struct StageRecord {
    std::string name;
    std::string status;
};

struct AnalysisReport {
    int schema_version = 1;
    std::string status = "failed";
    std::string start_status = "running";
    int exit_code = 0;
    std::string input_path;
    std::string input_sha256;
    std::string tool_version;
    int configuration_version = 1;
    std::string lief_version;
    std::string capstone_version;
    std::vector<StageRecord> stages;
    std::vector<Diagnostic> diagnostics;
    std::vector<std::string> artifacts;
};

struct SymbolCandidate {
    std::string name;
    std::uint64_t address = 0;
    std::uint64_t declared_size = 0;
    std::vector<std::string> instructions;
    bool decode_complete = false;
};

class Decompiler {
public:
    Decompiler();
    ~Decompiler();

    Decompiler(const Decompiler&) = delete;
    Decompiler& operator=(const Decompiler&) = delete;

    bool load_binary(const std::string& path, AnalysisReport& report);
    bool analyze(AnalysisReport& report);
    std::string emit_annotated_disassembly(const AnalysisReport& report) const;

private:
    std::unique_ptr<LIEF::Binary> binary_;
    csh capstone_handle_ = 0;
    std::vector<SymbolCandidate> candidates_;
};

std::string report_to_json(const AnalysisReport& report);

} // namespace nexusrev
