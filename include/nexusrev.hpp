#pragma once

#include "pe_image.hpp"
#include <capstone/capstone.h>
#include <array>
#include <cstdint>
#include <memory>
#include <optional>
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

struct X86OperandRecord {
    std::string type;
    std::uint8_t size = 0;
    std::uint8_t access = 0;
    std::string reg;
    std::int64_t immediate = 0;
    std::string segment;
    std::string base;
    std::string index;
    int scale = 0;
    std::int64_t displacement = 0;
    std::uint8_t avx_broadcast = 0;
    bool avx_zero_opmask = false;
};

struct InstructionRecord {
    std::size_t section_index = 0;
    std::uint64_t va = 0;
    std::uint32_t rva = 0;
    std::uint64_t file_offset = 0;
    std::string bytes;
    std::string mnemonic;
    std::string operands;
    bool detail_available = false;
    std::uint32_t instruction_id = 0;
    std::string instruction_name;
    std::vector<std::string> groups;
    std::vector<std::string> registers_read;
    std::vector<std::string> registers_written;
    std::array<std::uint8_t, 4> prefixes{};
    std::array<std::uint8_t, 4> opcodes{};
    std::uint8_t rex = 0;
    std::uint8_t address_size = 0;
    std::uint8_t modrm = 0;
    std::uint8_t sib = 0;
    std::int64_t displacement = 0;
    std::uint64_t flags = 0;
    std::uint8_t modrm_offset = 0;
    std::uint8_t displacement_offset = 0;
    std::uint8_t displacement_size = 0;
    std::uint8_t immediate_offset = 0;
    std::uint8_t immediate_size = 0;
    std::vector<X86OperandRecord> detail_operands;
};

struct DecodeGap {
    std::size_t section_index = 0;
    std::uint32_t rva = 0;
    std::uint64_t va = 0;
    std::optional<std::uint64_t> file_offset;
    std::uint64_t size = 0;
    std::string bytes;
    std::string reason;
};

struct DecodeSummary {
    std::uint64_t executable_file_backed_bytes = 0;
    std::uint64_t processed_bytes = 0;
    std::uint64_t decoded_bytes = 0;
    std::uint64_t undecoded_bytes = 0;
    std::uint64_t executable_zero_fill_bytes = 0;
    std::uint64_t limited_bytes = 0;
    std::uint64_t instruction_count = 0;
};

struct PdbFunctionSymbol {
    std::string name;
    std::uint32_t start_rva = 0;
    std::optional<std::uint32_t> end_rva;
    std::optional<std::uint32_t> type_index;
    std::string provenance;
    double confidence = 1.0;
};

struct SymbolProviderRecord {
    std::string status = "not_present";
    std::string requested_path;
    std::string resolved_path;
    std::string expected_guid;
    std::uint32_t expected_age = 0;
    std::string observed_guid;
    std::uint32_t observed_age = 0;
    std::vector<PdbFunctionSymbol> functions;
    std::vector<Diagnostic> diagnostics;
};

struct FunctionEvidence {
    std::string source;
    std::string description;
    double confidence = 0.0;
    std::optional<std::uint32_t> reference_rva;
    std::optional<std::uint32_t> start_rva;
    std::optional<std::uint32_t> end_rva;
};

struct FunctionRecord {
    std::string entity_kind = "candidate_function";
    std::string boundary_status = "unknown";
    std::uint32_t start_rva = 0;
    std::optional<std::uint32_t> end_rva;
    std::optional<std::uint64_t> file_offset;
    std::string label;
    std::vector<std::string> aliases;
    double confidence = 0.0;
    bool ambiguous = false;
    std::vector<FunctionEvidence> evidence;
};

struct UnresolvedExecutableRange {
    std::size_t section_index = 0;
    std::uint32_t start_rva = 0;
    std::uint32_t end_rva = 0;
    std::string reason;
};

struct UnresolvedControlFlow {
    std::uint32_t from_rva = 0;
    std::optional<std::uint32_t> target_rva;
    std::string flow_kind;
    std::string reason;
};

struct FunctionRecoveryRecord {
    std::string status = "partial";
    std::vector<FunctionRecord> known_functions;
    std::vector<FunctionRecord> candidate_functions;
    std::vector<FunctionRecord> fragments;
    std::vector<UnresolvedExecutableRange> unresolved_ranges;
    std::vector<UnresolvedControlFlow> unresolved_control_flow;
};

struct AnalysisReport {
    int schema_version = 3;
    std::string status = "failed";
    std::string start_status = "running";
    int exit_code = 0;
    std::string input_path;
    std::string input_sha256;
    std::string tool_version;
    int configuration_version = 2;
    std::string lief_version;
    std::string capstone_version;
    std::vector<StageRecord> stages;
    std::vector<Diagnostic> diagnostics;
    std::vector<std::string> artifacts;
    PeImage pe;
    DecodeSummary decode;
    std::vector<InstructionRecord> instructions;
    std::vector<DecodeGap> decode_gaps;
    SymbolProviderRecord symbols;
    FunctionRecoveryRecord function_recovery;
};

class Decompiler {
public:
    Decompiler();
    ~Decompiler();
    Decompiler(const Decompiler&) = delete;
    Decompiler& operator=(const Decompiler&) = delete;
    bool load_binary(const std::string& path, AnalysisReport& report);
    bool analyze(AnalysisReport& report, const std::string& pdb_path = {});
    std::string emit_annotated_disassembly(const AnalysisReport& report) const;
private:
    PeImage image_;
    std::unique_ptr<LIEF::Binary> lief_binary_;
    csh capstone_handle_ = 0;
};

std::string report_to_json(const AnalysisReport& report);

} // namespace nexusrev
