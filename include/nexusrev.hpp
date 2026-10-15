#pragma once

#include "pe_image.hpp"
#include <capstone/capstone.h>
#include <array>
#include <cstdint>
#include <chrono>
#include <iosfwd>
#include <optional>
#include <string>
#include <vector>

namespace nexusrev {

enum class StopReason { none, cancelled, timed_out };

void request_cancellation() noexcept;
void set_analysis_timeout_ms(std::uint64_t timeout_ms) noexcept;
StopReason analysis_stop_reason() noexcept;

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
    std::string type_status = "unknown";
    std::string return_type = "unknown";
    std::vector<std::string> parameter_types;
    std::string type_provenance;
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

struct SemanticInstructionRecord {
    std::uint32_t rva = 0;
    std::string status = "unsupported";
    std::string operation;
    std::string condition;
    std::vector<X86OperandRecord> operands;
    std::vector<std::string> registers_read;
    std::vector<std::string> registers_written;
    std::vector<std::string> flags_read;
    std::vector<std::string> flags_written;
    std::vector<std::string> flags_conditionally_written;
    std::vector<std::string> flags_undefined;
    std::vector<std::string> flags_preserved;
    bool memory_read = false;
    bool memory_written = false;
    std::string stack_action;
    std::optional<std::int32_t> stack_delta;
    std::string control_flow = "fallthrough";
    std::optional<std::uint32_t> target_rva;
    std::string unresolved_reason;
};

struct SemanticBasicBlock {
    std::uint32_t id = 0;
    std::uint32_t function_start_rva = 0;
    std::uint32_t start_rva = 0;
    std::uint32_t end_rva = 0;
    std::vector<std::uint32_t> instruction_rvas;
};

struct SemanticCfgEdge {
    std::uint32_t function_start_rva = 0;
    std::uint32_t from_block = 0;
    std::optional<std::uint32_t> to_block;
    std::uint32_t from_rva = 0;
    std::optional<std::uint32_t> target_rva;
    std::string kind;
    std::string provenance = "nexusrev_x64_semantics_v1";
};

struct SemanticCallGraphEdge {
    std::uint32_t caller_start_rva = 0;
    std::uint32_t call_rva = 0;
    std::optional<std::uint32_t> target_rva;
    std::string resolution;
    std::string provenance = "decoded_call_operand";
};

struct SemanticFunctionRecord {
    std::uint32_t start_rva = 0;
    std::optional<std::uint32_t> end_rva;
    std::string label;
    std::string provenance;
    std::string status = "partial";
    bool boundary_ambiguous = false;
    bool semantic_complete = false;
    std::uint64_t instruction_count = 0;
    std::uint64_t unsupported_instruction_count = 0;
    std::uint64_t unresolved_control_flow_count = 0;
    std::vector<std::string> issues;
};

struct ReferenceDifference {
    std::string category;
    std::optional<std::uint32_t> rva;
    std::string expected;
    std::string observed;
};

struct ReferenceComparisonRecord {
    std::string status = "not_configured";
    std::string tool = "Ghidra";
    std::string version;
    std::string input_sha256;
    std::uint64_t reference_function_count = 0;
    std::uint64_t compared_flow_count = 0;
    std::uint64_t difference_count = 0;
    std::vector<ReferenceDifference> differences;
};

struct SemanticAnalysisRecord {
    std::string status = "partial";
    std::string backend = "nexusrev-x64-windows-v1";
    std::string architecture = "x86_64";
    std::string abi = "Microsoft x64";
    std::uint64_t modeled_instruction_count = 0;
    std::uint64_t unsupported_instruction_count = 0;
    std::uint64_t unresolved_control_flow_count = 0;
    std::vector<SemanticInstructionRecord> instructions;
    std::vector<SemanticFunctionRecord> functions;
    std::vector<SemanticBasicBlock> basic_blocks;
    std::vector<SemanticCfgEdge> cfg_edges;
    std::vector<SemanticCallGraphEdge> call_graph;
    ReferenceComparisonRecord reference;
};

struct Phase4Evidence {
    std::string source;
    std::string description;
    double confidence = 0.0;
};

struct RecoveredVariable {
    std::string name;
    std::string storage = "unknown";
    std::optional<std::int64_t> stack_offset;
    std::string reg;
    std::uint8_t size = 0;
    std::string type = "unknown";
    double confidence = 0.0;
    std::uint64_t read_count = 0;
    std::uint64_t write_count = 0;
    std::vector<Phase4Evidence> evidence;
};

struct AbiParameterRecord {
    std::uint32_t index = 0;
    std::string location = "unknown";
    std::string reg;
    std::optional<std::int64_t> stack_offset;
    std::string type = "unknown";
    std::string type_status = "unknown";
    double confidence = 0.0;
    std::vector<Phase4Evidence> evidence;
};

struct FunctionSignatureRecord {
    std::uint32_t function_start_rva = 0;
    std::string label;
    std::string status = "partial";
    std::string calling_convention = "Microsoft x64";
    std::string return_type = "unknown";
    std::string return_type_status = "unknown";
    double confidence = 0.0;
    std::vector<Phase4Evidence> evidence;
    std::vector<AbiParameterRecord> parameters;
};

struct StackFrameRecord {
    std::uint32_t function_start_rva = 0;
    std::string status = "partial";
    bool has_frame_pointer = false;
    std::string frame_pointer_register;
    std::optional<std::uint64_t> max_stack_depth_bytes_below_entry_rsp;
    std::vector<RecoveredVariable> variables;
    std::vector<std::string> issues;
};

struct CallArgumentFlowRecord {
    std::uint32_t caller_start_rva = 0;
    std::uint32_t call_rva = 0;
    std::optional<std::uint32_t> target_rva;
    std::string callee;
    std::uint32_t parameter_index = 0;
    std::string argument_register;
    std::string source_kind = "unknown";
    std::string source_description;
    std::optional<std::uint32_t> source_rva;
    std::string argument_type = "unknown";
    std::string type_status = "unknown";
    double type_confidence = 0.0;
    double confidence = 0.0;
    std::vector<Phase4Evidence> evidence;
};

struct ImportedCallRecord {
    std::uint32_t caller_start_rva = 0;
    std::uint32_t call_rva = 0;
    std::uint32_t iat_rva = 0;
    std::string library;
    std::string name;
    std::string prototype_status = "unknown";
    std::string return_type = "unknown";
    std::vector<std::string> parameter_types;
    std::string prototype_source;
    double confidence = 0.0;
    std::vector<CallArgumentFlowRecord> arguments;
};

struct ControlStructureRecord {
    std::uint32_t function_start_rva = 0;
    std::string kind;
    std::string status = "partial";
    std::optional<std::uint32_t> test_rva;
    std::optional<std::uint32_t> join_block;
    std::vector<std::uint32_t> block_ids;
    double confidence = 0.0;
    std::string reason;
    std::vector<Phase4Evidence> evidence;
};

struct RttiVtableRecord {
    std::string type_name;
    std::uint32_t type_descriptor_rva = 0;
    std::uint32_t complete_object_locator_rva = 0;
    std::uint32_t class_hierarchy_descriptor_rva = 0;
    std::uint32_t vtable_rva = 0;
    std::vector<std::string> base_type_names;
    std::vector<std::uint32_t> virtual_method_rvas;
    double confidence = 0.0;
    std::vector<Phase4Evidence> evidence;
};

struct Phase4AnalysisRecord {
    std::string status = "partial";
    std::string backend = "nexusrev-x64-microsoft-abi-phase4-v1";
    std::string abi = "Microsoft x64";
    std::vector<StackFrameRecord> stack_frames;
    std::vector<FunctionSignatureRecord> signatures;
    std::vector<CallArgumentFlowRecord> call_argument_flows;
    std::vector<ImportedCallRecord> imported_calls;
    std::vector<ControlStructureRecord> control_structures;
    std::vector<RttiVtableRecord> rtti_vtables;
    std::vector<std::string> limitations;
};

struct AnalysisReport {
    int schema_version = 6;
    std::string status = "failed";
    std::string start_status = "running";
    int exit_code = 0;
    std::string input_path;
    std::string input_sha256;
    std::string tool_version;
    int configuration_version = 4;
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
    SemanticAnalysisRecord semantic_analysis;
    Phase4AnalysisRecord phase4_analysis;
};

class Decompiler {
public:
    Decompiler();
    ~Decompiler();
    Decompiler(const Decompiler&) = delete;
    Decompiler& operator=(const Decompiler&) = delete;
    bool load_binary(const std::string& path, AnalysisReport& report);
    bool analyze(AnalysisReport& report, const std::string& pdb_path = {},
                 const std::string& decode_strategy = "linear",
                 std::size_t decode_workers = 0U);
    std::string emit_annotated_disassembly(const AnalysisReport& report) const;
private:
    csh capstone_handle_ = 0;
};

void write_report_json(std::ostream& output, const AnalysisReport& report);
std::string report_to_json(const AnalysisReport& report);

} // namespace nexusrev
