#include "phase4.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <iterator>
#include <limits>
#include <map>
#include <queue>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

namespace nexusrev {
namespace {
constexpr std::size_t kMaxPhase4Functions = 4096U;
constexpr std::size_t kMaxPhase4Instructions = 20000U;
constexpr std::size_t kMaxPhase4Variables = 8192U;
constexpr std::size_t kMaxPseudocodeBytes = 16U * 1024U * 1024U;

std::string json_escape(const std::string& value) {
    std::ostringstream out;
    constexpr char hex[] = "0123456789abcdef";
    for (const unsigned char c : value) {
        switch (c) {
        case '"': out << "\\\""; break;
        case '\\': out << "\\\\"; break;
        case '\b': out << "\\b"; break;
        case '\f': out << "\\f"; break;
        case '\n': out << "\\n"; break;
        case '\r': out << "\\r"; break;
        case '\t': out << "\\t"; break;
        default:
            if (c < 0x20U) out << "\\u00" << hex[(c >> 4U) & 15U] << hex[c & 15U];
            else out << static_cast<char>(c);
        }
    }
    return out.str();
}

void emit_strings(std::ostringstream& out, const std::vector<std::string>& values) {
    out << '[';
    for (std::size_t i = 0; i < values.size(); ++i)
        out << (i ? "," : "") << '"' << json_escape(values[i]) << '"';
    out << ']';
}

void emit_evidence(std::ostringstream& out, const std::vector<Phase4Evidence>& evidence) {
    out << '[';
    for (std::size_t i = 0; i < evidence.size(); ++i) {
        const auto& item = evidence[i];
        out << (i ? "," : "") << "{\"source\":\"" << json_escape(item.source)
            << "\",\"description\":\"" << json_escape(item.description)
            << "\",\"confidence\":" << item.confidence << '}';
    }
    out << ']';
}

void emit_optional_i64(std::ostringstream& out, const std::optional<std::int64_t>& value) {
    if (value) out << *value; else out << "null";
}

std::string canonical_register(std::string name) {
    std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    static const std::map<std::string, std::string> aliases = {
        {"al","rax"},{"ah","rax"},{"ax","rax"},{"eax","rax"},
        {"bl","rbx"},{"bh","rbx"},{"bx","rbx"},{"ebx","rbx"},
        {"cl","rcx"},{"ch","rcx"},{"cx","rcx"},{"ecx","rcx"},
        {"dl","rdx"},{"dh","rdx"},{"dx","rdx"},{"edx","rdx"},
        {"sil","rsi"},{"si","rsi"},{"esi","rsi"},
        {"dil","rdi"},{"di","rdi"},{"edi","rdi"},
        {"spl","rsp"},{"sp","rsp"},{"esp","rsp"},
        {"bpl","rbp"},{"bp","rbp"},{"ebp","rbp"},
        {"r8b","r8"},{"r8w","r8"},{"r8d","r8"},
        {"r9b","r9"},{"r9w","r9"},{"r9d","r9"},
        {"r10b","r10"},{"r10w","r10"},{"r10d","r10"},
        {"r11b","r11"},{"r11w","r11"},{"r11d","r11"},
        {"r12b","r12"},{"r12w","r12"},{"r12d","r12"},
        {"r13b","r13"},{"r13w","r13"},{"r13d","r13"},
        {"r14b","r14"},{"r14w","r14"},{"r14d","r14"},
        {"r15b","r15"},{"r15w","r15"},{"r15d","r15"}
    };
    const auto found = aliases.find(name);
    return found == aliases.end() ? name : found->second;
}

bool has_register(const std::vector<std::string>& registers, const std::string& wanted) {
    return std::any_of(registers.begin(), registers.end(), [&wanted](const std::string& item) {
        return canonical_register(item) == wanted;
    });
}

std::size_t byte_count(const std::string& bytes) {
    return bytes.empty() ? 0U : 1U + static_cast<std::size_t>(std::count(bytes.begin(), bytes.end(), ' '));
}

std::string lower(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return text;
}

std::string hex_value(std::uint64_t value) {
    std::ostringstream out;
    out << "0x" << std::hex << value;
    return out.str();
}

std::string stack_name(std::int64_t offset) {
    std::ostringstream out;
    out << "stack_" << (offset < 0 ? "m" : "p") << std::hex
        << static_cast<std::uint64_t>(offset < 0 ? -(offset + 1) + 1 : offset);
    return out.str();
}

struct FunctionView {
    const SemanticFunctionRecord* semantic = nullptr;
    std::vector<const InstructionRecord*> instructions;
};

struct Prototype {
    const char* name;
    const char* result;
    std::vector<std::string> parameters;
};

const Prototype* prototype_for(const std::string& import_name) {
    static const std::vector<Prototype> prototypes = {
        {"exitprocess", "void", {"UINT"}},
        {"getstdhandle", "HANDLE", {"DWORD"}},
        {"closehandle", "BOOL", {"HANDLE"}},
        {"readfile", "BOOL", {"HANDLE", "LPVOID", "DWORD", "LPDWORD", "LPOVERLAPPED"}},
        {"writefile", "BOOL", {"HANDLE", "LPCVOID", "DWORD", "LPDWORD", "LPOVERLAPPED"}},
        {"heapalloc", "LPVOID", {"HANDLE", "DWORD", "SIZE_T"}},
        {"heapfree", "BOOL", {"HANDLE", "DWORD", "LPVOID"}},
        {"virtualalloc", "LPVOID", {"LPVOID", "SIZE_T", "DWORD", "DWORD"}},
        {"virtualfree", "BOOL", {"LPVOID", "SIZE_T", "DWORD"}},
        {"sleep", "void", {"DWORD"}},
        {"createfilea", "HANDLE", {"LPCSTR", "DWORD", "DWORD", "LPSECURITY_ATTRIBUTES", "DWORD", "DWORD", "HANDLE"}},
        {"createfilew", "HANDLE", {"LPCWSTR", "DWORD", "DWORD", "LPSECURITY_ATTRIBUTES", "DWORD", "DWORD", "HANDLE"}},
        {"memcpy", "void*", {"void*", "const void*", "size_t"}},
        {"memset", "void*", {"void*", "int", "size_t"}}
    };
    const auto wanted = lower(import_name);
    const auto found = std::find_if(prototypes.begin(), prototypes.end(), [&wanted](const Prototype& item) {
        return wanted == item.name;
    });
    return found == prototypes.end() ? nullptr : &*found;
}

std::optional<std::uint32_t> imported_iat_target(const PeImage& pe, const InstructionRecord& insn) {
    const auto length = byte_count(insn.bytes);
    if (length == 0U || insn.va > std::numeric_limits<std::uint64_t>::max() - length) return std::nullopt;
    for (const auto& operand : insn.detail_operands) {
        if (operand.type != "memory" || lower(operand.base) != "rip") continue;
        const auto next = insn.va + length;
        std::uint64_t target_va = 0;
        if (operand.displacement < 0) {
            const auto magnitude = static_cast<std::uint64_t>(-(operand.displacement + 1)) + 1U;
            if (next < magnitude) continue;
            target_va = next - magnitude;
        } else {
            const auto displacement = static_cast<std::uint64_t>(operand.displacement);
            if (next > std::numeric_limits<std::uint64_t>::max() - displacement) continue;
            target_va = next + displacement;
        }
        std::uint32_t target_rva = 0;
        if (!pe.va_to_rva(target_va, target_rva)) continue;
        for (const auto& imported : pe.imports)
            if (imported.iat_rva == target_rva) return target_rva;
    }
    return std::nullopt;
}

std::vector<const InstructionRecord*> range_instructions(
    const std::map<std::uint32_t, const InstructionRecord*>& decoded,
    const SemanticFunctionRecord& function) {
    std::vector<const InstructionRecord*> members;
    if (!function.end_rva || *function.end_rva <= function.start_rva) return members;
    for (auto it = decoded.lower_bound(function.start_rva); it != decoded.end() && it->first < *function.end_rva; ++it)
        members.push_back(it->second);
    return members;
}

std::string source_register(const InstructionRecord& insn, const std::string& reg) {
    std::ostringstream out;
    out << "last local definition of " << reg << " is ";
    if (insn.mnemonic.empty()) out << "an instruction";
    else out << insn.mnemonic << (insn.operands.empty() ? "" : " " + insn.operands);
    out << " at RVA " << hex_value(insn.rva);
    return out.str();
}

std::optional<std::int64_t> stack_location(const X86OperandRecord& operand,
                                           const std::optional<std::int64_t>& rsp_delta,
                                           const std::optional<std::int64_t>& rbp_delta) {
    const auto base = canonical_register(operand.base);
    if (base == "rsp" && rsp_delta) return *rsp_delta + operand.displacement;
    if (base == "rbp" && rbp_delta) return *rbp_delta + operand.displacement;
    return std::nullopt;
}

void add_issue(std::vector<std::string>& issues, const std::string& code) {
    if (std::find(issues.begin(), issues.end(), code) == issues.end()) issues.push_back(code);
}

void analyze_frame(const FunctionView& view, StackFrameRecord& frame) {
    frame.function_start_rva = view.semantic->start_rva;
    if (!view.semantic->end_rva || view.instructions.empty()) {
        frame.status = "partial";
        frame.max_stack_depth_bytes_below_entry_rsp = std::nullopt;
        add_issue(frame.issues, "bounded_decoded_instructions_required");
        return;
    }
    std::optional<std::int64_t> rsp_delta = 0;
    std::optional<std::int64_t> rbp_delta;
    std::int64_t minimum_delta = 0;
    std::map<std::int64_t, RecoveredVariable> slots;
    std::size_t seen = 0U;
    for (const auto* insn : view.instructions) {
        if (++seen > kMaxPhase4Instructions) {
            add_issue(frame.issues, "phase4_instruction_limit");
            rsp_delta.reset();
            break;
        }
        const auto& ops = insn->detail_operands;
        const auto mnemonic = lower(insn->mnemonic);
        if (ops.size() >= 2U && ops[0].type == "register" && ops[1].type == "register" &&
            canonical_register(ops[0].reg) == "rbp" && canonical_register(ops[1].reg) == "rsp" && rsp_delta) {
            rbp_delta = *rsp_delta;
            frame.has_frame_pointer = true;
            frame.frame_pointer_register = "rbp";
        }
        if (ops.size() >= 2U && ops[0].type == "register" && ops[1].type == "register" &&
            canonical_register(ops[0].reg) == "rsp" && canonical_register(ops[1].reg) == "rbp") {
            if (rbp_delta) rsp_delta = rbp_delta;
            else { rsp_delta.reset(); add_issue(frame.issues, "stack_pointer_restored_from_unknown_frame_pointer"); }
        }
        if (mnemonic == "leave") {
            if (rbp_delta) {
                rsp_delta = *rbp_delta + 8;
                rbp_delta.reset();
            } else {
                rsp_delta.reset();
                add_issue(frame.issues, "leave_without_known_frame_pointer");
            }
        }

        for (std::size_t op_index = 0; op_index < ops.size(); ++op_index) {
            const auto& operand = ops[op_index];
            if (operand.type != "memory") continue;
            const auto location = stack_location(operand, rsp_delta, rbp_delta);
            if (!location) {
                const auto base = canonical_register(operand.base);
                if (base == "rsp" || base == "rbp") add_issue(frame.issues, "stack_address_state_unknown");
                continue;
            }
            auto& variable = slots[*location];
            variable.name = stack_name(*location);
            variable.storage = "stack_slot";
            variable.stack_offset = *location;
            variable.size = std::max(variable.size, operand.size);
            const bool explicit_read = (operand.access & 1U) != 0U;
            const bool explicit_write = (operand.access & 2U) != 0U;
            bool reads = explicit_read;
            bool writes = explicit_write;
            if (!operand.access) {
                if (mnemonic == "mov" || mnemonic == "movabs" || mnemonic == "movzx" || mnemonic == "movsx" || mnemonic == "movsxd") {
                    reads = op_index != 0U;
                    writes = op_index == 0U;
                } else if (mnemonic == "lea") {
                    reads = false;
                    writes = false;
                } else {
                    reads = true;
                    writes = op_index == 0U && mnemonic != "cmp" && mnemonic != "test";
                }
            }
            if (reads) ++variable.read_count;
            if (writes) ++variable.write_count;
            const std::string direction = reads && writes ? "read/write" : (writes ? "write" : (reads ? "read" : "address use"));
            if (variable.evidence.empty() || variable.evidence.back().description.find(hex_value(insn->rva)) == std::string::npos)
                variable.evidence.push_back({"decoded_stack_operand", direction + " at RVA " + hex_value(insn->rva), 0.62});
        }

        if (mnemonic == "sub" && ops.size() >= 2U && ops[0].type == "register" &&
            canonical_register(ops[0].reg) == "rsp" && ops[1].type == "immediate" && rsp_delta) {
            if (ops[1].immediate < 0 || ops[1].immediate > 16 * 1024 * 1024) {
                rsp_delta.reset(); add_issue(frame.issues, "stack_allocation_immediate_out_of_bounds");
            } else *rsp_delta -= ops[1].immediate;
        } else if (mnemonic == "add" && ops.size() >= 2U && ops[0].type == "register" &&
                   canonical_register(ops[0].reg) == "rsp" && ops[1].type == "immediate" && rsp_delta) {
            if (ops[1].immediate < 0 || ops[1].immediate > 16 * 1024 * 1024) {
                rsp_delta.reset(); add_issue(frame.issues, "stack_adjustment_immediate_out_of_bounds");
            } else *rsp_delta += ops[1].immediate;
        } else if ((mnemonic == "push" || mnemonic == "pushq" || mnemonic == "pushfq") && rsp_delta) {
            const std::int64_t width = !ops.empty() && ops[0].size == 2U ? 2 : 8;
            *rsp_delta -= width;
        } else if ((mnemonic == "pop" || mnemonic == "popq" || mnemonic == "popfq") && rsp_delta) {
            const std::int64_t width = !ops.empty() && ops[0].size == 2U ? 2 : 8;
            *rsp_delta += width;
            if (!ops.empty() && ops[0].type == "register" && canonical_register(ops[0].reg) == "rbp") rbp_delta.reset();
        } else if (mnemonic == "and" && !ops.empty() && ops[0].type == "register" && canonical_register(ops[0].reg) == "rsp") {
            rsp_delta.reset(); add_issue(frame.issues, "aligned_dynamic_stack_pointer_not_modeled");
        }
        const bool pop_rsp = (mnemonic == "pop" || mnemonic == "popq") && !ops.empty() &&
            ops[0].type == "register" && canonical_register(ops[0].reg) == "rsp";
        if (pop_rsp) {
            rsp_delta.reset();
            add_issue(frame.issues, "stack_pointer_loaded_from_pop_value");
        }
        if (has_register(insn->registers_written, "rsp")) {
            const bool immediate_adjust = (mnemonic == "sub" || mnemonic == "add") && ops.size() >= 2U &&
                ops[0].type == "register" && canonical_register(ops[0].reg) == "rsp" && ops[1].type == "immediate";
            const bool push_or_pop = mnemonic == "push" || mnemonic == "pushq" || mnemonic == "pushfq" ||
                mnemonic == "pop" || mnemonic == "popq" || mnemonic == "popfq";
            const bool frame_restore = ops.size() >= 2U && ops[0].type == "register" && ops[1].type == "register" &&
                canonical_register(ops[0].reg) == "rsp" && canonical_register(ops[1].reg) == "rbp";
            const bool modeled = immediate_adjust || push_or_pop || frame_restore || mnemonic == "leave" ||
                mnemonic == "and" || mnemonic == "call" || mnemonic == "callq" || mnemonic == "ret" || mnemonic == "retq";
            if (!modeled) {
                rsp_delta.reset();
                add_issue(frame.issues, "unmodeled_stack_pointer_write");
            }
        }
        if (rsp_delta) minimum_delta = std::min(minimum_delta, *rsp_delta);
    }
    frame.max_stack_depth_bytes_below_entry_rsp = rsp_delta ?
        std::optional<std::uint64_t>(static_cast<std::uint64_t>(-minimum_delta)) : std::nullopt;
    for (auto& item : slots) {
        if (frame.variables.size() >= kMaxPhase4Variables) {
            add_issue(frame.issues, "phase4_variable_limit");
            break;
        }
        frame.variables.push_back(std::move(item.second));
    }
    frame.status = frame.issues.empty() ? "complete" : "partial";
}

FunctionSignatureRecord infer_signature(const FunctionView& view, const AnalysisReport& report) {
    FunctionSignatureRecord signature;
    signature.function_start_rva = view.semantic->start_rva;
    signature.label = view.semantic->label;
    signature.calling_convention = "Microsoft x64";
    signature.status = "partial";
    signature.return_type = "unknown";
    signature.return_type_status = "unknown";
    static const std::array<const char*, 4> abi_registers = {"rcx", "rdx", "r8", "r9"};
    std::set<std::uint32_t> used_register_parameters;
    std::set<std::uint32_t> stack_parameter_indices;
    std::set<std::string> written;
    std::map<std::uint32_t, std::int64_t> entry_stack_parameter_offsets;
    std::optional<std::int64_t> rsp_delta = 0;
    std::optional<std::int64_t> rbp_delta;
    bool observed_return_value = false;
    for (const auto* insn : view.instructions) {
        for (std::uint32_t index = 0; index < abi_registers.size(); ++index) {
            const std::string reg = abi_registers[index];
            if (has_register(insn->registers_read, reg) && written.find(reg) == written.end())
                used_register_parameters.insert(index);
        }
        for (const auto& operand : insn->detail_operands) {
            if (operand.type == "memory") {
                const auto offset = stack_location(operand, rsp_delta, rbp_delta);
                if (offset && *offset >= 40 && ((*offset - 40) % 8) == 0 && *offset <= 4096) {
                    const auto index = static_cast<std::uint32_t>(4 + (*offset - 40) / 8);
                    stack_parameter_indices.insert(index);
                    entry_stack_parameter_offsets[index] = *offset;
                }
            }
        }
        for (const auto& reg : insn->registers_written) {
            const auto canonical = canonical_register(reg);
            if (canonical == "rax") observed_return_value = true;
            written.insert(canonical);
        }
        const auto& ops = insn->detail_operands;
        const auto mnemonic = lower(insn->mnemonic);
        if (ops.size() >= 2U && ops[0].type == "register" && ops[1].type == "register" &&
            canonical_register(ops[0].reg) == "rbp" && canonical_register(ops[1].reg) == "rsp" && rsp_delta)
            rbp_delta = rsp_delta;
        bool modeled_rsp_write = false;
        if (ops.size() >= 2U && ops[0].type == "register" && ops[1].type == "register" &&
            canonical_register(ops[0].reg) == "rsp" && canonical_register(ops[1].reg) == "rbp") {
            if (rbp_delta) rsp_delta = rbp_delta; else rsp_delta.reset();
            modeled_rsp_write = true;
        }
        if (ops.size() >= 2U && ops[0].type == "register" && canonical_register(ops[0].reg) == "rsp" &&
            ops[1].type == "immediate" && rsp_delta && (mnemonic == "sub" || mnemonic == "add")) {
            *rsp_delta += mnemonic == "sub" ? -ops[1].immediate : ops[1].immediate;
            modeled_rsp_write = true;
        } else if ((mnemonic == "push" || mnemonic == "pushq" || mnemonic == "pushfq") && rsp_delta) {
            *rsp_delta -= 8; modeled_rsp_write = true;
        } else if ((mnemonic == "pop" || mnemonic == "popq" || mnemonic == "popfq") && rsp_delta) {
            if (!ops.empty() && ops[0].type == "register" && canonical_register(ops[0].reg) == "rsp") rsp_delta.reset();
            else *rsp_delta += 8;
            modeled_rsp_write = true;
        } else if (mnemonic == "leave") {
            if (rbp_delta) { rsp_delta = *rbp_delta + 8; rbp_delta.reset(); }
            else rsp_delta.reset();
            modeled_rsp_write = true;
        } else if (mnemonic == "and" && !ops.empty() && ops[0].type == "register" && canonical_register(ops[0].reg) == "rsp") {
            rsp_delta.reset(); modeled_rsp_write = true;
        }
        if (has_register(insn->registers_written, "rsp") && !modeled_rsp_write &&
            mnemonic != "call" && mnemonic != "callq" && mnemonic != "ret" && mnemonic != "retq") rsp_delta.reset();
    }
    for (const auto index : used_register_parameters) {
        AbiParameterRecord parameter;
        parameter.index = index;
        parameter.location = "register";
        parameter.reg = abi_registers[index];
        parameter.confidence = 0.80;
        parameter.evidence.push_back({"microsoft_x64_abi_register_read_before_write",
            std::string("first observed use of ABI argument register ") + abi_registers[index] + " precedes a local definition under the Microsoft x64 ABI", 0.80});
        signature.parameters.push_back(std::move(parameter));
    }
    for (const auto index : stack_parameter_indices) {
        AbiParameterRecord parameter;
        parameter.index = index;
        parameter.location = "stack";
        parameter.stack_offset = entry_stack_parameter_offsets[index];
        parameter.confidence = 0.72;
        parameter.evidence.push_back({"microsoft_x64_stack_argument_slot",
            "stack read at the ABI overflow-argument area relative to entry RSP", 0.72});
        signature.parameters.push_back(std::move(parameter));
    }
    std::sort(signature.parameters.begin(), signature.parameters.end(), [](const auto& lhs, const auto& rhs) {
        return lhs.index < rhs.index;
    });
    if (observed_return_value)
        signature.evidence.push_back({"rax_family_write", "a decoded instruction writes the RAX register family; source return type remains unknown", 0.38});
    else
        signature.evidence.push_back({"return_type_unknown", "no confidently typed return value was recovered", 0.0});
    for (const auto& symbol : report.symbols.functions) {
        if (symbol.start_rva == signature.function_start_rva && symbol.type_index && symbol.type_status == "unknown") {
            signature.evidence.push_back({"pdb_type_index_unresolved",
                "a matching PDB supplies a function type index, but it did not resolve to a supported TPI procedure signature", 0.0});
            break;
        }
    }
    signature.confidence = signature.parameters.empty() ? 0.25 : 0.80;
    return signature;
}

std::vector<CallArgumentFlowRecord> call_arguments_for(
    const FunctionView& view, const InstructionRecord& call, std::size_t count,
    const std::map<std::string, const InstructionRecord*>& last_definitions,
    const std::set<std::string>& entry_arguments,
    std::optional<std::uint32_t> target, const std::string& callee) {
    static const std::array<const char*, 4> abi_registers = {"rcx", "rdx", "r8", "r9"};
    std::vector<CallArgumentFlowRecord> result;
    const auto limit = std::min(count, abi_registers.size());
    for (std::size_t index = 0; index < limit; ++index) {
        const std::string reg = abi_registers[index];
        CallArgumentFlowRecord flow;
        flow.caller_start_rva = view.semantic->start_rva;
        flow.call_rva = call.rva;
        flow.target_rva = target;
        flow.callee = callee;
        flow.parameter_index = static_cast<std::uint32_t>(index);
        flow.argument_register = reg;
        const auto definition = last_definitions.find(reg);
        if (definition != last_definitions.end()) {
            flow.source_kind = "linear_register_definition";
            flow.source_rva = definition->second->rva;
            flow.source_description = source_register(*definition->second, reg) + "; path-sensitive merge is not performed";
            flow.confidence = 0.42;
            flow.evidence.push_back({"linear_register_reaching_definition", flow.source_description, 0.42});
        } else if (entry_arguments.find(reg) != entry_arguments.end()) {
            flow.source_kind = "caller_entry_parameter";
            flow.source_description = "register remains sourced from this function's entry value; path-sensitive merge is not performed";
            flow.confidence = 0.45;
            flow.evidence.push_back({"caller_signature_register", flow.source_description, 0.45});
        } else {
            flow.source_kind = "unknown";
            flow.source_description = "no local definition was observed for this argument register";
            flow.confidence = 0.0;
            flow.evidence.push_back({"argument_value_unknown", flow.source_description, 0.0});
        }
        result.push_back(std::move(flow));
    }
    return result;
}

std::map<std::uint32_t, std::set<std::uint32_t>> block_adjacency(
    const SemanticAnalysisRecord& semantic, std::uint32_t function_start,
    const std::set<std::uint32_t>& blocks) {
    std::map<std::uint32_t, std::set<std::uint32_t>> adjacency;
    for (const auto block : blocks) adjacency[block];
    for (const auto& edge : semantic.cfg_edges) {
        if (edge.function_start_rva != function_start || !edge.to_block || !blocks.count(*edge.to_block)) continue;
        if (edge.kind == "call" || edge.kind == "indirect_call") continue;
        adjacency[edge.from_block].insert(*edge.to_block);
    }
    return adjacency;
}

std::map<std::uint32_t, int> distances_from(
    std::uint32_t start, const std::map<std::uint32_t, std::set<std::uint32_t>>& adjacency) {
    std::map<std::uint32_t, int> distances;
    std::queue<std::uint32_t> pending;
    pending.push(start);
    distances[start] = 0;
    while (!pending.empty()) {
        const auto current = pending.front(); pending.pop();
        const auto found = adjacency.find(current);
        if (found == adjacency.end()) continue;
        for (const auto next : found->second) {
            if (distances.emplace(next, distances[current] + 1).second) pending.push(next);
        }
    }
    return distances;
}

std::map<std::uint32_t, std::set<std::uint32_t>> dominators(
    const std::set<std::uint32_t>& blocks,
    const std::map<std::uint32_t, std::set<std::uint32_t>>& adjacency,
    std::uint32_t entry) {
    std::map<std::uint32_t, std::set<std::uint32_t>> predecessors;
    for (const auto& item : adjacency)
        for (const auto target : item.second) predecessors[target].insert(item.first);
    std::map<std::uint32_t, std::set<std::uint32_t>> dom;
    for (const auto block : blocks) dom[block] = block == entry ? std::set<std::uint32_t>{block} : blocks;
    bool changed = true;
    std::size_t iterations = 0;
    while (changed && ++iterations <= blocks.size() + 1U) {
        changed = false;
        for (const auto block : blocks) {
            if (block == entry) continue;
            const auto pred = predecessors.find(block);
            std::set<std::uint32_t> next;
            if (pred != predecessors.end() && !pred->second.empty()) {
                next = dom[*pred->second.begin()];
                for (auto it = std::next(pred->second.begin()); it != pred->second.end(); ++it) {
                    std::set<std::uint32_t> intersection;
                    std::set_intersection(next.begin(), next.end(), dom[*it].begin(), dom[*it].end(),
                                          std::inserter(intersection, intersection.begin()));
                    next = std::move(intersection);
                }
            }
            next.insert(block);
            if (next != dom[block]) { dom[block] = std::move(next); changed = true; }
        }
    }
    return dom;
}

void recover_structures(const SemanticFunctionRecord& function, const SemanticAnalysisRecord& semantic,
                        Phase4AnalysisRecord& output) {
    std::set<std::uint32_t> blocks;
    for (const auto& block : semantic.basic_blocks)
        if (block.function_start_rva == function.start_rva) blocks.insert(block.id);
    if (blocks.empty()) {
        ControlStructureRecord record;
        record.function_start_rva = function.start_rva;
        record.kind = "lower_level_cfg";
        record.status = "partial";
        record.confidence = 0.0;
        record.reason = "bounded CFG blocks are unavailable";
        output.control_structures.push_back(std::move(record));
        return;
    }
    const auto adjacency = block_adjacency(semantic, function.start_rva, blocks);
    std::map<std::uint32_t, std::uint32_t> block_rva;
    for (const auto& block : semantic.basic_blocks)
        if (block.function_start_rva == function.start_rva) block_rva[block.id] = block.start_rva;
    for (const auto& edge : semantic.cfg_edges) {
        if (edge.function_start_rva != function.start_rva || edge.kind != "conditional_true" || !edge.to_block) continue;
        const auto false_edge = std::find_if(semantic.cfg_edges.begin(), semantic.cfg_edges.end(), [&edge](const SemanticCfgEdge& item) {
            return item.function_start_rva == edge.function_start_rva && item.from_rva == edge.from_rva && item.kind == "conditional_false";
        });
        ControlStructureRecord structure;
        structure.function_start_rva = function.start_rva;
        structure.kind = "conditional_region";
        structure.status = "partial";
        structure.test_rva = edge.from_rva;
        structure.confidence = 0.0;
        if (false_edge == semantic.cfg_edges.end() || !false_edge->to_block || !blocks.count(*false_edge->to_block)) {
            structure.reason = "conditional branch lacks two resolved in-function successors; retain CFG";
            structure.evidence.push_back({"cfg_conditional_edges", structure.reason, 0.0});
            output.control_structures.push_back(std::move(structure));
            continue;
        }
        const auto true_distances = distances_from(*edge.to_block, adjacency);
        const auto false_distances = distances_from(*false_edge->to_block, adjacency);
        std::optional<std::tuple<int, int, std::uint32_t>> best;
        for (const auto& item : true_distances) {
            const auto other = false_distances.find(item.first);
            if (other == false_distances.end()) continue;
            const auto candidate = std::make_tuple(std::max(item.second, other->second), item.second + other->second, item.first);
            if (!best || candidate < *best) best = candidate;
        }
        if (!best) {
            structure.kind = "lower_level_conditional";
            structure.reason = "no common reachable join was established; preserve block-level control flow";
        } else {
            structure.kind = "if_region";
            structure.status = "complete";
            structure.join_block = std::get<2>(*best);
            structure.block_ids = {*edge.to_block, *false_edge->to_block, *structure.join_block};
            structure.confidence = 0.62;
            structure.reason = "two resolved CFG successors converge at a common reachable block";
            structure.evidence.push_back({"cfg_successor_convergence", structure.reason, structure.confidence});
        }
        output.control_structures.push_back(std::move(structure));
    }
    if (!blocks.empty()) {
        const auto entry = *blocks.begin();
        const auto dom = dominators(blocks, adjacency, entry);
        for (const auto& edge : semantic.cfg_edges) {
            if (edge.function_start_rva != function.start_rva || !edge.to_block || !blocks.count(edge.from_block)) continue;
            if (edge.kind == "call" || edge.kind == "indirect_call" || edge.kind == "conditional_false") continue;
            const auto target_rva = block_rva.find(*edge.to_block);
            const auto source_rva = block_rva.find(edge.from_block);
            if (target_rva == block_rva.end() || source_rva == block_rva.end() || target_rva->second > source_rva->second) continue;
            const auto dominator_set = dom.find(edge.from_block);
            if (dominator_set != dom.end() && dominator_set->second.count(*edge.to_block)) {
                ControlStructureRecord loop;
                loop.function_start_rva = function.start_rva;
                loop.kind = "natural_loop";
                loop.status = "complete";
                loop.test_rva = edge.from_rva;
                loop.block_ids = {*edge.to_block, edge.from_block};
                loop.confidence = 0.66;
                loop.reason = "back edge targets a block that dominates its source";
                loop.evidence.push_back({"cfg_dominance_back_edge", loop.reason, loop.confidence});
                output.control_structures.push_back(std::move(loop));
            } else {
                ControlStructureRecord lower_level;
                lower_level.function_start_rva = function.start_rva;
                lower_level.kind = "lower_level_cycle";
                lower_level.status = "partial";
                lower_level.test_rva = edge.from_rva;
                lower_level.block_ids = {*edge.to_block, edge.from_block};
                lower_level.reason = "backward edge is not proven to be a natural-loop back edge; preserve CFG";
                lower_level.evidence.push_back({"cfg_backward_edge", lower_level.reason, 0.0});
                output.control_structures.push_back(std::move(lower_level));
            }
        }
    }
    for (const auto& edge : semantic.cfg_edges) {
        if (edge.function_start_rva == function.start_rva && (edge.kind == "indirect_branch" || edge.kind == "unknown")) {
            ControlStructureRecord unresolved;
            unresolved.function_start_rva = function.start_rva;
            unresolved.kind = "lower_level_indirect_flow";
            unresolved.status = "unsupported";
            unresolved.test_rva = edge.from_rva;
            unresolved.reason = "indirect or unmodeled control transfer is not forced into if/loop/switch syntax";
            unresolved.evidence.push_back({"unresolved_cfg_edge", unresolved.reason, 0.0});
            output.control_structures.push_back(std::move(unresolved));
        }
    }
    if (output.control_structures.empty() || std::none_of(output.control_structures.begin(), output.control_structures.end(), [&function](const ControlStructureRecord& item) {
            return item.function_start_rva == function.start_rva;
        })) {
        ControlStructureRecord linear;
        linear.function_start_rva = function.start_rva;
        linear.kind = "linear_or_unstructured";
        linear.status = function.semantic_complete ? "complete" : "partial";
        linear.confidence = function.semantic_complete ? 0.7 : 0.0;
        linear.reason = function.semantic_complete ? "no unsupported branch structure was observed" : "function is incomplete; retain annotated disassembly and CFG";
        if (function.semantic_complete) linear.evidence.push_back({"complete_semantic_cfg", linear.reason, linear.confidence});
        output.control_structures.push_back(std::move(linear));
    }
}

std::string safe_identifier(std::string name) {
    if (name.empty()) return "sub_unknown";
    for (auto& c : name) {
        const auto value = static_cast<unsigned char>(c);
        if (!std::isalnum(value) && c != '_') c = '_';
    }
    if (std::isdigit(static_cast<unsigned char>(name.front()))) name.insert(name.begin(), '_');
    return name;
}

std::string render_operand(const X86OperandRecord& operand) {
    if (operand.type == "register") return operand.reg.empty() ? "unknown_register" : operand.reg;
    if (operand.type == "immediate") return operand.immediate < 0 ? "-" + hex_value(static_cast<std::uint64_t>(-(operand.immediate + 1)) + 1U) : hex_value(static_cast<std::uint64_t>(operand.immediate));
    if (operand.type != "memory") return "unknown_operand";
    std::ostringstream out;
    out << "MEM[";
    bool has_term = false;
    if (!operand.segment.empty()) { out << operand.segment << ':'; }
    if (!operand.base.empty()) { out << operand.base; has_term = true; }
    if (!operand.index.empty()) {
        if (has_term) out << " + ";
        out << operand.index;
        if (operand.scale > 1) out << '*' << operand.scale;
        has_term = true;
    }
    if (operand.displacement != 0 || !has_term) {
        if (has_term && operand.displacement > 0) out << " + ";
        if (has_term && operand.displacement < 0) out << " - ";
        const auto magnitude = operand.displacement < 0 ? static_cast<std::uint64_t>(-(operand.displacement + 1)) + 1U : static_cast<std::uint64_t>(operand.displacement);
        out << hex_value(magnitude);
    }
    out << ']';
    return out.str();
}

std::string instruction_pseudocode(const InstructionRecord& insn,
                                   const SemanticInstructionRecord* semantic,
                                   const ImportedCallRecord* imported) {
    const auto mnemonic = lower(insn.mnemonic);
    std::vector<std::string> operands;
    for (const auto& item : insn.detail_operands) operands.push_back(render_operand(item));
    const auto op = [&operands](std::size_t index) { return index < operands.size() ? operands[index] : std::string("unknown"); };
    if (!semantic || semantic->status != "modeled")
        return "unsupported_instruction(\"" + insn.mnemonic + (insn.operands.empty() ? "" : " " + insn.operands) + "\");";
    if (mnemonic == "ret" || mnemonic == "retq" || mnemonic == "retn") return "return rax;";
    if (mnemonic == "nop" || mnemonic == "nopl" || mnemonic == "nopw") return "/* no operation */";
    if (mnemonic == "mov" || mnemonic == "movabs" || mnemonic == "movzx" || mnemonic == "movsx" || mnemonic == "movsxd")
        return op(0) + " = " + op(1) + ";";
    if (mnemonic == "lea") return op(0) + " = address_of(" + op(1) + ");";
    if (mnemonic == "add" || mnemonic == "sub" || mnemonic == "and" || mnemonic == "or" || mnemonic == "xor" ||
        mnemonic == "adc" || mnemonic == "sbb" || mnemonic == "imul") {
        const std::map<std::string, std::string> operators = {
            {"add", "+"}, {"sub", "-"}, {"and", "&"}, {"or", "|"}, {"xor", "^"},
            {"adc", "+ with carry"}, {"sbb", "- with borrow"}, {"imul", "*"}
        };
        return op(0) + " = " + op(0) + " " + operators.at(mnemonic) + " " + op(1) + ";";
    }
    if (mnemonic == "inc" || mnemonic == "dec") return op(0) + (mnemonic == "inc" ? " += 1;" : " -= 1;");
    if (mnemonic == "cmp" || mnemonic == "test") return "compare(" + op(0) + ", " + op(1) + ");";
    if (mnemonic == "push" || mnemonic == "pushq" || mnemonic == "pushfq") return "push(" + op(0) + ");";
    if (mnemonic == "pop" || mnemonic == "popq" || mnemonic == "popfq") return op(0) + " = pop();";
    if (mnemonic == "leave") return "restore_frame_and_stack();";
    if (semantic->control_flow == "conditional_branch")
        return "if (" + semantic->condition + " /* flags predicate */) goto loc_" + hex_value(semantic->target_rva.value_or(0U)) + ";";
    if (semantic->control_flow == "direct_branch") return "goto loc_" + hex_value(semantic->target_rva.value_or(0U)) + ";";
    if (semantic->control_flow == "direct_call" || semantic->control_flow == "indirect_call") {
        if (imported) return "call " + imported->name + "(/* ABI argument registers; see report */);";
        return "call " + (semantic->target_rva ? "loc_" + hex_value(*semantic->target_rva) : "unknown_target") + "(/* see report for argument flows */);";
    }
    if (semantic->control_flow == "indirect_branch" || semantic->control_flow == "unknown")
        return "unresolved_control_transfer(/* inspect CFG and disassembly */);";
    if (!semantic->operation.empty()) return semantic->operation + "(/* operands: " + insn.operands + " */);";
    return "unsupported_instruction(\"" + insn.mnemonic + "\");";
}

} // namespace

void analyze_phase4(AnalysisReport& report) {
    auto& result = report.phase4_analysis;
    result = Phase4AnalysisRecord{};
    if (!report.pe.supported_x64_native || report.pe.clr.present) {
        result.status = "unsupported";
        result.limitations = {"Phase 4 supports native PE32+ x86-64 only"};
        report.stages.push_back({"dataflow_analysis", "unsupported"});
        return;
    }
    std::map<std::uint32_t, const InstructionRecord*> decoded;
    for (const auto& insn : report.instructions) decoded.emplace(insn.rva, &insn);
    std::vector<FunctionView> views;
    views.reserve(std::min(report.semantic_analysis.functions.size(), kMaxPhase4Functions));
    for (std::size_t i = 0; i < report.semantic_analysis.functions.size() && i < kMaxPhase4Functions; ++i) {
        FunctionView view;
        view.semantic = &report.semantic_analysis.functions[i];
        view.instructions = range_instructions(decoded, *view.semantic);
        views.push_back(std::move(view));
    }
    if (report.semantic_analysis.functions.size() > kMaxPhase4Functions)
        result.limitations.push_back("function analysis stopped at the configured 4096-function bound");
    std::map<std::uint32_t, FunctionSignatureRecord> signatures_by_start;
    std::map<std::uint32_t, std::set<std::string>> entry_arguments_by_start;
    for (const auto& view : views) {
        StackFrameRecord frame;
        analyze_frame(view, frame);
        result.stack_frames.push_back(std::move(frame));
        auto signature = infer_signature(view, report);
        auto& entry_args = entry_arguments_by_start[signature.function_start_rva];
        for (const auto& parameter : signature.parameters)
            if (parameter.location == "register") entry_args.insert(parameter.reg);
        signatures_by_start.emplace(signature.function_start_rva, signature);
        result.signatures.push_back(std::move(signature));
    }

    for (const auto& view : views) {
        if (view.instructions.empty()) continue;
        auto caller = signatures_by_start.find(view.semantic->start_rva);
        if (caller == signatures_by_start.end() || !caller->second.parameters.empty()) continue;
        const auto* tail = view.instructions.back();
        const auto tail_semantic = std::find_if(report.semantic_analysis.instructions.begin(), report.semantic_analysis.instructions.end(), [tail](const SemanticInstructionRecord& item) {
            return item.rva == tail->rva;
        });
        if (tail_semantic == report.semantic_analysis.instructions.end() || tail_semantic->control_flow != "direct_branch" || !tail_semantic->target_rva) continue;
        const auto target = signatures_by_start.find(*tail_semantic->target_rva);
        if (target == signatures_by_start.end() || target->second.parameters.empty()) continue;
        bool copied = false;
        for (const auto& target_parameter : target->second.parameters) {
            if (target_parameter.location != "register") continue;
            const auto register_name = canonical_register(target_parameter.reg);
            const bool modified = std::any_of(view.instructions.begin(), std::prev(view.instructions.end()), [&register_name](const InstructionRecord* insn) {
                return has_register(insn->registers_written, register_name);
            });
            if (modified) continue;
            AbiParameterRecord parameter = target_parameter;
            parameter.confidence = 0.72;
            parameter.evidence.push_back({"unmodified_tail_call_argument_forwarding",
                "bounded function ends in a direct tail branch to a known function and does not write this ABI argument register", 0.72});
            caller->second.parameters.push_back(std::move(parameter));
            entry_arguments_by_start[view.semantic->start_rva].insert(register_name);
            copied = true;
        }
        if (copied) {
            caller->second.confidence = 0.72;
            caller->second.evidence.push_back({"direct_tail_call_signature_forwarding",
                "argument locations are forwarded to a bounded callee without a local register definition; source types remain unknown", 0.72});
            auto output_signature = std::find_if(result.signatures.begin(), result.signatures.end(), [&view](const FunctionSignatureRecord& item) {
                return item.function_start_rva == view.semantic->start_rva;
            });
            if (output_signature != result.signatures.end()) *output_signature = caller->second;
        }
    }

    static const std::array<const char*, 4> pdb_argument_registers = {"rcx", "rdx", "r8", "r9"};
    for (auto& signature : result.signatures) {
        const auto pdb_symbol = std::find_if(report.symbols.functions.begin(), report.symbols.functions.end(), [&signature](const PdbFunctionSymbol& item) {
            return item.start_rva == signature.function_start_rva && item.type_index.has_value();
        });
        if (pdb_symbol == report.symbols.functions.end() || pdb_symbol->type_status == "unknown") continue;
        signature.parameters.clear();
        for (std::size_t index = 0; index < pdb_symbol->parameter_types.size(); ++index) {
            AbiParameterRecord parameter;
            parameter.index = static_cast<std::uint32_t>(index);
            if (index < pdb_argument_registers.size()) {
                parameter.location = "register";
                parameter.reg = pdb_argument_registers[index];
            } else {
                parameter.location = "stack";
                parameter.stack_offset = static_cast<std::int64_t>(40U + (index - 4U) * 8U);
            }
            parameter.type = pdb_symbol->parameter_types[index];
            parameter.type_status = parameter.type == "unknown" ? "unknown" : "observed";
            parameter.confidence = pdb_symbol->type_status == "decoded" ? 0.99 : 0.75;
            parameter.evidence.push_back({"pdb_tpi_procedure_record",
                "parameter count/type index came from the PE-identity-matched PDB; ABI location follows Microsoft x64", parameter.confidence});
            if (parameter.location == "register") entry_arguments_by_start[signature.function_start_rva].insert(parameter.reg);
            signature.parameters.push_back(std::move(parameter));
        }
        if (pdb_symbol->return_type != "unknown") {
            signature.return_type = pdb_symbol->return_type;
            signature.return_type_status = "observed";
        }
        signature.status = pdb_symbol->type_status == "decoded" ? "complete" : "partial";
        signature.confidence = pdb_symbol->type_status == "decoded" ? 0.99 : 0.75;
        signature.evidence.push_back({"pdb_tpi_procedure_record",
            "function prototype is read from the PDB TPI record after the PE CodeView GUID/age matched", signature.confidence});
        signatures_by_start[signature.function_start_rva] = signature;
    }

    std::map<std::pair<std::uint32_t, std::uint32_t>, ImportedCallRecord> imported_calls;
    for (const auto& view : views) {
        std::map<std::string, const InstructionRecord*> last_definitions;
        for (const auto* insn : view.instructions) {
            const auto mnemonic = lower(insn->mnemonic);
            const bool is_call = mnemonic == "call" || mnemonic == "callq";
            if (is_call) {
                const auto iat = imported_iat_target(report.pe, *insn);
                const auto target_sem = std::find_if(report.semantic_analysis.instructions.begin(), report.semantic_analysis.instructions.end(), [insn](const SemanticInstructionRecord& item) {
                    return item.rva == insn->rva;
                });
                std::optional<std::uint32_t> target;
                if (target_sem != report.semantic_analysis.instructions.end()) target = target_sem->target_rva;
                std::string callee = "unknown_target";
                std::size_t argument_count = 0U;
                const Prototype* prototype = nullptr;
                const PeImport* imported = nullptr;
                if (iat) {
                    const auto item = std::find_if(report.pe.imports.begin(), report.pe.imports.end(), [iat](const PeImport& value) { return value.iat_rva == *iat; });
                    if (item != report.pe.imports.end()) {
                        imported = &*item;
                        callee = item->name.empty() ? "ordinal_" + std::to_string(item->ordinal) : item->name;
                        prototype = prototype_for(item->name);
                        if (prototype) argument_count = prototype->parameters.size();
                    }
                }
                const FunctionSignatureRecord* target_signature = nullptr;
                if (!imported && target) {
                    const auto found = signatures_by_start.find(*target);
                    if (found != signatures_by_start.end()) {
                        target_signature = &found->second;
                        callee = target_signature->label.empty() ? "sub_" + hex_value(*target) : target_signature->label;
                        argument_count = target_signature->parameters.size();
                    }
                }
                const auto entry_args = entry_arguments_by_start.find(view.semantic->start_rva);
                const std::set<std::string> empty_args;
                auto flows = call_arguments_for(view, *insn, argument_count, last_definitions,
                    entry_args == entry_arguments_by_start.end() ? empty_args : entry_args->second, target, callee);
                if (imported && iat) {
                    ImportedCallRecord record;
                    record.caller_start_rva = view.semantic->start_rva;
                    record.call_rva = insn->rva;
                    record.iat_rva = *iat;
                    record.library = imported->library;
                    record.name = imported->name.empty() ? "ordinal_" + std::to_string(imported->ordinal) : imported->name;
                    record.arguments = std::move(flows);
                    if (prototype) {
                        record.prototype_status = "catalogued";
                        record.return_type = prototype->result;
                        record.parameter_types = prototype->parameters;
                        record.prototype_source = "windows_sdk_prototype_catalog_v1";
                        record.confidence = 0.88;
                    } else {
                        record.prototype_status = "unknown";
                        record.prototype_source = "none";
                        record.confidence = 0.0;
                    }
                    imported_calls.emplace(std::make_pair(record.caller_start_rva, record.call_rva), std::move(record));
                } else {
                    for (auto& flow : flows) result.call_argument_flows.push_back(std::move(flow));
                    (void)target_signature;
                }
            }
            for (const auto& reg : insn->registers_written) {
                const auto canonical = canonical_register(reg);
                if (!canonical.empty()) last_definitions[canonical] = insn;
            }
        }
    }
    for (auto& item : imported_calls) {
        result.imported_calls.push_back(std::move(item.second));
        for (const auto& flow : result.imported_calls.back().arguments) result.call_argument_flows.push_back(flow);
    }
    for (const auto& function : report.semantic_analysis.functions)
        recover_structures(function, report.semantic_analysis, result);

    result.limitations.push_back("PDB TPI support is limited to procedure/argument-list records and scalar/modifier/pointer types; UDT layouts, RTTI, vtables, and general aggregate types remain unknown");
    result.limitations.push_back("register reaching definitions use a bounded linear scan and are not path-sensitive; call-argument provenance is labelled accordingly");
    result.limitations.push_back("indirect jump tables are not recognized as switches; unresolved or irreducible flow stays in the CFG/disassembly representation");
    result.limitations.push_back("confidence values are evidence-strength labels; calibration is measured only by the checked-in Gate 4 ground-truth benchmark");
    result.status = "partial";
    report.stages.push_back({"dataflow_analysis", result.status});
}

std::string emit_pseudocode(const AnalysisReport& report) {
    std::ostringstream out;
    out << "NexussREV best-effort C-like pseudocode\n"
        << "NOTICE: This is an incomplete analysis representation, not original source,\n"
        << "not guaranteed compilable, and not an equivalence or correctness claim.\n"
        << "Input SHA-256: " << report.input_sha256 << "\n"
        << "ABI model: Microsoft x64; unknown types and unresolved flow are intentional.\n\n";
    std::map<std::uint32_t, const SemanticInstructionRecord*> semantic;
    for (const auto& item : report.semantic_analysis.instructions) semantic.emplace(item.rva, &item);
    std::map<std::uint32_t, const ImportedCallRecord*> imported;
    for (const auto& item : report.phase4_analysis.imported_calls) imported.emplace(item.call_rva, &item);
    if (report.semantic_analysis.functions.empty()) out << "/* No candidate functions are available; use the annotated disassembly and JSON report. */\n";
    for (const auto& function : report.semantic_analysis.functions) {
        const auto signature = std::find_if(report.phase4_analysis.signatures.begin(), report.phase4_analysis.signatures.end(), [&function](const FunctionSignatureRecord& item) {
            return item.function_start_rva == function.start_rva;
        });
        const auto frame = std::find_if(report.phase4_analysis.stack_frames.begin(), report.phase4_analysis.stack_frames.end(), [&function](const StackFrameRecord& item) {
            return item.function_start_rva == function.start_rva;
        });
        const auto structures = std::count_if(report.phase4_analysis.control_structures.begin(), report.phase4_analysis.control_structures.end(), [&function](const ControlStructureRecord& item) {
            return item.function_start_rva == function.start_rva && item.status == "complete";
        });
        const std::string name = safe_identifier(function.label.empty() ? "sub_" + hex_value(function.start_rva) : function.label);
        out << "/* function RVA=" << hex_value(function.start_rva) << " end=";
        if (function.end_rva) out << hex_value(*function.end_rva); else out << "unknown";
        out << " semantic=" << function.status << " recovered_structures=" << structures << " */\n";
        const std::string return_type = signature != report.phase4_analysis.signatures.end() ? signature->return_type : "unknown";
        out << return_type << ' ' << name << '(';
        if (signature != report.phase4_analysis.signatures.end() && !signature->parameters.empty()) {
            for (std::size_t i = 0; i < signature->parameters.size(); ++i) {
                const auto& parameter = signature->parameters[i];
                if (i) out << ", ";
                out << (parameter.type.empty() ? "unknown" : parameter.type) << " arg" << parameter.index;
                if (parameter.location == "register") out << " /* " << parameter.reg << ", confidence=" << parameter.confidence << " */";
                else if (parameter.stack_offset) out << " /* stack+" << *parameter.stack_offset << " */";
            }
        } else out << "/* parameters unknown */";
        out << ") /* return type " << (return_type == "unknown" ? "unknown" : "observed: " + return_type) << " */ {\n";
        if (frame != report.phase4_analysis.stack_frames.end()) {
            if (frame->max_stack_depth_bytes_below_entry_rsp)
                out << "    /* max observed stack depth below entry RSP: " << *frame->max_stack_depth_bytes_below_entry_rsp << " bytes */\n";
            else out << "    /* stack depth unknown */\n";
            for (const auto& variable : frame->variables)
                out << "    unknown " << variable.name << "; /* entry-RSP offset=" << variable.stack_offset.value_or(0)
                    << ", observed size=" << static_cast<unsigned int>(variable.size) << " bytes; type unknown */\n";
            for (const auto& issue : frame->issues) out << "    /* frame limitation: " << issue << " */\n";
        }
        for (const auto& structure : report.phase4_analysis.control_structures) {
            if (structure.function_start_rva == function.start_rva)
                out << "    /* control structure: " << structure.kind << " (" << structure.status << "): " << structure.reason << " */\n";
        }
        if (!function.end_rva) {
            out << "    /* Unbounded candidate: no instructions are assigned beyond its evidence-backed range. */\n";
        } else {
            for (const auto& insn : report.instructions) {
                if (insn.rva < function.start_rva || insn.rva >= *function.end_rva) continue;
                const auto sem = semantic.find(insn.rva);
                const auto import = imported.find(insn.rva);
                out << "    /* RVA " << hex_value(insn.rva) << ": " << insn.mnemonic;
                if (!insn.operands.empty()) out << ' ' << insn.operands;
                out << " */\n    " << instruction_pseudocode(insn,
                    sem == semantic.end() ? nullptr : sem->second,
                    import == imported.end() ? nullptr : import->second) << "\n";
            }
        }
        out << "}\n\n";
    }
    for (const auto& limitation : report.phase4_analysis.limitations) out << "/* limitation: " << limitation << " */\n";
    auto result = out.str();
    if (result.size() > kMaxPseudocodeBytes) throw std::runtime_error("pseudocode exceeds the configured 16 MiB output limit");
    return result;
}

std::string phase4_analysis_to_json(const Phase4AnalysisRecord& r) {
    std::ostringstream out;
    out << "{\"status\":\"" << json_escape(r.status) << "\",\"backend\":\"" << json_escape(r.backend)
        << "\",\"abi\":\"" << json_escape(r.abi) << "\",\"stack_frames\":[";
    for (std::size_t i = 0; i < r.stack_frames.size(); ++i) {
        const auto& frame = r.stack_frames[i];
        out << (i ? "," : "") << "{\"function_start_rva\":" << frame.function_start_rva
            << ",\"status\":\"" << json_escape(frame.status) << "\",\"has_frame_pointer\":" << (frame.has_frame_pointer ? "true" : "false")
            << ",\"frame_pointer_register\":\"" << json_escape(frame.frame_pointer_register) << "\",\"max_stack_depth_bytes_below_entry_rsp\":";
        if (frame.max_stack_depth_bytes_below_entry_rsp) out << *frame.max_stack_depth_bytes_below_entry_rsp; else out << "null";
        out << ",\"variables\":[";
        for (std::size_t j = 0; j < frame.variables.size(); ++j) {
            const auto& variable = frame.variables[j];
            out << (j ? "," : "") << "{\"name\":\"" << json_escape(variable.name) << "\",\"storage\":\"" << json_escape(variable.storage)
                << "\",\"stack_offset\":";
            emit_optional_i64(out, variable.stack_offset);
            out << ",\"register\":\"" << json_escape(variable.reg) << "\",\"size\":" << static_cast<unsigned int>(variable.size)
                << ",\"type\":\"" << json_escape(variable.type) << "\",\"confidence\":" << variable.confidence
                << ",\"read_count\":" << variable.read_count << ",\"write_count\":" << variable.write_count << ",\"evidence\":";
            emit_evidence(out, variable.evidence);
            out << '}';
        }
        out << "],\"issues\":";
        emit_strings(out, frame.issues);
        out << '}';
    }
    out << "],\"signatures\":[";
    for (std::size_t i = 0; i < r.signatures.size(); ++i) {
        const auto& signature = r.signatures[i];
        out << (i ? "," : "") << "{\"function_start_rva\":" << signature.function_start_rva
            << ",\"label\":\"" << json_escape(signature.label) << "\",\"status\":\"" << json_escape(signature.status)
            << "\",\"calling_convention\":\"" << json_escape(signature.calling_convention)
            << "\",\"return_type\":\"" << json_escape(signature.return_type) << "\",\"return_type_status\":\""
            << json_escape(signature.return_type_status) << "\",\"confidence\":" << signature.confidence << ",\"evidence\":";
        emit_evidence(out, signature.evidence);
        out << ",\"parameters\":[";
        for (std::size_t j = 0; j < signature.parameters.size(); ++j) {
            const auto& parameter = signature.parameters[j];
            out << (j ? "," : "") << "{\"index\":" << parameter.index << ",\"location\":\"" << json_escape(parameter.location)
                << "\",\"register\":\"" << json_escape(parameter.reg) << "\",\"stack_offset\":";
            emit_optional_i64(out, parameter.stack_offset);
            out << ",\"type\":\"" << json_escape(parameter.type) << "\",\"type_status\":\"" << json_escape(parameter.type_status)
                << "\",\"confidence\":" << parameter.confidence << ",\"evidence\":";
            emit_evidence(out, parameter.evidence);
            out << '}';
        }
        out << "]}";
    }
    const auto emit_flow = [&out](const CallArgumentFlowRecord& flow) {
        out << "{\"caller_start_rva\":" << flow.caller_start_rva << ",\"call_rva\":" << flow.call_rva << ",\"target_rva\":";
        if (flow.target_rva) out << *flow.target_rva; else out << "null";
        out << ",\"callee\":\"" << json_escape(flow.callee) << "\",\"parameter_index\":" << flow.parameter_index
            << ",\"argument_register\":\"" << json_escape(flow.argument_register) << "\",\"source_kind\":\""
            << json_escape(flow.source_kind) << "\",\"source_description\":\"" << json_escape(flow.source_description) << "\",\"source_rva\":";
        if (flow.source_rva) out << *flow.source_rva; else out << "null";
        out << ",\"confidence\":" << flow.confidence << ",\"evidence\":";
        emit_evidence(out, flow.evidence);
        out << '}';
    };
    out << "],\"call_argument_flows\":[";
    for (std::size_t i = 0; i < r.call_argument_flows.size(); ++i) { if (i) out << ','; emit_flow(r.call_argument_flows[i]); }
    out << "],\"imported_calls\":[";
    for (std::size_t i = 0; i < r.imported_calls.size(); ++i) {
        const auto& call = r.imported_calls[i];
        out << (i ? "," : "") << "{\"caller_start_rva\":" << call.caller_start_rva << ",\"call_rva\":" << call.call_rva
            << ",\"iat_rva\":" << call.iat_rva << ",\"library\":\"" << json_escape(call.library)
            << "\",\"name\":\"" << json_escape(call.name) << "\",\"prototype_status\":\"" << json_escape(call.prototype_status)
            << "\",\"return_type\":\"" << json_escape(call.return_type) << "\",\"parameter_types\":[";
        for (std::size_t j = 0; j < call.parameter_types.size(); ++j) out << (j ? "," : "") << '"' << json_escape(call.parameter_types[j]) << '"';
        out << "],\"prototype_source\":\"" << json_escape(call.prototype_source) << "\",\"confidence\":" << call.confidence
            << ",\"arguments\":[";
        for (std::size_t j = 0; j < call.arguments.size(); ++j) { if (j) out << ','; emit_flow(call.arguments[j]); }
        out << "]}";
    }
    out << "],\"control_structures\":[";
    for (std::size_t i = 0; i < r.control_structures.size(); ++i) {
        const auto& item = r.control_structures[i];
        out << (i ? "," : "") << "{\"function_start_rva\":" << item.function_start_rva << ",\"kind\":\"" << json_escape(item.kind)
            << "\",\"status\":\"" << json_escape(item.status) << "\",\"test_rva\":";
        if (item.test_rva) out << *item.test_rva; else out << "null";
        out << ",\"join_block\":";
        if (item.join_block) out << *item.join_block; else out << "null";
        out << ",\"block_ids\":[";
        for (std::size_t j = 0; j < item.block_ids.size(); ++j) out << (j ? "," : "") << item.block_ids[j];
        out << "],\"confidence\":" << item.confidence << ",\"reason\":\"" << json_escape(item.reason) << "\",\"evidence\":";
        emit_evidence(out, item.evidence);
        out << '}';
    }
    out << "],\"limitations\":";
    emit_strings(out, r.limitations);
    out << '}';
    return out.str();
}

} // namespace nexusrev
