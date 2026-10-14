#include "phase3.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace nexusrev {
namespace {
constexpr std::size_t kMaxSemanticInstructions = 20000U;
constexpr std::size_t kMaxSemanticFunctions = 4096U;
constexpr std::size_t kMaxSemanticBlocks = 40000U;
constexpr std::size_t kMaxReferenceBytes = 16U * 1024U * 1024U;
constexpr std::size_t kMaxReferenceRows = 200000U;

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

void add_unique(std::vector<std::string>& values, const std::string& value) {
    if (!value.empty() && std::find(values.begin(), values.end(), value) == values.end())
        values.push_back(value);
}

std::size_t instruction_size(const InstructionRecord& insn) {
    return insn.bytes.empty() ? 0U : 1U + static_cast<std::size_t>(std::count(insn.bytes.begin(), insn.bytes.end(), ' '));
}

bool has_operand_access(const X86OperandRecord& op, unsigned int access) {
    return (static_cast<unsigned int>(op.access) & access) != 0U;
}

bool is_one_of(const std::string& value, std::initializer_list<const char*> choices) {
    return std::any_of(choices.begin(), choices.end(), [&value](const char* choice) { return value == choice; });
}

std::string canonical_condition(const std::string& mnemonic) {
    if (is_one_of(mnemonic, {"je", "jz", "cmove", "cmovz", "sete", "setz"})) return "equal";
    if (is_one_of(mnemonic, {"jne", "jnz", "cmovne", "cmovnz", "setne", "setnz"})) return "not_equal";
    if (is_one_of(mnemonic, {"jb", "jc", "jnae", "cmovb", "cmovc", "cmovnae", "setb", "setc", "setnae"})) return "unsigned_below";
    if (is_one_of(mnemonic, {"jae", "jnb", "jnc", "cmovae", "cmovnb", "cmovnc", "setae", "setnb", "setnc"})) return "unsigned_above_or_equal";
    if (is_one_of(mnemonic, {"jbe", "jna", "cmovbe", "cmovna", "setbe", "setna"})) return "unsigned_below_or_equal";
    if (is_one_of(mnemonic, {"ja", "jnbe", "cmova", "cmovnbe", "seta", "setnbe"})) return "unsigned_above";
    if (is_one_of(mnemonic, {"jl", "jnge", "cmovl", "cmovnge", "setl", "setnge"})) return "signed_less";
    if (is_one_of(mnemonic, {"jge", "jnl", "cmovge", "cmovnl", "setge", "setnl"})) return "signed_greater_or_equal";
    if (is_one_of(mnemonic, {"jle", "jng", "cmovle", "cmovng", "setle", "setng"})) return "signed_less_or_equal";
    if (is_one_of(mnemonic, {"jg", "jnle", "cmovg", "cmovnle", "setg", "setnle"})) return "signed_greater";
    if (is_one_of(mnemonic, {"jo", "cmovo", "seto"})) return "overflow";
    if (is_one_of(mnemonic, {"jno", "cmovno", "setno"})) return "not_overflow";
    if (is_one_of(mnemonic, {"js", "cmovs", "sets"})) return "sign";
    if (is_one_of(mnemonic, {"jns", "cmovns", "setns"})) return "not_sign";
    if (is_one_of(mnemonic, {"jp", "jpe", "cmovp", "cmovpe", "setp", "setpe"})) return "parity_even";
    if (is_one_of(mnemonic, {"jnp", "jpo", "cmovnp", "cmovpo", "setnp", "setpo"})) return "parity_odd";
    return {};
}

std::vector<std::string> condition_flags(const std::string& condition) {
    if (condition == "equal" || condition == "not_equal") return {"ZF"};
    if (condition == "unsigned_below" || condition == "unsigned_above_or_equal") return {"CF"};
    if (condition == "unsigned_below_or_equal" || condition == "unsigned_above") return {"CF", "ZF"};
    if (condition == "signed_less" || condition == "signed_greater_or_equal") return {"SF", "OF"};
    if (condition == "signed_less_or_equal" || condition == "signed_greater") return {"ZF", "SF", "OF"};
    if (condition == "overflow" || condition == "not_overflow") return {"OF"};
    if (condition == "sign" || condition == "not_sign") return {"SF"};
    if (condition == "parity_even" || condition == "parity_odd") return {"PF"};
    return {};
}

bool is_conditional_branch(const std::string& mnemonic) {
    if (!mnemonic.empty() && mnemonic[0] == 'j' && canonical_condition(mnemonic).size() != 0U) return true;
    return is_one_of(mnemonic, {"jcxz", "jecxz", "jrcxz"});
}

bool is_cmov_or_set(const std::string& mnemonic) {
    return mnemonic.rfind("cmov", 0U) == 0U || mnemonic.rfind("set", 0U) == 0U;
}

std::optional<std::uint32_t> direct_target(const PeImage& pe, const InstructionRecord& insn) {
    for (const auto& operand : insn.detail_operands) {
        if (operand.type != "immediate" || operand.immediate < 0) continue;
        std::uint32_t rva = 0;
        if (pe.va_to_rva(static_cast<std::uint64_t>(operand.immediate), rva)) return rva;
    }
    return std::nullopt;
}

bool has_direct_immediate_operand(const InstructionRecord& insn) {
    return std::any_of(insn.detail_operands.begin(), insn.detail_operands.end(),
        [](const X86OperandRecord& operand) { return operand.type == "immediate"; });
}

bool has_operand_size_override(const InstructionRecord& insn) {
    return std::find(insn.prefixes.begin(), insn.prefixes.end(), static_cast<std::uint8_t>(0x66U)) != insn.prefixes.end();
}

std::int32_t stack_operand_width(const InstructionRecord& insn) {
    return has_operand_size_override(insn) ? 2 : 8;
}

bool may_transfer_control(const InstructionRecord& insn) {
    for (const auto& group : insn.groups)
        if (is_one_of(group, {"jump", "call", "ret", "iret", "branch_relative", "int"})) return true;
    const auto& m = insn.mnemonic;
    return (!m.empty() && (m[0] == 'j' || m.rfind("loop", 0U) == 0U || m.rfind("ret", 0U) == 0U ||
                           m.rfind("iret", 0U) == 0U || m.rfind("ljmp", 0U) == 0U || m.rfind("lcall", 0U) == 0U)) ||
        is_one_of(m, {"call", "callq", "jmp", "jmpq", "syscall", "sysret", "sysenter", "sysexit",
                      "int", "int1", "int3", "into", "hlt", "ud2", "ud2b", "icebp"});
}

void flag_writes_arithmetic(SemanticInstructionRecord& sem, bool preserve_cf = false) {
    for (const auto* flag : {"CF", "PF", "AF", "ZF", "SF", "OF"}) {
        if (preserve_cf && std::string(flag) == "CF") add_unique(sem.flags_preserved, flag);
        else add_unique(sem.flags_written, flag);
    }
}

void flag_writes_logical(SemanticInstructionRecord& sem) {
    for (const auto* flag : {"CF", "PF", "ZF", "SF", "OF"}) add_unique(sem.flags_written, flag);
    add_unique(sem.flags_undefined, "AF");
}

void derive_operand_effects(SemanticInstructionRecord& sem, const std::string& mnemonic) {
    for (std::size_t index = 0; index < sem.operands.size(); ++index) {
        const auto& op = sem.operands[index];
        if (op.type == "register") {
            if (has_operand_access(op, 1U)) add_unique(sem.registers_read, op.reg);
            if (has_operand_access(op, 2U)) add_unique(sem.registers_written, op.reg);
            continue;
        }
        if (op.type != "memory") continue;
        const bool move_or_lea = is_one_of(mnemonic, {"mov", "movabs", "movzx", "movsx", "movsxd", "lea"});
        const bool compare = is_one_of(mnemonic, {"cmp", "test"});
        const bool stack_pop = mnemonic == "pop" || mnemonic == "popq";
        const bool stack_push = mnemonic == "push" || mnemonic == "pushq" || mnemonic == "pushfq";
        if (has_operand_access(op, 1U) || (!op.access && index > 0U) || compare || stack_push ||
            (!move_or_lea && !stack_pop && index == 0U)) sem.memory_read = true;
        if (has_operand_access(op, 2U) || (!op.access && stack_pop) ||
            (!move_or_lea && !compare && !stack_push && !stack_pop && index == 0U)) sem.memory_written = true;
        add_unique(sem.registers_read, op.base);
        add_unique(sem.registers_read, op.index);
        add_unique(sem.registers_read, op.segment);
    }
}

SemanticInstructionRecord lift_one(const PeImage& pe, const InstructionRecord& insn) {
    SemanticInstructionRecord sem;
    sem.rva = insn.rva;
    sem.operands = insn.detail_operands;
    sem.registers_read = insn.registers_read;
    sem.registers_written = insn.registers_written;
    const std::string& m = insn.mnemonic;
    if (!insn.detail_available) {
        sem.control_flow = "unknown";
        sem.unresolved_reason = "decoder_detail_unavailable_control_flow_unknown";
        return sem;
    }

    const bool conditional = is_conditional_branch(m);
    const bool cmov_set = is_cmov_or_set(m);
    const bool direct_call = m == "call" || m == "callq";
    const bool jump = m == "jmp" || m == "jmpq";
    const bool return_instruction = is_one_of(m, {"ret", "retq", "retn"});
    const bool push = is_one_of(m, {"push", "pushq", "pushfq"});
    const bool pop = is_one_of(m, {"pop", "popq", "popfq"});

    if ((m == "leave" && has_operand_size_override(insn)) ||
        ((m == "pushfq" || m == "popfq") && has_operand_size_override(insn))) {
        sem.unresolved_reason = "operand_size_override_semantics_not_implemented";
        return sem;
    }
    if (pop && !insn.detail_operands.empty() && insn.detail_operands[0].type == "register" &&
        insn.detail_operands[0].reg == "rsp") {
        sem.unresolved_reason = "pop_rsp_stack_effect_not_implemented";
        return sem;
    }

    if (is_one_of(m, {"nop", "nopl", "nopw"})) sem.operation = "nop";
    else if (is_one_of(m, {"mov", "movabs"})) sem.operation = "copy";
    else if (is_one_of(m, {"movzx", "movsx", "movsxd"})) sem.operation = m;
    else if (m == "lea") sem.operation = "address_of";
    else if (m == "add" || m == "sub" || m == "adc" || m == "sbb") sem.operation = m;
    else if (m == "inc" || m == "dec" || m == "neg") sem.operation = m;
    else if (m == "and" || m == "or" || m == "xor" || m == "not") sem.operation = m;
    else if (m == "cmp" || m == "test") sem.operation = m;
    else if (m == "imul" || m == "mul" || m == "div" || m == "idiv") sem.operation = m;
    else if (m == "xchg") sem.operation = "exchange";
    else if (push) sem.operation = "push";
    else if (pop) sem.operation = "pop";
    else if (m == "leave") sem.operation = "leave";
    else if (direct_call) sem.operation = "call";
    else if (jump) sem.operation = "branch";
    else if (conditional) sem.operation = "conditional_branch";
    else if (cmov_set) sem.operation = m.rfind("cmov", 0U) == 0U ? "conditional_copy" : "conditional_set";
    else if (return_instruction) sem.operation = "return";
    else {
        if (may_transfer_control(insn)) {
            sem.control_flow = "unknown";
            sem.unresolved_reason = "unsupported_control_flow_semantics";
        } else {
            sem.unresolved_reason = "instruction_semantics_not_implemented";
        }
        return sem;
    }
    if (cmov_set && canonical_condition(m).empty()) {
        sem.operation.clear();
        sem.unresolved_reason = "condition_code_semantics_not_implemented";
        return sem;
    }

    sem.status = "modeled";
    derive_operand_effects(sem, m);
    if (sem.operation == "add" || sem.operation == "sub" || sem.operation == "adc" ||
        sem.operation == "sbb" || sem.operation == "cmp" || sem.operation == "neg") {
        if (m == "adc" || m == "sbb") add_unique(sem.flags_read, "CF");
        flag_writes_arithmetic(sem);
    } else if (sem.operation == "inc" || sem.operation == "dec") {
        flag_writes_arithmetic(sem, true);
    } else if (m == "and" || m == "or" || m == "xor" || m == "test") {
        flag_writes_logical(sem);
    } else if (m == "not") {
        for (const auto* flag : {"CF", "PF", "AF", "ZF", "SF", "OF"}) add_unique(sem.flags_preserved, flag);
    } else if (m == "imul" || m == "mul") {
        add_unique(sem.flags_written, "CF"); add_unique(sem.flags_written, "OF");
        for (const auto* flag : {"PF", "AF", "ZF", "SF"}) add_unique(sem.flags_undefined, flag);
    } else if (m == "div" || m == "idiv") {
        for (const auto* flag : {"CF", "PF", "AF", "ZF", "SF", "OF"}) add_unique(sem.flags_undefined, flag);
    } else if (conditional || cmov_set) {
        sem.condition = canonical_condition(m);
        sem.flags_read = condition_flags(sem.condition);
        if (sem.condition.empty()) {
            // JCXZ/JECXZ/JRCXZ test a counter register rather than RFLAGS.
            if (m == "jcxz") add_unique(sem.registers_read, "cx");
            else if (m == "jecxz") add_unique(sem.registers_read, "ecx");
            else if (m == "jrcxz") add_unique(sem.registers_read, "rcx");
        }
    } else if (m == "pushfq") {
        add_unique(sem.flags_read, "RFLAGS");
    } else if (m == "popfq") {
        add_unique(sem.flags_written, "RFLAGS");
    }
    if (m == "xchg") {
        for (const auto& op : sem.operands) if (op.type == "register") {
            add_unique(sem.registers_read, op.reg);
            add_unique(sem.registers_written, op.reg);
        }
    }

    if (push) {
        sem.stack_action = "decrement_rsp_then_store_operand";
        sem.stack_delta = -stack_operand_width(insn);
        sem.memory_written = true;
        add_unique(sem.registers_read, "rsp"); add_unique(sem.registers_written, "rsp");
    } else if (pop) {
        sem.stack_action = "load_operand_then_increment_rsp";
        sem.stack_delta = stack_operand_width(insn);
        sem.memory_read = true;
        add_unique(sem.registers_read, "rsp"); add_unique(sem.registers_written, "rsp");
    } else if (direct_call) {
        sem.stack_action = "push_return_address_then_restore_after_callee_returns";
        sem.stack_delta = 0;
        sem.memory_written = true;
        add_unique(sem.registers_read, "rsp"); add_unique(sem.registers_written, "rsp");
        for (const auto* reg : {"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"})
            add_unique(sem.registers_written, reg);
        add_unique(sem.flags_undefined, "RFLAGS");
    } else if (return_instruction) {
        sem.stack_action = "load_return_address_then_increment_rsp";
        std::int32_t adjustment = stack_operand_width(insn);
        for (const auto& op : sem.operands) {
            if (op.type == "immediate" && op.immediate >= 0 && op.immediate <= 65535) {
                adjustment += static_cast<std::int32_t>(op.immediate);
                break;
            }
        }
        sem.stack_delta = adjustment;
        sem.memory_read = true;
        add_unique(sem.registers_read, "rsp"); add_unique(sem.registers_written, "rsp");
    } else if (m == "leave") {
        sem.stack_action = "rsp_equals_rbp_then_pop_rbp";
        add_unique(sem.registers_read, "rbp"); add_unique(sem.registers_read, "rsp");
        add_unique(sem.registers_written, "rbp"); add_unique(sem.registers_written, "rsp");
        sem.memory_read = true;
    }

    if (!direct_call && m != "popfq") {
        for (const auto* flag : {"CF", "PF", "AF", "ZF", "SF", "OF"}) {
            if (std::find(sem.flags_written.begin(), sem.flags_written.end(), flag) == sem.flags_written.end() &&
                std::find(sem.flags_undefined.begin(), sem.flags_undefined.end(), flag) == sem.flags_undefined.end())
                add_unique(sem.flags_preserved, flag);
        }
    }
    if (conditional) {
        sem.control_flow = "conditional_branch";
        sem.target_rva = direct_target(pe, insn);
        if (!sem.target_rva) sem.unresolved_reason = has_direct_immediate_operand(insn) ?
            "conditional_branch_target_outside_image" : "conditional_branch_target_indirect";
    } else if (jump) {
        sem.target_rva = direct_target(pe, insn);
        const bool direct = has_direct_immediate_operand(insn);
        sem.control_flow = direct ? "direct_branch" : "indirect_branch";
        if (!sem.target_rva) sem.unresolved_reason = direct ?
            "direct_branch_target_outside_image" : "indirect_branch_destination_unknown";
    } else if (direct_call) {
        sem.target_rva = direct_target(pe, insn);
        const bool direct = has_direct_immediate_operand(insn);
        sem.control_flow = direct ? "direct_call" : "indirect_call";
        if (!sem.target_rva) sem.unresolved_reason = direct ?
            "direct_call_target_outside_image" : "indirect_call_destination_unknown";
    } else if (return_instruction) {
        sem.control_flow = "return";
    } else {
        sem.control_flow = "fallthrough";
    }
    return sem;
}

std::string provenance(const FunctionRecord& function) {
    if (!function.evidence.empty()) return function.evidence.front().source;
    return function.entity_kind;
}

void issue(SemanticFunctionRecord& function, std::string code, bool unresolved_flow = true) {
    if (std::find(function.issues.begin(), function.issues.end(), code) == function.issues.end()) {
        function.issues.push_back(std::move(code));
        if (unresolved_flow) ++function.unresolved_control_flow_count;
    }
}

struct FlowKey {
    std::uint32_t from = 0;
    std::string kind;
    std::optional<std::uint32_t> target;
    bool operator<(const FlowKey& rhs) const {
        return std::tie(from, kind, target) < std::tie(rhs.from, rhs.kind, rhs.target);
    }
};

bool parse_u32(const std::string& text, std::uint32_t& value) {
    if (text.empty() || text[0] == '-') return false;
    try {
        std::size_t used = 0;
        const unsigned long long parsed = std::stoull(text, &used, 10);
        if (used != text.size() || parsed > std::numeric_limits<std::uint32_t>::max()) return false;
        value = static_cast<std::uint32_t>(parsed);
        return true;
    } catch (...) { return false; }
}

std::vector<std::string> split_tabs(const std::string& line) {
    std::vector<std::string> fields;
    std::size_t start = 0;
    while (true) {
        const auto tab = line.find('\t', start);
        if (tab == std::string::npos) { fields.push_back(line.substr(start)); break; }
        fields.push_back(line.substr(start, tab - start));
        start = tab + 1U;
    }
    return fields;
}

} // namespace

void analyze_semantics(AnalysisReport& report) {
    auto& result = report.semantic_analysis;
    result = SemanticAnalysisRecord{};
    if (!report.pe.supported_x64_native || report.pe.clr.present) {
        result.status = "unsupported";
        report.stages.push_back({"semantic_analysis", "unsupported"});
        return;
    }
    const std::size_t semantic_count = std::min(report.instructions.size(), kMaxSemanticInstructions);
    result.instructions.reserve(semantic_count);
    std::map<std::uint32_t, const InstructionRecord*> decoded;
    std::unordered_map<std::uint32_t, std::size_t> semantics;
    semantics.reserve(semantic_count);
    for (std::size_t i = 0; i < semantic_count; ++i) {
        const auto& insn = report.instructions[i];
        auto sem = lift_one(report.pe, insn);
        if (sem.status == "modeled") ++result.modeled_instruction_count;
        else ++result.unsupported_instruction_count;
        decoded.emplace(insn.rva, &insn);
        semantics.emplace(insn.rva, result.instructions.size());
        result.instructions.push_back(std::move(sem));
    }

    std::vector<const FunctionRecord*> source_functions;
    for (const auto* collection : {&report.function_recovery.known_functions,
                                   &report.function_recovery.candidate_functions,
                                   &report.function_recovery.fragments})
        for (const auto& function : *collection) source_functions.push_back(&function);
    std::stable_sort(source_functions.begin(), source_functions.end(), [](const auto* lhs, const auto* rhs) {
        if (lhs->start_rva != rhs->start_rva) return lhs->start_rva < rhs->start_rva;
        if (lhs->entity_kind != rhs->entity_kind) return lhs->entity_kind == "known_function";
        return lhs->end_rva < rhs->end_rva;
    });
    std::set<std::pair<std::uint32_t, std::uint32_t>> seen_ranges;
    std::size_t function_count = 0;
    bool function_limit_hit = false;
    for (const auto* source : source_functions) {
        if (function_count >= kMaxSemanticFunctions) { function_limit_hit = true; break; }
        const auto range_key = std::make_pair(source->start_rva, source->end_rva.value_or(0U));
        if (!seen_ranges.insert(range_key).second) continue;
        SemanticFunctionRecord function;
        function.start_rva = source->start_rva;
        function.end_rva = source->end_rva;
        function.label = source->label;
        function.provenance = provenance(*source);
        function.boundary_ambiguous = source->ambiguous;
        if (source->ambiguous) issue(function, "function_boundary_ambiguous", false);
        ++function_count;
        if (!source->end_rva || *source->end_rva <= source->start_rva) {
            function.status = "partial";
            issue(function, "function_boundary_unbounded", false);
            result.functions.push_back(std::move(function));
            continue;
        }
        for (const auto& gap : report.decode_gaps) {
            const std::uint64_t gap_end = static_cast<std::uint64_t>(gap.rva) + gap.size;
            if (gap.size != 0U && gap.rva < *source->end_rva && gap_end > source->start_rva) {
                issue(function, "decode_gap_intersects_function", false);
                break;
            }
        }
        std::vector<const InstructionRecord*> members;
        auto it = decoded.lower_bound(source->start_rva);
        while (it != decoded.end() && it->first < *source->end_rva) {
            members.push_back(it->second);
            ++it;
        }
        if (members.empty() || members.front()->rva != source->start_rva) {
            issue(function, "no_decoded_instruction_at_function_start", false);
        }
        function.instruction_count = members.size();
        std::unordered_map<std::uint32_t, std::size_t> member_index;
        for (std::size_t i = 0; i < members.size(); ++i) {
            member_index.emplace(members[i]->rva, i);
            const auto sem_it = semantics.find(members[i]->rva);
            if (sem_it != semantics.end() && result.instructions[sem_it->second].status != "modeled")
                ++function.unsupported_instruction_count;
        }
        std::vector<bool> leader(members.size(), false);
        if (!members.empty()) leader[0] = true;
        for (std::size_t i = 0; i < members.size(); ++i) {
            const auto& insn = *members[i];
            const auto sem_it = semantics.find(insn.rva);
            if (sem_it == semantics.end()) continue;
            const auto& sem = result.instructions[sem_it->second];
            const std::size_t size = instruction_size(insn);
            const std::uint64_t next64 = static_cast<std::uint64_t>(insn.rva) + size;
            if (i + 1U < members.size() && next64 != members[i + 1U]->rva) {
                leader[i + 1U] = true;
                issue(function, "decode_gap_inside_function", false);
            }
            if (sem.target_rva && *sem.target_rva >= source->start_rva && *sem.target_rva < *source->end_rva) {
                const auto target = member_index.find(*sem.target_rva);
                if (target != member_index.end()) leader[target->second] = true;
                else issue(function, "branch_target_not_decoded_instruction_boundary");
            }
            if ((sem.control_flow == "conditional_branch" || sem.control_flow == "direct_branch" ||
                 sem.control_flow == "indirect_branch" || sem.control_flow == "direct_call" ||
                 sem.control_flow == "indirect_call" || sem.control_flow == "unknown" ||
                 sem.control_flow == "return") && i + 1U < members.size())
                leader[i + 1U] = true;
            if (sem.control_flow != "fallthrough" && !sem.unresolved_reason.empty())
                issue(function, sem.unresolved_reason);
        }
        std::vector<std::uint32_t> local_block_ids;
        std::unordered_map<std::uint32_t, std::uint32_t> block_for_rva;
        for (std::size_t i = 0; i < members.size();) {
            if (result.basic_blocks.size() >= kMaxSemanticBlocks) {
                issue(function, "basic_block_record_limit", false);
                break;
            }
            const std::size_t first = i;
            ++i;
            while (i < members.size() && !leader[i]) ++i;
            SemanticBasicBlock block;
            block.id = static_cast<std::uint32_t>(result.basic_blocks.size());
            block.function_start_rva = source->start_rva;
            block.start_rva = members[first]->rva;
            const auto* last = members[i - 1U];
            const std::size_t last_size = instruction_size(*last);
            const std::uint64_t end64 = static_cast<std::uint64_t>(last->rva) + last_size;
            block.end_rva = end64 > UINT32_MAX ? UINT32_MAX : static_cast<std::uint32_t>(end64);
            for (std::size_t j = first; j < i; ++j) {
                block.instruction_rvas.push_back(members[j]->rva);
                block_for_rva.emplace(members[j]->rva, block.id);
            }
            local_block_ids.push_back(block.id);
            result.basic_blocks.push_back(std::move(block));
        }
        for (const auto block_id : local_block_ids) {
            const auto& block = result.basic_blocks[block_id];
            if (block.instruction_rvas.empty()) continue;
            const auto from_rva = block.instruction_rvas.back();
            const auto sem_it = semantics.find(from_rva);
            if (sem_it == semantics.end()) { issue(function, "semantic_record_missing", false); continue; }
            const auto& sem = result.instructions[sem_it->second];
            const auto member_it = member_index.find(from_rva);
            const std::size_t index = member_it == member_index.end() ? members.size() : member_it->second;
            const bool has_fallthrough = index + 1U < members.size() &&
                static_cast<std::uint64_t>(members[index]->rva) + instruction_size(*members[index]) == members[index + 1U]->rva;
            const auto next_rva = has_fallthrough ? std::optional<std::uint32_t>(members[index + 1U]->rva) : std::nullopt;
            const auto block_for_target = [&block_for_rva](std::optional<std::uint32_t> rva) -> std::optional<std::uint32_t> {
                if (!rva) return std::nullopt;
                const auto found = block_for_rva.find(*rva);
                return found == block_for_rva.end() ? std::nullopt : std::optional<std::uint32_t>(found->second);
            };
            if (sem.control_flow == "return") continue;
            if (sem.control_flow == "unknown") {
                result.cfg_edges.push_back({source->start_rva, block_id, std::nullopt, from_rva,
                                            std::nullopt, "unknown", "unsupported_control_flow"});
                issue(function, sem.unresolved_reason.empty() ? "unsupported_control_flow_semantics" : sem.unresolved_reason);
                continue;
            }
            if (sem.control_flow == "direct_branch") {
                const auto target_block = block_for_target(sem.target_rva);
                result.cfg_edges.push_back({source->start_rva, block_id, target_block, from_rva,
                                            sem.target_rva, "direct_branch", "decoded_direct_branch"});
                if (!target_block) issue(function, "direct_branch_target_outside_function_or_unresolved");
                continue;
            }
            if (sem.control_flow == "indirect_branch") {
                result.cfg_edges.push_back({source->start_rva, block_id, std::nullopt, from_rva,
                                            std::nullopt, "indirect_branch", "decoded_indirect_branch"});
                issue(function, "indirect_branch_destination_unknown");
                continue;
            }
            if (sem.control_flow == "conditional_branch") {
                const auto target_block = block_for_target(sem.target_rva);
                result.cfg_edges.push_back({source->start_rva, block_id, target_block, from_rva,
                                            sem.target_rva, "conditional_true", "decoded_conditional_branch"});
                if (!target_block) issue(function, "conditional_branch_target_outside_function_or_unresolved");
                if (next_rva) {
                    result.cfg_edges.push_back({source->start_rva, block_id, block_for_target(next_rva), from_rva,
                                                next_rva, "conditional_false", "fallthrough"});
                } else {
                    result.cfg_edges.push_back({source->start_rva, block_id, std::nullopt, from_rva,
                                                std::nullopt, "conditional_false", "fallthrough"});
                    issue(function, "conditional_fallthrough_not_decoded");
                }
                continue;
            }
            if (sem.control_flow == "direct_call" || sem.control_flow == "indirect_call") {
                const bool resolved = sem.target_rva.has_value();
                const bool direct = sem.control_flow == "direct_call";
                result.cfg_edges.push_back({source->start_rva, block_id, block_for_target(sem.target_rva),
                                            from_rva, sem.target_rva,
                                            direct ? "call" : "indirect_call",
                                            direct ? (resolved ? "decoded_direct_call" : "direct_call_target_outside_image") :
                                                     "indirect_call_unresolved"});
                result.call_graph.push_back({source->start_rva, from_rva, sem.target_rva,
                    resolved ? "direct_target" : (direct ? "unresolved_direct_target" : "unresolved_indirect_target"),
                    direct ? (resolved ? "decoded_call_operand" : "direct_call_target_outside_image") :
                             "indirect_call_target_unknown"});
                if (!resolved && sem.unresolved_reason.empty())
                    issue(function, direct ? "direct_call_target_outside_image" : "indirect_call_destination_unknown");
            }
            if (next_rva) {
                const bool next_is_new_block = block_for_target(next_rva) != std::optional<std::uint32_t>(block_id);
                if (next_is_new_block)
                    result.cfg_edges.push_back({source->start_rva, block_id, block_for_target(next_rva), from_rva,
                                                next_rva, "fallthrough", "instruction_order"});
            } else if (sem.control_flow == "fallthrough" || sem.control_flow == "direct_call" ||
                       sem.control_flow == "indirect_call") {
                issue(function, "fallthrough_exits_bounded_function");
            }
        }
        function.status = function.unsupported_instruction_count == 0U && function.issues.empty() &&
                         !function.boundary_ambiguous ? "complete" : "partial";
        function.semantic_complete = function.status == "complete";
        result.functions.push_back(std::move(function));
    }
    if (report.instructions.size() > kMaxSemanticInstructions) {
        result.status = "partial";
        report.diagnostics.push_back({"SEMANTIC_INSTRUCTION_LIMIT", "warning",
            "semantic lifting stopped at the configured 20000-instruction bound; remaining decoded instructions are unmodeled"});
        result.unsupported_instruction_count += report.instructions.size() - kMaxSemanticInstructions;
    }
    for (const auto& function : result.functions)
        result.unresolved_control_flow_count += function.unresolved_control_flow_count;
    if (function_limit_hit)
        report.diagnostics.push_back({"SEMANTIC_FUNCTION_LIMIT", "warning",
            "semantic CFG construction stopped at the configured function-count bound; remaining functions are unmodeled"});
    const bool all_complete = !result.functions.empty() && !function_limit_hit &&
        std::all_of(result.functions.begin(), result.functions.end(), [](const auto& f) { return f.semantic_complete; }) &&
        result.unsupported_instruction_count == 0U && result.unresolved_control_flow_count == 0U &&
        report.function_recovery.unresolved_ranges.empty() && report.function_recovery.unresolved_control_flow.empty() &&
        report.decode_gaps.empty();
    result.status = all_complete ? "complete" : "partial";
    report.stages.push_back({"semantic_analysis", result.status});
    if (result.unsupported_instruction_count != 0U)
        report.diagnostics.push_back({"SEMANTIC_INSTRUCTIONS_UNSUPPORTED", "warning",
            std::to_string(result.unsupported_instruction_count) + " decoded instruction(s) have no implemented semantic model; affected functions remain partial"});
    if (result.unresolved_control_flow_count != 0U)
        report.diagnostics.push_back({"SEMANTIC_CONTROL_FLOW_UNRESOLVED", "warning",
            std::to_string(result.unresolved_control_flow_count) + " function-level control-flow issue(s) remain explicit; affected functions remain partial"});
}

void compare_ghidra_reference(AnalysisReport& report, const std::string& path) {
    auto& comparison = report.semantic_analysis.reference;
    comparison = ReferenceComparisonRecord{};
    std::error_code ec;
    const auto file_size = std::filesystem::file_size(path, ec);
    if (ec || file_size > kMaxReferenceBytes) {
        comparison.status = "invalid";
        report.diagnostics.push_back({"GHIDRA_REFERENCE_UNAVAILABLE", "warning",
            ec ? "cannot read the specified Ghidra reference report" : "Ghidra reference report exceeds the 16 MiB limit"});
        return;
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        comparison.status = "invalid";
        report.diagnostics.push_back({"GHIDRA_REFERENCE_UNAVAILABLE", "warning", "cannot open the specified Ghidra reference report"});
        return;
    }
    std::string line;
    if (!std::getline(input, line)) {
        comparison.status = "invalid";
        report.diagnostics.push_back({"GHIDRA_REFERENCE_INVALID", "warning", "Ghidra reference report is empty"});
        return;
    }
    if (!line.empty() && line.back() == '\r') line.pop_back();
    const auto header = split_tabs(line);
    if (header.size() != 4U || header[0] != "NEXUSREV_GHIDRA_REFERENCE" || header[1] != "1" || header[3].empty()) {
        comparison.status = "invalid";
        report.diagnostics.push_back({"GHIDRA_REFERENCE_INVALID", "warning", "Ghidra reference report has an invalid v1 header"});
        return;
    }
    comparison.version = header[3];
    comparison.input_sha256 = header[2];
    if (comparison.input_sha256 != report.input_sha256) {
        comparison.status = "invalid";
        report.diagnostics.push_back({"GHIDRA_REFERENCE_INPUT_MISMATCH", "warning",
            "Ghidra reference input SHA-256 does not match the analyzed PE; comparison was skipped"});
        return;
    }
    std::set<std::uint32_t> reference_functions;
    std::set<FlowKey> reference_flows;
    std::size_t rows = 0U;
    bool valid = true;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        if (++rows > kMaxReferenceRows) { valid = false; break; }
        const auto fields = split_tabs(line);
        if (fields.size() == 2U && fields[0] == "F") {
            std::uint32_t rva = 0;
            if (!parse_u32(fields[1], rva)) { valid = false; break; }
            reference_functions.insert(rva);
        } else if (fields.size() == 4U && fields[0] == "E") {
            std::uint32_t from = 0;
            if (!parse_u32(fields[1], from) ||
                !is_one_of(fields[2], {"call", "branch", "conditional_branch", "indirect_branch", "return"})) {
                valid = false; break;
            }
            std::optional<std::uint32_t> target;
            if (fields[3] != "-") {
                std::uint32_t target_value = 0;
                if (!parse_u32(fields[3], target_value)) { valid = false; break; }
                target = target_value;
            }
            reference_flows.insert({from, fields[2], target});
        } else { valid = false; break; }
    }
    if (!valid || !input.eof()) {
        comparison.status = "invalid";
        report.diagnostics.push_back({"GHIDRA_REFERENCE_INVALID", "warning", "Ghidra reference report contains a malformed or excessive row"});
        return;
    }
    comparison.reference_function_count = reference_functions.size();
    std::set<std::uint32_t> local_functions;
    for (const auto* collection : {&report.function_recovery.known_functions,
                                   &report.function_recovery.candidate_functions,
                                   &report.function_recovery.fragments})
        for (const auto& item : *collection) local_functions.insert(item.start_rva);
    for (const auto rva : reference_functions) {
        if (local_functions.find(rva) == local_functions.end())
            comparison.differences.push_back({"function_start_missing_locally", rva, std::to_string(rva), "missing"});
    }
    for (const auto rva : local_functions) {
        if (reference_functions.find(rva) == reference_functions.end())
            comparison.differences.push_back({"function_start_missing_in_ghidra", rva, "missing", std::to_string(rva)});
    }
    std::set<FlowKey> local_flows;
    for (const auto& sem : report.semantic_analysis.instructions) {
        if (sem.control_flow == "direct_call") local_flows.insert({sem.rva, "call", sem.target_rva});
        else if (sem.control_flow == "conditional_branch") local_flows.insert({sem.rva, "conditional_branch", sem.target_rva});
        else if (sem.control_flow == "direct_branch") local_flows.insert({sem.rva, "branch", sem.target_rva});
        else if (sem.control_flow == "indirect_branch") local_flows.insert({sem.rva, "indirect_branch", std::nullopt});
        else if (sem.control_flow == "return") local_flows.insert({sem.rva, "return", std::nullopt});
    }
    comparison.compared_flow_count = std::max(local_flows.size(), reference_flows.size());
    for (const auto& flow : reference_flows) {
        if (local_flows.find(flow) == local_flows.end()) {
            comparison.differences.push_back({"flow_missing_locally", flow.from,
                flow.kind + ":" + (flow.target ? std::to_string(*flow.target) : "unknown"), "missing"});
        }
    }
    for (const auto& flow : local_flows) {
        if (reference_flows.find(flow) == reference_flows.end()) {
            comparison.differences.push_back({"flow_missing_in_ghidra", flow.from, "missing",
                flow.kind + ":" + (flow.target ? std::to_string(*flow.target) : "unknown")});
        }
    }
    comparison.difference_count = comparison.differences.size();
    comparison.status = comparison.differences.empty() ? "compared" : "divergent";
    if (comparison.status == "divergent")
        report.diagnostics.push_back({"GHIDRA_REFERENCE_DIVERGENCE", "warning",
            std::to_string(comparison.difference_count) + " function-start/control-flow disagreement(s) with the Ghidra reference are recorded in semantic_analysis.reference"});
}

std::string semantic_analysis_to_json(const SemanticAnalysisRecord& r) {
    std::ostringstream o;
    o << "{\"status\":\"" << json_escape(r.status) << "\",\"backend\":\"" << json_escape(r.backend)
      << "\",\"architecture\":\"" << json_escape(r.architecture) << "\",\"abi\":\"" << json_escape(r.abi)
      << "\",\"modeled_instruction_count\":" << r.modeled_instruction_count
      << ",\"unsupported_instruction_count\":" << r.unsupported_instruction_count
      << ",\"unresolved_control_flow_count\":" << r.unresolved_control_flow_count << ",\"instructions\":[";
    for (std::size_t i = 0; i < r.instructions.size(); ++i) {
        const auto& x = r.instructions[i];
        o << (i ? "," : "") << "{\"rva\":" << x.rva << ",\"status\":\"" << json_escape(x.status)
          << "\",\"operation\":\"" << json_escape(x.operation) << "\",\"condition\":\"" << json_escape(x.condition)
          << "\",\"operands\":[";
        for (std::size_t j = 0; j < x.operands.size(); ++j) {
            const auto& op = x.operands[j];
            o << (j ? "," : "") << "{\"type\":\"" << json_escape(op.type) << "\",\"size\":" << unsigned(op.size)
              << ",\"access\":" << unsigned(op.access) << ",\"register\":\"" << json_escape(op.reg)
              << "\",\"immediate\":" << op.immediate << ",\"segment\":\"" << json_escape(op.segment)
              << "\",\"base\":\"" << json_escape(op.base) << "\",\"index\":\"" << json_escape(op.index)
              << "\",\"scale\":" << op.scale << ",\"displacement\":" << op.displacement
              << ",\"avx_broadcast\":" << unsigned(op.avx_broadcast)
              << ",\"avx_zero_opmask\":" << (op.avx_zero_opmask ? "true" : "false") << '}';
        }
        o << "],\"registers_read\":"; emit_strings(o, x.registers_read);
        o << ",\"registers_written\":"; emit_strings(o, x.registers_written);
        o << ",\"flags_read\":"; emit_strings(o, x.flags_read);
        o << ",\"flags_written\":"; emit_strings(o, x.flags_written);
        o << ",\"flags_conditionally_written\":"; emit_strings(o, x.flags_conditionally_written);
        o << ",\"flags_undefined\":"; emit_strings(o, x.flags_undefined);
        o << ",\"flags_preserved\":"; emit_strings(o, x.flags_preserved);
        o << ",\"memory_read\":" << (x.memory_read ? "true" : "false")
          << ",\"memory_written\":" << (x.memory_written ? "true" : "false")
          << ",\"stack_action\":\"" << json_escape(x.stack_action) << "\",\"stack_delta\":";
        if (x.stack_delta) o << *x.stack_delta; else o << "null";
        o << ",\"control_flow\":\"" << json_escape(x.control_flow) << "\",\"target_rva\":";
        if (x.target_rva) o << *x.target_rva; else o << "null";
        o << ",\"unresolved_reason\":\"" << json_escape(x.unresolved_reason) << "\"}";
    }
    o << "],\"functions\":[";
    for (std::size_t i = 0; i < r.functions.size(); ++i) {
        const auto& f = r.functions[i];
        o << (i ? "," : "") << "{\"start_rva\":" << f.start_rva << ",\"end_rva\":";
        if (f.end_rva) o << *f.end_rva; else o << "null";
        o << ",\"label\":\"" << json_escape(f.label) << "\",\"provenance\":\"" << json_escape(f.provenance)
          << "\",\"status\":\"" << json_escape(f.status) << "\",\"boundary_ambiguous\":"
          << (f.boundary_ambiguous ? "true" : "false") << ",\"semantic_complete\":"
          << (f.semantic_complete ? "true" : "false") << ",\"instruction_count\":" << f.instruction_count
          << ",\"unsupported_instruction_count\":" << f.unsupported_instruction_count
          << ",\"unresolved_control_flow_count\":" << f.unresolved_control_flow_count << ",\"issues\":";
        emit_strings(o, f.issues); o << '}';
    }
    o << "],\"basic_blocks\":[";
    for (std::size_t i = 0; i < r.basic_blocks.size(); ++i) {
        const auto& b = r.basic_blocks[i];
        o << (i ? "," : "") << "{\"id\":" << b.id << ",\"function_start_rva\":" << b.function_start_rva
          << ",\"start_rva\":" << b.start_rva << ",\"end_rva\":" << b.end_rva << ",\"instruction_rvas\":[";
        for (std::size_t j = 0; j < b.instruction_rvas.size(); ++j) o << (j ? "," : "") << b.instruction_rvas[j];
        o << "]}";
    }
    o << "],\"cfg_edges\":[";
    for (std::size_t i = 0; i < r.cfg_edges.size(); ++i) {
        const auto& e = r.cfg_edges[i];
        o << (i ? "," : "") << "{\"function_start_rva\":" << e.function_start_rva << ",\"from_block\":" << e.from_block
          << ",\"to_block\":";
        if (e.to_block) o << *e.to_block; else o << "null";
        o << ",\"from_rva\":" << e.from_rva << ",\"target_rva\":";
        if (e.target_rva) o << *e.target_rva; else o << "null";
        o << ",\"kind\":\"" << json_escape(e.kind) << "\",\"provenance\":\"" << json_escape(e.provenance) << "\"}";
    }
    o << "],\"call_graph\":[";
    for (std::size_t i = 0; i < r.call_graph.size(); ++i) {
        const auto& e = r.call_graph[i];
        o << (i ? "," : "") << "{\"caller_start_rva\":" << e.caller_start_rva << ",\"call_rva\":" << e.call_rva
          << ",\"target_rva\":";
        if (e.target_rva) o << *e.target_rva; else o << "null";
        o << ",\"resolution\":\"" << json_escape(e.resolution) << "\",\"provenance\":\"" << json_escape(e.provenance) << "\"}";
    }
    o << "],\"reference\":{\"status\":\"" << json_escape(r.reference.status) << "\",\"tool\":\""
      << json_escape(r.reference.tool) << "\",\"version\":\"" << json_escape(r.reference.version)
      << "\",\"input_sha256\":\"" << json_escape(r.reference.input_sha256)
      << "\",\"reference_function_count\":" << r.reference.reference_function_count
      << ",\"compared_flow_count\":" << r.reference.compared_flow_count
      << ",\"difference_count\":" << r.reference.difference_count << ",\"differences\":[";
    for (std::size_t i = 0; i < r.reference.differences.size(); ++i) {
        const auto& d = r.reference.differences[i];
        o << (i ? "," : "") << "{\"category\":\"" << json_escape(d.category) << "\",\"rva\":";
        if (d.rva) o << *d.rva; else o << "null";
        o << ",\"expected\":\"" << json_escape(d.expected) << "\",\"observed\":\"" << json_escape(d.observed) << "\"}";
    }
    o << "]}}";
    return o.str();
}

} // namespace nexusrev
