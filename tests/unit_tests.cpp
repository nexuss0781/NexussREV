#include "sha256.hpp"
#include "nexusrev.hpp"
#include "pe_image.hpp"
#include "phase3.hpp"
#include "phase4.hpp"

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

namespace {
void put16(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint16_t value) {
    bytes[offset] = static_cast<std::uint8_t>(value);
    bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 8U);
}
void put32(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint32_t value) {
    for (unsigned int i = 0; i < 4U; ++i) bytes[offset + i] = static_cast<std::uint8_t>(value >> (8U * i));
}
void put64(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint64_t value) {
    for (unsigned int i = 0; i < 8U; ++i) bytes[offset + i] = static_cast<std::uint8_t>(value >> (8U * i));
}
std::vector<std::uint8_t> minimal_pe() {
    std::vector<std::uint8_t> bytes(0x220U, 0U);
    bytes[0] = 'M'; bytes[1] = 'Z'; put32(bytes, 0x3cU, 0x80U);
    bytes[0x80] = 'P'; bytes[0x81] = 'E';
    put16(bytes, 0x84U, 0x8664U); put16(bytes, 0x86U, 1U);
    put16(bytes, 0x94U, 0xf0U); put16(bytes, 0x96U, 0x0022U);
    const std::size_t opt = 0x98U;
    put16(bytes, opt, 0x20bU); put32(bytes, opt + 16U, 0x1000U);
    put64(bytes, opt + 24U, 0x140000000ULL); put32(bytes, opt + 32U, 0x1000U);
    put32(bytes, opt + 36U, 0x200U); put32(bytes, opt + 56U, 0x2000U);
    put32(bytes, opt + 60U, 0x200U); put32(bytes, opt + 108U, 16U);
    const std::size_t section = 0x188U;
    bytes[section] = '.'; bytes[section + 1U] = 't'; bytes[section + 2U] = 'e';
    bytes[section + 3U] = 'x'; bytes[section + 4U] = 't';
    put32(bytes, section + 8U, 0x40U); put32(bytes, section + 12U, 0x1000U);
    put32(bytes, section + 16U, 0x20U); put32(bytes, section + 20U, 0x200U);
    put32(bytes, section + 36U, 0x60000020U);
    bytes[0x200U] = 0xc3U;
    return bytes;
}

bool has(const std::vector<std::string>& values, const std::string& wanted) {
    for (const auto& value : values) if (value == wanted) return true;
    return false;
}

nexusrev::X86OperandRecord reg_operand(const std::string& name, std::uint8_t access = 3U) {
    nexusrev::X86OperandRecord op;
    op.type = "register"; op.reg = name; op.size = 8U; op.access = access;
    return op;
}
nexusrev::X86OperandRecord imm_operand(std::uint64_t va) {
    nexusrev::X86OperandRecord op;
    op.type = "immediate"; op.size = 4U; op.access = 1U;
    op.immediate = static_cast<std::int64_t>(va);
    return op;
}
nexusrev::X86OperandRecord memory_operand(std::string base, std::int64_t displacement,
                                           std::uint8_t size, std::uint8_t access) {
    nexusrev::X86OperandRecord op;
    op.type = "memory"; op.base = std::move(base); op.displacement = displacement;
    op.size = size; op.access = access;
    return op;
}
nexusrev::InstructionRecord synthetic_instruction(std::uint32_t rva, std::string mnemonic,
                                                   std::string bytes = "90") {
    nexusrev::InstructionRecord insn;
    insn.rva = rva;
    insn.va = 0x140000000ULL + rva;
    insn.bytes = std::move(bytes);
    insn.mnemonic = std::move(mnemonic);
    insn.detail_available = true;
    insn.detail_operands = {reg_operand("rax"), reg_operand("rcx", 1U)};
    return insn;
}
void configure_pe(nexusrev::AnalysisReport& report) {
    report.pe.supported_x64_native = true;
    report.pe.machine = 0x8664U;
    report.pe.pe32_plus = true;
    report.pe.image_base = 0x140000000ULL;
    report.pe.size_of_image = 0x4000U;
    nexusrev::PeSection section;
    section.name = ".text"; section.virtual_address = 0x1000U;
    section.file_backed_size = 0x3000U; section.mapped_size = 0x3000U;
    section.virtual_size = 0x3000U; section.executable = true;
    report.pe.sections.push_back(section);
}

bool pe_parser_tests() {
    nexusrev::PeImage image;
    std::string code, message;
    if (!nexusrev::PeImage::parse(minimal_pe(), image, code, message)) {
        std::cerr << "PE32+ fixture parse failed: " << code << " " << message << '\n'; return false;
    }
    std::uint64_t offset = 0;
    std::uint32_t rva = 0;
    if (!image.supported_x64_native || image.machine != 0x8664U || !image.pe32_plus ||
        !image.rva_to_file_offset(0x1000U, offset) || offset != 0x200U ||
        !image.rva_to_file_offset(0x101fU, offset) || offset != 0x21fU ||
        !image.rva_to_file_offset(0x1ffU, offset) || offset != 0x1ffU ||
        !image.va_to_rva(0x140001020ULL, rva) || rva != 0x1020U ||
        image.va_to_rva(0x140002000ULL, rva)) {
        std::cerr << "RVA/VA/file-offset conversion failed\n"; return false;
    }
    const auto zero_fill = image.map_rva(0x1020U);
    if (!zero_fill.virtual_zero_fill || zero_fill.mapped || image.rva_to_file_offset(0x1020U, offset) ||
        image.map_rva(0x1040U).mapped) {
        std::cerr << "section edge or virtual zero-fill mapping failed\n"; return false;
    }
    std::vector<std::uint8_t> crossing;
    if (image.read_rva(0x1000U, 0x21U, crossing)) {
        std::cerr << "read across file-backed/zero-fill boundary unexpectedly succeeded\n"; return false;
    }
    auto bad_count = minimal_pe(); put32(bad_count, 0x98U + 108U, 17U);
    if (nexusrev::PeImage::parse(std::move(bad_count), image, code, message) || code != "PE_DIRECTORY_COUNT_INVALID") {
        std::cerr << "oversized data-directory count was not rejected\n"; return false;
    }
    auto bad_raw = minimal_pe(); put32(bad_raw, 0x188U + 20U, 0xfffffff0U);
    if (nexusrev::PeImage::parse(std::move(bad_raw), image, code, message) || code != "SECTION_RAW_RANGE_INVALID") {
        std::cerr << "out-of-file section range was not rejected\n"; return false;
    }
    auto truncated_optional = minimal_pe(); put16(truncated_optional, 0x94U, 80U);
    if (nexusrev::PeImage::parse(std::move(truncated_optional), image, code, message) ||
        code != "OPTIONAL_HEADER_TRUNCATED") {
        std::cerr << "truncated optional header was not rejected\n"; return false;
    }
    auto overflowing_base = minimal_pe(); put64(overflowing_base, 0x98U + 24U, 0xffffffffffffefffULL);
    if (nexusrev::PeImage::parse(std::move(overflowing_base), image, code, message) ||
        code != "PE_IMAGE_BASE_OVERFLOW") {
        std::cerr << "image-base arithmetic overflow was not rejected\n"; return false;
    }
    auto unsupported = minimal_pe(); put16(unsupported, 0x84U, 0xaa64U);
    if (!nexusrev::PeImage::parse(std::move(unsupported), image, code, message) || image.supported_x64_native) {
        std::cerr << "unsupported machine was not identified without being treated as x64\n"; return false;
    }
    return true;
}

bool stop_control_tests() {
    nexusrev::set_analysis_timeout_ms(60000U);
    if (nexusrev::analysis_stop_reason() != nexusrev::StopReason::none) {
        std::cerr << "unexpected stop state before cancellation test\n";
        return false;
    }
    nexusrev::request_cancellation();
    if (nexusrev::analysis_stop_reason() != nexusrev::StopReason::cancelled) {
        std::cerr << "cancellation request was not visible to analysis checkpoints\n";
        return false;
    }
    return true;
}

bool semantic_operation_tests() {
    nexusrev::AnalysisReport report;
    configure_pe(report);
    const std::vector<std::string> operations = {
        "nop", "mov", "movabs", "movzx", "movsx", "movsxd", "lea",
        "add", "sub", "adc", "sbb", "inc", "dec", "neg", "and", "or", "xor", "not",
        "cmp", "test", "imul", "mul", "div", "idiv", "xchg", "shl", "sal", "shr", "sar",
        "push", "pop", "pushfq", "popfq", "leave", "call", "call", "jmp", "jmp",
        "je", "jne", "jb", "ja", "jl", "jge", "jle", "jg", "jo", "jno", "js", "jns", "jp", "jnp",
        "setne", "cmovg", "ret", "vzeroupper"
    };
    std::uint32_t rva = 0x1000U;
    for (const auto& mnemonic : operations) {
        auto insn = synthetic_instruction(rva++, mnemonic);
        if (mnemonic == "call" || mnemonic == "jmp" || mnemonic[0] == 'j') {
            if (mnemonic == "jmp" && insn.rva == 0x1025U) insn.detail_operands = {reg_operand("rax", 1U)};
            else insn.detail_operands = {imm_operand(0x140001100ULL)};
        }
        report.instructions.push_back(std::move(insn));
    }
    auto push16 = synthetic_instruction(rva++, "push", "66 50");
    push16.prefixes[0] = 0x66U;
    auto ax = reg_operand("ax", 1U); ax.size = 2U;
    push16.detail_operands = {ax};
    report.instructions.push_back(std::move(push16));
    auto pop16 = synthetic_instruction(rva++, "pop", "66 58");
    pop16.prefixes[0] = 0x66U;
    auto bx = reg_operand("bx", 2U); bx.size = 2U;
    pop16.detail_operands = {bx};
    report.instructions.push_back(std::move(pop16));
    // Exercise detail-unavailable behavior independently from the unsupported opcode case.
    auto no_detail = synthetic_instruction(rva, "mov");
    no_detail.detail_available = false;
    report.instructions.push_back(std::move(no_detail));
    nexusrev::analyze_semantics(report);
    const auto find_sem = [&report](std::uint32_t address) -> const nexusrev::SemanticInstructionRecord* {
        for (const auto& sem : report.semantic_analysis.instructions) if (sem.rva == address) return &sem;
        return nullptr;
    };
    if (report.semantic_analysis.instructions.size() != operations.size() + 3U ||
        report.semantic_analysis.unsupported_instruction_count != 6U) {
        std::cerr << "semantic lifting did not account for all modeled/unsupported instructions\n"; return false;
    }
    const auto add = find_sem(0x1007U);
    const auto inc = find_sem(0x100bU);
    const auto logical = find_sem(0x100eU);
    if (add == nullptr || add->status != "modeled" || !has(add->flags_written, "CF") || !has(add->flags_written, "OF") ||
        inc == nullptr || !has(inc->flags_preserved, "CF") || has(inc->flags_written, "CF") ||
        logical == nullptr || !has(logical->flags_undefined, "AF")) {
        std::cerr << "arithmetic/logical flag effects are missing or incorrect\n"; return false;
    }
    bool checked_unsigned = false, checked_signed = false, checked_preserved = false;
    unsigned int unsupported_shifts = 0U;
    for (const auto& sem : report.semantic_analysis.instructions) {
        if (sem.condition == "unsigned_below") checked_unsigned = has(sem.flags_read, "CF");
        if (sem.condition == "signed_less") checked_signed = has(sem.flags_read, "SF") && has(sem.flags_read, "OF");
        if (sem.rva >= 0x1019U && sem.rva <= 0x101cU && sem.status == "unsupported") ++unsupported_shifts;
        if (sem.operation == "copy") checked_preserved = has(sem.flags_preserved, "CF") && has(sem.flags_preserved, "ZF");
    }
    if (!checked_unsigned || !checked_signed || !checked_preserved || unsupported_shifts != 4U) {
        std::cerr << "condition-code effects are missing or count-dependent shifts were falsely modeled\n"; return false;
    }
    bool saw_push = false, saw_pop = false, saw_return = false, saw_pushf = false, saw_popf = false;
    bool saw_push16 = false, saw_pop16 = false, saw_direct_call = false, saw_indirect_jump = false;
    for (const auto& sem : report.semantic_analysis.instructions) {
        if (sem.operation == "push" && sem.stack_delta == -8 && sem.memory_written) saw_push = true;
        if (sem.operation == "pop" && sem.stack_delta == 8 && sem.memory_read) saw_pop = true;
        if (sem.rva == rva - 2U) saw_push16 = sem.operation == "push" && sem.stack_delta == -2;
        if (sem.rva == rva - 1U) saw_pop16 = sem.operation == "pop" && sem.stack_delta == 2;
        if (sem.operation == "return") saw_return = sem.stack_delta == 8 && sem.control_flow == "return";
        if (sem.rva == 0x101fU) saw_pushf = has(sem.flags_read, "RFLAGS");
        if (sem.rva == 0x1020U) saw_popf = has(sem.flags_written, "RFLAGS");
        if (sem.control_flow == "direct_call") saw_direct_call = sem.target_rva == 0x1100U && sem.stack_delta == 0;
        if (sem.control_flow == "indirect_branch") saw_indirect_jump = !sem.target_rva && !sem.unresolved_reason.empty();
    }
    if (!saw_push || !saw_pop || !saw_push16 || !saw_pop16 || !saw_return || !saw_pushf || !saw_popf || !saw_direct_call || !saw_indirect_jump) {
        std::cerr << "stack, call/return, or indirect-branch semantics are missing\n"; return false;
    }
    const auto unsupported = find_sem(rva - 3U);
    const auto no_detail_sem = find_sem(rva);
    if (unsupported == nullptr || unsupported->status != "unsupported" ||
        no_detail_sem == nullptr || no_detail_sem->unresolved_reason != "decoder_detail_unavailable_control_flow_unknown" ||
        no_detail_sem->control_flow != "unknown") {
        std::cerr << "unsupported instruction or missing-detail diagnostics are not visible\n"; return false;
    }
    return true;
}

bool cfg_and_reference_tests() {
    nexusrev::AnalysisReport report;
    configure_pe(report);
    report.input_sha256 = std::string(64U, 'a');
    auto add = [&report](std::uint32_t rva, const std::string& mnemonic, const std::string& bytes,
                         std::vector<nexusrev::X86OperandRecord> operands = {}) {
        auto insn = synthetic_instruction(rva, mnemonic, bytes);
        if (!operands.empty()) insn.detail_operands = std::move(operands);
        report.instructions.push_back(std::move(insn));
    };
    add(0x1000U, "push", "50", {reg_operand("rbx", 1U)});
    add(0x1001U, "cmp", "83 f8 00", {reg_operand("eax", 1U), imm_operand(0)});
    add(0x1004U, "jb", "72 02", {imm_operand(0x140001008ULL)});
    add(0x1006U, "nop", "90", {});
    add(0x1007U, "nop", "90", {});
    add(0x1008U, "call", "e8 13 00 00 00", {imm_operand(0x140001020ULL)});
    add(0x100dU, "pop", "5b", {reg_operand("rbx", 2U)});
    add(0x100eU, "ret", "c3", {});
    nexusrev::FunctionRecord function;
    function.entity_kind = "candidate_function"; function.boundary_status = "evidence_bounded";
    function.start_rva = 0x1000U; function.end_rva = 0x100fU; function.label = "synthetic";
    function.evidence.push_back({"synthetic_test", "labelled synthetic function", 1.0, std::nullopt, 0x1000U, 0x100fU});
    report.function_recovery.candidate_functions.push_back(function);
    nexusrev::analyze_semantics(report);
    nexusrev::analyze_phase4(report);
    if (report.semantic_analysis.functions.size() != 1U || !report.semantic_analysis.functions[0].semantic_complete ||
        report.semantic_analysis.functions[0].status != "complete") {
        std::cerr << "fully modeled bounded synthetic function was not semantically complete\n"; return false;
    }
    bool true_edge = false, false_edge = false, call_edge = false, fallthrough = false;
    for (const auto& edge : report.semantic_analysis.cfg_edges) {
        if (edge.kind == "conditional_true" && edge.from_rva == 0x1004U && edge.target_rva == 0x1008U) true_edge = true;
        if (edge.kind == "conditional_false" && edge.from_rva == 0x1004U && edge.target_rva == 0x1006U) false_edge = true;
        if (edge.kind == "call" && edge.from_rva == 0x1008U && edge.target_rva == 0x1020U) call_edge = true;
        if (edge.kind == "fallthrough" && edge.from_rva == 0x1008U && edge.target_rva == 0x100dU) fallthrough = true;
    }
    if (!true_edge || !false_edge || !call_edge || !fallthrough || report.semantic_analysis.call_graph.size() != 1U ||
        report.semantic_analysis.call_graph[0].resolution != "direct_target") {
        std::cerr << "CFG conditional, call, or fallthrough edges are missing\n"; return false;
    }
    if (std::none_of(report.phase4_analysis.control_structures.begin(), report.phase4_analysis.control_structures.end(),
                     [](const nexusrev::ControlStructureRecord& item) { return item.kind == "if_region" && item.status == "complete"; })) {
        std::cerr << "CFG-backed conditional region was not conservatively recovered\n"; return false;
    }
    const auto reference_path = std::filesystem::temp_directory_path() / "nexusrev-ghidra-reference-test.tsv";
    {
        std::ofstream reference(reference_path, std::ios::binary | std::ios::trunc);
        reference << "NEXUSREV_GHIDRA_REFERENCE\t1\t" << report.input_sha256 << "\t11.3-test\r\n"
                  << "F\t4096\r\n"
                  << "E\t4100\tconditional_branch\t4104\r\n"
                  << "E\t4104\tcall\t4128\r\n"
                  << "E\t4110\treturn\t-\r\n";
    }
    nexusrev::compare_ghidra_reference(report, reference_path.string());
    if (report.semantic_analysis.reference.status != "compared" || report.semantic_analysis.reference.difference_count != 0U) {
        std::filesystem::remove(reference_path);
        std::cerr << "matching Ghidra reference facts were reported as divergent\n"; return false;
    }
    {
        std::ofstream reference(reference_path, std::ios::binary | std::ios::trunc);
        reference << "NEXUSREV_GHIDRA_REFERENCE\t1\t" << report.input_sha256 << "\t11.3-test\n"
                  << "F\t4097\nE\t4100\tconditional_branch\t4103\n";
    }
    nexusrev::compare_ghidra_reference(report, reference_path.string());
    if (report.semantic_analysis.reference.status != "divergent" ||
        report.semantic_analysis.reference.difference_count == 0U) {
        std::cerr << "Ghidra reference disagreements were not exposed\n"; return false;
    }
    report.input_sha256 = std::string(64U, 'b');
    {
        std::ofstream reference(reference_path, std::ios::binary | std::ios::trunc);
        reference << "NEXUSREV_GHIDRA_REFERENCE\t1\t" << std::string(64U, 'a') << "\t11.3-test\n";
    }
    nexusrev::compare_ghidra_reference(report, reference_path.string());
    std::filesystem::remove(reference_path);
    if (report.semantic_analysis.reference.status != "invalid") {
        std::cerr << "unavailable or mismatched reference report was not marked invalid\n"; return false;
    }

    nexusrev::AnalysisReport indirect;
    configure_pe(indirect);
    auto indirect_jump = synthetic_instruction(0x1000U, "jmp", "ff e0");
    indirect_jump.detail_operands = {reg_operand("rax", 1U)};
    indirect.instructions.push_back(indirect_jump);
    indirect.instructions.push_back(synthetic_instruction(0x1002U, "ret", "c3"));
    function.start_rva = 0x1000U; function.end_rva = 0x1003U;
    indirect.function_recovery.candidate_functions.push_back(function);
    nexusrev::analyze_semantics(indirect);
    if (indirect.semantic_analysis.functions[0].semantic_complete ||
        indirect.semantic_analysis.functions[0].unresolved_control_flow_count == 0U ||
        indirect.semantic_analysis.cfg_edges.empty() ||
        indirect.semantic_analysis.cfg_edges[0].kind != "indirect_branch") {
        std::cerr << "function with unknown indirect branch was incorrectly marked complete\n"; return false;
    }
    nexusrev::AnalysisReport unsupported_transfer;
    configure_pe(unsupported_transfer);
    auto loop = synthetic_instruction(0x1000U, "loopne", "e0 fe");
    loop.detail_operands = {imm_operand(0x140001000ULL)};
    unsupported_transfer.instructions.push_back(loop);
    unsupported_transfer.instructions.push_back(synthetic_instruction(0x1002U, "ret", "c3"));
    function.start_rva = 0x1000U; function.end_rva = 0x1003U; function.ambiguous = false;
    unsupported_transfer.function_recovery.candidate_functions.push_back(function);
    auto far_jump = synthetic_instruction(0x1100U, "ljmp", "ea 00 00 00 00 00 00");
    far_jump.detail_operands = {imm_operand(0x140001100ULL)};
    unsupported_transfer.instructions.push_back(far_jump);
    unsupported_transfer.instructions.push_back(synthetic_instruction(0x1107U, "ret", "c3"));
    function.start_rva = 0x1100U; function.end_rva = 0x1108U; function.label = "far-transfer";
    unsupported_transfer.function_recovery.candidate_functions.push_back(function);
    nexusrev::analyze_semantics(unsupported_transfer);
    if (unsupported_transfer.semantic_analysis.instructions[0].control_flow != "unknown" ||
        unsupported_transfer.semantic_analysis.instructions[2].control_flow != "unknown" ||
        unsupported_transfer.semantic_analysis.cfg_edges.size() < 2U ||
        unsupported_transfer.semantic_analysis.cfg_edges[0].kind != "unknown" ||
        unsupported_transfer.semantic_analysis.cfg_edges[1].kind != "unknown" ||
        unsupported_transfer.semantic_analysis.functions[0].semantic_complete ||
        unsupported_transfer.semantic_analysis.functions[1].semantic_complete) {
        std::cerr << "unsupported conditional/unconditional flow was incorrectly reduced to fallthrough\n"; return false;
    }
    nexusrev::AnalysisReport trailing_gap;
    configure_pe(trailing_gap);
    trailing_gap.instructions.push_back(synthetic_instruction(0x1000U, "ret", "c3"));
    trailing_gap.decode_gaps.push_back({0U, 0x1001U, 0x140001001ULL, 0x201U, 3U, "90 90 90", "decoder_rejected"});
    function.start_rva = 0x1000U; function.end_rva = 0x1004U;
    trailing_gap.function_recovery.candidate_functions.push_back(function);
    nexusrev::analyze_semantics(trailing_gap);
    if (trailing_gap.semantic_analysis.functions[0].semantic_complete ||
        !has(trailing_gap.semantic_analysis.functions[0].issues, "decode_gap_intersects_function")) {
        std::cerr << "function with a trailing in-range decode gap was incorrectly marked complete\n"; return false;
    }
    nexusrev::AnalysisReport external_call;
    configure_pe(external_call);
    auto call = synthetic_instruction(0x1000U, "call", "e8 00 00 00 00");
    call.detail_operands = {imm_operand(0x140005000ULL)};
    external_call.instructions.push_back(call);
    external_call.instructions.push_back(synthetic_instruction(0x1005U, "ret", "c3"));
    function.start_rva = 0x1000U; function.end_rva = 0x1006U;
    external_call.function_recovery.candidate_functions.push_back(function);
    nexusrev::analyze_semantics(external_call);
    if (external_call.semantic_analysis.instructions[0].control_flow != "direct_call" ||
        external_call.semantic_analysis.call_graph.empty() ||
        external_call.semantic_analysis.call_graph[0].resolution != "unresolved_direct_target" ||
        external_call.semantic_analysis.cfg_edges.empty() || external_call.semantic_analysis.cfg_edges[0].kind != "call") {
        std::cerr << "direct call outside the image was mislabeled as an indirect call\n"; return false;
    }
    nexusrev::AnalysisReport ambiguous;
    configure_pe(ambiguous);
    ambiguous.instructions.push_back(synthetic_instruction(0x1000U, "ret", "c3"));
    function.start_rva = 0x1000U; function.end_rva = 0x1001U; function.ambiguous = true;
    ambiguous.function_recovery.candidate_functions.push_back(function);
    nexusrev::analyze_semantics(ambiguous);
    if (ambiguous.semantic_analysis.functions[0].semantic_complete ||
        !ambiguous.semantic_analysis.functions[0].boundary_ambiguous ||
        !has(ambiguous.semantic_analysis.functions[0].issues, "function_boundary_ambiguous")) {
        std::cerr << "ambiguous function boundary was incorrectly marked semantically complete\n"; return false;
    }
    return true;
}

bool phase4_stack_and_signature_tests() {
    nexusrev::AnalysisReport report;
    configure_pe(report);
    auto add = [&report](std::uint32_t rva, std::string mnemonic, std::string bytes,
                         std::vector<nexusrev::X86OperandRecord> operands,
                         std::vector<std::string> reads, std::vector<std::string> writes) {
        auto insn = synthetic_instruction(rva, std::move(mnemonic), std::move(bytes));
        insn.detail_operands = std::move(operands);
        insn.registers_read = std::move(reads);
        insn.registers_written = std::move(writes);
        report.instructions.push_back(std::move(insn));
    };
    add(0x1000U, "push", "55", {reg_operand("rbp", 1U)}, {"rbp", "rsp"}, {"rsp"});
    add(0x1001U, "mov", "48 89 e5", {reg_operand("rbp", 2U), reg_operand("rsp", 1U)}, {"rsp"}, {"rbp"});
    auto rsp_write = reg_operand("rsp", 3U);
    auto allocation = imm_operand(32U); allocation.size = 1U; allocation.access = 1U;
    add(0x1004U, "sub", "48 83 ec 20", {rsp_write, allocation}, {"rsp"}, {"rsp"});
    auto local_write = memory_operand("rbp", -4, 4U, 2U);
    auto ecx_read = reg_operand("ecx", 1U); ecx_read.size = 4U;
    add(0x1008U, "mov", "89 4d fc", {local_write, ecx_read}, {"rbp", "ecx"}, {});
    auto local_read = memory_operand("rbp", -4, 4U, 1U);
    auto eax_write = reg_operand("eax", 2U); eax_write.size = 4U;
    add(0x100bU, "mov", "8b 45 fc", {eax_write, local_read}, {"rbp"}, {"eax"});
    auto eax_rw = reg_operand("eax", 3U); eax_rw.size = 4U;
    auto one = imm_operand(1U); one.size = 1U;
    add(0x100eU, "add", "83 c0 01", {eax_rw, one}, {"eax"}, {"eax"});
    add(0x1011U, "mov", "48 89 ec", {reg_operand("rsp", 2U), reg_operand("rbp", 1U)}, {"rbp"}, {"rsp"});
    add(0x1014U, "pop", "5d", {reg_operand("rbp", 2U)}, {"rsp"}, {"rsp", "rbp"});
    add(0x1015U, "ret", "c3", {}, {"rsp"}, {"rsp"});
    nexusrev::FunctionRecord function;
    function.entity_kind = "candidate_function"; function.boundary_status = "evidence_bounded";
    function.start_rva = 0x1000U; function.end_rva = 0x1016U; function.label = "frame_sample";
    function.evidence.push_back({"synthetic_test", "bounded phase 4 stack/ABI fixture", 1.0, std::nullopt, 0x1000U, 0x1016U});
    report.function_recovery.candidate_functions.push_back(function);
    nexusrev::analyze_semantics(report);
    nexusrev::analyze_phase4(report);
    if (report.phase4_analysis.stack_frames.size() != 1U || report.phase4_analysis.signatures.size() != 1U) {
        std::cerr << "Phase 4 omitted a bounded function frame or signature\n"; return false;
    }
    const auto& frame = report.phase4_analysis.stack_frames[0];
    const auto& signature = report.phase4_analysis.signatures[0];
    if (frame.status != "complete" || !frame.has_frame_pointer ||
        frame.max_stack_depth_bytes_below_entry_rsp != 40U || frame.variables.size() != 1U ||
        frame.variables[0].stack_offset != -12 || frame.variables[0].size != 4U ||
        frame.variables[0].read_count != 1U || frame.variables[0].write_count != 1U) {
        std::cerr << "Stack-frame depth or stack-local slot recovery is incorrect\n"; return false;
    }
    if (signature.parameters.size() != 1U || signature.parameters[0].index != 0U ||
        signature.parameters[0].reg != "rcx" || signature.parameters[0].type != "unknown" ||
        signature.parameters[0].confidence < 0.7) {
        std::cerr << "Microsoft x64 argument-register recovery invented a type or missed RCX\n"; return false;
    }
    const auto pseudocode = nexusrev::emit_pseudocode(report);
    if (pseudocode.find("best-effort C-like pseudocode") == std::string::npos ||
        pseudocode.find("not original source") == std::string::npos ||
        pseudocode.find("not guaranteed compilable") == std::string::npos ||
        pseudocode.find("unknown stack_m") == std::string::npos) {
        std::cerr << "Pseudocode output lacks limitation labels or recovered frame annotations\n"; return false;
    }
    return true;
}

bool phase4_import_dataflow_tests() {
    nexusrev::AnalysisReport report;
    configure_pe(report);
    nexusrev::PeImport imported;
    imported.library = "KERNEL32.dll"; imported.name = "ExitProcess"; imported.iat_rva = 0x2000U;
    report.pe.imports.push_back(imported);
    auto set_code = synthetic_instruction(0x1000U, "mov", "b9 07 00 00 00");
    auto ecx_write = reg_operand("ecx", 2U); ecx_write.size = 4U;
    auto immediate = imm_operand(7U); immediate.size = 4U; immediate.access = 1U;
    set_code.detail_operands = {ecx_write, immediate};
    set_code.registers_written = {"ecx"};
    report.instructions.push_back(set_code);
    auto call = synthetic_instruction(0x1005U, "call", "ff 15 f5 0f 00 00");
    call.detail_operands = {memory_operand("rip", 0xff5, 8U, 1U)};
    call.registers_read = {"rip"};
    report.instructions.push_back(call);
    report.instructions.push_back(synthetic_instruction(0x100bU, "ret", "c3"));
    nexusrev::FunctionRecord function;
    function.entity_kind = "candidate_function"; function.boundary_status = "evidence_bounded";
    function.start_rva = 0x1000U; function.end_rva = 0x100cU; function.label = "import_user";
    function.evidence.push_back({"synthetic_test", "direct import call fixture", 1.0, std::nullopt, 0x1000U, 0x100cU});
    report.function_recovery.candidate_functions.push_back(function);
    nexusrev::analyze_semantics(report);
    nexusrev::analyze_phase4(report);
    if (report.phase4_analysis.imported_calls.size() != 1U) {
        std::cerr << "RIP-relative import call was not resolved to the IAT\n"; return false;
    }
    const auto& import_call = report.phase4_analysis.imported_calls[0];
    if (import_call.name != "ExitProcess" || import_call.prototype_status != "catalogued" ||
        import_call.return_type != "void" || import_call.parameter_types != std::vector<std::string>{"UINT"} ||
        import_call.arguments.size() != 1U || import_call.arguments[0].argument_register != "rcx" ||
        import_call.arguments[0].source_kind != "linear_register_definition" ||
        import_call.arguments[0].source_rva != 0x1000U) {
        std::cerr << "Import prototype or call-site argument provenance is incomplete\n"; return false;
    }
    return true;
}

bool phase4_callee_type_propagation_tests() {
    nexusrev::AnalysisReport report;
    configure_pe(report);
    auto caller_move = synthetic_instruction(0x1000U, "mov", "8b c1");
    auto eax_write = reg_operand("eax", 2U); eax_write.size = 4U;
    auto ecx_read = reg_operand("ecx", 1U); ecx_read.size = 4U;
    caller_move.detail_operands = {eax_write, ecx_read};
    caller_move.registers_read = {"ecx"}; caller_move.registers_written = {"eax"};
    report.instructions.push_back(caller_move);
    auto call = synthetic_instruction(0x1002U, "call", "e8 19 00 00 00");
    call.detail_operands = {imm_operand(0x140001020ULL)};
    report.instructions.push_back(call);
    report.instructions.push_back(synthetic_instruction(0x1007U, "ret", "c3"));
    auto callee_move = synthetic_instruction(0x1020U, "mov", "8b c1");
    callee_move.detail_operands = {eax_write, ecx_read};
    callee_move.registers_read = {"ecx"}; callee_move.registers_written = {"eax"};
    report.instructions.push_back(callee_move);
    report.instructions.push_back(synthetic_instruction(0x1022U, "ret", "c3"));
    nexusrev::FunctionRecord caller;
    caller.entity_kind = "candidate_function"; caller.boundary_status = "evidence_bounded";
    caller.start_rva = 0x1000U; caller.end_rva = 0x1008U; caller.label = "typed_caller";
    caller.evidence.push_back({"synthetic_test", "direct caller type-propagation fixture", 1.0, std::nullopt, 0x1000U, 0x1008U});
    report.function_recovery.candidate_functions.push_back(caller);
    nexusrev::FunctionRecord callee = caller;
    callee.start_rva = 0x1020U; callee.end_rva = 0x1023U; callee.label = "typed_callee";
    callee.evidence.clear();
    callee.evidence.push_back({"synthetic_test", "direct callee type-propagation fixture", 1.0, std::nullopt, 0x1020U, 0x1023U});
    report.function_recovery.candidate_functions.push_back(callee);
    report.symbols.status = "matched";
    nexusrev::PdbFunctionSymbol symbol;
    symbol.name = "typed_callee"; symbol.start_rva = 0x1020U; symbol.type_index = 0x1008U;
    symbol.type_status = "decoded"; symbol.return_type = "int"; symbol.parameter_types = {"int"};
    symbol.type_provenance = "pdb_tpi_procedure_record";
    report.symbols.functions.push_back(symbol);
    nexusrev::analyze_semantics(report);
    nexusrev::analyze_phase4(report);
    const auto caller_signature = std::find_if(report.phase4_analysis.signatures.begin(), report.phase4_analysis.signatures.end(), [](const auto& item) {
        return item.function_start_rva == 0x1000U;
    });
    const auto flow = std::find_if(report.phase4_analysis.call_argument_flows.begin(), report.phase4_analysis.call_argument_flows.end(), [](const auto& item) {
        return item.caller_start_rva == 0x1000U && item.call_rva == 0x1002U && item.parameter_index == 0U;
    });
    if (caller_signature == report.phase4_analysis.signatures.end() || caller_signature->parameters.empty() ||
        caller_signature->parameters[0].type != "int" || caller_signature->parameters[0].type_status != "inferred" ||
        flow == report.phase4_analysis.call_argument_flows.end() || flow->argument_type != "int" ||
        flow->type_status != "inferred" || flow->evidence.empty()) {
        std::cerr << "callee parameter type was not propagated through an unchanged caller-entry argument\n"; return false;
    }
    return true;
}

bool phase4_rtti_vtable_tests() {
    nexusrev::AnalysisReport report;
    configure_pe(report);
    auto& text = report.pe.sections[0];
    text.raw_offset = 0x200U; text.raw_size = 0x20U; text.file_backed_size = 0x20U;
    text.mapped_size = 0x20U; text.virtual_size = 0x20U;
    nexusrev::PeSection data;
    data.name = ".rdata"; data.virtual_address = 0x3000U; data.virtual_size = 0x200U;
    data.raw_offset = 0U; data.raw_size = 0x200U; data.file_backed_size = 0x200U;
    data.mapped_size = 0x200U; data.executable = false;
    report.pe.sections.push_back(data);
    std::vector<std::uint8_t> bytes(0x400U, 0U);
    const std::string decorated_name = ".?AVWidget@@";
    std::copy(decorated_name.begin(), decorated_name.end(), bytes.begin() + 0x30U);
    put32(bytes, 0x80U, 0U); put32(bytes, 0x84U, 0U); put32(bytes, 0x88U, 1U); put32(bytes, 0x8cU, 0x3090U);
    put32(bytes, 0x90U, 0x30a0U); put32(bytes, 0xa0U, 0x3020U);
    put32(bytes, 0xb0U, 1U); put32(bytes, 0xb4U, 0U); put32(bytes, 0xb8U, 0U);
    put32(bytes, 0xbcU, 0x3020U); put32(bytes, 0xc0U, 0x3080U); put32(bytes, 0xc4U, 0x30b0U);
    put64(bytes, 0xc8U, report.pe.image_base + 0x30b0U);
    put64(bytes, 0xd0U, report.pe.image_base + 0x1000U);
    put64(bytes, 0xd8U, report.pe.image_base + 0x1010U);
    report.pe.file_bytes = std::make_shared<const std::vector<std::uint8_t>>(std::move(bytes));
    nexusrev::analyze_phase4(report);
    if (report.phase4_analysis.rtti_vtables.size() != 1U ||
        report.phase4_analysis.rtti_vtables[0].type_name != "Widget" ||
        report.phase4_analysis.rtti_vtables[0].vtable_rva != 0x30d0U ||
        report.phase4_analysis.rtti_vtables[0].virtual_method_rvas != std::vector<std::uint32_t>({0x1000U, 0x1010U}) ||
        report.phase4_analysis.rtti_vtables[0].evidence.size() < 2U) {
        std::cerr << "bounded MSVC RTTI/vtable evidence was not recovered from synthetic in-memory PE data\n"; return false;
    }
    if (nexusrev::emit_pseudocode(report).find("MSVC RTTI class=Widget") == std::string::npos) {
        std::cerr << "pseudocode did not preserve recovered RTTI/vtable evidence\n"; return false;
    }
    return true;
}
}

int main() {
    const std::string empty_expected =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const std::string abc_expected =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    if (nexusrev::sha256("") != empty_expected) {
        std::cerr << "SHA-256 empty-string test failed\n";
        return 1;
    }
    if (nexusrev::sha256("abc") != abc_expected) {
        std::cerr << "SHA-256 abc test failed\n";
        return 1;
    }
    if (!pe_parser_tests() || !semantic_operation_tests() || !cfg_and_reference_tests() ||
        !phase4_stack_and_signature_tests() || !phase4_import_dataflow_tests() ||
        !phase4_callee_type_propagation_tests() || !phase4_rtti_vtable_tests()) return 1;
    if (!stop_control_tests()) return 1;
    std::cout << "SHA-256, PE parser, Phase 3 semantic/CFG, Phase 4 ABI/dataflow, and reference tests passed\n";
    return 0;
}
