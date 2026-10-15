#include "nexusrev.hpp"

#include <LIEF/LIEF.hpp>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <limits>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <streambuf>
#include <string_view>
#include <thread>
#include <utility>

#include "sha256.hpp"
#include "phase2.hpp"
#include "phase3.hpp"
#include "phase4.hpp"

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
constexpr std::uint64_t kMaxDecodeBytes = 64ULL * 1024ULL * 1024ULL;
constexpr std::uint64_t kMaxOutputBytes = 64ULL * 1024ULL * 1024ULL;
constexpr std::size_t kMaxInstructions = 20000U;
constexpr std::size_t kMaxDecodeGaps = 20000U;
constexpr std::size_t kMaxDecodeGapRecords = kMaxDecodeGaps - kMaxSections;
volatile std::sig_atomic_t g_cancel_requested = 0;
std::chrono::steady_clock::time_point g_analysis_deadline{};
bool g_deadline_enabled = false;

StopReason current_stop_reason() noexcept {
    if (g_cancel_requested != 0) return StopReason::cancelled;
    if (g_deadline_enabled && std::chrono::steady_clock::now() >= g_analysis_deadline)
        return StopReason::timed_out;
    return StopReason::none;
}

void diagnostic(AnalysisReport& report, std::string code, std::string severity, std::string message) {
    report.diagnostics.push_back({std::move(code), std::move(severity), std::move(message)});
}

void add_stop_diagnostic(AnalysisReport& report, StopReason reason) {
    const bool timed_out = reason == StopReason::timed_out;
    diagnostic(report, timed_out ? "ANALYSIS_TIMEOUT" : "ANALYSIS_CANCELLED", "error",
               timed_out ? "analysis exceeded its cooperative wall-clock deadline" :
                           "analysis was cancelled by the caller");
    report.status = "failed";
}

struct JsonEscapedString {
    const std::string& value;
};

JsonEscapedString escape_json(const std::string& value) { return {value}; }

std::ostream& operator<<(std::ostream& result, JsonEscapedString escaped) {
    constexpr char hex[] = "0123456789abcdef";
    std::size_t i = 0U;
    std::size_t run_start = 0U;
    while (i < escaped.value.size()) {
        const auto c = static_cast<unsigned char>(escaped.value[i]);
        const char* replacement = nullptr;
        std::size_t replacement_size = 0U;
        switch (c) {
        case '"': replacement = "\\\""; replacement_size = 2U; break;
        case '\\': replacement = "\\\\"; replacement_size = 2U; break;
        case '\b': replacement = "\\b"; replacement_size = 2U; break;
        case '\f': replacement = "\\f"; replacement_size = 2U; break;
        case '\n': replacement = "\\n"; replacement_size = 2U; break;
        case '\r': replacement = "\\r"; replacement_size = 2U; break;
        case '\t': replacement = "\\t"; replacement_size = 2U; break;
        default: break;
        }
        bool unicode_byte = false;
        if (replacement == nullptr && c < 0x20U) {
            unicode_byte = true;
        } else if (replacement == nullptr && c >= 0x80U) {
            const std::size_t length = c >= 0xc2U && c <= 0xdfU ? 2U :
                                      c >= 0xe0U && c <= 0xefU ? 3U :
                                      c >= 0xf0U && c <= 0xf4U ? 4U : 0U;
            bool valid = length != 0U && i + length <= escaped.value.size();
            for (std::size_t j = 1U; valid && j < length; ++j) {
                const auto continuation = static_cast<unsigned char>(escaped.value[i + j]);
                valid = continuation >= 0x80U && continuation <= 0xbfU;
            }
            if (valid && length == 3U) {
                const auto second = static_cast<unsigned char>(escaped.value[i + 1U]);
                valid = (c != 0xe0U || second >= 0xa0U) && (c != 0xedU || second <= 0x9fU);
            }
            if (valid && length == 4U) {
                const auto second = static_cast<unsigned char>(escaped.value[i + 1U]);
                valid = (c != 0xf0U || second >= 0x90U) && (c != 0xf4U || second <= 0x8fU);
            }
            if (valid) {
                i += length;
                continue;
            }
            unicode_byte = true;
        } else if (replacement == nullptr) {
            ++i;
            continue;
        }
        if (i > run_start)
            result.write(escaped.value.data() + static_cast<std::ptrdiff_t>(run_start),
                         static_cast<std::streamsize>(i - run_start));
        if (unicode_byte) {
            char encoded[] = {'\\', 'u', '0', '0', hex[(c >> 4U) & 15U], hex[c & 15U]};
            result.write(encoded, static_cast<std::streamsize>(sizeof(encoded)));
        } else {
            result.write(replacement, static_cast<std::streamsize>(replacement_size));
        }
        ++i;
        run_start = i;
    }
    if (i > run_start)
        result.write(escaped.value.data() + static_cast<std::ptrdiff_t>(run_start),
                     static_cast<std::streamsize>(i - run_start));
    return result;
}

std::string bytes_hex(const std::uint8_t* bytes, std::size_t size) {
    constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(size * 3U);
    for (std::size_t i = 0; i < size; ++i) {
        if (i) result.push_back(' ');
        result.push_back(hex[bytes[i] >> 4U]);
        result.push_back(hex[bytes[i] & 15U]);
    }
    return result;
}

std::string machine_label(std::uint16_t machine) {
    switch (machine) {
    case 0x8664U: return "AMD64";
    case 0x014cU: return "I386";
    case 0xaa64U: return "ARM64";
    case 0x01c0U: return "ARM";
    case 0x0200U: return "IA64";
    default: return "unknown";
    }
}

bool truncated_x86_tail(const std::vector<std::uint8_t>& bytes, std::size_t pos) {
    const std::size_t left = bytes.size() - pos;
    const std::uint8_t op = bytes[pos];
    if ((op == 0xe8U || op == 0xe9U || op == 0x68U) && left < 5U) return true;
    if ((op == 0xebU || op == 0x6aU || (op >= 0x70U && op <= 0x7fU)) && left < 2U) return true;
    if (op == 0xc2U && left < 3U) return true;
    if (op == 0x0fU && left >= 2U && bytes[pos + 1U] >= 0x80U && bytes[pos + 1U] <= 0x8fU && left < 6U) return true;
    if (op >= 0xb8U && op <= 0xbfU && left < 5U) return true;
    if (op >= 0x40U && op <= 0x4fU && left >= 2U && bytes[pos + 1U] >= 0xb8U &&
        bytes[pos + 1U] <= 0xbfU && left < 10U) return true;
    return false;
}

bool read_input(const std::string& path, std::vector<std::uint8_t>& bytes,
                std::string& code, std::string& message) {
    std::error_code ec;
    const std::filesystem::path input(path);
    if (!std::filesystem::exists(input, ec)) {
        code = "INPUT_NOT_FOUND";
        message = "cannot open input '" + path + "': " + (ec ? ec.message() : "file does not exist");
        return false;
    }
    if (!std::filesystem::is_regular_file(input, ec) || ec) {
        code = "INPUT_NOT_FILE";
        message = "input is not a readable regular file: " + path;
        return false;
    }
    const auto size = std::filesystem::file_size(input, ec);
    if (ec) { code = "INPUT_READ_FAILED"; message = "cannot determine input size: " + ec.message(); return false; }
    if (size > kMaxInputBytes) {
        code = "INPUT_SIZE_LIMIT"; message = "input exceeds the configured 256 MiB static-analysis limit"; return false;
    }
    std::ifstream stream(input, std::ios::binary);
    if (!stream) { code = "INPUT_READ_FAILED"; message = "cannot open input for reading: " + path; return false; }
    bytes.resize(static_cast<std::size_t>(size));
    if (!bytes.empty()) {
        stream.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        if (stream.gcount() != static_cast<std::streamsize>(bytes.size()) || !stream) {
            bytes.clear(); code = "INPUT_READ_FAILED"; message = "input changed or could not be read completely"; return false;
        }
    }
    return true;
}

void add_limit_gap(AnalysisReport& report, std::size_t section_index,
                   std::uint64_t delta, std::uint64_t size) {
    if (size == 0U || section_index >= report.pe.sections.size()) return;
    const auto& sec = report.pe.sections[section_index];
    const std::uint64_t rva = static_cast<std::uint64_t>(sec.virtual_address) + delta;
    if (report.decode_gaps.size() < kMaxDecodeGaps && rva <= UINT32_MAX) {
        report.decode_gaps.push_back({section_index, static_cast<std::uint32_t>(rva),
            report.pe.image_base + rva, static_cast<std::uint64_t>(sec.raw_offset) + delta,
            size, {}, "analysis_limit"});
    }
    report.decode.limited_bytes += size;
}

void add_bad_byte(AnalysisReport& report, std::size_t section_index,
                  std::uint64_t delta, std::uint8_t byte, const std::string& reason) {
    const auto& sec = report.pe.sections[section_index];
    const std::uint64_t rva = static_cast<std::uint64_t>(sec.virtual_address) + delta;
    const std::uint64_t file = static_cast<std::uint64_t>(sec.raw_offset) + delta;
    if (!report.decode_gaps.empty()) {
        auto& tail = report.decode_gaps.back();
        if (tail.section_index == section_index && tail.reason == reason && tail.file_offset &&
            static_cast<std::uint64_t>(tail.rva) + tail.size == rva && *tail.file_offset + tail.size == file) {
            tail.bytes += " " + bytes_hex(&byte, 1U);
            ++tail.size;
            ++report.decode.undecoded_bytes;
            return;
        }
    }
    if (report.decode_gaps.size() < kMaxDecodeGaps && rva <= UINT32_MAX) {
        report.decode_gaps.push_back({section_index, static_cast<std::uint32_t>(rva),
            report.pe.image_base + rva, file, 1U, bytes_hex(&byte, 1U), reason});
    }
    ++report.decode.undecoded_bytes;
}

std::string register_name(csh handle, unsigned int reg) {
    const char* name = cs_reg_name(handle, reg);
    return name == nullptr ? std::string{} : std::string(name);
}

InstructionRecord make_instruction_record(const cs_insn& insn, csh handle,
                                            std::size_t section_index, std::uint64_t va,
                                            std::uint32_t rva, std::uint64_t file_offset) {
    InstructionRecord record;
    record.section_index = section_index;
    record.va = va;
    record.rva = rva;
    record.file_offset = file_offset;
    record.bytes = bytes_hex(insn.bytes, insn.size);
    record.mnemonic = insn.mnemonic;
    record.operands = insn.op_str;
    record.instruction_id = insn.id;
    const char* instruction_name = cs_insn_name(handle, insn.id);
    if (instruction_name != nullptr) record.instruction_name = instruction_name;
    if (insn.detail == nullptr) return record;

    record.detail_available = true;
    const cs_detail& detail = *insn.detail;
    for (std::size_t i = 0; i < detail.groups_count; ++i) {
        const char* name = cs_group_name(handle, detail.groups[i]);
        record.groups.emplace_back(name == nullptr ? "unknown" : name);
    }
    cs_regs regs_read{};
    cs_regs regs_written{};
    std::uint8_t regs_read_count = 0;
    std::uint8_t regs_written_count = 0;
    if (cs_regs_access(handle, &insn, regs_read, &regs_read_count,
                       regs_written, &regs_written_count) == CS_ERR_OK) {
        for (std::size_t i = 0; i < regs_read_count; ++i)
            record.registers_read.push_back(register_name(handle, regs_read[i]));
        for (std::size_t i = 0; i < regs_written_count; ++i)
            record.registers_written.push_back(register_name(handle, regs_written[i]));
    }

    const cs_x86& x86 = detail.x86;
    for (std::size_t i = 0; i < record.prefixes.size(); ++i) {
        record.prefixes[i] = x86.prefix[i];
        record.opcodes[i] = x86.opcode[i];
    }
    record.rex = x86.rex;
    record.address_size = x86.addr_size;
    record.modrm = x86.modrm;
    record.sib = x86.sib;
    record.displacement = x86.disp;
    record.flags = x86.eflags;
    record.modrm_offset = x86.encoding.modrm_offset;
    record.displacement_offset = x86.encoding.disp_offset;
    record.displacement_size = x86.encoding.disp_size;
    record.immediate_offset = x86.encoding.imm_offset;
    record.immediate_size = x86.encoding.imm_size;
    for (std::size_t i = 0; i < x86.op_count; ++i) {
        const cs_x86_op& source = x86.operands[i];
        X86OperandRecord operand;
        operand.size = source.size;
        operand.access = source.access;
        operand.avx_broadcast = static_cast<std::uint8_t>(source.avx_bcast);
        operand.avx_zero_opmask = source.avx_zero_opmask;
        switch (source.type) {
        case X86_OP_REG:
            operand.type = "register";
            operand.reg = register_name(handle, source.reg);
            break;
        case X86_OP_IMM:
            operand.type = "immediate";
            operand.immediate = source.imm;
            break;
        case X86_OP_MEM:
            operand.type = "memory";
            operand.segment = register_name(handle, source.mem.segment);
            operand.base = register_name(handle, source.mem.base);
            operand.index = register_name(handle, source.mem.index);
            operand.scale = source.mem.scale;
            operand.displacement = source.mem.disp;
            break;
        default:
            operand.type = "invalid";
            break;
        }
        record.detail_operands.push_back(std::move(operand));
    }
    return record;
}

void decode_sections_linear(AnalysisReport& report, csh handle) {
    struct InsnDeleter {
        void operator()(cs_insn* value) const { if (value != nullptr) cs_free(value, 1U); }
    };
    std::unique_ptr<cs_insn, InsnDeleter> instruction(cs_malloc(handle));
    if (!instruction) {
        diagnostic(report, "DECODER_ALLOCATION_FAILED", "error", "Capstone could not allocate an instruction record");
        report.stages.push_back({"analysis", "failed"});
        report.status = "failed";
        return;
    }
    for (std::size_t i = 0; i < report.pe.sections.size(); ++i) {
        const auto& sec = report.pe.sections[i];
        if (!sec.executable) continue;
        report.decode.executable_file_backed_bytes += sec.file_backed_size;
        if (sec.zero_fill_size != 0U) {
            report.decode.executable_zero_fill_bytes += sec.zero_fill_size;
            const std::uint64_t rva = static_cast<std::uint64_t>(sec.virtual_address) + sec.raw_size;
            if (report.decode_gaps.size() < kMaxDecodeGaps && rva <= UINT32_MAX) {
                report.decode_gaps.push_back({i, static_cast<std::uint32_t>(rva), report.pe.image_base + rva,
                    std::nullopt, sec.zero_fill_size, {},
                    "virtual_zero_fill_not_file_backed"});
            }
        }
    }
    std::uint64_t budget = kMaxDecodeBytes;
    bool stop_for_record_limit = false;
    for (std::size_t si = 0; si < report.pe.sections.size(); ++si) {
        const auto& sec = report.pe.sections[si];
        if (!sec.executable || sec.file_backed_size == 0U) continue;
        if (stop_for_record_limit || budget == 0U) { add_limit_gap(report, si, 0U, sec.file_backed_size); continue; }
        const std::uint64_t portion = std::min(sec.file_backed_size, budget);
        std::vector<std::uint8_t> code;
        if (!report.pe.read_file(sec.raw_offset, static_cast<std::size_t>(portion), code)) {
            diagnostic(report, "SECTION_CONTENT_UNREADABLE", "error", "validated executable bytes could not be read from the file snapshot");
            report.stages.push_back({"analysis", "failed"}); report.status = "failed"; return;
        }
        std::size_t pos = 0;
        while (pos < code.size()) {
            const auto reason = current_stop_reason();
            if (reason != StopReason::none) {
                add_stop_diagnostic(report, reason);
                report.stages.push_back({"analysis", "failed"});
                return;
            }
            if (report.instructions.size() >= kMaxInstructions || report.decode_gaps.size() >= kMaxDecodeGapRecords) {
                add_limit_gap(report, si, pos, sec.file_backed_size - pos);
                stop_for_record_limit = true;
                diagnostic(report, "ANALYSIS_RECORD_LIMIT", "warning", "instruction or gap record limit reached; remaining executable ranges are reported as limited intervals");
                break;
            }
            const std::uint64_t rva64 = static_cast<std::uint64_t>(sec.virtual_address) + pos;
            const std::uint64_t va = report.pe.image_base + rva64;
            const std::uint64_t file_offset = static_cast<std::uint64_t>(sec.raw_offset) + pos;
            const std::uint8_t* cursor = code.data() + pos;
            const std::uint8_t* next = cursor;
            std::size_t left = code.size() - pos;
            std::size_t next_left = left;
            std::uint64_t address = va;
            if (cs_disasm_iter(handle, &next, &next_left, &address, instruction.get())) {
                const std::size_t size = static_cast<std::size_t>(next - cursor);
                if (size == 0U || rva64 > UINT32_MAX) {
                    add_bad_byte(report, si, pos, code[pos], "decoder_rejected");
                    ++pos; ++report.decode.processed_bytes; --budget;
                    continue;
                }
                report.instructions.push_back(make_instruction_record(*instruction, handle, si,
                    instruction->address, static_cast<std::uint32_t>(rva64), file_offset));
                pos += size; report.decode.processed_bytes += size; report.decode.decoded_bytes += size;
                ++report.decode.instruction_count; budget -= size;
            } else {
                if (truncated_x86_tail(code, pos)) {
                    const std::size_t gap_size = code.size() - pos;
                    const std::uint64_t gap_rva = static_cast<std::uint64_t>(sec.virtual_address) + pos;
                    if (report.decode_gaps.size() < kMaxDecodeGaps && gap_rva <= UINT32_MAX) {
                        report.decode_gaps.push_back({si, static_cast<std::uint32_t>(gap_rva),
                            report.pe.image_base + gap_rva, file_offset, gap_size,
                            bytes_hex(code.data() + pos, gap_size), "truncated_instruction"});
                    }
                    pos += gap_size;
                    report.decode.processed_bytes += gap_size;
                    report.decode.undecoded_bytes += gap_size;
                    budget -= gap_size;
                } else {
                    add_bad_byte(report, si, pos, code[pos], "decoder_rejected");
                    ++pos; ++report.decode.processed_bytes; --budget;
                }
            }
        }
        if (!stop_for_record_limit && portion < sec.file_backed_size) {
            add_limit_gap(report, si, portion, sec.file_backed_size - portion);
            diagnostic(report, "ANALYSIS_BYTE_LIMIT", "warning", "executable-byte analysis stopped at the configured 64 MiB work limit");
        }
    }
    if (report.decode.executable_file_backed_bytes == 0U)
        diagnostic(report, "NO_EXECUTABLE_FILE_BACKED_BYTES", "warning", "no file-backed executable section bytes were available for decoding");
    if (report.decode.undecoded_bytes != 0U)
        diagnostic(report, "DECODE_GAPS_PRESENT", "warning", "some executable bytes were rejected by the decoder; exact intervals and byte values are reported");
    if (report.decode.executable_zero_fill_bytes != 0U)
        diagnostic(report, "EXECUTABLE_ZERO_FILL_PRESENT", "info", "virtual zero-fill has no source-file bytes and was not decoded");
    diagnostic(report, "SEMANTIC_ANALYSIS_BOUNDED", "info", "Phase 3 emits conservative x86-64 semantic IR and control-flow evidence; unsupported instructions and unresolved flow remain explicit, and source-level reconstruction is not claimed");
    report.stages.push_back({"analysis", "partial"});
    report.status = "partial";
}

struct FunctionRangeTask {
    std::size_t section_index = 0U;
    std::uint32_t begin_rva = 0U;
    std::uint32_t end_rva = 0U;
    std::size_t instruction_budget = 0U;
    std::uint64_t byte_budget = 0U;
};

struct FunctionRangeResult {
    std::vector<InstructionRecord> instructions;
    std::vector<DecodeGap> gaps;
    std::vector<std::pair<std::uint32_t, std::uint32_t>> processed_intervals;
    std::uint64_t consumed_bytes = 0U;
    std::uint64_t decoded_bytes = 0U;
    std::uint64_t undecoded_bytes = 0U;
};

void append_task_bad_byte(FunctionRangeResult& result, std::size_t section_index,
                          std::uint64_t image_base, std::uint32_t rva,
                          std::uint64_t file_offset, std::uint8_t byte,
                          std::size_t gap_record_limit) {
    if (!result.gaps.empty()) {
        auto& tail = result.gaps.back();
        if (tail.section_index == section_index && tail.reason == "decoder_rejected" &&
            tail.file_offset && static_cast<std::uint64_t>(tail.rva) + tail.size == rva &&
            *tail.file_offset + tail.size == file_offset) {
            tail.bytes += " " + bytes_hex(&byte, 1U);
            ++tail.size;
            ++result.undecoded_bytes;
            return;
        }
    }
    if (result.gaps.size() < gap_record_limit)
        result.gaps.push_back({section_index, rva, image_base + rva, file_offset, 1U,
                               bytes_hex(&byte, 1U), "decoder_rejected"});
    ++result.undecoded_bytes;
}

bool decode_runtime_function_ranges(AnalysisReport& report, std::size_t requested_workers) {
    constexpr std::size_t kMaximumFunctionTasks = 1024U;
    constexpr std::size_t kMaximumDecodeWorkers = 8U;
    std::vector<FunctionRangeTask> candidates;
    candidates.reserve(std::min(report.pe.runtime_functions.size(), kMaxRuntimeFunctionRecords));
    for (const auto& runtime : report.pe.runtime_functions) {
        if (!runtime.unwind_info_available || runtime.begin_rva >= runtime.end_rva) continue;
        const auto mapping = report.pe.map_rva(runtime.begin_rva);
        if (!mapping.mapped || mapping.virtual_zero_fill || mapping.section_index < 0) continue;
        const auto section_index = static_cast<std::size_t>(mapping.section_index);
        if (section_index >= report.pe.sections.size()) continue;
        const auto& section = report.pe.sections[section_index];
        if (!section.executable || runtime.begin_rva < section.virtual_address) continue;
        const std::uint64_t section_file_end =
            static_cast<std::uint64_t>(section.virtual_address) + section.file_backed_size;
        if (runtime.end_rva > section_file_end ||
            static_cast<std::uint64_t>(runtime.end_rva - runtime.begin_rva) > mapping.available_file_bytes)
            continue;
        candidates.push_back({section_index, runtime.begin_rva, runtime.end_rva, 0U, 0U});
    }
    std::sort(candidates.begin(), candidates.end(), [](const auto& left, const auto& right) {
        if (left.section_index != right.section_index) return left.section_index < right.section_index;
        if (left.begin_rva != right.begin_rva) return left.begin_rva < right.begin_rva;
        return left.end_rva < right.end_rva;
    });
    std::vector<FunctionRangeTask> non_overlapping;
    non_overlapping.reserve(candidates.size());
    for (const auto& candidate : candidates) {
        if (!non_overlapping.empty() &&
            non_overlapping.back().section_index == candidate.section_index &&
            candidate.begin_rva < non_overlapping.back().end_rva)
            continue;
        if (!non_overlapping.empty() &&
            non_overlapping.back().section_index == candidate.section_index &&
            candidate.begin_rva == non_overlapping.back().begin_rva)
            continue;
        non_overlapping.push_back(candidate);
    }
    if (non_overlapping.empty()) return false;

    const std::size_t task_count = std::min(non_overlapping.size(), kMaximumFunctionTasks);
    std::vector<FunctionRangeTask> tasks;
    tasks.reserve(task_count);
    for (std::size_t i = 0U; i < task_count; ++i) {
        const std::size_t candidate_index = (i * non_overlapping.size()) / task_count;
        tasks.push_back(non_overlapping[candidate_index]);
    }
    const std::size_t instructions_per_task = kMaxInstructions / task_count;
    const std::size_t extra_instruction_slots = kMaxInstructions % task_count;
    const std::uint64_t bytes_per_task = kMaxDecodeBytes / task_count;
    const std::uint64_t extra_byte_slots = kMaxDecodeBytes % task_count;
    for (std::size_t i = 0U; i < tasks.size(); ++i) {
        tasks[i].instruction_budget = instructions_per_task + (i < extra_instruction_slots ? 1U : 0U);
        tasks[i].byte_budget = bytes_per_task + (i < extra_byte_slots ? 1U : 0U);
    }

    for (std::size_t i = 0U; i < report.pe.sections.size(); ++i) {
        const auto& section = report.pe.sections[i];
        if (!section.executable) continue;
        report.decode.executable_file_backed_bytes += section.file_backed_size;
        if (section.zero_fill_size != 0U) {
            report.decode.executable_zero_fill_bytes += section.zero_fill_size;
            const std::uint64_t rva = static_cast<std::uint64_t>(section.virtual_address) + section.raw_size;
            if (report.decode_gaps.size() < kMaxDecodeGaps && rva <= UINT32_MAX)
                report.decode_gaps.push_back({i, static_cast<std::uint32_t>(rva), report.pe.image_base + rva,
                    std::nullopt, section.zero_fill_size, {}, "virtual_zero_fill_not_file_backed"});
        }
    }

    std::vector<FunctionRangeResult> results(tasks.size());
    std::atomic<std::size_t> next_task{0U};
    std::atomic<bool> worker_failed{false};
    std::mutex error_mutex;
    std::string worker_error;
    std::string worker_error_code = "FUNCTION_RANGE_DECODE_FAILED";
    const auto fail_worker = [&](const char* code, const char* message) {
        bool expected = false;
        if (!worker_failed.compare_exchange_strong(expected, true)) return;
        try {
            std::lock_guard<std::mutex> guard(error_mutex);
            worker_error_code = code;
            worker_error = message;
        } catch (...) {}
    };
    const std::size_t per_task_gap_limit = std::max<std::size_t>(
        1U, kMaxDecodeGapRecords / tasks.size() + 1U);
    const auto worker = [&]() {
        csh handle = 0;
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
            fail_worker("DECODER_INITIALIZATION_FAILED", "unable to initialize a Capstone handle for a function-range worker");
            return;
        }
        if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
            cs_close(&handle);
            fail_worker("DECODER_DETAIL_FAILED", "unable to enable Capstone detail mode for a function-range worker");
            return;
        }
        try {
            struct InsnDeleter {
                void operator()(cs_insn* value) const { if (value != nullptr) cs_free(value, 1U); }
            };
            std::unique_ptr<cs_insn, InsnDeleter> instruction(cs_malloc(handle));
            if (!instruction) {
                fail_worker("DECODER_ALLOCATION_FAILED", "Capstone could not allocate an instruction record for a function-range worker");
                cs_close(&handle);
                return;
            }
            while (!worker_failed.load()) {
            const std::size_t task_index = next_task.fetch_add(1U);
            if (task_index >= tasks.size()) break;
            const auto& task = tasks[task_index];
            auto& result = results[task_index];
            const auto& section = report.pe.sections[task.section_index];
            const std::uint64_t range_size = static_cast<std::uint64_t>(task.end_rva) - task.begin_rva;
            const std::uint64_t window_size = std::min(range_size, task.byte_budget);
            if (window_size > std::numeric_limits<std::size_t>::max()) {
                fail_worker("FUNCTION_RANGE_SIZE_INVALID", "function range exceeds the addressable decode window");
                break;
            }
            std::vector<std::uint8_t> code;
            if (!report.pe.read_rva(task.begin_rva, static_cast<std::size_t>(window_size), code)) {
                fail_worker("FUNCTION_RANGE_CONTENT_UNREADABLE", "validated runtime-function bytes could not be read from the input snapshot");
                break;
            }
            const std::uint64_t window_end64 = static_cast<std::uint64_t>(task.begin_rva) + window_size;
            const auto window_end = static_cast<std::uint32_t>(window_end64);
            std::set<std::uint32_t> pending;
            std::set<std::uint32_t> enqueued;
            std::map<std::uint32_t, std::uint32_t> occupied;
            pending.insert(task.begin_rva);
            enqueued.insert(task.begin_rva);
            const auto enqueue_rva = [&](std::uint32_t target) {
                if (target >= task.begin_rva && target < window_end && enqueued.insert(target).second)
                    pending.insert(target);
            };
            while (!pending.empty() && result.instructions.size() < task.instruction_budget &&
                   result.consumed_bytes < task.byte_budget) {
                if (current_stop_reason() != StopReason::none) break;
                std::uint32_t current = *pending.begin();
                pending.erase(pending.begin());
                while (current < window_end && result.instructions.size() < task.instruction_budget &&
                       result.consumed_bytes < task.byte_budget) {
                    if (current_stop_reason() != StopReason::none) break;
                    const auto next_occupied = occupied.upper_bound(current);
                    if ((next_occupied != occupied.begin() && std::prev(next_occupied)->second > current) ||
                        (next_occupied != occupied.end() && next_occupied->first == current))
                        break;
                    const std::size_t pos = static_cast<std::size_t>(current - task.begin_rva);
                    const std::uint64_t rva64 = current;
                    if (rva64 > UINT32_MAX || report.pe.image_base > UINT64_MAX - rva64) {
                        fail_worker("FUNCTION_RANGE_ADDRESS_INVALID", "runtime-function address overflows the supported PE address model");
                        break;
                    }
                    const std::uint64_t file_offset = static_cast<std::uint64_t>(section.raw_offset) +
                        (static_cast<std::uint64_t>(task.begin_rva) - section.virtual_address) + pos;
                    const std::uint8_t* cursor = code.data() + pos;
                    const std::uint8_t* next = cursor;
                    std::size_t next_left = code.size() - pos;
                    std::uint64_t address = report.pe.image_base + rva64;
                    if (cs_disasm_iter(handle, &next, &next_left, &address, instruction.get())) {
                        const std::size_t size = static_cast<std::size_t>(next - cursor);
                        if (size == 0U) {
                            append_task_bad_byte(result, task.section_index, report.pe.image_base,
                                                 current, file_offset, code[pos], per_task_gap_limit);
                            result.processed_intervals.emplace_back(pos, pos + 1U);
                            ++result.consumed_bytes;
                            ++current;
                            continue;
                        }
                        const std::uint64_t next_rva64 = static_cast<std::uint64_t>(current) + size;
                        const auto overlap = occupied.lower_bound(current);
                        if (next_rva64 > window_end64 ||
                            (overlap != occupied.end() && overlap->first < next_rva64) ||
                            (overlap != occupied.begin() && std::prev(overlap)->second > current))
                            break;
                        result.instructions.push_back(make_instruction_record(*instruction, handle, task.section_index,
                            instruction->address, current, file_offset));
                        occupied.emplace(current, static_cast<std::uint32_t>(next_rva64));
                        result.processed_intervals.emplace_back(pos, pos + static_cast<std::uint32_t>(size));
                        result.consumed_bytes += size;
                        result.decoded_bytes += size;

                        const bool is_call = cs_insn_group(handle, instruction.get(), CS_GRP_CALL);
                        const bool is_jump = cs_insn_group(handle, instruction.get(), CS_GRP_JUMP);
                        const bool is_return = cs_insn_group(handle, instruction.get(), CS_GRP_RET) ||
                            std::strncmp(instruction->mnemonic, "iret", 4U) == 0;
                        std::optional<std::uint32_t> branch_target;
                        if (is_jump && instruction->detail != nullptr) {
                            for (std::size_t operand_index = 0U;
                                 operand_index < instruction->detail->x86.op_count; ++operand_index) {
                                const auto& operand = instruction->detail->x86.operands[operand_index];
                                if (operand.type != X86_OP_IMM) continue;
                                std::uint32_t target = 0U;
                                if (report.pe.va_to_rva(static_cast<std::uint64_t>(operand.imm), target))
                                    branch_target = target;
                                break;
                            }
                        }
                        const std::uint32_t fallthrough = static_cast<std::uint32_t>(next_rva64);
                        if (is_return) break;
                        if (is_call) {
                            current = fallthrough;
                            continue;
                        }
                        if (is_jump) {
                            if (branch_target) enqueue_rva(*branch_target);
                            const bool unconditional = std::strcmp(instruction->mnemonic, "jmp") == 0 ||
                                std::strcmp(instruction->mnemonic, "jmpq") == 0 ||
                                std::strcmp(instruction->mnemonic, "ljmp") == 0 ||
                                std::strcmp(instruction->mnemonic, "ljmpq") == 0;
                            if (unconditional) break;
                        }
                        current = fallthrough;
                    } else if (truncated_x86_tail(code, pos)) {
                        const std::size_t gap_size = code.size() - pos;
                        if (result.gaps.size() < per_task_gap_limit) {
                            result.gaps.push_back({task.section_index, current, report.pe.image_base + current,
                                file_offset, gap_size, bytes_hex(code.data() + pos, gap_size), "truncated_instruction"});
                        }
                        result.processed_intervals.emplace_back(pos, pos + static_cast<std::uint32_t>(gap_size));
                        result.consumed_bytes += gap_size;
                        result.undecoded_bytes += gap_size;
                        break;
                    } else {
                        append_task_bad_byte(result, task.section_index, report.pe.image_base,
                                             current, file_offset, code[pos], per_task_gap_limit);
                        result.processed_intervals.emplace_back(pos, pos + 1U);
                        ++result.consumed_bytes;
                        ++current;
                    }
                }
            }
            }
        } catch (const std::exception&) {
            fail_worker("FUNCTION_RANGE_WORKER_EXCEPTION", "function-range worker failed while allocating or processing a decode task");
        } catch (...) {
            fail_worker("FUNCTION_RANGE_WORKER_EXCEPTION", "function-range worker failed with an unknown exception");
        }
        cs_close(&handle);
    };

    unsigned int hardware_workers = std::thread::hardware_concurrency();
    if (hardware_workers == 0U) hardware_workers = 1U;
    const std::size_t available_workers = requested_workers == 0U ?
        std::min<std::size_t>(hardware_workers, kMaximumDecodeWorkers) :
        std::min<std::size_t>(requested_workers, kMaximumDecodeWorkers);
    const std::size_t worker_count = std::min(tasks.size(), std::max<std::size_t>(1U, available_workers));
    std::vector<std::thread> threads;
    threads.reserve(worker_count);
    try {
        for (std::size_t i = 0U; i < worker_count; ++i) threads.emplace_back(worker);
    } catch (const std::exception&) {
        fail_worker("DECODE_WORKER_START_FAILED", "could not start the bounded decoder worker pool");
    }
    for (auto& thread : threads) if (thread.joinable()) thread.join();
    const auto stop_reason = current_stop_reason();
    if (stop_reason != StopReason::none) {
        add_stop_diagnostic(report, stop_reason);
        report.stages.push_back({"analysis", "failed"});
        return true;
    }
    if (worker_failed.load()) {
        diagnostic(report, worker_error_code, "error", worker_error.empty() ? "function-range decode worker failed" : worker_error);
        report.stages.push_back({"analysis", "failed"});
        report.status = "failed";
        return true;
    }

    struct ProcessedInterval { std::size_t section_index; std::uint64_t begin; std::uint64_t end; };
    std::vector<ProcessedInterval> processed_intervals;
    processed_intervals.reserve(tasks.size());
    for (std::size_t i = 0U; i < tasks.size(); ++i) {
        const auto& task = tasks[i];
        auto& result = results[i];
        report.decode.processed_bytes += result.consumed_bytes;
        report.decode.decoded_bytes += result.decoded_bytes;
        report.decode.undecoded_bytes += result.undecoded_bytes;
        report.decode.instruction_count += result.instructions.size();
        report.instructions.insert(report.instructions.end(),
            std::make_move_iterator(result.instructions.begin()), std::make_move_iterator(result.instructions.end()));
        for (auto& gap : result.gaps)
            if (report.decode_gaps.size() < kMaxDecodeGaps) report.decode_gaps.push_back(std::move(gap));
        const auto& section = report.pe.sections[task.section_index];
        const std::uint64_t section_offset = static_cast<std::uint64_t>(task.begin_rva) - section.virtual_address;
        for (const auto& interval : result.processed_intervals)
            processed_intervals.push_back({task.section_index, section_offset + interval.first,
                                           section_offset + interval.second});
    }
    std::sort(processed_intervals.begin(), processed_intervals.end(), [](const auto& left, const auto& right) {
        if (left.section_index != right.section_index) return left.section_index < right.section_index;
        return left.begin < right.begin;
    });
    std::size_t interval_index = 0U;
    for (std::size_t section_index = 0U; section_index < report.pe.sections.size(); ++section_index) {
        const auto& section = report.pe.sections[section_index];
        if (!section.executable || section.file_backed_size == 0U) continue;
        std::uint64_t cursor = 0U;
        while (interval_index < processed_intervals.size() &&
               processed_intervals[interval_index].section_index == section_index) {
            const auto& interval = processed_intervals[interval_index++];
            if (interval.begin > cursor) add_limit_gap(report, section_index, cursor, interval.begin - cursor);
            cursor = std::max(cursor, interval.end);
        }
        if (cursor < section.file_backed_size)
            add_limit_gap(report, section_index, cursor, section.file_backed_size - cursor);
    }
    std::sort(report.instructions.begin(), report.instructions.end(), [](const auto& left, const auto& right) {
        if (left.section_index != right.section_index) return left.section_index < right.section_index;
        return left.rva < right.rva;
    });
    std::sort(report.decode_gaps.begin(), report.decode_gaps.end(), [](const auto& left, const auto& right) {
        if (left.section_index != right.section_index) return left.section_index < right.section_index;
        return left.rva < right.rva;
    });
    if (report.decode.executable_file_backed_bytes == 0U)
        diagnostic(report, "NO_EXECUTABLE_FILE_BACKED_BYTES", "warning", "no file-backed executable section bytes were available for decoding");
    diagnostic(report, "FUNCTION_RANGE_DECODE_USED", "info",
        "decoded deterministic, stratified AMD64 RUNTIME_FUNCTION ranges with RVA-ordered control-flow worklists; unwind metadata is evidence, not proof of source-level function boundaries");
    diagnostic(report, "FUNCTION_RANGE_WORKLIST_USED", "info",
        "each selected validated range was seeded at its begin RVA; direct in-range branch targets and fallthrough were followed, while unvisited bytes remain analysis-limit gaps");
    if (report.decode.limited_bytes != 0U)
        diagnostic(report, "ANALYSIS_FUNCTION_RANGE_LIMIT", "info",
            "bytes outside selected ranges, unreachable from worklist seeds, or beyond per-range budgets remain explicit analysis-limit gaps");
    if (report.decode.undecoded_bytes != 0U)
        diagnostic(report, "DECODE_GAPS_PRESENT", "warning", "some executable bytes were rejected by the decoder; exact intervals and byte values are reported where within the gap-record bound");
    if (report.decode.executable_zero_fill_bytes != 0U)
        diagnostic(report, "EXECUTABLE_ZERO_FILL_PRESENT", "info", "virtual zero-fill has no source-file bytes and was not decoded");
    diagnostic(report, "SEMANTIC_ANALYSIS_BOUNDED", "info",
        "Phase 3 emits conservative x86-64 semantic IR and control-flow evidence; unsupported instructions and unresolved flow remain explicit, and source-level reconstruction is not claimed");
    report.stages.push_back({"analysis", "partial"});
    report.status = "partial";
    return true;
}

void decode_sections(AnalysisReport& report, csh handle, const std::string& strategy,
                     std::size_t requested_workers) {
    if (strategy != "linear" && strategy != "auto" && strategy != "function-ranges") {
        diagnostic(report, "DECODE_STRATEGY_INVALID", "error", "decode strategy must be linear, auto, or function-ranges");
        report.stages.push_back({"analysis", "failed"});
        report.status = "failed";
        return;
    }
    std::uint64_t executable_bytes = 0U;
    for (const auto& section : report.pe.sections)
        if (section.executable) executable_bytes += section.file_backed_size;
    const bool automatic_function_ranges = strategy == "auto" && executable_bytes >= 8ULL * 1024ULL * 1024ULL &&
        report.pe.runtime_functions.size() >= 512U;
    if (strategy == "function-ranges" || automatic_function_ranges) {
        if (decode_runtime_function_ranges(report, requested_workers)) return;
        if (strategy == "function-ranges")
            diagnostic(report, "FUNCTION_RANGE_NO_VALID_SEEDS", "warning",
                "no validated file-backed AMD64 runtime-function ranges were available; falling back to linear decoding");
    }
    decode_sections_linear(report, handle);
}

void emit_diagnostics_json(std::ostream& output, const std::vector<Diagnostic>& diagnostics) {
    output << '[';
    for (std::size_t i = 0; i < diagnostics.size(); ++i) {
        const auto& item = diagnostics[i];
        output << (i ? "," : "") << "{\"code\":\"" << escape_json(item.code)
               << "\",\"severity\":\"" << escape_json(item.severity)
               << "\",\"message\":\"" << escape_json(item.message) << "\"}";
    }
    output << ']';
}

void emit_function_records_json(std::ostream& output, const std::vector<FunctionRecord>& records) {
    output << '[';
    for (std::size_t i = 0; i < records.size(); ++i) {
        const auto& record = records[i];
        output << (i ? "," : "") << "{\"entity_kind\":\"" << escape_json(record.entity_kind)
               << "\",\"boundary_status\":\"" << escape_json(record.boundary_status)
               << "\",\"start_rva\":" << record.start_rva << ",\"end_rva\":";
        if (record.end_rva) output << *record.end_rva; else output << "null";
        output << ",\"file_offset\":";
        if (record.file_offset) output << *record.file_offset; else output << "null";
        output << ",\"label\":\"" << escape_json(record.label) << "\",\"aliases\":[";
        for (std::size_t j = 0; j < record.aliases.size(); ++j)
            output << (j ? "," : "") << "\"" << escape_json(record.aliases[j]) << "\"";
        output << "],\"confidence\":" << record.confidence << ",\"ambiguous\":"
               << (record.ambiguous ? "true" : "false") << ",\"evidence\":[";
        for (std::size_t j = 0; j < record.evidence.size(); ++j) {
            const auto& evidence = record.evidence[j];
            output << (j ? "," : "") << "{\"source\":\"" << escape_json(evidence.source)
                   << "\",\"description\":\"" << escape_json(evidence.description)
                   << "\",\"confidence\":" << evidence.confidence << ",\"reference_rva\":";
            if (evidence.reference_rva) output << *evidence.reference_rva; else output << "null";
            output << ",\"start_rva\":";
            if (evidence.start_rva) output << *evidence.start_rva; else output << "null";
            output << ",\"end_rva\":";
            if (evidence.end_rva) output << *evidence.end_rva; else output << "null";
            output << '}';
        }
        output << "]}";
    }
    output << ']';
}

void make_json(std::ostream& o, const AnalysisReport& r) {
    const auto& p = r.pe;
    o << "{\n  \"schema_version\": " << r.schema_version << ",\n  \"status\": \"" << escape_json(r.status)
      << "\",\n  \"run\": {\"start_status\": \"" << escape_json(r.start_status) << "\", \"end_status\": \""
      << escape_json(r.status) << "\", \"exit_code\": " << r.exit_code << "},\n"
      << "  \"input\": {\"path\": \"" << escape_json(r.input_path) << "\", \"sha256\": \""
      << r.input_sha256 << "\", \"size_bytes\": " << (p.file_bytes ? p.file_bytes->size() : 0U) << "},\n"
      << "  \"tool\": {\"name\": \"NexussREV\", \"version\": \"" << escape_json(r.tool_version)
      << "\", \"configuration_version\": " << r.configuration_version << "},\n"
      << "  \"dependencies\": {\"lief\": \"" << escape_json(r.lief_version) << "\", \"capstone\": \""
      << escape_json(r.capstone_version) << "\"},\n  \"pe\": {\n"
      << "    \"machine\": " << p.machine << ", \"machine_name\": \"" << machine_label(p.machine)
      << "\", \"optional_header_magic\": " << p.optional_header_magic << ", \"pe32_plus\": " << (p.pe32_plus ? "true" : "false")
      << ", \"supported_x64_native\": " << (p.supported_x64_native ? "true" : "false")
      << ", \"is_dll\": " << (p.is_dll ? "true" : "false") << ", \"image_base\": " << p.image_base
      << ", \"entry_point\": {\"rva\": " << p.entry_point_rva << ", \"va\": ";
    if (p.image_base <= std::numeric_limits<std::uint64_t>::max() - p.entry_point_rva)
        o << (p.image_base + p.entry_point_rva);
    else
        o << "null";
    o << ", \"file_offset\": ";
    std::uint64_t ep_offset = 0;
    if (p.entry_point_rva != 0U && p.rva_to_file_offset(p.entry_point_rva, ep_offset)) o << ep_offset; else o << "null";
    o << "}, \"section_alignment\": " << p.section_alignment << ", \"file_alignment\": " << p.file_alignment
      << ", \"size_of_image\": " << p.size_of_image << ", \"size_of_headers\": " << p.size_of_headers
      << ", \"declared_directory_count\": " << p.declared_directory_count << ",\n    \"sections\": [";
    for (std::size_t i=0; i<p.sections.size(); ++i) { const auto& s=p.sections[i]; o << (i?",":"")
      << "{\"name\":\"" << escape_json(s.name) << "\",\"rva\":" << s.virtual_address << ",\"virtual_size\":" << s.virtual_size
      << ",\"mapped_size\":" << s.mapped_size << ",\"file_offset\":" << s.raw_offset << ",\"raw_size\":" << s.raw_size
      << ",\"file_backed_size\":" << s.file_backed_size << ",\"zero_fill_size\":" << s.zero_fill_size
      << ",\"characteristics\":" << s.characteristics << ",\"executable\":" << (s.executable?"true":"false") << "}"; }
    o << "],\n    \"data_directories\": [";
    for (std::size_t i=0; i<p.data_directories.size(); ++i) { const auto& d=p.data_directories[i]; o << (i?",":"")
      << "{\"index\":" << d.index << ",\"name\":\"" << d.name << "\",\"rva_or_file_offset\":" << d.rva
      << ",\"size\":" << d.size << ",\"address_kind\":\"" << (d.file_offset_addressed?"file_offset":"rva") << "\"}"; }
    o << "],\n    \"imports\": [";
    for (std::size_t i=0; i<p.imports.size(); ++i) { const auto& x=p.imports[i]; o << (i?",":"") << "{\"library\":\"" << escape_json(x.library)
      << "\",\"name\":\"" << escape_json(x.name) << "\",\"by_ordinal\":" << (x.by_ordinal?"true":"false")
      << ",\"ordinal\":" << x.ordinal << ",\"iat_rva\":" << x.iat_rva << "}"; }
    o << "],\n    \"exports\": [";
    for (std::size_t i=0; i<p.exports.size(); ++i) { const auto& x=p.exports[i]; o << (i?",":"") << "{\"name\":\"" << escape_json(x.name)
      << "\",\"ordinal\":" << x.ordinal << ",\"rva\":" << x.rva << ",\"forwarded_to\":\"" << escape_json(x.forwarded_to) << "\"}"; }
    o << "],\n    \"base_relocations\": [";
    for (std::size_t i=0; i<p.relocations.size(); ++i) o << (i?",":"") << "{\"rva\":" << p.relocations[i].rva << ",\"type\":" << unsigned(p.relocations[i].type) << "}";
    o << "],\n    \"debug_entries\": [";
    for (std::size_t i=0; i<p.debug_entries.size(); ++i) { const auto& x=p.debug_entries[i]; o << (i?",":"") << "{\"type\":" << x.type << ",\"data_size\":" << x.data_size
      << ",\"data_rva\":" << x.data_rva << ",\"data_file_offset\":" << x.data_file_offset << ",\"codeview_guid\":\"" << x.codeview_guid
      << "\",\"codeview_age\":" << x.codeview_age << ",\"pdb_path\":\"" << escape_json(x.pdb_path) << "\"}"; }
    o << "],\n    \"tls\": {\"present\":" << (p.has_tls?"true":"false") << ",\"raw_data_start_va\":" << p.tls.raw_data_start_va
      << ",\"raw_data_end_va\":" << p.tls.raw_data_end_va << ",\"index_va\":" << p.tls.index_va << ",\"callbacks_va\":" << p.tls.callbacks_va
      << ",\"zero_fill_size\":" << p.tls.zero_fill_size << ",\"characteristics\":" << p.tls.characteristics << ",\"callbacks\":[";
    for (std::size_t i=0; i<p.tls.callbacks.size(); ++i) o << (i?",":"") << p.tls.callbacks[i];
    o << "]},\n    \"runtime_functions\": [";
    for (std::size_t i=0; i<p.runtime_functions.size(); ++i) { const auto& x=p.runtime_functions[i]; o << (i?",":"") << "{\"begin_rva\":" << x.begin_rva
      << ",\"end_rva\":" << x.end_rva << ",\"unwind_rva\":" << x.unwind_rva << ",\"unwind_info_available\":" << (x.unwind_info_available?"true":"false")
      << ",\"unwind_version\":" << unsigned(x.unwind_version) << ",\"unwind_flags\":" << unsigned(x.unwind_flags)
      << ",\"prolog_size\":" << unsigned(x.prolog_size) << ",\"unwind_code_count\":" << unsigned(x.unwind_code_count)
      << ",\"frame_register\":" << unsigned(x.frame_register) << ",\"frame_offset\":" << unsigned(x.frame_offset) << "}"; }
    o << "],\n    \"clr\": {\"present\":" << (p.clr.present?"true":"false") << ",\"header_size\":" << p.clr.header_size
      << ",\"metadata_rva\":" << p.clr.metadata_rva << ",\"metadata_size\":" << p.clr.metadata_size << ",\"flags\":" << p.clr.flags
      << ",\"entry_point\":" << p.clr.entry_point << ",\"il_only\":" << (p.clr.il_only?"true":"false") << "},\n    \"diagnostics\": [";
    for (std::size_t i=0; i<p.diagnostics.size(); ++i) { const auto& d=p.diagnostics[i]; o << (i?",":"") << "{\"code\":\"" << escape_json(d.code)
      << "\",\"severity\":\"" << escape_json(d.severity) << "\",\"message\":\"" << escape_json(d.message) << "\"}"; }
    o << "]\n  },\n  \"decode\": {\"executable_file_backed_bytes\":" << r.decode.executable_file_backed_bytes
      << ",\"processed_bytes\":" << r.decode.processed_bytes << ",\"decoded_bytes\":" << r.decode.decoded_bytes
      << ",\"undecoded_bytes\":" << r.decode.undecoded_bytes << ",\"executable_zero_fill_bytes\":" << r.decode.executable_zero_fill_bytes
      << ",\"limited_bytes\":" << r.decode.limited_bytes << ",\"instruction_count\":" << r.decode.instruction_count << ",\"instructions\":[";
    for (std::size_t i = 0; i < r.instructions.size(); ++i) {
        const auto& x = r.instructions[i];
        o << (i ? "," : "") << "{\"section_index\":" << x.section_index << ",\"va\":" << x.va
          << ",\"rva\":" << x.rva << ",\"file_offset\":" << x.file_offset << ",\"bytes\":\"" << x.bytes
          << "\",\"mnemonic\":\"" << escape_json(x.mnemonic) << "\",\"operands\":\"" << escape_json(x.operands)
          << "\",\"detail\":{\"available\":" << (x.detail_available ? "true" : "false")
          << ",\"instruction_id\":" << x.instruction_id << ",\"instruction_name\":\""
          << escape_json(x.instruction_name) << "\",\"groups\":[";
        for (std::size_t j = 0; j < x.groups.size(); ++j)
            o << (j ? "," : "") << "\"" << escape_json(x.groups[j]) << "\"";
        o << "],\"registers_read\":[";
        for (std::size_t j = 0; j < x.registers_read.size(); ++j)
            o << (j ? "," : "") << "\"" << escape_json(x.registers_read[j]) << "\"";
        o << "],\"registers_written\":[";
        for (std::size_t j = 0; j < x.registers_written.size(); ++j)
            o << (j ? "," : "") << "\"" << escape_json(x.registers_written[j]) << "\"";
        o << "],\"prefixes\":[";
        for (std::size_t j = 0; j < x.prefixes.size(); ++j) o << (j ? "," : "") << unsigned(x.prefixes[j]);
        o << "],\"opcodes\":[";
        for (std::size_t j = 0; j < x.opcodes.size(); ++j) o << (j ? "," : "") << unsigned(x.opcodes[j]);
        o << "],\"rex\":" << unsigned(x.rex) << ",\"address_size\":" << unsigned(x.address_size)
          << ",\"modrm\":" << unsigned(x.modrm) << ",\"sib\":" << unsigned(x.sib)
          << ",\"displacement\":" << x.displacement << ",\"flags\":" << x.flags
          << ",\"encoding\":{\"modrm_offset\":" << unsigned(x.modrm_offset)
          << ",\"displacement_offset\":" << unsigned(x.displacement_offset)
          << ",\"displacement_size\":" << unsigned(x.displacement_size)
          << ",\"immediate_offset\":" << unsigned(x.immediate_offset)
          << ",\"immediate_size\":" << unsigned(x.immediate_size) << "},\"operands\":[";
        for (std::size_t j = 0; j < x.detail_operands.size(); ++j) {
            const auto& operand = x.detail_operands[j];
            o << (j ? "," : "") << "{\"type\":\"" << operand.type << "\",\"size\":" << unsigned(operand.size)
              << ",\"access\":" << unsigned(operand.access) << ",\"register\":\"" << escape_json(operand.reg)
              << "\",\"immediate\":" << operand.immediate << ",\"segment\":\"" << escape_json(operand.segment)
              << "\",\"base\":\"" << escape_json(operand.base) << "\",\"index\":\"" << escape_json(operand.index)
              << "\",\"scale\":" << operand.scale << ",\"displacement\":" << operand.displacement
              << ",\"avx_broadcast\":" << unsigned(operand.avx_broadcast)
              << ",\"avx_zero_opmask\":" << (operand.avx_zero_opmask ? "true" : "false") << "}";
        }
        o << "]}}";
    }
    o << "],\"gaps\":[";
    for (std::size_t i = 0; i < r.decode_gaps.size(); ++i) {
        const auto& x = r.decode_gaps[i];
        o << (i ? "," : "") << "{\"section_index\":" << x.section_index << ",\"rva\":" << x.rva
          << ",\"va\":" << x.va << ",\"file_offset\":";
        if (x.file_offset) o << *x.file_offset; else o << "null";
        o << ",\"size\":" << x.size << ",\"bytes\":\"" << x.bytes
          << "\",\"reason\":\"" << escape_json(x.reason) << "\"}";
    }
    o << "]},\n  \"symbols\":{\"status\":\"" << escape_json(r.symbols.status)
      << "\",\"requested_path\":\"" << escape_json(r.symbols.requested_path)
      << "\",\"resolved_path\":\"" << escape_json(r.symbols.resolved_path)
      << "\",\"expected_identity\":{\"guid\":\"" << escape_json(r.symbols.expected_guid)
      << "\",\"age\":" << r.symbols.expected_age << "},\"observed_identity\":{\"guid\":\""
      << escape_json(r.symbols.observed_guid) << "\",\"age\":" << r.symbols.observed_age
      << "},\"functions\":[";
    for (std::size_t i = 0; i < r.symbols.functions.size(); ++i) {
        const auto& symbol = r.symbols.functions[i];
        o << (i ? "," : "") << "{\"name\":\"" << escape_json(symbol.name)
          << "\",\"start_rva\":" << symbol.start_rva << ",\"end_rva\":";
        if (symbol.end_rva) o << *symbol.end_rva; else o << "null";
        o << ",\"type_index\":";
        if (symbol.type_index) o << *symbol.type_index; else o << "null";
        o << ",\"type_status\":\"" << escape_json(symbol.type_status)
          << "\",\"return_type\":\"" << escape_json(symbol.return_type) << "\",\"parameter_types\":[";
        for (std::size_t j = 0; j < symbol.parameter_types.size(); ++j)
            o << (j ? "," : "") << '\"' << escape_json(symbol.parameter_types[j]) << '\"';
        o << "],\"type_provenance\":\"" << escape_json(symbol.type_provenance) << '\"';
        o << ",\"provenance\":\"" << escape_json(symbol.provenance)
          << "\",\"confidence\":" << symbol.confidence << '}';
    }
    o << "],\"diagnostics\":";
    emit_diagnostics_json(o, r.symbols.diagnostics);
    o << "},\n  \"function_recovery\":{\"status\":\"" << escape_json(r.function_recovery.status)
      << "\",\"known_functions\":";
    emit_function_records_json(o, r.function_recovery.known_functions);
    o << ",\"candidate_functions\":";
    emit_function_records_json(o, r.function_recovery.candidate_functions);
    o << ",\"fragments\":";
    emit_function_records_json(o, r.function_recovery.fragments);
    o << ",\"unresolved_ranges\":[";
    for (std::size_t i = 0; i < r.function_recovery.unresolved_ranges.size(); ++i) {
        const auto& range = r.function_recovery.unresolved_ranges[i];
        o << (i ? "," : "") << "{\"section_index\":" << range.section_index
          << ",\"start_rva\":" << range.start_rva << ",\"end_rva\":" << range.end_rva
          << ",\"reason\":\"" << escape_json(range.reason) << "\"}";
    }
    o << "],\"unresolved_control_flow\":[";
    for (std::size_t i = 0; i < r.function_recovery.unresolved_control_flow.size(); ++i) {
        const auto& flow = r.function_recovery.unresolved_control_flow[i];
        o << (i ? "," : "") << "{\"from_rva\":" << flow.from_rva << ",\"target_rva\":";
        if (flow.target_rva) o << *flow.target_rva; else o << "null";
        o << ",\"flow_kind\":\"" << escape_json(flow.flow_kind)
          << "\",\"reason\":\"" << escape_json(flow.reason) << "\"}";
    }
    std::size_t bounded = 0U, ambiguous = 0U;
    for (const auto* records : {&r.function_recovery.known_functions, &r.function_recovery.candidate_functions,
                                &r.function_recovery.fragments}) {
        for (const auto& record : *records) {
            if (record.end_rva) ++bounded;
            if (record.ambiguous) ++ambiguous;
        }
    }
    o << "],\"metrics\":{\"known_function_count\":" << r.function_recovery.known_functions.size()
      << ",\"candidate_function_count\":" << r.function_recovery.candidate_functions.size()
      << ",\"fragment_count\":" << r.function_recovery.fragments.size()
      << ",\"bounded_range_count\":" << bounded << ",\"ambiguous_range_count\":" << ambiguous
      << ",\"unresolved_range_count\":" << r.function_recovery.unresolved_ranges.size() << "}},\n  \"image_discovery\":{\"status\":\""
      << escape_json(r.image_discovery.status) << "\",\"method\":\"" << escape_json(r.image_discovery.method)
      << "\",\"input_file_bytes\":" << r.image_discovery.input_file_bytes
      << ",\"accounted_file_bytes\":" << r.image_discovery.accounted_file_bytes
      << ",\"decoded_code_bytes\":" << r.image_discovery.decoded_code_bytes
      << ",\"likely_code_bytes\":" << r.image_discovery.likely_code_bytes
      << ",\"likely_data_bytes\":" << r.image_discovery.likely_data_bytes
      << ",\"unresolved_bytes\":" << r.image_discovery.unresolved_bytes
      << ",\"virtual_zero_fill_bytes\":" << r.image_discovery.virtual_zero_fill_bytes
      << ",\"memory_references_used\":" << r.image_discovery.memory_references_used
      << ",\"memory_references_truncated\":" << (r.image_discovery.memory_references_truncated ? "true" : "false")
      << ",\"range_records_truncated\":" << (r.image_discovery.range_records_truncated ? "true" : "false")
      << ",\"unreported_file_bytes\":" << r.image_discovery.unreported_file_bytes
      << ",\"unreported_range_count\":" << r.image_discovery.unreported_range_count << ",\"ranges\":[";
    for (std::size_t i = 0; i < r.image_discovery.ranges.size(); ++i) {
        const auto& range = r.image_discovery.ranges[i];
        o << (i ? "," : "") << "{\"file_offset\":" << range.file_offset << ",\"size\":" << range.size
          << ",\"section_index\":";
        if (range.section_index) o << *range.section_index; else o << "null";
        o << ",\"start_rva\":";
        if (range.start_rva) o << *range.start_rva; else o << "null";
        o << ",\"classification\":\"" << escape_json(range.classification) << "\",\"evidence\":[";
        for (std::size_t j = 0; j < range.evidence.size(); ++j)
            o << (j ? "," : "") << '\"' << escape_json(range.evidence[j]) << '\"';
        o << "]}";
    }
    o << "]},\n  \"semantic_analysis\":";
    semantic_analysis_to_json(o, r.semantic_analysis);
    o << ",\n  \"dataflow_analysis\":";
    phase4_analysis_to_json(o, r.phase4_analysis);
    o << ",\n  \"stages\":[";
    for (std::size_t i=0; i<r.stages.size(); ++i) o << (i?",":"") << "{\"name\":\"" << escape_json(r.stages[i].name) << "\",\"status\":\"" << escape_json(r.stages[i].status) << "\"}";
    o << "],\n  \"diagnostics\":[";
    for (std::size_t i=0; i<r.diagnostics.size(); ++i) { const auto& d=r.diagnostics[i]; o << (i?",":"") << "{\"code\":\"" << escape_json(d.code)
      << "\",\"severity\":\"" << escape_json(d.severity) << "\",\"message\":\"" << escape_json(d.message) << "\"}"; }
    o << "],\n  \"artifacts\":[";
    for (std::size_t i=0; i<r.artifacts.size(); ++i) o << (i?",":"") << "\"" << escape_json(r.artifacts[i]) << "\"";
    o << "]\n}\n";
}

class BoundedStreamBuffer final : public std::streambuf {
public:
    explicit BoundedStreamBuffer(std::streambuf* destination) : destination_(destination) {
        setp(buffer_, buffer_ + sizeof(buffer_));
    }

    bool limit_exceeded() const noexcept { return limit_exceeded_; }
    bool output_failed() const noexcept { return output_failed_; }

protected:
    int_type overflow(int_type character) override {
        if (!flush_buffer()) return traits_type::eof();
        if (!traits_type::eq_int_type(character, traits_type::eof())) {
            *pptr() = traits_type::to_char_type(character);
            pbump(1);
        }
        return traits_type::not_eof(character);
    }

    std::streamsize xsputn(const char* source, std::streamsize count) override {
        std::streamsize copied = 0;
        while (copied < count) {
            if (pptr() == epptr() && !flush_buffer()) break;
            const auto available = static_cast<std::streamsize>(epptr() - pptr());
            const auto chunk = std::min(available, count - copied);
            std::memcpy(pptr(), source + copied, static_cast<std::size_t>(chunk));
            pbump(static_cast<int>(chunk));
            copied += chunk;
        }
        return copied;
    }

    int sync() override {
        if (!flush_buffer()) return -1;
        return destination_->pubsync();
    }

private:
    bool flush_buffer() {
        const auto pending = static_cast<std::size_t>(pptr() - pbase());
        const std::size_t remaining = kMaxOutputBytes - written_;
        const std::size_t allowed = std::min(pending, remaining);
        const auto forwarded = destination_->sputn(pbase(), static_cast<std::streamsize>(allowed));
        written_ += static_cast<std::size_t>(forwarded);
        if (static_cast<std::size_t>(forwarded) != allowed) output_failed_ = true;
        if (allowed != pending) limit_exceeded_ = true;
        setp(buffer_, buffer_ + sizeof(buffer_));
        return !output_failed_ && !limit_exceeded_;
    }

    std::streambuf* destination_;
    char buffer_[8192]{};
    std::size_t written_ = 0;
    bool limit_exceeded_ = false;
    bool output_failed_ = false;
};

} // namespace

void request_cancellation() noexcept { g_cancel_requested = 1; }

void set_analysis_timeout_ms(std::uint64_t timeout_ms) noexcept {
    if (timeout_ms == 0U) {
        g_deadline_enabled = false;
        return;
    }
    constexpr std::uint64_t kMaxTimeoutMs = 3600000U;
    const auto bounded_ms = std::min(timeout_ms, kMaxTimeoutMs);
    g_analysis_deadline = std::chrono::steady_clock::now() +
        std::chrono::milliseconds(static_cast<std::chrono::milliseconds::rep>(bounded_ms));
    g_deadline_enabled = true;
}

StopReason analysis_stop_reason() noexcept { return current_stop_reason(); }

Decompiler::Decompiler() = default;
Decompiler::~Decompiler() { if (capstone_handle_ != 0) cs_close(&capstone_handle_); }

bool Decompiler::load_binary(const std::string& path, AnalysisReport& report) {
    report.input_path = path;
    report.tool_version = NEXUSREV_VERSION;
    report.lief_version = NEXUSREV_LIEF_VERSION;
    report.capstone_version = NEXUSREV_CAPSTONE_VERSION;
    report.stages.push_back({"parse", "failed"});
    std::vector<std::uint8_t> bytes;
    std::string code, message;
    if (current_stop_reason() != StopReason::none) {
        add_stop_diagnostic(report, current_stop_reason());
        return false;
    }
    if (!read_input(path, bytes, code, message)) { diagnostic(report, code, "error", message); return false; }
    report.input_sha256 = sha256(std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size()));
    if (!PeImage::parse(std::move(bytes), report.pe, code, message)) { diagnostic(report, code, "error", message); return false; }
    for (const auto& item : report.pe.diagnostics) diagnostic(report, item.code, item.severity, item.message);
    // LIEF remains an optional cross-check behind the validated adapter; its failure cannot bypass our bounds checks.
    if (report.pe.supported_x64_native) {
        try {
            const auto lief_binary = LIEF::PE::Parser::parse(report.pe.file_bytes->data(), report.pe.file_bytes->size());
            if (!lief_binary) diagnostic(report, "LIEF_CROSSCHECK_UNAVAILABLE", "warning", "validated PE adapter succeeded but LIEF returned no image");
        } catch (const std::exception& ex) {
            diagnostic(report, "LIEF_CROSSCHECK_UNAVAILABLE", "warning", std::string("validated PE adapter succeeded; LIEF cross-check failed: ") + ex.what());
        } catch (...) {
            diagnostic(report, "LIEF_CROSSCHECK_UNAVAILABLE", "warning", "validated PE adapter succeeded; LIEF cross-check failed");
        }
    }
    if (current_stop_reason() != StopReason::none) {
        add_stop_diagnostic(report, current_stop_reason());
        return false;
    }
    report.stages.back().status = "complete";
    return true;
}

bool Decompiler::analyze(AnalysisReport& report, const std::string& pdb_path,
                         const std::string& decode_strategy, std::size_t decode_workers) {
    if (!report.pe.file_bytes) {
        diagnostic(report, "ANALYSIS_WITHOUT_INPUT", "error", "analysis requires a validated PE image");
        report.stages.push_back({"analysis", "failed"}); report.status = "failed"; return false;
    }
    if (current_stop_reason() != StopReason::none) {
        add_stop_diagnostic(report, current_stop_reason());
        report.stages.push_back({"analysis", "failed"});
        return false;
    }
    if (!report.pe.supported_x64_native) {
        report.stages.push_back({"analysis", "unsupported"}); report.status = "unsupported";
        if (report.pe.clr.present) diagnostic(report, "MANAGED_CLR_UNSUPPORTED", "warning", "CLR/.NET images are identified but are not analyzed as native x86-64");
        else diagnostic(report, "ARCHITECTURE_UNSUPPORTED", "warning", "only native PE32+ x86-64 images are analyzed");
        analyze_semantics(report);
        discover_image(report);
        analyze_phase4(report);
        return true;
    }
    if (report.pe.clr.present) {
        report.stages.push_back({"analysis", "unsupported"}); report.status = "unsupported";
        diagnostic(report, "MANAGED_CLR_UNSUPPORTED", "warning", "CLR/.NET images are identified but are not analyzed as native x86-64");
        analyze_semantics(report);
        discover_image(report);
        analyze_phase4(report);
        return true;
    }
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &capstone_handle_) != CS_ERR_OK) {
        report.stages.push_back({"analysis", "failed"}); report.status = "failed";
        diagnostic(report, "DECODER_INITIALIZATION_FAILED", "error", "unable to initialize Capstone for AMD64"); return false;
    }
    if (cs_option(capstone_handle_, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
        cs_close(&capstone_handle_); capstone_handle_ = 0; report.stages.push_back({"analysis", "failed"}); report.status = "failed";
        diagnostic(report, "DECODER_DETAIL_FAILED", "error", "unable to enable Capstone instruction details"); return false;
    }
    decode_sections(report, capstone_handle_, decode_strategy, decode_workers);
    if (report.status != "failed") {
        recover_functions(report, pdb_path);
        analyze_semantics(report);
        discover_image(report);
        analyze_phase4(report);
    }
    if (current_stop_reason() != StopReason::none) {
        add_stop_diagnostic(report, current_stop_reason());
        return false;
    }
    return report.status != "failed";
}

std::string Decompiler::emit_annotated_disassembly(const AnalysisReport& r) const {
    std::ostringstream o;
    o << "NexussREV annotated disassembly and PE report\nTool version: " << r.tool_version
      << "\nInput SHA-256: " << r.input_sha256 << "\nMachine: " << machine_label(r.pe.machine)
      << " (0x" << std::hex << r.pe.machine << ")\n" << std::dec << "Image base: 0x" << std::hex << r.pe.image_base << std::dec << "\n";
    if (r.pe.entry_point_rva != 0U) {
        std::uint64_t file = 0;
        o << "Entry point: RVA=0x" << std::hex << r.pe.entry_point_rva << " VA=";
        if (r.pe.image_base <= std::numeric_limits<std::uint64_t>::max() - r.pe.entry_point_rva)
            o << "0x" << (r.pe.image_base + r.pe.entry_point_rva);
        else
            o << "overflow";
        o << " FILE=";
        if (r.pe.rva_to_file_offset(r.pe.entry_point_rva, file)) o << "0x" << file; else o << "unmapped";
        o << std::dec << "\n";
    }
    o << "Status: " << r.status << "\nNOTICE: Static PE metadata and best-effort instruction decoding only; this is not original source code,\n"
      << "not guaranteed compilable C/C++, and not a claim of complete function recovery.\nRVA, VA, and file offset are distinct.\n\nSections:\n";
    if (r.status == "unsupported")
        o << "UNSUPPORTED: this input is outside the native PE32+ x86-64 analysis surface; no x64 instruction decoding was performed.\n";
    for (const auto& s : r.pe.sections) o << "  " << s.name << " RVA=0x" << std::hex << s.virtual_address << " FILE=0x" << s.raw_offset << std::dec
      << " raw=" << s.raw_size << " file-backed=" << s.file_backed_size << " zero-fill=" << s.zero_fill_size << " executable=" << (s.executable?"yes":"no") << "\n";
    o << "\nMetadata: imports=" << r.pe.imports.size() << " exports=" << r.pe.exports.size() << " relocations=" << r.pe.relocations.size()
      << " debug=" << r.pe.debug_entries.size() << " runtime-functions=" << r.pe.runtime_functions.size() << " TLS=" << (r.pe.has_tls?"yes":"no")
      << " CLR=" << (r.pe.clr.present?"yes":"no") << "\nDecode accounting: executable file-backed=" << r.decode.executable_file_backed_bytes
      << " processed=" << r.decode.processed_bytes << " decoded=" << r.decode.decoded_bytes << " undecoded=" << r.decode.undecoded_bytes
      << " zero-fill=" << r.decode.executable_zero_fill_bytes << " limited=" << r.decode.limited_bytes << "\n"
      << "Symbol provider: " << r.symbols.status << " (" << r.symbols.functions.size() << " procedure records)\n"
      << "Function-boundary evidence: known=" << r.function_recovery.known_functions.size()
      << " candidates=" << r.function_recovery.candidate_functions.size()
      << " fragments=" << r.function_recovery.fragments.size()
      << " unresolved-ranges=" << r.function_recovery.unresolved_ranges.size() << "\n";
    const auto emit_function_group = [&o](const std::string& heading, const std::vector<FunctionRecord>& records) {
        o << heading << ":\n";
        if (records.empty()) o << "  none\n";
        for (const auto& record : records) {
            o << "  " << (record.label.empty() ? "<unlabelled>" : record.label) << " RVA=0x"
              << std::hex << record.start_rva << "-";
            if (record.end_rva) o << "0x" << *record.end_rva; else o << "unknown";
            o << std::dec << " confidence=" << record.confidence << " boundary=" << record.boundary_status
              << (record.ambiguous ? " ambiguous" : "") << " evidence=";
            for (std::size_t i = 0; i < record.evidence.size(); ++i)
                o << (i ? "," : "") << record.evidence[i].source;
            o << "\n";
        }
    };
    emit_function_group("Known functions", r.function_recovery.known_functions);
    emit_function_group("Candidate functions", r.function_recovery.candidate_functions);
    emit_function_group("Fragments", r.function_recovery.fragments);
    o << "\n";
    for (const auto& x : r.instructions) {
        const std::string name = x.section_index < r.pe.sections.size() ? r.pe.sections[x.section_index].name : "?";
        o << name << " RVA=0x" << std::hex << std::setw(8) << std::setfill('0') << x.rva << " VA=0x" << std::setw(16) << x.va
          << " FILE=0x" << std::setw(8) << x.file_offset << std::dec << "  " << std::left << std::setw(42) << x.bytes << std::right << x.mnemonic;
        if (!x.operands.empty()) o << " " << x.operands;
        o << "\n";
    }
    if (r.instructions.empty()) o << "No instructions were emitted.\n";
    if (!r.decode_gaps.empty()) {
        o << "\nUndecoded/unprocessed intervals:\n";
        for (const auto& g : r.decode_gaps) {
            const std::string name = g.section_index < r.pe.sections.size() ? r.pe.sections[g.section_index].name : "?";
            o << "  " << name << " RVA=0x" << std::hex << g.rva << " VA=0x" << g.va << " FILE=";
            if (g.file_offset) o << "0x" << *g.file_offset; else o << "unmapped";
            o << std::dec << " size=" << g.size << " reason=" << g.reason;
            if (!g.bytes.empty()) o << " bytes=" << g.bytes;
            o << "\n";
        }
    }
    for (const auto& d : r.diagnostics) o << "[" << d.severity << "] " << d.code << ": " << d.message << "\n";
    std::string result = o.str();
    if (result.size() > kMaxOutputBytes) throw std::runtime_error("annotated disassembly exceeds the configured 64 MiB output limit");
    return result;
}

void write_report_json(std::ostream& output, const AnalysisReport& report) {
    BoundedStreamBuffer buffer(output.rdbuf());
    std::ostream bounded_output(&buffer);
    bounded_output.imbue(output.getloc());
    make_json(bounded_output, report);
    bounded_output.flush();
    if (buffer.limit_exceeded())
        throw std::runtime_error("analysis report exceeds the configured 64 MiB output limit");
    if (buffer.output_failed() || !bounded_output)
        throw std::runtime_error("failed while streaming the analysis report");
}

std::string report_to_json(const AnalysisReport& report) {
    std::ostringstream output;
    write_report_json(output, report);
    return output.str();
}
} // namespace nexusrev
