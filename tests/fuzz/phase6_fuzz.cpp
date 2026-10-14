#include "nexusrev.hpp"
#include "pe_image.hpp"

#include <capstone/capstone.h>

#include <algorithm>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace {

constexpr std::size_t kMaxFuzzInput = 1024U * 1024U;
constexpr std::size_t kMaxDecodeInstructions = 128U;

std::string bounded_string(const std::uint8_t* data, std::size_t size) {
    const std::size_t length = std::min<std::size_t>(size, 256U);
    if (length == 0U) return {};
    return std::string(reinterpret_cast<const char*>(data), length);
}

void exercise_rva_mapping(const nexusrev::PeImage& image,
                          const std::uint8_t* data, std::size_t size) {
    std::vector<std::uint32_t> probes;
    for (std::size_t offset = 0U; offset + 4U <= size && probes.size() < 64U; offset += 4U) {
        const std::uint32_t value = static_cast<std::uint32_t>(data[offset]) |
            (static_cast<std::uint32_t>(data[offset + 1U]) << 8U) |
            (static_cast<std::uint32_t>(data[offset + 2U]) << 16U) |
            (static_cast<std::uint32_t>(data[offset + 3U]) << 24U);
        probes.push_back(value);
    }
    for (const auto& section : image.sections) {
        probes.push_back(section.virtual_address);
        if (section.virtual_address != 0U) probes.push_back(section.virtual_address - 1U);
        const std::uint64_t end = static_cast<std::uint64_t>(section.virtual_address) + section.mapped_size;
        if (end <= UINT32_MAX) probes.push_back(static_cast<std::uint32_t>(end));
        const std::uint64_t file_end = static_cast<std::uint64_t>(section.virtual_address) +
                                       section.file_backed_size;
        if (file_end <= UINT32_MAX) probes.push_back(static_cast<std::uint32_t>(file_end));
    }
    for (const std::uint32_t rva : probes) {
        const auto mapping = image.map_rva(rva);
        std::uint64_t offset = 0U;
        const bool convertible = image.rva_to_file_offset(rva, offset);
        if (mapping.mapped != convertible) __builtin_trap();
        if (mapping.mapped && (offset >= image.file_bytes->size() ||
                               offset + mapping.available_file_bytes > image.file_bytes->size()))
            __builtin_trap();
        std::vector<std::uint8_t> bytes;
        const std::size_t requested = static_cast<std::size_t>(rva & 31U);
        if (image.read_rva(rva, requested, bytes) &&
            (bytes.size() != requested || offset + requested > image.file_bytes->size()))
            __builtin_trap();
    }
}

void exercise_instruction_stream(const std::uint8_t* data, std::size_t size,
                                 nexusrev::AnalysisReport& report) {
    static csh handle = []() {
        csh value = 0;
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &value) != CS_ERR_OK) return csh{0};
        (void)cs_option(value, CS_OPT_DETAIL, CS_OPT_ON);
        return value;
    }();
    if (handle == 0U || size == 0U) return;

    cs_insn* instruction = cs_malloc(handle);
    if (instruction == nullptr) return;
    const std::size_t bounded_size = std::min<std::size_t>(size, 65536U);
    const std::uint8_t* cursor = data;
    std::size_t remaining = bounded_size;
    std::uint64_t address = 0U;
    for (std::size_t count = 0U; remaining != 0U && count < kMaxDecodeInstructions; ++count) {
        const std::uint8_t* next = cursor;
        std::size_t next_remaining = remaining;
        std::uint64_t next_address = address;
        if (cs_disasm_iter(handle, &next, &next_remaining, &next_address, instruction)) {
            nexusrev::InstructionRecord record;
            record.va = instruction->address;
            record.rva = static_cast<std::uint32_t>(instruction->address & UINT32_MAX);
            record.mnemonic = instruction->mnemonic;
            record.operands = instruction->op_str;
            record.detail_available = instruction->detail != nullptr;
            report.instructions.push_back(std::move(record));
            cursor = next;
            remaining = next_remaining;
            address = next_address;
        } else {
            ++cursor;
            --remaining;
            ++address;
        }
    }
    cs_free(instruction, 1U);
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size > kMaxFuzzInput) return 0;
    std::vector<std::uint8_t> bytes;
    if (size != 0U) bytes.assign(data, data + size);

    nexusrev::AnalysisReport report;
    report.status = "partial";
    report.input_path = bounded_string(data, size);
    report.diagnostics.push_back({"FUZZ_INPUT", "info", bounded_string(data, size)});

    nexusrev::PeImage image;
    std::string error_code;
    std::string error_message;
    if (nexusrev::PeImage::parse(std::move(bytes), image, error_code, error_message)) {
        exercise_rva_mapping(image, data, size);
        report.pe = image;
    } else {
        report.diagnostics.push_back({std::move(error_code), "warning", std::move(error_message)});
    }
    exercise_instruction_stream(data, size, report);
    const std::string json = nexusrev::report_to_json(report);
    if (json.empty() || json.front() != '{' || json.back() != '\n') __builtin_trap();
    return 0;
}
