#include "phase2.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <limits>
#include <queue>
#include <set>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace nexusrev {
namespace {
constexpr std::uint64_t kMaxPdbBytes = 256ULL * 1024ULL * 1024ULL;
constexpr std::size_t kMaxPdbStreams = 4096U;
constexpr std::size_t kMaxPdbFunctions = 20000U;
constexpr std::size_t kMaxRecoveryRecords = 20000U;
constexpr std::size_t kMaxRecursiveInstructions = 20000U;

bool read_u16(const std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint16_t& value) {
    if (offset > bytes.size() || bytes.size() - offset < 2U) return false;
    value = static_cast<std::uint16_t>(bytes[offset]) |
            static_cast<std::uint16_t>(static_cast<std::uint16_t>(bytes[offset + 1U]) << 8U);
    return true;
}

bool read_u32(const std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint32_t& value) {
    if (offset > bytes.size() || bytes.size() - offset < 4U) return false;
    value = static_cast<std::uint32_t>(bytes[offset]) |
            (static_cast<std::uint32_t>(bytes[offset + 1U]) << 8U) |
            (static_cast<std::uint32_t>(bytes[offset + 2U]) << 16U) |
            (static_cast<std::uint32_t>(bytes[offset + 3U]) << 24U);
    return true;
}

std::string raw_guid_hex(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
    static constexpr char hex[] = "0123456789abcdef";
    std::string result;
    if (offset > bytes.size() || bytes.size() - offset < 16U) return result;
    result.reserve(32U);
    for (std::size_t i = 0; i < 16U; ++i) {
        result.push_back(hex[bytes[offset + i] >> 4U]);
        result.push_back(hex[bytes[offset + i] & 0x0fU]);
    }
    return result;
}

struct PdbModule {
    std::uint16_t stream_index = 0xffffU;
    std::uint32_t symbol_bytes = 0;
};

class MsfPdb {
public:
    bool load(const std::filesystem::path& path, std::string& error,
              std::string& guid, std::uint32_t& age,
              std::vector<PdbFunctionSymbol>& functions, const PeImage& image) {
        std::error_code ec;
        const auto size = std::filesystem::file_size(path, ec);
        if (ec) { error = "cannot determine PDB size: " + ec.message(); return false; }
        if (size < 56U || size > kMaxPdbBytes) {
            error = "PDB size is outside the supported 56-byte to 256-MiB bounds";
            return false;
        }
        std::ifstream input(path, std::ios::binary);
        if (!input) { error = "cannot open PDB for reading"; return false; }
        bytes_.resize(static_cast<std::size_t>(size));
        input.read(reinterpret_cast<char*>(bytes_.data()), static_cast<std::streamsize>(bytes_.size()));
        if (!input || input.gcount() != static_cast<std::streamsize>(bytes_.size())) {
            error = "PDB changed or could not be read completely";
            return false;
        }
        if (!open_msf(error)) return false;
        std::vector<std::uint8_t> info;
        if (!read_stream(1U, info) || info.size() < 28U || !read_u32(info, 8U, age)) {
            error = "PDB information stream is missing or truncated";
            return false;
        }
        guid = raw_guid_hex(info, 12U);
        if (guid.size() != 32U) { error = "PDB information stream has no complete GUID"; return false; }
        std::vector<std::uint8_t> dbi;
        if (!read_stream(3U, dbi) || dbi.size() < 64U) {
            error = "PDB DBI stream is missing or truncated";
            return false;
        }
        std::uint32_t module_info_bytes = 0;
        if (!read_u32(dbi, 24U, module_info_bytes) || module_info_bytes > dbi.size() - 64U) {
            error = "PDB DBI module-info substream exceeds its stream bounds";
            return false;
        }
        std::vector<PdbModule> modules;
        if (!parse_modules(dbi, module_info_bytes, modules, error)) return false;
        for (const auto& module : modules) {
            if (module.stream_index == 0xffffU || module.symbol_bytes == 0U) continue;
            std::vector<std::uint8_t> stream;
            if (!read_stream(module.stream_index, stream)) continue;
            const std::size_t symbol_start = stream.size() >= 4U ? 4U : 0U;
            const std::size_t declared = std::min<std::size_t>(module.symbol_bytes, stream.size() - symbol_start);
            parse_module_symbols(stream, symbol_start, declared, functions, image);
            if (functions.size() >= kMaxPdbFunctions) break;
        }
        return true;
    }

private:
    struct StreamInfo {
        std::uint32_t size = 0xffffffffU;
        std::vector<std::uint32_t> blocks;
    };

    bool open_msf(std::string& error) {
        static constexpr char signature[] = "Microsoft C/C++ MSF 7.00\r\n\x1a" "DS\0\0\0";
        if (bytes_.size() < sizeof(signature) - 1U ||
            !std::equal(signature, signature + sizeof(signature) - 1U, bytes_.begin())) {
            error = "file is not a Microsoft MSF 7.0 PDB container";
            return false;
        }
        std::uint32_t block_size = 0, block_count = 0, directory_bytes = 0, block_map = 0;
        if (!read_u32(bytes_, 32U, block_size) || !read_u32(bytes_, 40U, block_count) ||
            !read_u32(bytes_, 44U, directory_bytes) || !read_u32(bytes_, 52U, block_map) ||
            block_size < 512U || block_size > 65536U || (block_size & (block_size - 1U)) != 0U ||
            block_count == 0U || static_cast<std::uint64_t>(block_count) * block_size > bytes_.size() ||
            directory_bytes == 0U || directory_bytes > bytes_.size()) {
            error = "MSF superblock contains invalid block or directory bounds";
            return false;
        }
        block_size_ = block_size;
        const std::uint64_t directory_blocks = (static_cast<std::uint64_t>(directory_bytes) + block_size - 1U) / block_size;
        const std::uint64_t map_offset = static_cast<std::uint64_t>(block_map) * block_size;
        if (block_map >= block_count || directory_blocks > block_size / 4U || map_offset > bytes_.size() ||
            directory_blocks * 4U > bytes_.size() - map_offset) {
            error = "MSF directory block map is outside the file or exceeds its bounded map size";
            return false;
        }
        std::vector<std::uint8_t> directory;
        directory.reserve(directory_bytes);
        for (std::uint64_t i = 0; i < directory_blocks; ++i) {
            std::uint32_t block = 0;
            if (!read_u32(bytes_, static_cast<std::size_t>(map_offset + i * 4U), block) || block >= block_count) {
                error = "MSF directory references a block outside the file";
                return false;
            }
            const std::uint64_t offset = static_cast<std::uint64_t>(block) * block_size;
            const std::size_t take = std::min<std::size_t>(block_size, directory_bytes - directory.size());
            if (offset > bytes_.size() || take > bytes_.size() - offset) {
                error = "MSF directory block is truncated";
                return false;
            }
            directory.insert(directory.end(), bytes_.begin() + static_cast<std::ptrdiff_t>(offset),
                             bytes_.begin() + static_cast<std::ptrdiff_t>(offset + take));
        }
        std::uint32_t stream_count = 0;
        if (!read_u32(directory, 0U, stream_count) || stream_count < 4U || stream_count > kMaxPdbStreams ||
            directory.size() < 4U + static_cast<std::size_t>(stream_count) * 4U) {
            error = "MSF stream directory is invalid or exceeds the stream-count bound";
            return false;
        }
        streams_.resize(stream_count);
        std::size_t cursor = 4U;
        for (auto& stream : streams_) {
            if (!read_u32(directory, cursor, stream.size)) { error = "truncated MSF stream-size table"; return false; }
            cursor += 4U;
            if (stream.size != 0xffffffffU && stream.size > kMaxPdbBytes) {
                error = "an MSF stream exceeds the 256-MiB parsing bound";
                return false;
            }
        }
        for (auto& stream : streams_) {
            if (stream.size == 0xffffffffU || stream.size == 0U) continue;
            const std::uint64_t needed = (static_cast<std::uint64_t>(stream.size) + block_size - 1U) / block_size;
            if (needed > (directory.size() - cursor) / 4U) {
                error = "MSF stream block list is truncated";
                return false;
            }
            stream.blocks.reserve(static_cast<std::size_t>(needed));
            for (std::uint64_t i = 0; i < needed; ++i) {
                std::uint32_t block = 0;
                if (!read_u32(directory, cursor, block) || block >= block_count) {
                    error = "MSF stream references a block outside the file";
                    return false;
                }
                cursor += 4U;
                stream.blocks.push_back(block);
            }
        }
        return true;
    }

    bool read_stream(std::size_t index, std::vector<std::uint8_t>& result) const {
        result.clear();
        if (index >= streams_.size() || streams_[index].size == 0xffffffffU) return false;
        const auto& stream = streams_[index];
        result.reserve(stream.size);
        for (const auto block : stream.blocks) {
            const std::uint64_t offset = static_cast<std::uint64_t>(block) * block_size_;
            const std::size_t take = std::min<std::size_t>(block_size_, stream.size - result.size());
            if (offset > bytes_.size() || take > bytes_.size() - offset) return false;
            result.insert(result.end(), bytes_.begin() + static_cast<std::ptrdiff_t>(offset),
                          bytes_.begin() + static_cast<std::ptrdiff_t>(offset + take));
            if (result.size() == stream.size) break;
        }
        return result.size() == stream.size;
    }

    static bool parse_modules(const std::vector<std::uint8_t>& dbi, std::uint32_t substream_size,
                              std::vector<PdbModule>& modules, std::string& error) {
        const std::size_t begin = 64U;
        const std::size_t end = begin + substream_size;
        std::size_t cursor = begin;
        while (cursor < end) {
            if (end - cursor < 64U) { error = "truncated PDB DBI module descriptor"; return false; }
            PdbModule module;
            (void)read_u16(dbi, cursor + 34U, module.stream_index);
            (void)read_u32(dbi, cursor + 36U, module.symbol_bytes);
            // The 64-byte ModInfo prefix includes PdbFilePathNameIndex at +60.
            const std::size_t strings = cursor + 64U;
            const auto first_end = std::find(dbi.begin() + static_cast<std::ptrdiff_t>(strings),
                                             dbi.begin() + static_cast<std::ptrdiff_t>(end), 0U);
            if (first_end == dbi.begin() + static_cast<std::ptrdiff_t>(end)) {
                error = "unterminated module name in PDB DBI substream";
                return false;
            }
            const auto second_start = first_end + 1;
            const auto second_end = std::find(second_start, dbi.begin() + static_cast<std::ptrdiff_t>(end), 0U);
            if (second_end == dbi.begin() + static_cast<std::ptrdiff_t>(end)) {
                error = "unterminated object name in PDB DBI substream";
                return false;
            }
            modules.push_back(module);
            const std::size_t next = static_cast<std::size_t>(second_end - dbi.begin()) + 1U;
            cursor = (next + 3U) & ~std::size_t(3U);
        }
        return cursor == end || cursor <= end + 3U;
    }

    static void parse_module_symbols(const std::vector<std::uint8_t>& stream, std::size_t begin,
                                     std::size_t byte_count, std::vector<PdbFunctionSymbol>& functions,
                                     const PeImage& image) {
        const std::size_t end = std::min(stream.size(), begin + byte_count);
        std::size_t cursor = begin;
        while (cursor + 4U <= end && functions.size() < kMaxPdbFunctions) {
            std::uint16_t record_length = 0, kind = 0;
            if (!read_u16(stream, cursor, record_length)) break;
            if (record_length < 2U || record_length > end - cursor - 2U) {
                if (stream[cursor] >= 0xf1U && stream[cursor] <= 0xf3U) { ++cursor; continue; }
                break;
            }
            (void)read_u16(stream, cursor + 2U, kind);
            const std::size_t record_end = cursor + 2U + record_length;
            if (kind == 0x110fU || kind == 0x1110U || kind == 0x1146U || kind == 0x1147U ||
                kind == 0x1154U || kind == 0x1155U) {
                std::uint32_t code_size = 0, type_index = 0, code_offset = 0;
                std::uint16_t segment = 0;
                // Procedure records use a fixed 35-byte payload after the kind:
                // seven DWORD fields, section-relative code offset, segment, flags, then name.
                if (record_length >= 39U && read_u32(stream, cursor + 16U, code_size) &&
                    read_u32(stream, cursor + 28U, type_index) && read_u32(stream, cursor + 32U, code_offset) &&
                    read_u16(stream, cursor + 36U, segment) && segment != 0U) {
                    const std::size_t name_start = cursor + 39U;
                    const auto name_end = std::find(stream.begin() + static_cast<std::ptrdiff_t>(name_start),
                                                    stream.begin() + static_cast<std::ptrdiff_t>(record_end), 0U);
                    if (name_end != stream.begin() + static_cast<std::ptrdiff_t>(record_end) && code_size != 0U) {
                        PdbFunctionSymbol symbol;
                        symbol.name.assign(stream.begin() + static_cast<std::ptrdiff_t>(name_start), name_end);
                        if (segment > image.sections.size()) {
                            cursor = record_end;
                            while (cursor < end && (cursor & 3U) != 0U && stream[cursor] >= 0xf1U && stream[cursor] <= 0xf3U)
                                ++cursor;
                            continue;
                        }
                        const auto& section = image.sections[segment - 1U];
                        const std::uint64_t start_rva = static_cast<std::uint64_t>(section.virtual_address) + code_offset;
                        const std::uint64_t end_rva = start_rva + code_size;
                        if (start_rva > std::numeric_limits<std::uint32_t>::max() ||
                            end_rva > static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max()) + 1U ||
                            code_offset >= section.file_backed_size || code_size > section.file_backed_size - code_offset) {
                            cursor = record_end;
                            while (cursor < end && (cursor & 3U) != 0U && stream[cursor] >= 0xf1U && stream[cursor] <= 0xf3U)
                                ++cursor;
                            continue;
                        }
                        symbol.start_rva = static_cast<std::uint32_t>(start_rva);
                        if (end_rva <= std::numeric_limits<std::uint32_t>::max())
                            symbol.end_rva = static_cast<std::uint32_t>(end_rva);
                        symbol.type_index = type_index;
                        symbol.provenance = "pdb_procedure_record";
                        functions.push_back(std::move(symbol));
                    }
                }
            }
            cursor = record_end;
            while (cursor < end && (cursor & 3U) != 0U && stream[cursor] >= 0xf1U && stream[cursor] <= 0xf3U)
                ++cursor;
        }
    }

    std::vector<std::uint8_t> bytes_;
    std::vector<StreamInfo> streams_;
    std::uint32_t block_size_ = 0;
};

bool is_executable_rva(const PeImage& image, std::uint32_t rva, std::size_t* section_index = nullptr) {
    for (std::size_t i = 0; i < image.sections.size(); ++i) {
        const auto& section = image.sections[i];
        if (!section.executable || rva < section.virtual_address) continue;
        const std::uint64_t delta = static_cast<std::uint64_t>(rva) - section.virtual_address;
        if (delta < section.file_backed_size) {
            if (section_index != nullptr) *section_index = i;
            return true;
        }
    }
    return false;
}

bool is_executable_range(const PeImage& image, std::uint32_t start_rva, std::uint32_t end_rva) {
    if (end_rva <= start_rva) return false;
    for (const auto& section : image.sections) {
        if (!section.executable || start_rva < section.virtual_address) continue;
        const std::uint64_t delta = static_cast<std::uint64_t>(start_rva) - section.virtual_address;
        const std::uint64_t length = static_cast<std::uint64_t>(end_rva) - start_rva;
        if (delta < section.file_backed_size && length <= section.file_backed_size - delta) return true;
    }
    return false;
}

std::optional<std::uint64_t> file_offset_for(const PeImage& image, std::uint32_t rva) {
    std::uint64_t offset = 0;
    if (image.rva_to_file_offset(rva, offset)) return offset;
    return std::nullopt;
}

void append_alias(FunctionRecord& record, const std::string& label) {
    if (label.empty()) return;
    if (record.label.empty()) record.label = label;
    else if (record.label != label && std::find(record.aliases.begin(), record.aliases.end(), label) == record.aliases.end())
        record.aliases.push_back(label);
}

FunctionRecord* find_record(FunctionRecoveryRecord& recovery, std::uint32_t start_rva) {
    for (auto* group : {&recovery.known_functions, &recovery.candidate_functions, &recovery.fragments}) {
        const auto found = std::find_if(group->begin(), group->end(), [&](const auto& record) {
            return record.start_rva == start_rva;
        });
        if (found != group->end()) return &*found;
    }
    return nullptr;
}

void add_evidence(FunctionRecoveryRecord& recovery, const PeImage& image, std::string kind,
                  std::uint32_t start, std::optional<std::uint32_t> end, const std::string& label,
                  double confidence, FunctionEvidence evidence) {
    if (!is_executable_rva(image, start) || start == 0U || recovery.known_functions.size() +
        recovery.candidate_functions.size() + recovery.fragments.size() >= kMaxRecoveryRecords) return;
    if (end && *end <= start) end.reset();
    FunctionRecord* existing = find_record(recovery, start);
    if (existing != nullptr && kind != "fragment" && existing->entity_kind != "fragment") {
        if (end && existing->end_rva && *end != *existing->end_rva) {
            existing->ambiguous = true;
            existing->boundary_status = "ambiguous";
        } else if (end && !existing->end_rva) {
            existing->end_rva = end;
            existing->boundary_status = "evidence_bounded";
        }
        append_alias(*existing, label);
        existing->confidence = std::max(existing->confidence, confidence);
        existing->evidence.push_back(std::move(evidence));
        return;
    }
    auto& target = kind == "known_function" ? recovery.known_functions :
                   kind == "fragment" ? recovery.fragments : recovery.candidate_functions;
    auto found = std::find_if(target.begin(), target.end(), [&](const auto& record) { return record.start_rva == start; });
    if (found == target.end()) {
        FunctionRecord record;
        record.entity_kind = kind;
        record.boundary_status = end ? (kind == "known_function" ? "pdb_bounded" : "evidence_bounded") : "unknown";
        record.start_rva = start;
        record.end_rva = end;
        record.file_offset = file_offset_for(image, start);
        record.confidence = confidence;
        record.evidence.push_back(std::move(evidence));
        append_alias(record, label);
        target.push_back(std::move(record));
        return;
    }
    if (end && found->end_rva && *end != *found->end_rva) {
        found->ambiguous = true;
        found->boundary_status = "ambiguous";
    } else if (end && !found->end_rva) {
        found->end_rva = end;
        found->boundary_status = kind == "known_function" ? "pdb_bounded" : "evidence_bounded";
    }
    append_alias(*found, label);
    found->confidence = std::max(found->confidence, confidence);
    found->evidence.push_back(std::move(evidence));
}

void set_symbol_path(AnalysisReport& report, const std::string& requested_path,
                     std::filesystem::path& resolved, bool& identity_available) {
    auto& symbols = report.symbols;
    symbols.requested_path = requested_path;
    const PeDebugEntry* codeview = nullptr;
    for (const auto& entry : report.pe.debug_entries) {
        if (!entry.codeview_guid.empty()) { codeview = &entry; break; }
    }
    if (codeview == nullptr) {
        symbols.status = requested_path.empty() ? "not_present" : "unverifiable";
        symbols.diagnostics.push_back({"CODEVIEW_IDENTITY_UNAVAILABLE", "info",
            "the PE has no usable RSDS CodeView GUID/age; a supplied PDB cannot be safely matched"});
        identity_available = false;
        return;
    }
    symbols.expected_guid = codeview->codeview_guid;
    symbols.expected_age = codeview->codeview_age;
    identity_available = true;
    if (!requested_path.empty()) {
        resolved = std::filesystem::path(requested_path);
    } else {
        const std::filesystem::path input(report.input_path);
        std::vector<std::filesystem::path> candidates;
        if (!codeview->pdb_path.empty()) candidates.push_back(input.parent_path() / std::filesystem::path(codeview->pdb_path).filename());
        candidates.push_back(input.parent_path() / (input.stem().string() + ".pdb"));
        std::error_code ec;
        for (const auto& candidate : candidates) {
            if (std::filesystem::is_regular_file(candidate, ec) && !ec) { resolved = candidate; break; }
            ec.clear();
        }
        if (resolved.empty()) {
            symbols.status = "missing";
            symbols.diagnostics.push_back({"PDB_NOT_FOUND", "info",
                "no adjacent PDB matching the PE CodeView identity was found; PE evidence remains available"});
            return;
        }
    }
    symbols.resolved_path = resolved.string();
}

std::optional<std::uint32_t> direct_target(const PeImage& image, const InstructionRecord& instruction) {
    for (const auto& operand : instruction.detail_operands) {
        if (operand.type != "immediate" || operand.immediate < 0) continue;
        std::uint32_t rva = 0;
        if (image.va_to_rva(static_cast<std::uint64_t>(operand.immediate), rva)) return rva;
    }
    return std::nullopt;
}

std::size_t instruction_size(const InstructionRecord& instruction) {
    return instruction.bytes.empty() ? 0U : 1U + static_cast<std::size_t>(std::count(instruction.bytes.begin(), instruction.bytes.end(), ' '));
}

bool has_group(const InstructionRecord& instruction, const std::string& group) {
    return std::find(instruction.groups.begin(), instruction.groups.end(), group) != instruction.groups.end();
}

void recursive_descent(AnalysisReport& report,
                       const std::unordered_map<std::uint32_t, const InstructionRecord*>& by_rva) {
    std::queue<std::uint32_t> pending;
    std::unordered_set<std::uint32_t> queued;
    for (const auto& item : report.function_recovery.known_functions) { pending.push(item.start_rva); queued.insert(item.start_rva); }
    for (const auto& item : report.function_recovery.candidate_functions) { pending.push(item.start_rva); queued.insert(item.start_rva); }
    for (const auto& item : report.function_recovery.fragments) { pending.push(item.start_rva); queued.insert(item.start_rva); }
    std::unordered_set<std::uint32_t> visited;
    std::size_t processed = 0;
    while (!pending.empty() && processed < kMaxRecursiveInstructions) {
        const std::uint32_t seed = pending.front();
        pending.pop();
        std::uint32_t current = seed;
        while (processed < kMaxRecursiveInstructions) {
            const auto found = by_rva.find(current);
            if (found == by_rva.end() || !visited.insert(current).second) break;
            ++processed;
            const auto& insn = *found->second;
            const std::size_t size = instruction_size(insn);
            if (size == 0U || current > std::numeric_limits<std::uint32_t>::max() - size) break;
            const std::uint32_t next = current + static_cast<std::uint32_t>(size);
            const bool call = has_group(insn, "call");
            const bool jump = has_group(insn, "jump");
            const bool returns = has_group(insn, "ret") || insn.mnemonic == "ret" || insn.mnemonic == "retq" ||
                                 insn.mnemonic == "iret" || insn.mnemonic == "iretq";
            const auto target = direct_target(report.pe, insn);
            if (call) {
                if (target && is_executable_rva(report.pe, *target)) {
                    FunctionEvidence evidence{"recursive_descent_call", "direct call target from RVA " +
                        std::to_string(current), 0.58, current, *target, std::nullopt};
                    add_evidence(report.function_recovery, report.pe, "candidate_function", *target,
                                 std::nullopt, {}, 0.58, std::move(evidence));
                    if (queued.insert(*target).second) pending.push(*target);
                } else if (!target && report.function_recovery.unresolved_control_flow.size() < kMaxRecoveryRecords) {
                    report.function_recovery.unresolved_control_flow.push_back({current, std::nullopt, "call",
                        "indirect_call_target_not_resolved"});
                }
                current = next;
                continue;
            }
            if (jump) {
                const bool unconditional = insn.mnemonic == "jmp" || insn.mnemonic == "jmpq" || insn.mnemonic == "ljmp";
                if (target && is_executable_rva(report.pe, *target)) {
                    if (unconditional && *target != seed) {
                        const FunctionRecord* owner = nullptr;
                        for (const auto& item : report.function_recovery.known_functions)
                            if (item.start_rva <= current && item.end_rva && current < *item.end_rva) { owner = &item; break; }
                        if (owner == nullptr) for (const auto& item : report.function_recovery.candidate_functions)
                            if (item.start_rva <= current && item.end_rva && current < *item.end_rva) { owner = &item; break; }
                        const bool outside_owner = owner == nullptr || *target < owner->start_rva ||
                            (owner->end_rva && *target >= *owner->end_rva);
                        if (outside_owner && report.function_recovery.unresolved_control_flow.size() < kMaxRecoveryRecords) {
                            report.function_recovery.unresolved_control_flow.push_back({current, *target, "tail_jump",
                                "direct_jump_may_be_a_tail_call_or_shared_fragment"});
                            FunctionEvidence evidence{"recursive_descent_tail_jump", "direct jump outside the current bounded range; may be a tail call or shared fragment",
                                0.42, current, *target, std::nullopt};
                            add_evidence(report.function_recovery, report.pe, "candidate_function", *target,
                                         std::nullopt, {}, 0.42, std::move(evidence));
                        }
                    }
                    if (queued.insert(*target).second) pending.push(*target);
                    if (unconditional) break;
                } else if (!target && report.function_recovery.unresolved_control_flow.size() < kMaxRecoveryRecords) {
                    report.function_recovery.unresolved_control_flow.push_back({current, std::nullopt,
                        unconditional ? "indirect_jump" : "indirect_conditional_branch",
                        "indirect_control_flow_or_jump_table_not_resolved"});
                    if (unconditional) break;
                }
                current = next;
                continue;
            }
            if (returns) break;
            current = next;
        }
    }
    if (processed >= kMaxRecursiveInstructions) {
        report.diagnostics.push_back({"FUNCTION_DISCOVERY_LIMIT", "warning",
            "recursive-descent traversal reached its bounded instruction-work limit; remaining code is unresolved"});
    }
}

void mark_overlaps(FunctionRecoveryRecord& recovery) {
    std::vector<FunctionRecord*> records;
    for (auto* group : {&recovery.known_functions, &recovery.candidate_functions, &recovery.fragments})
        for (auto& record : *group) if (record.end_rva && *record.end_rva > record.start_rva) records.push_back(&record);
    std::sort(records.begin(), records.end(), [](const auto* lhs, const auto* rhs) {
        if (lhs->start_rva != rhs->start_rva) return lhs->start_rva < rhs->start_rva;
        return lhs->end_rva.value_or(0U) < rhs->end_rva.value_or(0U);
    });
    bool warned = false;
    for (std::size_t i = 0; i < records.size(); ++i) {
        for (std::size_t j = i + 1U; j < records.size() && records[j]->start_rva < *records[i]->end_rva; ++j) {
            if (records[i]->start_rva == records[j]->start_rva && records[i]->end_rva == records[j]->end_rva) continue;
            records[i]->ambiguous = true;
            records[j]->ambiguous = true;
            records[i]->boundary_status = "ambiguous";
            records[j]->boundary_status = "ambiguous";
            warned = true;
        }
    }
    if (warned) recovery.status = "partial";
}

void calculate_unresolved_ranges(AnalysisReport& report) {
    auto& recovery = report.function_recovery;
    for (std::size_t index = 0; index < report.pe.sections.size(); ++index) {
        const auto& section = report.pe.sections[index];
        if (!section.executable || section.file_backed_size == 0U) continue;
        const std::uint64_t start64 = section.virtual_address;
        const std::uint64_t end64 = start64 + section.file_backed_size;
        if (end64 > std::numeric_limits<std::uint32_t>::max()) continue;
        std::vector<std::pair<std::uint32_t, std::uint32_t>> covered;
        for (const auto* group : {&recovery.known_functions, &recovery.candidate_functions, &recovery.fragments}) {
            for (const auto& record : *group) {
                if (!record.end_rva || record.start_rva >= end64 || *record.end_rva <= start64) continue;
                const auto begin = static_cast<std::uint32_t>(std::max<std::uint64_t>(record.start_rva, start64));
                const auto end = static_cast<std::uint32_t>(std::min<std::uint64_t>(*record.end_rva, end64));
                if (begin < end) covered.emplace_back(begin, end);
            }
        }
        std::sort(covered.begin(), covered.end());
        std::uint32_t cursor = static_cast<std::uint32_t>(start64);
        for (const auto& interval : covered) {
            if (interval.first > cursor)
                recovery.unresolved_ranges.push_back({index, cursor, interval.first,
                    "no bounded function evidence; executable bytes may include code, padding, or data"});
            cursor = std::max(cursor, interval.second);
        }
        if (cursor < end64)
            recovery.unresolved_ranges.push_back({index, cursor, static_cast<std::uint32_t>(end64),
                "no bounded function evidence; executable bytes may include code, padding, or data"});
    }
}

} // namespace

void recover_functions(AnalysisReport& report, const std::string& requested_pdb_path) {
    auto& recovery = report.function_recovery;
    recovery.status = "partial";
    report.symbols = SymbolProviderRecord{};
    std::filesystem::path pdb_path;
    bool identity_available = false;
    set_symbol_path(report, requested_pdb_path, pdb_path, identity_available);
    if (identity_available && !pdb_path.empty()) {
        std::error_code pdb_error;
        if (!std::filesystem::is_regular_file(pdb_path, pdb_error) || pdb_error) {
            report.symbols.status = "missing";
            report.symbols.diagnostics.push_back({"PDB_NOT_FOUND", "info",
                "the requested PDB is unavailable; PE evidence remains available"});
        } else {
            MsfPdb pdb;
            std::string parse_error;
            std::string observed_guid;
            std::uint32_t observed_age = 0;
            std::vector<PdbFunctionSymbol> pdb_functions;
            if (!pdb.load(pdb_path, parse_error, observed_guid, observed_age, pdb_functions, report.pe)) {
                report.symbols.status = "invalid";
                report.symbols.diagnostics.push_back({"PDB_PARSE_FAILED", "warning", parse_error});
            } else {
                report.symbols.observed_guid = observed_guid;
                report.symbols.observed_age = observed_age;
                if (observed_guid != report.symbols.expected_guid || observed_age != report.symbols.expected_age) {
                    report.symbols.status = "mismatched";
                    report.symbols.diagnostics.push_back({"PDB_IDENTITY_MISMATCH", "warning",
                        "PDB GUID/age does not match the PE RSDS identity; no PDB labels or ranges were trusted"});
                } else {
                    report.symbols.status = "matched";
                    report.symbols.functions = std::move(pdb_functions);
                    if (report.symbols.functions.empty())
                        report.symbols.diagnostics.push_back({"PDB_NO_PROCEDURE_RECORDS", "info",
                            "matching PDB identity was verified, but no supported procedure records were found"});
                }
            }
        }
    }
    std::unordered_map<std::uint32_t, const InstructionRecord*> by_rva;
    by_rva.reserve(report.instructions.size());
    for (const auto& instruction : report.instructions) by_rva.emplace(instruction.rva, &instruction);

    if (report.symbols.status == "matched") {
        for (const auto& symbol : report.symbols.functions) {
            if (!is_executable_rva(report.pe, symbol.start_rva)) {
                report.symbols.diagnostics.push_back({"PDB_PROCEDURE_OUTSIDE_EXECUTABLE_RANGE", "warning",
                    "PDB procedure '" + symbol.name + "' is outside a file-backed executable section and was ignored"});
                continue;
            }
            std::optional<std::uint32_t> end_rva;
            if (symbol.end_rva && is_executable_range(report.pe, symbol.start_rva, *symbol.end_rva))
                end_rva = symbol.end_rva;
            if (symbol.end_rva && !end_rva)
                report.symbols.diagnostics.push_back({"PDB_PROCEDURE_RANGE_INVALID", "warning",
                    "PDB procedure '" + symbol.name + "' has an end outside its file-backed executable section"});
            FunctionEvidence evidence{"pdb_procedure_record", "matching PDB procedure record; GUID/age verified",
                symbol.confidence, std::nullopt, symbol.start_rva, end_rva};
            add_evidence(recovery, report.pe, "known_function", symbol.start_rva, end_rva,
                         symbol.name, symbol.confidence, std::move(evidence));
        }
    }
    for (const auto& item : report.symbols.diagnostics) report.diagnostics.push_back(item);

    for (const auto& runtime : report.pe.runtime_functions) {
        if (!is_executable_range(report.pe, runtime.begin_rva, runtime.end_rva)) {
            report.diagnostics.push_back({"UNWIND_FUNCTION_RANGE_INVALID", "warning",
                "a PE RUNTIME_FUNCTION range was not contained in one file-backed executable section and was ignored"});
            continue;
        }
        const bool chained = (runtime.unwind_flags & 4U) != 0U;
        FunctionEvidence evidence{"x64_unwind_range", chained ? "RUNTIME_FUNCTION range with UNW_FLAG_CHAININFO; retained as a fragment" :
            "validated PE x64 exception/unwind RUNTIME_FUNCTION range", chained ? 0.72 : 0.82,
            std::nullopt, runtime.begin_rva, runtime.end_rva};
        add_evidence(recovery, report.pe, chained ? "fragment" : "candidate_function", runtime.begin_rva,
                     runtime.end_rva, {}, chained ? 0.72 : 0.82, std::move(evidence));
    }
    for (const auto& exported : report.pe.exports) {
        if (exported.rva == 0U || !exported.forwarded_to.empty() || !is_executable_rva(report.pe, exported.rva)) continue;
        FunctionEvidence evidence{"pe_export", "non-forwarded PE export target; export is evidence, not proof of a function boundary",
            0.68, std::nullopt, exported.rva, std::nullopt};
        add_evidence(recovery, report.pe, "candidate_function", exported.rva, std::nullopt,
                     exported.name, 0.68, std::move(evidence));
    }
    if (report.pe.entry_point_rva != 0U && is_executable_rva(report.pe, report.pe.entry_point_rva)) {
        FunctionEvidence evidence{"pe_entry_point", "PE AddressOfEntryPoint seed; may be a runtime stub or non-user function",
            0.62, std::nullopt, report.pe.entry_point_rva, std::nullopt};
        add_evidence(recovery, report.pe, "candidate_function", report.pe.entry_point_rva, std::nullopt,
                     "entry_point", 0.62, std::move(evidence));
    }

    recursive_descent(report, by_rva);
    mark_overlaps(recovery);
    calculate_unresolved_ranges(report);
    std::sort(recovery.known_functions.begin(), recovery.known_functions.end(), [](const auto& a, const auto& b) { return a.start_rva < b.start_rva; });
    std::sort(recovery.candidate_functions.begin(), recovery.candidate_functions.end(), [](const auto& a, const auto& b) { return a.start_rva < b.start_rva; });
    std::sort(recovery.fragments.begin(), recovery.fragments.end(), [](const auto& a, const auto& b) { return a.start_rva < b.start_rva; });
    std::sort(recovery.unresolved_ranges.begin(), recovery.unresolved_ranges.end(), [](const auto& a, const auto& b) {
        return a.start_rva < b.start_rva;
    });
    if (recovery.known_functions.empty() && recovery.candidate_functions.empty() && recovery.fragments.empty())
        report.diagnostics.push_back({"NO_FUNCTION_BOUNDARIES_CONFIRMED", "info",
            "no evidence-backed function starts were identified; executable ranges remain unresolved"});
    report.stages.push_back({"symbol_provider", report.symbols.status == "matched" ? "complete" : "partial"});
    report.stages.push_back({"function_recovery", "partial"});
    report.diagnostics.push_back({"FUNCTION_BOUNDARIES_EVIDENCE_LABELLED", "info",
        "function starts and ranges are candidates backed by named evidence; unresolved and ambiguous intervals remain explicit"});
}

} // namespace nexusrev
