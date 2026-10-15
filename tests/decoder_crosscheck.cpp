#include "pe_image.hpp"
#include "sha256.hpp"

#include <Zydis/Decoder.h>
#include <Zydis/Utils.h>
#include <capstone/capstone.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace {
constexpr std::size_t kMaximumFixtureBytes = 16U * 1024U * 1024U;
constexpr std::size_t kMaximumFunctionBytes = 1024U * 1024U;
constexpr std::size_t kMaximumRuntimeFunctions = 4096U;
std::size_t access_metadata_unavailable = 0U;

struct ReferenceFunction {
    std::uint32_t start_rva = 0U;
    std::optional<std::uint32_t> return_rva;
};

struct PairDecode {
    cs_insn* capstone = nullptr;
    std::size_t capstone_count = 0U;
    ZydisDecodedInstruction zydis{};
    std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> zydis_operands{};
    bool zydis_ok = false;

    bool capstone_ok() const { return capstone_count == 1U && capstone != nullptr; }
    std::size_t capstone_length() const {
        return capstone_ok() ? capstone[0].size : 0U;
    }
    void release() {
        if (capstone != nullptr) {
            cs_free(capstone, capstone_count);
            capstone = nullptr;
            capstone_count = 0U;
        }
    }
};

struct InstructionCase {
    const char* label;
    std::vector<std::uint8_t> bytes;
    std::uint64_t address;
    std::size_t expected_length;
    unsigned int expected_vector_bits;
    std::optional<std::uint64_t> expected_relative_target;
    bool expected_zero_mask = false;
    std::string expected_mask_register;

    InstructionCase(const char* case_label, std::vector<std::uint8_t> case_bytes,
                    std::uint64_t case_address, std::size_t case_length,
                    unsigned int vector_bits,
                    std::optional<std::uint64_t> relative_target,
                    bool zero_mask = false, std::string mask_register = {})
        : label(case_label), bytes(std::move(case_bytes)), address(case_address),
          expected_length(case_length), expected_vector_bits(vector_bits),
          expected_relative_target(relative_target), expected_zero_mask(zero_mask),
          expected_mask_register(std::move(mask_register)) {}
};

std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

std::string normalized_mnemonic(const char* value) {
    auto mnemonic = lower(value == nullptr ? std::string{} : std::string(value));
    if (mnemonic == "jnz") return "jne";
    if (mnemonic == "jz") return "je";
    return mnemonic;
}

void mismatch(std::size_t& mismatch_count, const std::string& label,
              std::uint64_t address, const std::string& fact,
              const std::string& capstone_value, const std::string& zydis_value) {
    ++mismatch_count;
    std::cerr << "decoder disagreement [" << label << "] at 0x" << std::hex << address
              << std::dec << ": " << fact << " (Capstone=" << capstone_value
              << ", Zydis=" << zydis_value << ")\n";
}

PairDecode decode_pair(csh capstone_handle, const ZydisDecoder& zydis_decoder,
                       const std::uint8_t* bytes, std::size_t size,
                       std::uint64_t address) {
    PairDecode result;
    result.capstone_count = cs_disasm(capstone_handle, bytes, size, address, 1U,
                                      &result.capstone);
    result.zydis_ok = ZYAN_SUCCESS(ZydisDecoderDecodeFull(
        &zydis_decoder, bytes, size, &result.zydis, result.zydis_operands.data()));
    return result;
}

std::string capstone_register_name(csh handle, x86_reg reg) {
    if (reg == X86_REG_INVALID) return {};
    const char* name = cs_reg_name(handle, static_cast<unsigned int>(reg));
    return name == nullptr ? std::string{} : lower(name);
}

std::string zydis_register_name(ZydisRegister reg) {
    if (reg == ZYDIS_REGISTER_NONE) return {};
    const char* name = ZydisRegisterGetString(reg);
    return name == nullptr ? std::string{} : lower(name);
}

std::uint8_t capstone_access(const cs_x86_op& operand) {
    return static_cast<std::uint8_t>(operand.access & (CS_AC_READ | CS_AC_WRITE));
}

std::uint8_t zydis_access(const ZydisDecodedOperand& operand) {
    std::uint8_t access = 0U;
    if ((operand.actions & (ZYDIS_OPERAND_ACTION_READ | ZYDIS_OPERAND_ACTION_CONDREAD)) != 0U)
        access = static_cast<std::uint8_t>(access | CS_AC_READ);
    if ((operand.actions & (ZYDIS_OPERAND_ACTION_WRITE | ZYDIS_OPERAND_ACTION_CONDWRITE)) != 0U)
        access = static_cast<std::uint8_t>(access | CS_AC_WRITE);
    return access;
}

unsigned int vector_bits(const ZydisDecodedInstruction& instruction) {
    const auto bits = static_cast<unsigned int>(instruction.avx.vector_length);
    return bits == 128U || bits == 256U || bits == 512U ? bits : 0U;
}

unsigned int capstone_vector_register_bits(csh handle, const cs_x86& x86) {
    unsigned int bits = 0U;
    for (std::uint8_t i = 0U; i < x86.op_count; ++i) {
        const auto& operand = x86.operands[i];
        if (operand.type != X86_OP_REG) continue;
        const auto name = capstone_register_name(handle, operand.reg);
        if (name.rfind("xmm", 0U) == 0U || name.rfind("ymm", 0U) == 0U ||
            name.rfind("zmm", 0U) == 0U)
            bits = std::max(bits, static_cast<unsigned int>(operand.size) * 8U);
    }
    return bits;
}

bool compare_instruction_facts(csh handle, const PairDecode& pair,
                               const std::string& label, std::uint64_t address,
                               std::size_t& mismatch_count,
                               std::optional<std::uint64_t> expected_relative_target = std::nullopt,
                               unsigned int expected_vector_bits = 0U,
                               bool expected_zero_mask = false,
                               const std::string& expected_mask_register = {}) {
    if (!pair.capstone_ok() || !pair.zydis_ok) return false;
    const auto& capstone_instruction = pair.capstone[0];
    const auto& capstone_x86 = capstone_instruction.detail->x86;
    const auto zydis_mnemonic = normalized_mnemonic(ZydisMnemonicGetString(pair.zydis.mnemonic));
    if (normalized_mnemonic(capstone_instruction.mnemonic) != zydis_mnemonic)
        mismatch(mismatch_count, label, address, "mnemonic", capstone_instruction.mnemonic,
                 zydis_mnemonic);

    std::vector<const ZydisDecodedOperand*> zydis_visible_operands;
    zydis_visible_operands.reserve(pair.zydis.operand_count_visible);
    for (std::size_t i = 0U; i < pair.zydis.operand_count_visible; ++i) {
        const auto& operand = pair.zydis_operands[i];
        const bool embedded_mask = operand.type == ZYDIS_OPERAND_TYPE_REGISTER &&
            pair.zydis.avx.mask.reg != ZYDIS_REGISTER_NONE &&
            operand.reg.value == pair.zydis.avx.mask.reg;
        bool embedded_segment = false;
        if (operand.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            for (std::size_t j = 0U; j < pair.zydis.operand_count_visible; ++j) {
                const auto& other = pair.zydis_operands[j];
                if (other.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                    other.mem.segment != ZYDIS_REGISTER_NONE &&
                    other.mem.segment == operand.reg.value) {
                    embedded_segment = true;
                    break;
                }
            }
        }
        if (!embedded_mask && !embedded_segment) zydis_visible_operands.push_back(&operand);
    }
    std::vector<const cs_x86_op*> capstone_visible_operands;
    capstone_visible_operands.reserve(capstone_x86.op_count);
    for (std::uint8_t i = 0U; i < capstone_x86.op_count; ++i) {
        const auto& operand = capstone_x86.operands[i];
        bool embedded_mask = false;
        bool embedded_segment = false;
        if (operand.type == X86_OP_REG) {
            const auto name = capstone_register_name(handle, operand.reg);
            embedded_mask = !zydis_register_name(pair.zydis.avx.mask.reg).empty() &&
                            name == zydis_register_name(pair.zydis.avx.mask.reg);
            for (std::size_t j = 0U; j < pair.zydis.operand_count_visible; ++j) {
                const auto& other = pair.zydis_operands[j];
                if (other.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                    other.mem.segment != ZYDIS_REGISTER_NONE &&
                    name == zydis_register_name(other.mem.segment)) {
                    embedded_segment = true;
                    break;
                }
            }
        }
        if (!embedded_mask && !embedded_segment) capstone_visible_operands.push_back(&operand);
    }
    if (capstone_visible_operands.size() != zydis_visible_operands.size())
        mismatch(mismatch_count, label, address, "visible operand count",
                 std::to_string(capstone_visible_operands.size()),
                 std::to_string(zydis_visible_operands.size()));

    const auto operand_count = std::min<std::size_t>(capstone_visible_operands.size(),
                                                      zydis_visible_operands.size());
    bool relative_target_seen = false;
    for (std::size_t i = 0U; i < operand_count; ++i) {
        const auto& cap = *capstone_visible_operands[i];
        const auto& zydis = *zydis_visible_operands[i];
        const auto operand_label = label + " operand " + std::to_string(i);
        const bool address_generation = zydis.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                                        zydis.mem.type == ZYDIS_MEMOP_TYPE_AGEN;
        if (cap.type != X86_OP_IMM && !address_generation &&
            static_cast<unsigned int>(cap.size) * 8U != zydis.size)
            mismatch(mismatch_count, operand_label, address, "operand width in bits",
                     std::to_string(static_cast<unsigned int>(cap.size) * 8U),
                     std::to_string(zydis.size));
        if (cap.type != X86_OP_IMM && !address_generation &&
            capstone_access(cap) != zydis_access(zydis)) {
            if (capstone_access(cap) == 0U && zydis_access(zydis) != 0U) {
                ++access_metadata_unavailable;
                std::cerr << "decoder metadata unavailable [" << operand_label << "] at 0x"
                          << std::hex << address << std::dec
                          << ": Capstone did not report operand access; Zydis reports "
                          << static_cast<unsigned int>(zydis_access(zydis)) << '\n';
            } else {
                mismatch(mismatch_count, operand_label, address, "read/write access",
                         std::to_string(capstone_access(cap)), std::to_string(zydis_access(zydis)));
            }
        }

        switch (cap.type) {
            case X86_OP_REG: {
                if (zydis.type != ZYDIS_OPERAND_TYPE_REGISTER) {
                    mismatch(mismatch_count, operand_label, address, "operand type", "register",
                             std::to_string(static_cast<int>(zydis.type)));
                    break;
                }
                const auto cap_name = capstone_register_name(handle, cap.reg);
                const auto zy_name = zydis_register_name(zydis.reg.value);
                if (cap_name != zy_name)
                    mismatch(mismatch_count, operand_label, address, "register", cap_name, zy_name);
                break;
            }
            case X86_OP_IMM: {
                if (zydis.type != ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    mismatch(mismatch_count, operand_label, address, "operand type", "immediate",
                             std::to_string(static_cast<int>(zydis.type)));
                    break;
                }
                std::uint64_t zydis_value = zydis.imm.is_signed
                    ? static_cast<std::uint64_t>(zydis.imm.value.s)
                    : zydis.imm.value.u;
                if (zydis.imm.is_relative) {
                    relative_target_seen = true;
                    ZyanU64 absolute = 0U;
                    if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&pair.zydis, &zydis, address, &absolute))) {
                        mismatch(mismatch_count, operand_label, address, "relative target calculation",
                                 "unavailable", "failed");
                        break;
                    }
                    zydis_value = absolute;
                    if (expected_relative_target && absolute != *expected_relative_target)
                        mismatch(mismatch_count, operand_label, address, "expected relative target",
                                 "0x" + [&] { std::ostringstream s; s << std::hex << *expected_relative_target; return s.str(); }(),
                                 "0x" + [&] { std::ostringstream s; s << std::hex << absolute; return s.str(); }());
                }
                const auto capstone_value = static_cast<std::uint64_t>(cap.imm);
                if (capstone_value != zydis_value) {
                    std::ostringstream cap_value, zy_value;
                    cap_value << "0x" << std::hex << capstone_value;
                    zy_value << "0x" << std::hex << zydis_value;
                    mismatch(mismatch_count, operand_label, address, "immediate/target",
                             cap_value.str(), zy_value.str());
                }
                break;
            }
            case X86_OP_MEM: {
                if (zydis.type != ZYDIS_OPERAND_TYPE_MEMORY) {
                    mismatch(mismatch_count, operand_label, address, "operand type", "memory",
                             std::to_string(static_cast<int>(zydis.type)));
                    break;
                }
                const auto cap_base = capstone_register_name(handle, cap.mem.base);
                const auto zy_base = zydis_register_name(zydis.mem.base);
                if (cap_base != zy_base)
                    mismatch(mismatch_count, operand_label, address, "memory base", cap_base, zy_base);
                const auto cap_index = capstone_register_name(handle, cap.mem.index);
                const auto zy_index = zydis_register_name(zydis.mem.index);
                if (cap_index != zy_index)
                    mismatch(mismatch_count, operand_label, address, "memory index", cap_index, zy_index);
                const auto cap_segment = capstone_register_name(handle, cap.mem.segment);
                const auto zy_segment = zydis_register_name(zydis.mem.segment);
                if (!cap_segment.empty() && cap_segment != zy_segment)
                    mismatch(mismatch_count, operand_label, address, "memory segment",
                             cap_segment, zy_segment);
                if (!cap_index.empty() && static_cast<unsigned int>(cap.mem.scale) != zydis.mem.scale)
                    mismatch(mismatch_count, operand_label, address, "memory scale",
                             std::to_string(cap.mem.scale), std::to_string(zydis.mem.scale));
                if (cap.mem.disp != zydis.mem.disp.value)
                    mismatch(mismatch_count, operand_label, address, "memory displacement",
                             std::to_string(cap.mem.disp), std::to_string(zydis.mem.disp.value));
                break;
            }
            default:
                mismatch(mismatch_count, operand_label, address, "unsupported normalized operand type",
                         std::to_string(static_cast<int>(cap.type)),
                         std::to_string(static_cast<int>(zydis.type)));
                break;
        }
    }

    if (expected_relative_target && !relative_target_seen)
        mismatch(mismatch_count, label, address, "expected a relative branch/call target", "missing", "missing");

    if (expected_vector_bits != 0U) {
        const auto zy_bits = vector_bits(pair.zydis);
        const auto cap_bits = capstone_vector_register_bits(handle, capstone_x86);
        if (zy_bits != expected_vector_bits)
            mismatch(mismatch_count, label, address, "Zydis AVX vector-length metadata",
                     std::to_string(expected_vector_bits), std::to_string(zy_bits));
        if (cap_bits != expected_vector_bits)
            mismatch(mismatch_count, label, address, "Capstone vector-register width",
                     std::to_string(expected_vector_bits), std::to_string(cap_bits));
        if (zy_bits != cap_bits)
            mismatch(mismatch_count, label, address, "AVX vector length vs register width",
                     std::to_string(cap_bits), std::to_string(zy_bits));
        const bool zydis_zero_mask = pair.zydis.avx.mask.mode == ZYDIS_MASK_MODE_ZEROING ||
                                     pair.zydis.avx.mask.mode == ZYDIS_MASK_MODE_CONTROL_ZEROING;
        const bool capstone_zero_mask = std::any_of(
            capstone_x86.operands, capstone_x86.operands + capstone_x86.op_count,
            [](const cs_x86_op& operand) { return operand.avx_zero_opmask; });
        if (zydis_zero_mask != capstone_zero_mask)
            mismatch(mismatch_count, label, address, "AVX zero-opmask metadata",
                     capstone_zero_mask ? "zeroing" : "not-zeroing",
                     zydis_zero_mask ? "zeroing" : "not-zeroing");
        if (zydis_zero_mask != expected_zero_mask)
            mismatch(mismatch_count, label, address, "expected zero-opmask mode",
                     expected_zero_mask ? "zeroing" : "not-zeroing",
                     zydis_zero_mask ? "zeroing" : "not-zeroing");
        if (!expected_mask_register.empty() &&
            zydis_register_name(pair.zydis.avx.mask.reg) != expected_mask_register)
            mismatch(mismatch_count, label, address, "expected AVX mask register",
                     expected_mask_register, zydis_register_name(pair.zydis.avx.mask.reg));
    }
    return true;
}

bool compare_one(csh capstone_handle, const ZydisDecoder& zydis_decoder,
                 const std::uint8_t* bytes, std::size_t size, std::uint64_t address,
                 const std::string& label, std::size_t& mismatch_count,
                 bool require_both, std::size_t expected_length = 0U,
                 std::optional<std::uint64_t> expected_relative_target = std::nullopt,
                 unsigned int expected_vector_bits = 0U,
                 bool expected_zero_mask = false,
                 const std::string& expected_mask_register = {}) {
    auto pair = decode_pair(capstone_handle, zydis_decoder, bytes, size, address);
    if (pair.capstone_ok() != pair.zydis_ok) {
        mismatch(mismatch_count, label, address, "decode acceptance",
                 pair.capstone_ok() ? "accepted" : "rejected",
                 pair.zydis_ok ? "accepted" : "rejected");
        pair.release();
        return false;
    }
    if (!pair.capstone_ok()) {
        pair.release();
        return !require_both;
    }
    if (pair.capstone_length() != pair.zydis.length)
        mismatch(mismatch_count, label, address, "instruction length",
                 std::to_string(pair.capstone_length()), std::to_string(pair.zydis.length));
    if (expected_length != 0U && pair.capstone_length() != expected_length)
        mismatch(mismatch_count, label, address, "expected instruction length",
                 std::to_string(expected_length), std::to_string(pair.capstone_length()));
    if (pair.capstone_length() == pair.zydis.length)
        compare_instruction_facts(capstone_handle, pair, label, address, mismatch_count,
                                  expected_relative_target, expected_vector_bits,
                                  expected_zero_mask, expected_mask_register);
    pair.release();
    return true;
}

std::vector<InstructionCase> curated_cases() {
    return {
        {"push-rbp", {0x55U}, 0x1000U, 1U, 0U, std::nullopt},
        {"mov-rbp-rsp", {0x48U, 0x89U, 0xe5U}, 0x1000U, 3U, 0U, std::nullopt},
        {"sub-rsp-imm8", {0x48U, 0x83U, 0xecU, 0x20U}, 0x1000U, 4U, 0U, std::nullopt},
        {"mov-indexed-memory", {0x48U, 0x8bU, 0x44U, 0x8bU, 0x08U}, 0x1000U, 5U, 0U, std::nullopt},
        {"mov-eax-imm32", {0xb8U, 0x78U, 0x56U, 0x34U, 0x12U}, 0x1000U, 5U, 0U, std::nullopt},
        {"call-rel32", {0xe8U, 0x05U, 0x00U, 0x00U, 0x00U}, 0x1000U, 5U, 0U, 0x100aU},
        {"jne-rel8", {0x75U, 0x03U}, 0x2000U, 2U, 0U, 0x2005U},
        {"vaddps-xmm-vex", {0xc5U, 0xf0U, 0x58U, 0xc2U}, 0x3000U, 4U, 128U, std::nullopt},
        {"vaddps-ymm-vex", {0xc5U, 0xf4U, 0x58U, 0xc2U}, 0x3000U, 4U, 256U, std::nullopt},
        {"vaddps-zmm-evex", {0x62U, 0xf1U, 0x74U, 0x48U, 0x58U, 0xc2U}, 0x3000U, 6U, 512U, std::nullopt},
        {"vaddps-zmm-k1-zeroing", {0x62U, 0xf1U, 0x74U, 0xc9U, 0x58U, 0xc2U}, 0x3000U, 6U, 512U, std::nullopt, true, "k1"},
    };
}

bool read_file(const std::filesystem::path& path, std::vector<std::uint8_t>& bytes) {
    std::error_code ec;
    const auto size = std::filesystem::file_size(path, ec);
    if (ec || size == 0U || size > nexusrev::kMaxInputBytes ||
        size > static_cast<std::uintmax_t>(std::numeric_limits<std::size_t>::max()))
        return false;
    std::ifstream input(path, std::ios::binary);
    if (!input) return false;
    bytes.resize(static_cast<std::size_t>(size));
    input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    return input.good() || input.eof();
}

bool read_reference_function_starts(const std::filesystem::path& path,
                                    const std::vector<std::uint8_t>& fixture_bytes,
                                    std::vector<ReferenceFunction>& functions) {
    std::ifstream input(path);
    std::string line;
    if (!input || !std::getline(input, line)) return false;
    std::vector<std::string> header;
    std::stringstream header_stream(line);
    std::string field;
    while (std::getline(header_stream, field, '\t')) header.push_back(field);
    if (header.size() < 4U || header[0] != "NEXUSREV_GHIDRA_REFERENCE" ||
        header[1] != "1")
        return false;
    const std::string_view fixture_view(reinterpret_cast<const char*>(fixture_bytes.data()),
                                        fixture_bytes.size());
    if (nexusrev::sha256(fixture_view) != header[2]) {
        std::cerr << "Ghidra reference SHA-256 does not match the compiler fixture\n";
        return false;
    }
    while (std::getline(input, line)) {
        std::stringstream record_stream(line);
        std::vector<std::string> record;
        while (std::getline(record_stream, field, '\t')) record.push_back(field);
        if (record.size() < 2U) continue;
        if (record[0] == "F") {
            try {
                const auto value = std::stoull(record[1]);
                if (value > std::numeric_limits<std::uint32_t>::max()) return false;
                functions.push_back({static_cast<std::uint32_t>(value), std::nullopt});
            } catch (const std::exception&) {
                return false;
            }
        } else if (record[0] == "E" && record.size() >= 3U && record[2] == "return" &&
                   !functions.empty()) {
            try {
                const auto value = std::stoull(record[1]);
                if (value > std::numeric_limits<std::uint32_t>::max()) return false;
                const auto return_rva = static_cast<std::uint32_t>(value);
                auto& current = functions.back().return_rva;
                if (!current || return_rva > *current) current = return_rva;
            } catch (const std::exception&) {
                return false;
            }
        }
    }
    std::sort(functions.begin(), functions.end(), [](const auto& left, const auto& right) {
        return left.start_rva < right.start_rva;
    });
    functions.erase(std::unique(functions.begin(), functions.end(), [](const auto& left, const auto& right) {
        return left.start_rva == right.start_rva;
    }), functions.end());
    functions.erase(std::remove_if(functions.begin(), functions.end(), [](const auto& function) {
        return !function.return_rva || *function.return_rva < function.start_rva;
    }), functions.end());
    return !functions.empty() && functions.size() <= kMaximumRuntimeFunctions;
}

bool run_compiler_fixture(csh capstone_handle, const ZydisDecoder& zydis_decoder,
                          const std::filesystem::path& path,
                          const std::filesystem::path& reference_path,
                          std::size_t& mismatch_count,
                          std::size_t& compared_instructions,
                          std::size_t& compared_functions) {
    std::vector<std::uint8_t> file_bytes;
    if (!read_file(path, file_bytes)) {
        std::cerr << "unable to read bounded compiler fixture: " << path << '\n';
        return false;
    }
    std::vector<ReferenceFunction> reference_functions;
    if (!read_reference_function_starts(reference_path, file_bytes, reference_functions)) {
        std::cerr << "unable to read hash-matched source-known function ranges from "
                  << reference_path << '\n';
        return false;
    }
    nexusrev::PeImage image;
    std::string error_code, error_message;
    if (!nexusrev::PeImage::parse(std::move(file_bytes), image, error_code, error_message) ||
        !image.supported_x64_native) {
        std::cerr << "compiler fixture did not parse as native x86-64 PE: "
                  << error_code << ' ' << error_message << '\n';
        return false;
    }

    std::size_t examined_bytes = 0U;
    std::uint32_t previous_end = 0U;
    for (std::size_t i = 0U; i < reference_functions.size(); ++i) {
        const auto begin_rva = reference_functions[i].start_rva;
        const auto terminal_rva = *reference_functions[i].return_rva;
        const auto mapping = image.map_rva(begin_rva);
        if (!mapping.mapped || mapping.virtual_zero_fill || mapping.section_index < 0 ||
            static_cast<std::size_t>(mapping.section_index) >= image.sections.size())
            continue;
        const auto section_index = static_cast<std::size_t>(mapping.section_index);
        const auto& section = image.sections[section_index];
        if (!section.executable || begin_rva < section.virtual_address || begin_rva < previous_end)
            continue;
        const auto section_end = static_cast<std::uint64_t>(section.virtual_address) +
                                 section.file_backed_size;
        std::uint64_t end_rva = section_end;
        if (i + 1U < reference_functions.size()) {
            const auto next_start = reference_functions[i + 1U].start_rva;
            const auto next_mapping = image.map_rva(next_start);
            if (next_mapping.mapped && !next_mapping.virtual_zero_fill &&
                next_mapping.section_index == mapping.section_index &&
                next_start > begin_rva)
                end_rva = next_start;
        }
        if (end_rva > section_end) end_rva = section_end;
        if (end_rva <= begin_rva || end_rva > std::numeric_limits<std::uint32_t>::max()) continue;
        const auto range_size = static_cast<std::size_t>(end_rva - begin_rva);
        if (range_size > kMaximumFunctionBytes ||
            range_size > kMaximumFixtureBytes - examined_bytes)
            continue;
        std::vector<std::uint8_t> code;
        if (!image.read_rva(begin_rva, range_size, code)) continue;
        previous_end = static_cast<std::uint32_t>(end_rva);
        examined_bytes += range_size;
        ++compared_functions;

        std::size_t offset = 0U;
        bool terminal_compared = false;
        while (offset < code.size()) {
            const auto current_rva = static_cast<std::uint64_t>(begin_rva) + offset;
            if (current_rva > terminal_rva) {
                mismatch(mismatch_count, "compiler-fixture", image.image_base + terminal_rva,
                         "reference return boundary is an instruction start",
                         "passed without alignment", "passed without alignment");
                break;
            }
            auto pair = decode_pair(capstone_handle, zydis_decoder, code.data() + offset,
                                    code.size() - offset,
                                    image.image_base + begin_rva + offset);
            const auto address = image.image_base + begin_rva + offset;
            if (current_rva == terminal_rva && (!pair.capstone_ok() || !pair.zydis_ok)) {
                mismatch(mismatch_count, "compiler-fixture", address,
                         "reference return instruction decodes in both libraries",
                         pair.capstone_ok() ? "accepted" : "rejected",
                         pair.zydis_ok ? "accepted" : "rejected");
                pair.release();
                break;
            }
            if (pair.capstone_ok() != pair.zydis_ok) {
                mismatch(mismatch_count, "compiler-fixture", address, "decode acceptance",
                         pair.capstone_ok() ? "accepted" : "rejected",
                         pair.zydis_ok ? "accepted" : "rejected");
                const auto advance = pair.capstone_ok() ? pair.capstone_length() : pair.zydis.length;
                pair.release();
                if (current_rva == terminal_rva) break;
                offset += std::max<std::size_t>(advance, 1U);
                continue;
            }
            if (!pair.capstone_ok()) {
                pair.release();
                if (current_rva == terminal_rva) break;
                ++offset;
                continue;
            }
            if (pair.capstone_length() != pair.zydis.length) {
                mismatch(mismatch_count, "compiler-fixture", address, "instruction length",
                         std::to_string(pair.capstone_length()), std::to_string(pair.zydis.length));
                const auto advance = std::max<std::size_t>(pair.capstone_length(), pair.zydis.length);
                pair.release();
                if (current_rva == terminal_rva) break;
                offset += std::max<std::size_t>(advance, 1U);
                continue;
            }
            compare_instruction_facts(capstone_handle, pair, "compiler-fixture", address,
                                      mismatch_count);
            ++compared_instructions;
            const auto advance = pair.capstone_length();
            pair.release();
            if (current_rva == terminal_rva) {
                terminal_compared = true;
                break;
            }
            offset += std::max<std::size_t>(advance, 1U);
        }
        if (!terminal_compared)
            mismatch(mismatch_count, "compiler-fixture", image.image_base + terminal_rva,
                     "hash-pinned reference return instruction reached", "not reached", "not reached");
    }
    if (compared_functions == 0U || compared_instructions == 0U) {
        std::cerr << "compiler fixture yielded no bounded source-known executable instructions for comparison\n";
        return false;
    }
    return true;
}
} // namespace

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "usage: nexusrev_decoder_crosscheck <compiler-generated-x64.exe> "
                     "<compiler-generated-x64-ghidra-reference.tsv>\n";
        return 2;
    }

    csh capstone_handle = 0U;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &capstone_handle) != CS_ERR_OK ||
        cs_option(capstone_handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
        std::cerr << "unable to initialize Capstone with instruction details enabled\n";
        if (capstone_handle != 0U) cs_close(&capstone_handle);
        return 1;
    }

    ZydisDecoder zydis_decoder{};
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&zydis_decoder, ZYDIS_MACHINE_MODE_LONG_64,
                                       ZYDIS_STACK_WIDTH_64))) {
        std::cerr << "unable to initialize full-detail Zydis x86-64 decoder\n";
        cs_close(&capstone_handle);
        return 1;
    }

    std::size_t mismatches = 0U;
    std::size_t curated_count = 0U;
    for (const auto& item : curated_cases()) {
        const auto before = mismatches;
        const bool accepted = compare_one(capstone_handle, zydis_decoder,
                                          item.bytes.data(), item.bytes.size(), item.address,
                                          item.label, mismatches, true, item.expected_length,
                                          item.expected_relative_target, item.expected_vector_bits,
                                          item.expected_zero_mask, item.expected_mask_register);
        if (!accepted && mismatches == before) {
            mismatch(mismatches, item.label, item.address, "both decoders accept instruction",
                     "rejected", "rejected");
        }
        ++curated_count;
    }

    const std::vector<std::uint8_t> movabs = {
        0x48U, 0xb8U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U};
    for (std::size_t length = 1U; length < movabs.size(); ++length) {
        const auto before = mismatches;
        const bool accepted = compare_one(capstone_handle, zydis_decoder, movabs.data(), length,
                                          0x4000U, "truncated-movabs-" + std::to_string(length),
                                          mismatches, false);
        if (!accepted && mismatches == before)
            mismatch(mismatches, "truncated-movabs", 0x4000U, "both decoders reject truncation",
                     "accepted", "accepted");
    }
    const auto evex = curated_cases().back().bytes;
    for (std::size_t length = 1U; length < evex.size(); ++length) {
        const auto before = mismatches;
        const bool accepted = compare_one(capstone_handle, zydis_decoder, evex.data(), length,
                                          0x5000U, "truncated-evex-" + std::to_string(length),
                                          mismatches, false);
        if (!accepted && mismatches == before)
            mismatch(mismatches, "truncated-evex", 0x5000U, "both decoders reject truncation",
                     "accepted", "accepted");
    }

    std::size_t fixture_instructions = 0U;
    std::size_t fixture_functions = 0U;
    const bool fixture_ok = run_compiler_fixture(capstone_handle, zydis_decoder, argv[1], argv[2],
                                                  mismatches, fixture_instructions,
                                                  fixture_functions);
    cs_close(&capstone_handle);
    std::cout << "Decoder cross-check: " << curated_count << " curated instruction cases, "
              << (movabs.size() - 1U + evex.size() - 1U) << " truncated-buffer cases, "
              << fixture_instructions << " compiler-fixture instructions across "
              << fixture_functions << " source-known function regions; " << mismatches
              << " disagreement(s); " << access_metadata_unavailable
              << " access-metadata omission(s).\n";
    if (!fixture_ok || mismatches != 0U) return 1;
    return 0;
}
