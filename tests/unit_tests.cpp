#include "sha256.hpp"
#include "pe_image.hpp"

#include <cstdint>
#include <iostream>
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
    if (!pe_parser_tests()) return 1;
    std::cout << "SHA-256 and PE parser unit tests passed\n";
    return 0;
}
