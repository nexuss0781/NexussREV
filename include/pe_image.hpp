#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace nexusrev {

constexpr std::uint64_t kMaxInputBytes = 256ULL * 1024ULL * 1024ULL;
constexpr std::size_t kMaxSections = 96;
constexpr std::size_t kMaxDataDirectories = 32;
constexpr std::size_t kMaxMetadataRecords = 1000;
constexpr std::size_t kMaxStringBytes = 4096;

struct PeDiagnostic {
    std::string code;
    std::string severity;
    std::string message;
};

struct PeSection {
    std::string name;
    std::uint32_t virtual_address = 0;
    std::uint32_t virtual_size = 0;
    std::uint32_t raw_offset = 0;
    std::uint32_t raw_size = 0;
    std::uint32_t characteristics = 0;
    std::uint64_t mapped_size = 0;
    std::uint64_t file_backed_size = 0;
    std::uint64_t zero_fill_size = 0;
    bool executable = false;
};

struct PeDataDirectory {
    std::size_t index = 0;
    std::string name;
    std::uint32_t rva = 0;
    std::uint32_t size = 0;
    bool file_offset_addressed = false;
    std::uint64_t file_offset = 0;
};

struct PeImport {
    std::string library;
    std::string name;
    std::uint64_t ordinal = 0;
    std::uint32_t iat_rva = 0;
    bool by_ordinal = false;
};

struct PeExport {
    std::string name;
    std::uint32_t ordinal = 0;
    std::uint32_t rva = 0;
    std::string forwarded_to;
};

struct PeRelocation {
    std::uint32_t rva = 0;
    std::uint8_t type = 0;
};

struct PeDebugEntry {
    std::uint32_t type = 0;
    std::uint32_t data_size = 0;
    std::uint32_t data_rva = 0;
    std::uint32_t data_file_offset = 0;
    std::string codeview_guid;
    std::uint32_t codeview_age = 0;
    std::string pdb_path;
};

struct PeTlsInfo {
    std::uint64_t raw_data_start_va = 0;
    std::uint64_t raw_data_end_va = 0;
    std::uint64_t index_va = 0;
    std::uint64_t callbacks_va = 0;
    std::uint32_t zero_fill_size = 0;
    std::uint32_t characteristics = 0;
    std::vector<std::uint64_t> callbacks;
};

struct PeRuntimeFunction {
    std::uint32_t begin_rva = 0;
    std::uint32_t end_rva = 0;
    std::uint32_t unwind_rva = 0;
    bool unwind_info_available = false;
    std::uint8_t unwind_version = 0;
    std::uint8_t unwind_flags = 0;
    std::uint8_t prolog_size = 0;
    std::uint8_t unwind_code_count = 0;
    std::uint8_t frame_register = 0;
    std::uint8_t frame_offset = 0;
};

struct PeClrInfo {
    bool present = false;
    std::uint32_t header_size = 0;
    std::uint32_t metadata_rva = 0;
    std::uint32_t metadata_size = 0;
    std::uint32_t flags = 0;
    std::uint32_t entry_point = 0;
    bool il_only = false;
};

struct PeMapping {
    bool mapped = false;
    bool virtual_zero_fill = false;
    std::uint64_t file_offset = 0;
    std::uint64_t available_file_bytes = 0;
    std::uint64_t available_virtual_bytes = 0;
    int section_index = -1;
};

struct PeImage {
    std::shared_ptr<const std::vector<std::uint8_t>> file_bytes;
    std::uint16_t machine = 0;
    std::uint16_t section_count = 0;
    std::uint16_t optional_header_magic = 0;
    std::uint16_t characteristics = 0;
    bool pe32_plus = false;
    bool is_dll = false;
    bool supported_x64_native = false;
    std::uint64_t image_base = 0;
    std::uint32_t entry_point_rva = 0;
    std::uint32_t section_alignment = 0;
    std::uint32_t file_alignment = 0;
    std::uint32_t size_of_image = 0;
    std::uint32_t size_of_headers = 0;
    std::uint32_t declared_directory_count = 0;
    std::vector<PeSection> sections;
    std::vector<PeDataDirectory> data_directories;
    std::vector<PeImport> imports;
    std::vector<PeExport> exports;
    std::vector<PeRelocation> relocations;
    std::vector<PeDebugEntry> debug_entries;
    bool has_tls = false;
    PeTlsInfo tls;
    std::vector<PeRuntimeFunction> runtime_functions;
    PeClrInfo clr;
    std::vector<PeDiagnostic> diagnostics;

    static bool parse(std::vector<std::uint8_t> bytes, PeImage& image,
                      std::string& error_code, std::string& error_message);

    PeMapping map_rva(std::uint32_t rva) const;
    bool rva_to_file_offset(std::uint32_t rva, std::uint64_t& offset) const;
    bool va_to_rva(std::uint64_t va, std::uint32_t& rva) const;
    bool read_rva(std::uint32_t rva, std::size_t size,
                  std::vector<std::uint8_t>& result) const;
    bool read_file(std::uint64_t offset, std::size_t size,
                   std::vector<std::uint8_t>& result) const;
    const PeDataDirectory* directory(std::size_t index) const;
};

std::string pe_directory_name(std::size_t index);

} // namespace nexusrev
