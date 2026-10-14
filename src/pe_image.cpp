#include "pe_image.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <string_view>
#include <type_traits>
#include <utility>

namespace nexusrev {
namespace {
constexpr std::uint16_t kMachineAmd64 = 0x8664U;
constexpr std::uint16_t kPe32 = 0x010bU;
constexpr std::uint16_t kPe32Plus = 0x020bU;
constexpr std::uint32_t kImageScnMemExecute = 0x20000000U;
constexpr std::size_t kMaxThunkEntries = 65536;
constexpr std::size_t kMaxTlsCallbacks = 4096;
constexpr std::array<const char*, 16> kDirectoryNames = {
    "export", "import", "resource", "exception", "security", "base_relocation",
    "debug", "architecture", "global_pointer", "tls", "load_configuration",
    "bound_import", "iat", "delay_import", "clr", "reserved"};

bool range_fits(std::uint64_t offset, std::uint64_t length, std::uint64_t total) {
    return offset <= total && length <= total - offset;
}

template <typename T>
bool read_le(const std::vector<std::uint8_t>& bytes, std::uint64_t offset, T& value) {
    static_assert(std::is_integral<T>::value, "integer type required");
    if (!range_fits(offset, sizeof(T), bytes.size())) {
        return false;
    }
    using Unsigned = typename std::make_unsigned<T>::type;
    Unsigned result = 0;
    for (std::size_t index = 0; index < sizeof(T); ++index) {
        result |= static_cast<Unsigned>(bytes[static_cast<std::size_t>(offset) + index])
                  << (index * 8U);
    }
    value = static_cast<T>(result);
    return true;
}

void add_diagnostic(PeImage& image, std::string code, std::string severity,
                    std::string message) {
    image.diagnostics.push_back(
        {std::move(code), std::move(severity), std::move(message)});
}

bool read_rva_scalar(const PeImage& image, std::uint32_t rva, std::uint64_t& value) {
    const auto mapping = image.map_rva(rva);
    return mapping.mapped && mapping.available_file_bytes >= sizeof(value) &&
           read_le(*image.file_bytes, mapping.file_offset, value);
}

bool read_c_string_rva(const PeImage& image, std::uint32_t rva, std::string& value) {
    value.clear();
    for (std::size_t index = 0; index < kMaxStringBytes; ++index) {
        const std::uint64_t current = static_cast<std::uint64_t>(rva) + index;
        if (current > std::numeric_limits<std::uint32_t>::max()) {
            return false;
        }
        const auto mapping = image.map_rva(static_cast<std::uint32_t>(current));
        if (!mapping.mapped || mapping.available_file_bytes == 0U) {
            return false;
        }
        const auto byte = (*image.file_bytes)[static_cast<std::size_t>(mapping.file_offset)];
        if (byte == 0U) {
            return true;
        }
        value.push_back(static_cast<char>(byte));
    }
    return false;
}

bool directory_range_valid(const PeImage& image, const PeDataDirectory& directory) {
    if (directory.file_offset_addressed) {
        return range_fits(directory.file_offset, directory.size, image.file_bytes->size());
    }
    const auto mapping = image.map_rva(directory.rva);
    return mapping.mapped && mapping.available_file_bytes >= directory.size;
}

void parse_exports(PeImage& image) {
    const auto* dir = image.directory(0);
    if (dir == nullptr || dir->size == 0U) {
        return;
    }
    if (dir->size < 40U) {
        add_diagnostic(image, "EXPORT_DIRECTORY_TRUNCATED", "warning",
                       "export data directory is smaller than IMAGE_EXPORT_DIRECTORY");
        return;
    }
    std::vector<std::uint8_t> header;
    if (!image.read_rva(dir->rva, 40U, header)) {
        add_diagnostic(image, "EXPORT_DIRECTORY_UNREADABLE", "warning",
                       "export directory header is not file-backed");
        return;
    }
    std::uint32_t module_name_rva = 0;
    std::uint32_t ordinal_base = 0;
    std::uint32_t function_count = 0;
    std::uint32_t name_count = 0;
    std::uint32_t functions_rva = 0;
    std::uint32_t names_rva = 0;
    std::uint32_t ordinals_rva = 0;
    (void)read_le(header, 12U, module_name_rva);
    (void)read_le(header, 16U, ordinal_base);
    (void)read_le(header, 20U, function_count);
    (void)read_le(header, 24U, name_count);
    (void)read_le(header, 28U, functions_rva);
    (void)read_le(header, 32U, names_rva);
    (void)read_le(header, 36U, ordinals_rva);
    (void)module_name_rva;
    if (function_count > kMaxMetadataRecords || name_count > kMaxMetadataRecords ||
        name_count > function_count) {
        add_diagnostic(image, "EXPORT_COUNT_UNSUPPORTED", "warning",
                       "export table counts exceed safe limits or are inconsistent");
        return;
    }
    const std::uint64_t function_bytes = static_cast<std::uint64_t>(function_count) * 4U;
    const std::uint64_t name_bytes = static_cast<std::uint64_t>(name_count) * 4U;
    const std::uint64_t ordinal_bytes = static_cast<std::uint64_t>(name_count) * 2U;
    if (function_bytes > std::numeric_limits<std::size_t>::max() ||
        name_bytes > std::numeric_limits<std::size_t>::max() ||
        ordinal_bytes > std::numeric_limits<std::size_t>::max()) {
        add_diagnostic(image, "EXPORT_ARRAY_OVERFLOW", "warning",
                       "export array size cannot be represented safely");
        return;
    }
    std::vector<std::uint8_t> functions;
    std::vector<std::uint8_t> names;
    std::vector<std::uint8_t> ordinals;
    if ((function_count != 0U && !image.read_rva(functions_rva,
                                                  static_cast<std::size_t>(function_bytes),
                                                  functions)) ||
        (name_count != 0U && (!image.read_rva(names_rva, static_cast<std::size_t>(name_bytes), names) ||
                              !image.read_rva(ordinals_rva,
                                              static_cast<std::size_t>(ordinal_bytes), ordinals)))) {
        add_diagnostic(image, "EXPORT_ARRAY_UNREADABLE", "warning",
                       "one or more export arrays are not fully file-backed");
        return;
    }
    std::vector<std::string> names_by_index(function_count);
    for (std::uint32_t index = 0; index < name_count; ++index) {
        std::uint32_t name_rva = 0;
        std::uint16_t ordinal_index = 0;
        (void)read_le(names, static_cast<std::uint64_t>(index) * 4U, name_rva);
        (void)read_le(ordinals, static_cast<std::uint64_t>(index) * 2U, ordinal_index);
        if (ordinal_index >= function_count) {
            add_diagnostic(image, "EXPORT_ORDINAL_INVALID", "warning",
                           "export name ordinal index is outside the function array");
            continue;
        }
        if (!read_c_string_rva(image, name_rva, names_by_index[ordinal_index])) {
            add_diagnostic(image, "EXPORT_NAME_UNREADABLE", "warning",
                           "an export name could not be read as a bounded RVA string");
        }
    }
    for (std::uint32_t index = 0; index < function_count; ++index) {
        std::uint32_t function_rva = 0;
        (void)read_le(functions, static_cast<std::uint64_t>(index) * 4U, function_rva);
        if (function_rva == 0U) {
            continue;
        }
        PeExport entry;
        entry.name = names_by_index[index];
        const std::uint64_t ordinal = static_cast<std::uint64_t>(ordinal_base) + index;
        entry.ordinal = ordinal > std::numeric_limits<std::uint32_t>::max()
                            ? std::numeric_limits<std::uint32_t>::max()
                            : static_cast<std::uint32_t>(ordinal);
        entry.rva = function_rva;
        const std::uint64_t dir_end = static_cast<std::uint64_t>(dir->rva) + dir->size;
        if (function_rva >= dir->rva && function_rva < dir_end) {
            if (!read_c_string_rva(image, function_rva, entry.forwarded_to)) {
                add_diagnostic(image, "EXPORT_FORWARDER_UNREADABLE", "warning",
                               "an export forwarder string could not be read");
            }
        }
        image.exports.push_back(std::move(entry));
    }
}

void parse_imports(PeImage& image) {
    const auto* dir = image.directory(1);
    if (dir == nullptr || dir->size == 0U) {
        return;
    }
    if (!image.pe32_plus) {
        add_diagnostic(image, "IMPORTS_UNSUPPORTED_PE32", "warning",
                       "import thunk parsing is implemented for PE32+ only");
        return;
    }
    const std::size_t descriptors = dir->size / 20U;
    if (dir->size % 20U != 0U) {
        add_diagnostic(image, "IMPORT_DIRECTORY_TRAILING_BYTES", "warning",
                       "import directory size is not a multiple of descriptor size");
    }
    bool terminated = false;
    for (std::size_t index = 0; index < descriptors && index < kMaxMetadataRecords; ++index) {
        const std::uint64_t descriptor_rva64 = static_cast<std::uint64_t>(dir->rva) + index * 20U;
        if (descriptor_rva64 > std::numeric_limits<std::uint32_t>::max()) {
            break;
        }
        std::vector<std::uint8_t> descriptor;
        if (!image.read_rva(static_cast<std::uint32_t>(descriptor_rva64), 20U, descriptor)) {
            add_diagnostic(image, "IMPORT_DESCRIPTOR_UNREADABLE", "warning",
                           "an import descriptor is not fully file-backed");
            break;
        }
        std::uint32_t original_thunk = 0;
        std::uint32_t time_date_stamp = 0;
        std::uint32_t forwarder_chain = 0;
        std::uint32_t name_rva = 0;
        std::uint32_t first_thunk = 0;
        (void)read_le(descriptor, 0U, original_thunk);
        (void)read_le(descriptor, 4U, time_date_stamp);
        (void)read_le(descriptor, 8U, forwarder_chain);
        (void)read_le(descriptor, 12U, name_rva);
        (void)read_le(descriptor, 16U, first_thunk);
        if (original_thunk == 0U && time_date_stamp == 0U && forwarder_chain == 0U &&
            name_rva == 0U && first_thunk == 0U) {
            terminated = true;
            break;
        }
        std::string library;
        if (name_rva == 0U || !read_c_string_rva(image, name_rva, library)) {
            add_diagnostic(image, "IMPORT_LIBRARY_NAME_INVALID", "warning",
                           "an import descriptor has an invalid or unterminated library name");
            continue;
        }
        const std::uint32_t thunk_rva = original_thunk != 0U ? original_thunk : first_thunk;
        if (thunk_rva == 0U) {
            add_diagnostic(image, "IMPORT_THUNK_MISSING", "warning",
                           "an import descriptor has neither an original nor a first thunk");
            continue;
        }
        bool thunk_terminated = false;
        for (std::size_t thunk_index = 0; thunk_index < kMaxThunkEntries; ++thunk_index) {
            const std::uint64_t current_rva64 = static_cast<std::uint64_t>(thunk_rva) + thunk_index * 8U;
            const std::uint64_t iat_rva64 = static_cast<std::uint64_t>(first_thunk) + thunk_index * 8U;
            if (current_rva64 > std::numeric_limits<std::uint32_t>::max() ||
                iat_rva64 > std::numeric_limits<std::uint32_t>::max()) {
                break;
            }
            std::uint64_t thunk = 0;
            if (!read_rva_scalar(image, static_cast<std::uint32_t>(current_rva64), thunk)) {
                add_diagnostic(image, "IMPORT_THUNK_UNREADABLE", "warning",
                               "an import thunk entry is not fully file-backed");
                break;
            }
            if (thunk == 0U) {
                thunk_terminated = true;
                break;
            }
            PeImport imported;
            imported.library = library;
            imported.iat_rva = static_cast<std::uint32_t>(iat_rva64);
            if ((thunk & 0x8000000000000000ULL) != 0U) {
                imported.by_ordinal = true;
                imported.ordinal = thunk & 0xffffU;
            } else {
                if (thunk > std::numeric_limits<std::uint32_t>::max()) {
                    add_diagnostic(image, "IMPORT_NAME_RVA_INVALID", "warning",
                                   "an import name RVA exceeds the PE RVA address space");
                    continue;
                }
                std::vector<std::uint8_t> hint;
                const std::uint64_t name_entry_rva = thunk;
                if (name_entry_rva > std::numeric_limits<std::uint32_t>::max() - 2U ||
                    !image.read_rva(static_cast<std::uint32_t>(name_entry_rva), 2U, hint) ||
                    !read_c_string_rva(image, static_cast<std::uint32_t>(name_entry_rva + 2U), imported.name)) {
                    add_diagnostic(image, "IMPORT_NAME_UNREADABLE", "warning",
                                   "an import-by-name record is not fully file-backed");
                    continue;
                }
            }
            image.imports.push_back(std::move(imported));
            if (image.imports.size() >= kMaxMetadataRecords) {
                add_diagnostic(image, "IMPORT_COUNT_LIMIT", "warning",
                               "import enumeration stopped at the configured record limit");
                break;
            }
        }
        if (!thunk_terminated) {
            add_diagnostic(image, "IMPORT_THUNK_UNTERMINATED", "warning",
                           "an import thunk table did not terminate within the safe bound");
        }
    }
    if (!terminated) {
        add_diagnostic(image, "IMPORT_DIRECTORY_UNTERMINATED", "warning",
                       "import descriptor table has no null terminator within its declared size");
    }
}

void parse_relocations(PeImage& image) {
    const auto* dir = image.directory(5);
    if (dir == nullptr || dir->size == 0U) {
        return;
    }
    std::uint64_t consumed = 0;
    while (consumed < dir->size) {
        if (dir->size - consumed < 8U) {
            add_diagnostic(image, "RELOCATION_BLOCK_TRUNCATED", "warning",
                           "base-relocation directory ends with an incomplete block header");
            return;
        }
        const std::uint64_t block_rva64 = static_cast<std::uint64_t>(dir->rva) + consumed;
        if (block_rva64 > std::numeric_limits<std::uint32_t>::max()) {
            add_diagnostic(image, "RELOCATION_RVA_OVERFLOW", "warning",
                           "base-relocation block RVA exceeds the PE address space");
            return;
        }
        std::vector<std::uint8_t> block;
        if (!image.read_rva(static_cast<std::uint32_t>(block_rva64), 8U, block)) {
            add_diagnostic(image, "RELOCATION_BLOCK_UNREADABLE", "warning",
                           "base-relocation block header is not file-backed");
            return;
        }
        std::uint32_t page_rva = 0;
        std::uint32_t block_size = 0;
        (void)read_le(block, 0U, page_rva);
        (void)read_le(block, 4U, block_size);
        if (page_rva == 0U && block_size == 0U) {
            break;
        }
        if (block_size < 8U || (block_size & 1U) != 0U || block_size > dir->size - consumed) {
            add_diagnostic(image, "RELOCATION_BLOCK_INVALID", "warning",
                           "base-relocation block size is invalid or exceeds the declared directory");
            return;
        }
        const std::size_t entry_count = (block_size - 8U) / 2U;
        std::vector<std::uint8_t> entries;
        const std::uint64_t entries_rva64 = block_rva64 + 8U;
        if (entries_rva64 > std::numeric_limits<std::uint32_t>::max() ||
            !image.read_rva(static_cast<std::uint32_t>(entries_rva64), entry_count * 2U, entries)) {
            add_diagnostic(image, "RELOCATION_ENTRIES_UNREADABLE", "warning",
                           "base-relocation entries are not fully file-backed");
            return;
        }
        for (std::size_t index = 0; index < entry_count; ++index) {
            std::uint16_t raw_entry = 0;
            (void)read_le(entries, index * 2U, raw_entry);
            const std::uint8_t type = static_cast<std::uint8_t>(raw_entry >> 12U);
            const std::uint32_t delta = raw_entry & 0x0fffU;
            const std::uint64_t target_rva = static_cast<std::uint64_t>(page_rva) + delta;
            if (target_rva > std::numeric_limits<std::uint32_t>::max()) {
                add_diagnostic(image, "RELOCATION_TARGET_OVERFLOW", "warning",
                               "base-relocation target exceeds the PE RVA address space");
                continue;
            }
            image.relocations.push_back({static_cast<std::uint32_t>(target_rva), type});
            if (image.relocations.size() >= kMaxMetadataRecords) {
                add_diagnostic(image, "RELOCATION_COUNT_LIMIT", "warning",
                               "relocation enumeration stopped at the configured record limit");
                return;
            }
        }
        consumed += block_size;
    }
}

void parse_debug(PeImage& image) {
    const auto* dir = image.directory(6);
    if (dir == nullptr || dir->size == 0U) {
        return;
    }
    if (dir->size % 28U != 0U) {
        add_diagnostic(image, "DEBUG_DIRECTORY_TRAILING_BYTES", "warning",
                       "debug directory size is not a multiple of IMAGE_DEBUG_DIRECTORY");
    }
    const std::size_t count = dir->size / 28U;
    for (std::size_t index = 0; index < count && index < kMaxMetadataRecords; ++index) {
        const std::uint64_t entry_rva64 = static_cast<std::uint64_t>(dir->rva) + index * 28U;
        if (entry_rva64 > std::numeric_limits<std::uint32_t>::max()) {
            break;
        }
        std::vector<std::uint8_t> raw;
        if (!image.read_rva(static_cast<std::uint32_t>(entry_rva64), 28U, raw)) {
            add_diagnostic(image, "DEBUG_ENTRY_UNREADABLE", "warning",
                           "a debug-directory entry is not fully file-backed");
            break;
        }
        PeDebugEntry entry;
        std::uint32_t data_pointer = 0;
        (void)read_le(raw, 12U, entry.type);
        (void)read_le(raw, 16U, entry.data_size);
        (void)read_le(raw, 20U, entry.data_rva);
        (void)read_le(raw, 24U, data_pointer);
        entry.data_file_offset = data_pointer;
        std::uint64_t payload_offset = data_pointer;
        if (entry.data_size != 0U &&
            (data_pointer == 0U || !range_fits(payload_offset, entry.data_size, image.file_bytes->size())) &&
            entry.data_rva != 0U) {
            const auto mapping = image.map_rva(entry.data_rva);
            if (mapping.mapped && mapping.available_file_bytes >= entry.data_size) {
                payload_offset = mapping.file_offset;
                entry.data_file_offset = static_cast<std::uint32_t>(payload_offset);
            }
        }
        if (entry.data_size != 0U && range_fits(payload_offset, entry.data_size, image.file_bytes->size()) &&
            entry.type == 2U && entry.data_size >= 24U) {
            std::vector<std::uint8_t> payload;
            if (image.read_file(payload_offset, entry.data_size, payload) &&
                payload[0] == 'R' && payload[1] == 'S' && payload[2] == 'D' && payload[3] == 'S') {
                static constexpr char hex[] = "0123456789abcdef";
                for (std::size_t byte_index = 4U; byte_index < 20U; ++byte_index) {
                    const std::uint8_t byte = payload[byte_index];
                    entry.codeview_guid.push_back(hex[(byte >> 4U) & 0x0fU]);
                    entry.codeview_guid.push_back(hex[byte & 0x0fU]);
                }
                (void)read_le(payload, 20U, entry.codeview_age);
                const auto path_start = payload.begin() + 24;
                const auto path_end = std::find(path_start, payload.end(), 0U);
                entry.pdb_path.assign(path_start, path_end);
            } else if (!image.read_file(payload_offset, entry.data_size, payload)) {
                add_diagnostic(image, "DEBUG_PAYLOAD_UNREADABLE", "warning",
                               "a debug payload is not fully file-backed");
            }
        } else if (entry.data_size != 0U && entry.type == 2U) {
            add_diagnostic(image, "CODEVIEW_PAYLOAD_TRUNCATED", "warning",
                           "CodeView payload is too small to contain an RSDS identity");
        }
        image.debug_entries.push_back(std::move(entry));
    }
}

void parse_tls(PeImage& image) {
    const auto* dir = image.directory(9);
    if (dir == nullptr || dir->size == 0U) {
        return;
    }
    image.has_tls = true;
    if (!image.pe32_plus) {
        add_diagnostic(image, "TLS_UNSUPPORTED_PE32", "warning",
                       "TLS directory parsing is implemented for PE32+ only");
        return;
    }
    if (dir->size < 40U) {
        add_diagnostic(image, "TLS_DIRECTORY_TRUNCATED", "warning",
                       "TLS directory is smaller than IMAGE_TLS_DIRECTORY64");
        return;
    }
    std::vector<std::uint8_t> raw;
    if (!image.read_rva(dir->rva, 40U, raw)) {
        add_diagnostic(image, "TLS_DIRECTORY_UNREADABLE", "warning",
                       "TLS directory is not fully file-backed");
        return;
    }
    (void)read_le(raw, 0U, image.tls.raw_data_start_va);
    (void)read_le(raw, 8U, image.tls.raw_data_end_va);
    (void)read_le(raw, 16U, image.tls.index_va);
    (void)read_le(raw, 24U, image.tls.callbacks_va);
    (void)read_le(raw, 32U, image.tls.zero_fill_size);
    (void)read_le(raw, 36U, image.tls.characteristics);
    if (image.tls.callbacks_va == 0U) {
        return;
    }
    std::uint32_t callbacks_rva = 0;
    if (!image.va_to_rva(image.tls.callbacks_va, callbacks_rva)) {
        add_diagnostic(image, "TLS_CALLBACKS_ADDRESS_INVALID", "warning",
                       "TLS callback-array VA is outside the image address range");
        return;
    }
    bool terminated = false;
    for (std::size_t index = 0; index < kMaxTlsCallbacks; ++index) {
        const std::uint64_t slot_rva = static_cast<std::uint64_t>(callbacks_rva) + index * 8U;
        if (slot_rva > std::numeric_limits<std::uint32_t>::max()) {
            break;
        }
        std::uint64_t callback_va = 0;
        if (!read_rva_scalar(image, static_cast<std::uint32_t>(slot_rva), callback_va)) {
            add_diagnostic(image, "TLS_CALLBACK_UNREADABLE", "warning",
                           "TLS callback-array entry is not fully file-backed");
            break;
        }
        if (callback_va == 0U) {
            terminated = true;
            break;
        }
        image.tls.callbacks.push_back(callback_va);
    }
    if (!terminated) {
        add_diagnostic(image, "TLS_CALLBACKS_UNTERMINATED", "warning",
                       "TLS callback array did not terminate within the safe bound");
    }
}

void parse_exceptions(PeImage& image) {
    const auto* dir = image.directory(3);
    if (dir == nullptr || dir->size == 0U) {
        return;
    }
    if (!image.pe32_plus || image.machine != kMachineAmd64) {
        add_diagnostic(image, "EXCEPTION_DIRECTORY_UNSUPPORTED_PE32", "warning",
                       "x64 exception-directory parsing is unavailable for non-AMD64 images");
        return;
    }
    if (dir->size % 12U != 0U) {
        add_diagnostic(image, "EXCEPTION_DIRECTORY_TRAILING_BYTES", "warning",
                       "x64 exception directory size is not a multiple of RUNTIME_FUNCTION size");
    }
    const std::size_t count = dir->size / 12U;
    if (count > kMaxMetadataRecords) {
        add_diagnostic(image, "EXCEPTION_COUNT_LIMIT", "warning",
                       "runtime-function count exceeds the configured record limit");
        return;
    }
    for (std::size_t index = 0; index < count; ++index) {
        const std::uint64_t entry_rva64 = static_cast<std::uint64_t>(dir->rva) + index * 12U;
        if (entry_rva64 > std::numeric_limits<std::uint32_t>::max()) {
            break;
        }
        std::vector<std::uint8_t> raw;
        if (!image.read_rva(static_cast<std::uint32_t>(entry_rva64), 12U, raw)) {
            add_diagnostic(image, "EXCEPTION_ENTRY_UNREADABLE", "warning",
                           "a runtime-function entry is not fully file-backed");
            break;
        }
        PeRuntimeFunction function;
        (void)read_le(raw, 0U, function.begin_rva);
        (void)read_le(raw, 4U, function.end_rva);
        (void)read_le(raw, 8U, function.unwind_rva);
        if (function.begin_rva >= function.end_rva) {
            add_diagnostic(image, "EXCEPTION_RANGE_INVALID", "warning",
                           "a runtime-function record has an empty or reversed code range");
        }
        std::vector<std::uint8_t> unwind;
        if (image.read_rva(function.unwind_rva, 4U, unwind)) {
            const std::uint8_t version_flags = unwind[0];
            function.unwind_version = version_flags & 0x07U;
            function.unwind_flags = version_flags >> 3U;
            function.prolog_size = unwind[1];
            function.unwind_code_count = unwind[2];
            function.frame_register = unwind[3] & 0x0fU;
            function.frame_offset = unwind[3] >> 4U;
            const std::uint64_t codes_bytes = static_cast<std::uint64_t>(function.unwind_code_count) * 2U;
            const std::uint64_t total_unwind_size = 4U + ((codes_bytes + 3U) & ~std::uint64_t{3});
            const auto mapping = image.map_rva(function.unwind_rva);
            function.unwind_info_available = mapping.mapped &&
                                              mapping.available_file_bytes >= total_unwind_size;
            if (!function.unwind_info_available) {
                add_diagnostic(image, "UNWIND_INFO_TRUNCATED", "warning",
                               "UNWIND_INFO header is present but its code slots are truncated");
            }
        } else {
            add_diagnostic(image, "UNWIND_INFO_UNREADABLE", "warning",
                           "UNWIND_INFO header is not fully file-backed");
        }
        image.runtime_functions.push_back(function);
    }
}

void parse_clr(PeImage& image) {
    const auto* dir = image.directory(14);
    if (dir == nullptr || dir->size == 0U) {
        return;
    }
    image.clr.present = true;
    if (dir->size < 20U) {
        add_diagnostic(image, "CLR_HEADER_TRUNCATED", "warning",
                       "CLR directory is too small to contain a valid common-language-runtime header");
        return;
    }
    const std::size_t header_bytes = std::min<std::size_t>(dir->size, 72U);
    std::vector<std::uint8_t> raw;
    if (!image.read_rva(dir->rva, header_bytes, raw)) {
        add_diagnostic(image, "CLR_HEADER_UNREADABLE", "warning",
                       "CLR header is not fully file-backed");
        return;
    }
    (void)read_le(raw, 0U, image.clr.header_size);
    if (image.clr.header_size < 20U || image.clr.header_size > dir->size || image.clr.header_size > raw.size()) {
        add_diagnostic(image, "CLR_HEADER_SIZE_INVALID", "warning",
                       "CLR header declares a size outside its data-directory bounds");
        return;
    }
    if (image.clr.header_size >= 24U) {
        (void)read_le(raw, 8U, image.clr.metadata_rva);
        (void)read_le(raw, 12U, image.clr.metadata_size);
    }
    if (image.clr.header_size >= 24U) {
        (void)read_le(raw, 16U, image.clr.flags);
        (void)read_le(raw, 20U, image.clr.entry_point);
        image.clr.il_only = (image.clr.flags & 0x00000001U) != 0U;
    }
    if (image.clr.metadata_rva != 0U && image.clr.metadata_size != 0U) {
        const auto mapping = image.map_rva(image.clr.metadata_rva);
        if (!mapping.mapped || mapping.available_file_bytes < image.clr.metadata_size) {
            add_diagnostic(image, "CLR_METADATA_RANGE_INVALID", "warning",
                           "CLR metadata range is not fully file-backed");
        }
    }
}

bool validate_directories(PeImage& image, std::string& error_code, std::string& error_message) {
    for (const auto& directory : image.data_directories) {
        if (directory.rva == 0U && directory.size == 0U) {
            continue;
        }
        if (directory.rva == 0U || directory.size == 0U) {
            error_code = "PE_DIRECTORY_RANGE_INVALID";
            error_message = "data directory '" + directory.name + "' has only one of RVA/size set";
            return false;
        }
        if (!directory_range_valid(image, directory)) {
            error_code = "PE_DIRECTORY_RANGE_INVALID";
            error_message = "data directory '" + directory.name +
                             "' is not fully contained in file-backed image data";
            return false;
        }
    }
    return true;
}

bool parse_metadata(PeImage& image, std::string& error_code, std::string& error_message) {
    if (!validate_directories(image, error_code, error_message)) {
        return false;
    }
    parse_exports(image);
    parse_imports(image);
    parse_relocations(image);
    parse_debug(image);
    parse_tls(image);
    parse_exceptions(image);
    parse_clr(image);
    return true;
}

} // namespace

std::string pe_directory_name(std::size_t index) {
    if (index < kDirectoryNames.size()) {
        return kDirectoryNames[index];
    }
    return "directory_" + std::to_string(index);
}

PeMapping PeImage::map_rva(std::uint32_t rva) const {
    PeMapping result;
    if (!file_bytes) {
        return result;
    }
    if (rva < size_of_headers) {
        if (rva >= file_bytes->size()) {
            return result;
        }
        result.mapped = true;
        result.file_offset = rva;
        result.available_file_bytes = std::min<std::uint64_t>(
            static_cast<std::uint64_t>(size_of_headers) - rva,
            file_bytes->size() - rva);
        result.available_virtual_bytes = static_cast<std::uint64_t>(size_of_headers) - rva;
        return result;
    }
    int matched_section = -1;
    std::uint64_t delta = 0;
    for (std::size_t index = 0; index < sections.size(); ++index) {
        const auto& section = sections[index];
        const std::uint64_t begin = section.virtual_address;
        const std::uint64_t end = begin + section.mapped_size;
        if (rva >= begin && static_cast<std::uint64_t>(rva) < end) {
            if (matched_section >= 0) {
                return PeMapping{};
            }
            matched_section = static_cast<int>(index);
            delta = static_cast<std::uint64_t>(rva) - begin;
        }
    }
    if (matched_section < 0) {
        return result;
    }
    const auto& section = sections[static_cast<std::size_t>(matched_section)];
    result.section_index = matched_section;
    result.available_virtual_bytes = section.mapped_size - delta;
    if (delta >= section.raw_size) {
        result.virtual_zero_fill = true;
        return result;
    }
    const std::uint64_t file_offset = static_cast<std::uint64_t>(section.raw_offset) + delta;
    if (file_offset >= file_bytes->size()) {
        return PeMapping{};
    }
    result.mapped = true;
    result.file_offset = file_offset;
    result.available_file_bytes = std::min<std::uint64_t>(
        static_cast<std::uint64_t>(section.raw_size) - delta,
        file_bytes->size() - file_offset);
    return result;
}

bool PeImage::rva_to_file_offset(std::uint32_t rva, std::uint64_t& offset) const {
    const auto mapping = map_rva(rva);
    if (!mapping.mapped) {
        return false;
    }
    offset = mapping.file_offset;
    return true;
}

bool PeImage::va_to_rva(std::uint64_t va, std::uint32_t& rva) const {
    if (va < image_base) {
        return false;
    }
    const std::uint64_t difference = va - image_base;
    if (difference > std::numeric_limits<std::uint32_t>::max() || difference >= size_of_image) {
        return false;
    }
    rva = static_cast<std::uint32_t>(difference);
    return true;
}

bool PeImage::read_rva(std::uint32_t rva, std::size_t size,
                       std::vector<std::uint8_t>& result) const {
    result.clear();
    if (size == 0U) {
        return true;
    }
    const auto mapping = map_rva(rva);
    if (!mapping.mapped || mapping.available_file_bytes < size ||
        !range_fits(mapping.file_offset, size, file_bytes->size())) {
        return false;
    }
    const auto first = file_bytes->begin() + static_cast<std::ptrdiff_t>(mapping.file_offset);
    result.assign(first, first + static_cast<std::ptrdiff_t>(size));
    return true;
}

bool PeImage::read_file(std::uint64_t offset, std::size_t size,
                        std::vector<std::uint8_t>& result) const {
    result.clear();
    if (!file_bytes || !range_fits(offset, size, file_bytes->size())) {
        return false;
    }
    const auto first = file_bytes->begin() + static_cast<std::ptrdiff_t>(offset);
    result.assign(first, first + static_cast<std::ptrdiff_t>(size));
    return true;
}

const PeDataDirectory* PeImage::directory(std::size_t index) const {
    for (const auto& entry : data_directories) {
        if (entry.index == index) {
            return &entry;
        }
    }
    return nullptr;
}

bool PeImage::parse(std::vector<std::uint8_t> bytes, PeImage& image,
                    std::string& error_code, std::string& error_message) {
    image = PeImage{};
    error_code.clear();
    error_message.clear();
    if (bytes.size() > kMaxInputBytes) {
        error_code = "INPUT_SIZE_LIMIT";
        error_message = "input exceeds the configured 256 MiB static-analysis limit";
        return false;
    }
    image.file_bytes = std::make_shared<const std::vector<std::uint8_t>>(std::move(bytes));
    const auto& data = *image.file_bytes;
    auto fail = [&](const char* code, const std::string& message) {
        error_code = code;
        error_message = message;
        return false;
    };
    if (data.size() < 0x40U || data[0] != 'M' || data[1] != 'Z') {
        return fail("INPUT_PARSE_FAILED", "input does not contain a complete DOS header with MZ signature");
    }
    std::uint32_t pe_offset = 0;
    if (!read_le(data, 0x3cU, pe_offset) || !range_fits(pe_offset, 24U, data.size())) {
        return fail("PE_HEADER_TRUNCATED", "PE header offset is outside the file or truncated");
    }
    if (data[pe_offset] != 'P' || data[pe_offset + 1U] != 'E' ||
        data[pe_offset + 2U] != 0U || data[pe_offset + 3U] != 0U) {
        return fail("PE_SIGNATURE_INVALID", "PE signature is missing or malformed");
    }
    const std::uint64_t coff_offset = static_cast<std::uint64_t>(pe_offset) + 4U;
    std::uint16_t optional_header_size = 0;
    if (!read_le(data, coff_offset, image.machine) ||
        !read_le(data, coff_offset + 2U, image.section_count) ||
        !read_le(data, coff_offset + 16U, optional_header_size) ||
        !read_le(data, coff_offset + 18U, image.characteristics)) {
        return fail("COFF_HEADER_TRUNCATED", "COFF header is incomplete");
    }
    if (image.section_count == 0U || image.section_count > kMaxSections) {
        return fail("PE_SECTION_COUNT_INVALID", "PE section count must be between 1 and 96");
    }
    const std::uint64_t optional_offset = coff_offset + 20U;
    if (!range_fits(optional_offset, optional_header_size, data.size()) || optional_header_size < 96U) {
        return fail("OPTIONAL_HEADER_TRUNCATED", "optional header is truncated or smaller than its fixed fields");
    }
    if (!read_le(data, optional_offset, image.optional_header_magic)) {
        return fail("OPTIONAL_HEADER_TRUNCATED", "optional-header magic is missing");
    }
    std::uint64_t directory_count_offset = 0;
    std::uint64_t directories_offset = 0;
    if (image.optional_header_magic == kPe32Plus) {
        image.pe32_plus = true;
        if (optional_header_size < 112U ||
            !read_le(data, optional_offset + 24U, image.image_base) ||
            !read_le(data, optional_offset + 108U, image.declared_directory_count)) {
            return fail("OPTIONAL_HEADER_TRUNCATED", "PE32+ optional header is missing required fields");
        }
        directory_count_offset = optional_offset + 108U;
        directories_offset = optional_offset + 112U;
    } else if (image.optional_header_magic == kPe32) {
        image.pe32_plus = false;
        std::uint32_t image_base32 = 0;
        if (!read_le(data, optional_offset + 28U, image_base32) ||
            !read_le(data, optional_offset + 92U, image.declared_directory_count)) {
            return fail("OPTIONAL_HEADER_TRUNCATED", "PE32 optional header is missing required fields");
        }
        image.image_base = image_base32;
        directory_count_offset = optional_offset + 92U;
        directories_offset = optional_offset + 96U;
    } else {
        return fail("OPTIONAL_HEADER_MAGIC_UNSUPPORTED", "optional-header magic is not PE32 or PE32+");
    }
    (void)directory_count_offset;
    if (!read_le(data, optional_offset + 16U, image.entry_point_rva) ||
        !read_le(data, optional_offset + 32U, image.section_alignment) ||
        !read_le(data, optional_offset + 36U, image.file_alignment) ||
        !read_le(data, optional_offset + 56U, image.size_of_image) ||
        !read_le(data, optional_offset + 60U, image.size_of_headers)) {
        return fail("OPTIONAL_HEADER_TRUNCATED", "optional-header image layout fields are incomplete");
    }
    image.is_dll = (image.characteristics & 0x2000U) != 0U;
    if (image.image_base > std::numeric_limits<std::uint64_t>::max() - image.size_of_image) {
        return fail("PE_IMAGE_BASE_OVERFLOW", "image base plus SizeOfImage overflows the 64-bit virtual-address space");
    }
    if (image.entry_point_rva >= image.size_of_image && image.entry_point_rva != 0U) {
        add_diagnostic(image, "PE_ENTRY_POINT_OUTSIDE_IMAGE", "warning",
                       "entry-point RVA lies outside SizeOfImage");
    }
    image.supported_x64_native = image.machine == kMachineAmd64 && image.pe32_plus;
    const std::uint64_t available_directory_bytes =
        static_cast<std::uint64_t>(optional_header_size) - (directories_offset - optional_offset);
    const std::uint64_t available_directory_count = available_directory_bytes / 8U;
    if (image.declared_directory_count > available_directory_count ||
        image.declared_directory_count > kMaxDataDirectories) {
        return fail("PE_DIRECTORY_COUNT_INVALID",
                    "declared data-directory count exceeds the optional header or the safe limit of 32");
    }
    const std::uint64_t section_table_offset = optional_offset + optional_header_size;
    const std::uint64_t section_table_size = static_cast<std::uint64_t>(image.section_count) * 40U;
    if (!range_fits(section_table_offset, section_table_size, data.size())) {
        return fail("SECTION_TABLE_TRUNCATED", "section table is not fully contained in the input file");
    }
    const std::uint64_t section_table_end = section_table_offset + section_table_size;
    if (image.size_of_headers == 0U || image.size_of_headers < section_table_end ||
        image.size_of_headers > data.size() || image.size_of_image < image.size_of_headers) {
        return fail("PE_HEADER_RANGE_INVALID", "SizeOfHeaders or SizeOfImage does not cover the validated PE headers");
    }
    for (std::uint32_t index = 0; index < image.declared_directory_count; ++index) {
        const std::uint64_t entry_offset = directories_offset + static_cast<std::uint64_t>(index) * 8U;
        PeDataDirectory directory;
        directory.index = index;
        directory.name = pe_directory_name(index);
        if (!read_le(data, entry_offset, directory.rva) ||
            !read_le(data, entry_offset + 4U, directory.size)) {
            return fail("PE_DIRECTORY_TABLE_TRUNCATED", "data-directory entry is truncated");
        }
        if (index == 4U) {
            directory.file_offset_addressed = true;
            directory.file_offset = directory.rva;
        }
        image.data_directories.push_back(std::move(directory));
    }
    image.sections.reserve(image.section_count);
    for (std::uint16_t index = 0; index < image.section_count; ++index) {
        const std::uint64_t section_offset = section_table_offset + static_cast<std::uint64_t>(index) * 40U;
        PeSection section;
        if (!read_le(data, section_offset + 8U, section.virtual_size) ||
            !read_le(data, section_offset + 12U, section.virtual_address) ||
            !read_le(data, section_offset + 16U, section.raw_size) ||
            !read_le(data, section_offset + 20U, section.raw_offset) ||
            !read_le(data, section_offset + 36U, section.characteristics)) {
            return fail("SECTION_HEADER_TRUNCATED", "section header is incomplete");
        }
        const std::size_t name_offset = static_cast<std::size_t>(section_offset);
        for (std::size_t name_index = 0; name_index < 8U && data[name_offset + name_index] != 0U; ++name_index) {
            section.name.push_back(static_cast<char>(data[name_offset + name_index]));
        }
        if (section.name.empty()) {
            section.name = "<unnamed-" + std::to_string(index) + ">";
        }
        section.mapped_size = section.virtual_size == 0U ? section.raw_size : section.virtual_size;
        section.executable = (section.characteristics & kImageScnMemExecute) != 0U;
        section.file_backed_size = std::min<std::uint64_t>(section.raw_size,
            section.virtual_size == 0U ? section.raw_size : section.virtual_size);
        section.zero_fill_size = section.virtual_size > section.raw_size
                                     ? static_cast<std::uint64_t>(section.virtual_size) - section.raw_size
                                     : 0U;
        const std::uint64_t virtual_end = static_cast<std::uint64_t>(section.virtual_address) + section.mapped_size;
        if (section.mapped_size != 0U && section.virtual_address < image.size_of_headers) {
            return fail("SECTION_VIRTUAL_RANGE_INVALID", "section '" + section.name +
                        "' virtual range overlaps the PE headers");
        }
        if (section.mapped_size != 0U &&
            (virtual_end > std::numeric_limits<std::uint32_t>::max() + 1ULL ||
             virtual_end > image.size_of_image)) {
            return fail("SECTION_VIRTUAL_RANGE_INVALID", "section '" + section.name +
                        "' exceeds SizeOfImage or the PE RVA address space");
        }
        if (section.raw_size != 0U &&
            (!range_fits(section.raw_offset, section.raw_size, data.size()) ||
             section.raw_offset < image.size_of_headers)) {
            return fail("SECTION_RAW_RANGE_INVALID", "section '" + section.name +
                        "' raw data is outside the file or overlaps PE headers");
        }
        image.sections.push_back(std::move(section));
    }
    for (std::size_t left = 0; left < image.sections.size(); ++left) {
        const auto& a = image.sections[left];
        const std::uint64_t a_virtual_end = static_cast<std::uint64_t>(a.virtual_address) + a.mapped_size;
        const std::uint64_t a_raw_end = static_cast<std::uint64_t>(a.raw_offset) + a.raw_size;
        for (std::size_t right = left + 1U; right < image.sections.size(); ++right) {
            const auto& b = image.sections[right];
            const std::uint64_t b_virtual_end = static_cast<std::uint64_t>(b.virtual_address) + b.mapped_size;
            const std::uint64_t b_raw_end = static_cast<std::uint64_t>(b.raw_offset) + b.raw_size;
            if (a.mapped_size != 0U && b.mapped_size != 0U &&
                a.virtual_address < b_virtual_end && b.virtual_address < a_virtual_end) {
                return fail("SECTION_VIRTUAL_OVERLAP", "sections have overlapping virtual-address ranges");
            }
            if (a.raw_size != 0U && b.raw_size != 0U &&
                a.raw_offset < b_raw_end && b.raw_offset < a_raw_end) {
                return fail("SECTION_RAW_OVERLAP", "sections have overlapping file-offset ranges");
            }
        }
    }
    if (!validate_directories(image, error_code, error_message)) {
        return false;
    }
    if (image.machine != kMachineAmd64 || !image.pe32_plus) {
        add_diagnostic(image, "ARCHITECTURE_UNSUPPORTED", "warning",
                       "only native PE32+ x86-64 images are analyzed; this image is parsed for identification only");
    }
    if (image.entry_point_rva != 0U) {
        const auto entry_mapping = image.map_rva(image.entry_point_rva);
        const bool executable = entry_mapping.section_index >= 0 &&
            image.sections[static_cast<std::size_t>(entry_mapping.section_index)].executable;
        if (!entry_mapping.mapped || !executable) {
            add_diagnostic(image, "ENTRY_POINT_UNMAPPED", "warning",
                           "entry point is not in file-backed executable section data");
        }
    }
    if (!parse_metadata(image, error_code, error_message)) {
        return false;
    }
    return true;
}

} // namespace nexusrev
