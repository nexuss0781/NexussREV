#pragma once

#include <string>
#include <string_view>

namespace nexusrev {

std::string sha256(std::string_view input);
bool sha256_file(const std::string& path, std::string& digest, std::string& error);

} // namespace nexusrev
