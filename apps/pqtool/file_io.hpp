#pragma once

#include <filesystem>

#include "pq/secure_bytes.hpp"

namespace pq::tool {

SecureBytes read_input(const std::filesystem::path& path);
void write_new_file(const std::filesystem::path& path, ByteView contents);

}  // namespace pq::tool
