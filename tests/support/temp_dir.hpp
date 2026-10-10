#pragma once

// A unique directory under the system temp dir, removed with its contents on destruction.

#include <stdlib.h>

#include <filesystem>
#include <stdexcept>
#include <string>

namespace pq::test {

class TempDir {
 public:
  TempDir() {
    std::string tmpl = (std::filesystem::temp_directory_path() / "pqlab-test-XXXXXX").string();
    if (::mkdtemp(tmpl.data()) == nullptr) {
      throw std::runtime_error("mkdtemp failed");
    }
    path_ = tmpl;
  }
  ~TempDir() {
    std::error_code ec;
    std::filesystem::remove_all(path_, ec);
  }
  TempDir(const TempDir&) = delete;
  TempDir& operator=(const TempDir&) = delete;

  [[nodiscard]] const std::filesystem::path& path() const { return path_; }

 private:
  std::filesystem::path path_;
};

}  // namespace pq::test
