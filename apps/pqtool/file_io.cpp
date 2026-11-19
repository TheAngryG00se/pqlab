#include "file_io.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <string>

#include "keystore/fs_util.hpp"
#include "pq/error.hpp"

namespace pq::tool {
namespace {

[[noreturn]] void fail(const char* action, const std::filesystem::path& path) {
  const int error = errno;
  throw Error(std::string(action) + " '" + path.string() + "': " + std::strerror(error));
}

struct Fd {
  explicit Fd(int fd) : value(fd) {}
  ~Fd() {
    if (value >= 0) ::close(value);
  }
  Fd(const Fd&) = delete;
  Fd& operator=(const Fd&) = delete;
  int value;
};

constexpr size_t kIoChunk = 1U << 20;
}  // namespace

SecureBytes read_input(const std::filesystem::path& path) {
  Fd fd(::open(path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC));
  if (fd.value < 0) fail("cannot open input", path);
  struct stat stat {};
  if (::fstat(fd.value, &stat) != 0) fail("cannot inspect input", path);
  if (!S_ISREG(stat.st_mode) || stat.st_size < 0 ||
      static_cast<uintmax_t>(stat.st_size) > std::numeric_limits<size_t>::max()) {
    throw Error("input must be a regular file of representable size");
  }
  const size_t size = static_cast<size_t>(stat.st_size);
  SecureBytes data(size);
  size_t offset = 0;
  while (offset < size) {
    const ssize_t n = ::read(fd.value, data.data() + offset, std::min(kIoChunk, size - offset));
    if (n < 0 && errno == EINTR) continue;
    if (n < 0) fail("cannot read input", path);
    if (n == 0) throw Error("input shrank during read");
    offset += static_cast<size_t>(n);
  }
  struct stat after {};
  if (::fstat(fd.value, &after) != 0) fail("cannot inspect input", path);
  if (after.st_size != stat.st_size) throw Error("input size changed during read");
  return data;
}

void write_new_file(const std::filesystem::path& path, ByteView contents) {
  const auto directory = path.parent_path();
  std::string temporary = (directory / ".pqtool-XXXXXX").string();
  Fd fd(::mkostemp(temporary.data(), O_CLOEXEC));
  if (fd.value < 0) fail("cannot create temporary output", path);
  try {
    if (::fchmod(fd.value, 0600) != 0) fail("cannot set output permissions", path);
    size_t offset = 0;
    while (offset < contents.size()) {
      const ssize_t n =
          ::write(fd.value, contents.data() + offset, std::min(kIoChunk, contents.size() - offset));
      if (n < 0 && errno == EINTR) continue;
      if (n < 0) fail("cannot write output", path);
      if (n == 0) throw Error("cannot write output");
      offset += static_cast<size_t>(n);
    }
    if (::fsync(fd.value) != 0) fail("cannot sync output", path);
    const int status = ::close(fd.value);
    fd.value = -1;
    if (status != 0) fail("cannot close output", path);
    // Atomically publish a complete file only if the destination is still absent.
    if (::renameat2(AT_FDCWD, temporary.c_str(), AT_FDCWD, path.c_str(), RENAME_NOREPLACE) != 0) {
      fail("cannot publish new output", path);
    }
  } catch (...) {
    ::unlink(temporary.c_str());
    throw;
  }
  keystore::fs::fsync_dir(directory);
}

}  // namespace pq::tool
