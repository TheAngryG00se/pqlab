#include "keystore/fs_util.hpp"

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <system_error>

#include "pq/error.hpp"

namespace pq::keystore::fs {

namespace {

[[noreturn]] void fail(const char* what, const std::filesystem::path& path) {
  throw Error(std::string(what) + " '" + path.string() + "': " + std::strerror(errno));
}

void write_all(int fd, std::string_view data, const std::filesystem::path& path) {
  size_t done = 0;
  while (done < data.size()) {
    const ssize_t n = ::write(fd, data.data() + done, data.size() - done);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      fail("cannot write", path);
    }
    done += static_cast<size_t>(n);
  }
}

// Closes on scope exit.
struct Fd {
  int fd;
  explicit Fd(int f) : fd(f) {}
  ~Fd() {
    if (fd >= 0) {
      ::close(fd);
    }
  }
  Fd(const Fd&) = delete;
  Fd& operator=(const Fd&) = delete;
};

}  // namespace

std::string read_file(const std::filesystem::path& path) {
  Fd f(::open(path.c_str(), O_RDONLY | O_CLOEXEC));
  if (f.fd < 0) {
    fail("cannot open", path);
  }
  std::string out;
  char buf[4096];
  for (;;) {
    const ssize_t n = ::read(f.fd, buf, sizeof buf);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      fail("cannot read", path);
    }
    if (n == 0) {
      break;
    }
    out.append(buf, static_cast<size_t>(n));
  }
  return out;
}

SecureBytes read_secret_file(const std::filesystem::path& path) {
  constexpr off_t kMaxSecretFile = 1 << 20;
  Fd f(::open(path.c_str(), O_RDONLY | O_CLOEXEC));
  if (f.fd < 0) {
    fail("cannot open", path);
  }
  struct stat st{};
  if (::fstat(f.fd, &st) != 0) {
    fail("cannot stat", path);
  }
  if (st.st_size > kMaxSecretFile) {
    throw Error("secret file too large '" + path.string() + "'");
  }
  SecureBytes out(static_cast<size_t>(st.st_size));
  size_t done = 0;
  while (done < out.size()) {
    const ssize_t n = ::read(f.fd, out.data() + done, out.size() - done);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      fail("cannot read", path);
    }
    if (n == 0) {
      throw Error("secret file shrank while reading '" + path.string() + "'");
    }
    done += static_cast<size_t>(n);
  }
  return out;
}

void fsync_file(const std::filesystem::path& path) {
  Fd f(::open(path.c_str(), O_RDONLY | O_CLOEXEC));
  if (f.fd < 0) {
    fail("cannot open", path);
  }
  if (::fsync(f.fd) != 0) {
    fail("cannot sync", path);
  }
}

void write_file_atomic(const std::filesystem::path& path, std::string_view content) {
  const std::filesystem::path tmp = path.string() + ".tmp";
  ::unlink(tmp.c_str());  // a leftover of a crashed run
  {
    Fd f(::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600));
    if (f.fd < 0) {
      fail("cannot create", tmp);
    }
    write_all(f.fd, content, tmp);
    if (::fsync(f.fd) != 0) {
      fail("cannot sync", tmp);
    }
  }
  if (::rename(tmp.c_str(), path.c_str()) != 0) {
    const int saved = errno;
    ::unlink(tmp.c_str());
    errno = saved;
    fail("cannot rename onto", path);
  }
  fsync_dir(path.parent_path());
}

void append_file(const std::filesystem::path& path, std::string_view content) {
  Fd f(::open(path.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600));
  if (f.fd < 0) {
    fail("cannot open", path);
  }
  write_all(f.fd, content, path);
  if (::fsync(f.fd) != 0) {
    fail("cannot sync", path);
  }
}

void make_private_dir(const std::filesystem::path& dir) {
  std::error_code ec;
  if (std::filesystem::is_directory(dir, ec)) {
    return;
  }
  const std::filesystem::path parent = dir.parent_path();
  if (!parent.empty() && !std::filesystem::exists(parent, ec)) {
    make_private_dir(parent);
  }
  if (::mkdir(dir.c_str(), 0700) != 0 && errno != EEXIST) {
    fail("cannot create directory", dir);
  }
}

void fsync_dir(const std::filesystem::path& dir) {
  Fd f(::open(dir.empty() ? "." : dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
  if (f.fd < 0) {
    fail("cannot open directory", dir);
  }
  if (::fsync(f.fd) != 0) {
    fail("cannot sync directory", dir);
  }
}

void exchange_dirs(const std::filesystem::path& a, const std::filesystem::path& b) {
  if (::renameat2(AT_FDCWD, a.c_str(), AT_FDCWD, b.c_str(), RENAME_EXCHANGE) != 0) {
    fail("cannot exchange directory with", b);
  }
}

FileLock::FileLock(const std::filesystem::path& path) {
  fd_ = ::open(path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
  if (fd_ < 0) {
    fail("cannot open lock file", path);
  }
  while (::flock(fd_, LOCK_EX) != 0) {
    if (errno != EINTR) {
      const int saved = errno;
      ::close(fd_);
      errno = saved;
      fail("cannot lock", path);
    }
  }
}

FileLock::~FileLock() {
  if (fd_ >= 0) {
    ::close(fd_);  // releases the flock
  }
}

}  // namespace pq::keystore::fs
