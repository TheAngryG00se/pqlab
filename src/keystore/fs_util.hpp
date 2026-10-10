#pragma once

// POSIX file helpers for the keystore. Everything that holds key material is created
// with mode 0600 (files) or 0700 (directories). Errors throw pq::Error with the path
// and errno text, never with file contents.

#include <filesystem>
#include <string>
#include <string_view>

#include "pq/secure_bytes.hpp"

namespace pq::keystore::fs {

[[nodiscard]] std::string read_file(const std::filesystem::path& path);

// For files that hold a secret: the bytes never pass through a std::string. Throws
// pq::Error for files over 1 MiB.
[[nodiscard]] SecureBytes read_secret_file(const std::filesystem::path& path);

void fsync_file(const std::filesystem::path& path);

// Writes a temporary file next to path (mode 0600, fsync), then renames it over path.
// A reader sees either the old or the new content, never a mix.
void write_file_atomic(const std::filesystem::path& path, std::string_view content);

// O_APPEND write of one chunk, then fsync. Creates the file with mode 0600.
void append_file(const std::filesystem::path& path, std::string_view content);

// Creates the directory (and parents) with mode 0700 if it does not exist.
void make_private_dir(const std::filesystem::path& dir);

void fsync_dir(const std::filesystem::path& dir);

// Atomically swaps two directories on the same filesystem (renameat2 with
// RENAME_EXCHANGE). Throws pq::Error if the kernel or filesystem cannot do it.
void exchange_dirs(const std::filesystem::path& a, const std::filesystem::path& b);

// Exclusive advisory lock (flock) on a file, held for the lifetime of the object.
class FileLock {
 public:
  explicit FileLock(const std::filesystem::path& path);
  ~FileLock();
  FileLock(const FileLock&) = delete;
  FileLock& operator=(const FileLock&) = delete;

 private:
  int fd_ = -1;
};

}  // namespace pq::keystore::fs
