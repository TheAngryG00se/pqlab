#include "keystore/fs_util.hpp"

#include <gtest/gtest.h>
#include <sys/stat.h>

#include <atomic>
#include <chrono>
#include <optional>
#include <thread>

#include "pq/error.hpp"
#include "support/temp_dir.hpp"

namespace {

namespace fs = pq::keystore::fs;

mode_t mode_of(const std::filesystem::path& p) {
  struct stat st{};
  EXPECT_EQ(::stat(p.c_str(), &st), 0);
  return st.st_mode & 0777;
}

TEST(FsUtil, AtomicWriteCreatesPrivateFileAndReplaces) {
  pq::test::TempDir d;
  const auto f = d.path() / "a.json";
  fs::write_file_atomic(f, "one");
  EXPECT_EQ(fs::read_file(f), "one");
  EXPECT_EQ(mode_of(f), 0600U);
  fs::write_file_atomic(f, "two, longer");
  EXPECT_EQ(fs::read_file(f), "two, longer");
  EXPECT_EQ(mode_of(f), 0600U);
  // No temporary files are left behind.
  size_t n = 0;
  for (const auto& e : std::filesystem::directory_iterator(d.path())) {
    (void)e;
    ++n;
  }
  EXPECT_EQ(n, 1U);
}

TEST(FsUtil, AtomicWriteSurvivesLeftoverTempFile) {
  pq::test::TempDir d;
  const auto f = d.path() / "a.json";
  fs::write_file_atomic(d.path() / "a.json.tmp", "stale");
  fs::write_file_atomic(f, "fresh");
  EXPECT_EQ(fs::read_file(f), "fresh");
}

TEST(FsUtil, AppendCreatesPrivateFileAndAppends) {
  pq::test::TempDir d;
  const auto f = d.path() / "log";
  fs::append_file(f, "a\n");
  fs::append_file(f, "b\n");
  EXPECT_EQ(fs::read_file(f), "a\nb\n");
  EXPECT_EQ(mode_of(f), 0600U);
}

TEST(FsUtil, MakePrivateDirCreatesParentsWith0700) {
  pq::test::TempDir d;
  const auto sub = d.path() / "x" / "y";
  fs::make_private_dir(sub);
  EXPECT_EQ(mode_of(sub), 0700U);
  EXPECT_EQ(mode_of(sub.parent_path()), 0700U);
  EXPECT_NO_THROW(fs::make_private_dir(sub));  // already there
}

TEST(FsUtil, ReadMissingFileThrowsWithoutContents) {
  pq::test::TempDir d;
  EXPECT_THROW((void)fs::read_file(d.path() / "nope"), pq::Error);
}

TEST(FsUtil, ExchangeDirsSwapsContents) {
  pq::test::TempDir d;
  const auto a = d.path() / "a";
  const auto b = d.path() / "b";
  fs::make_private_dir(a);
  fs::make_private_dir(b);
  fs::write_file_atomic(a / "f", "in a");
  fs::write_file_atomic(b / "f", "in b");
  fs::exchange_dirs(a, b);
  EXPECT_EQ(fs::read_file(a / "f"), "in b");
  EXPECT_EQ(fs::read_file(b / "f"), "in a");
  EXPECT_THROW(fs::exchange_dirs(a, d.path() / "missing"), pq::Error);
}

TEST(FsUtil, FileLockExcludesAnotherHolder) {
  pq::test::TempDir d;
  const auto lock = d.path() / "lock";
  std::atomic<int> phase{0};
  std::optional<fs::FileLock> first;
  first.emplace(lock);
  std::thread t([&] {
    fs::FileLock second(lock);  // blocks until `first` is released
    phase = 2;
  });
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  EXPECT_EQ(phase.load(), 0);
  first.reset();
  t.join();
  EXPECT_EQ(phase.load(), 2);
}

}  // namespace
