#include <gtest/gtest.h>

#include <fstream>
#include <sstream>

#include "keystore/audit_log.hpp"
#include "keystore/fs_util.hpp"
#include "pq/error.hpp"
#include "support/temp_dir.hpp"

namespace {

using namespace pq::keystore;

class AuditTest : public ::testing::Test {
 protected:
  AuditTest() : file_(dir_.path() / "audit.log"), key_(32, 0x11) {}

  void fill(AuditLog& log, int n) {
    for (int i = 0; i < n; ++i) {
      log.append(1000 + i, "event" + std::to_string(i), "abcd", "detail " + std::to_string(i));
    }
  }

  std::vector<std::string> lines() {
    std::istringstream in(pq::keystore::fs::read_file(file_));
    std::vector<std::string> out;
    for (std::string l; std::getline(in, l);) {
      out.push_back(l);
    }
    return out;
  }

  void write_lines(const std::vector<std::string>& ls) {
    std::string text;
    for (const auto& l : ls) {
      text += l + "\n";
    }
    pq::keystore::fs::write_file_atomic(file_, text);
  }

  pq::test::TempDir dir_;
  std::filesystem::path file_;
  pq::Bytes key_;
};

TEST_F(AuditTest, EmptyOrMissingLogVerifies) {
  AuditLog log(file_, key_);
  EXPECT_TRUE(log.verify().ok);
  EXPECT_TRUE(log.read().empty());
}

TEST_F(AuditTest, AppendReadAndVerify) {
  AuditLog log(file_, key_);
  fill(log, 5);
  const auto entries = log.read();
  ASSERT_EQ(entries.size(), 5U);
  for (size_t i = 0; i < entries.size(); ++i) {
    EXPECT_EQ(entries[i].seq, i);
    EXPECT_EQ(entries[i].time, 1000 + static_cast<int64_t>(i));
    EXPECT_EQ(entries[i].event, "event" + std::to_string(i));
    EXPECT_EQ(entries[i].key_id, "abcd");
  }
  const AuditVerdict v = log.verify();
  EXPECT_TRUE(v.ok);
  EXPECT_EQ(v.entries, 5U);
}

TEST_F(AuditTest, ChainContinuesAcrossInstances) {
  {
    AuditLog log(file_, key_);
    fill(log, 2);
  }
  AuditLog again(file_, key_);
  again.append(2000, "later", "", "x");
  EXPECT_TRUE(again.verify().ok);
  EXPECT_EQ(again.read().back().seq, 2U);
}

TEST_F(AuditTest, FileIsPrivate) {
  AuditLog log(file_, key_);
  fill(log, 1);
  EXPECT_EQ(std::filesystem::status(file_).permissions() & std::filesystem::perms::others_all,
            std::filesystem::perms::none);
  EXPECT_EQ(std::filesystem::status(file_).permissions() & std::filesystem::perms::group_all,
            std::filesystem::perms::none);
}

TEST_F(AuditTest, EditedLineIsDetected) {
  AuditLog log(file_, key_);
  fill(log, 4);
  auto ls = lines();
  const auto pos = ls[1].find("detail 1");
  ASSERT_NE(pos, std::string::npos);
  ls[1].replace(pos, 8, "detail X");
  write_lines(ls);
  const AuditVerdict v = log.verify();
  EXPECT_FALSE(v.ok);
  EXPECT_EQ(v.bad_line, 2U);
  EXPECT_EQ(v.entries, 1U);
}

TEST_F(AuditTest, DeletedLineIsDetected) {
  AuditLog log(file_, key_);
  fill(log, 4);
  auto ls = lines();
  ls.erase(ls.begin() + 1);
  write_lines(ls);
  const AuditVerdict v = log.verify();
  EXPECT_FALSE(v.ok);
  EXPECT_EQ(v.bad_line, 2U);
}

TEST_F(AuditTest, SwappedLinesAreDetected) {
  AuditLog log(file_, key_);
  fill(log, 4);
  auto ls = lines();
  std::swap(ls[1], ls[2]);
  write_lines(ls);
  EXPECT_FALSE(log.verify().ok);
}

TEST_F(AuditTest, InsertedCopyIsDetected) {
  AuditLog log(file_, key_);
  fill(log, 3);
  auto ls = lines();
  ls.insert(ls.begin() + 2, ls[1]);
  write_lines(ls);
  EXPECT_FALSE(log.verify().ok);
}

TEST_F(AuditTest, LineSplicedInFromAnotherHistoryIsDetected) {
  // Every line carries a valid MAC of its own. Only the chain ties a line to its predecessors
  // and successors, so a valid line with the right seq from a different history must be caught.
  AuditLog log(file_, key_);
  fill(log, 4);
  const auto history_a = lines();

  write_lines({history_a[0], history_a[1]});
  log.append(5000, "forged", "abcd", "another history");  // seq 2 again, valid in history B
  const auto history_b = lines();
  ASSERT_EQ(history_b.size(), 3U);
  ASSERT_NE(history_b[2], history_a[2]);

  auto spliced = history_a;
  spliced[2] = history_b[2];
  write_lines(spliced);
  const AuditVerdict v = log.verify();
  EXPECT_FALSE(v.ok);
  EXPECT_EQ(v.bad_line, 4U);  // the line after the splice no longer fits

  // Each history alone is fine.
  write_lines(history_a);
  EXPECT_TRUE(log.verify().ok);
  write_lines(history_b);
  EXPECT_TRUE(log.verify().ok);
}

TEST_F(AuditTest, GarbageLineIsDetected) {
  AuditLog log(file_, key_);
  fill(log, 2);
  auto ls = lines();
  ls.push_back("not json");
  write_lines(ls);
  const AuditVerdict v = log.verify();
  EXPECT_FALSE(v.ok);
  EXPECT_EQ(v.bad_line, 3U);
  EXPECT_THROW((void)log.read(), pq::Error);
  EXPECT_THROW(log.append(1, "e", "", ""), pq::Error);
}

TEST_F(AuditTest, WrongKeyFailsFromTheFirstLine) {
  AuditLog log(file_, key_);
  fill(log, 2);
  AuditLog other(file_, pq::Bytes(32, 0x22));
  const AuditVerdict v = other.verify();
  EXPECT_FALSE(v.ok);
  EXPECT_EQ(v.bad_line, 1U);
}

TEST_F(AuditTest, TruncatingTheTailIsNotDetected) {
  // Documented limitation: nothing after the last line refers to it.
  AuditLog log(file_, key_);
  fill(log, 4);
  auto ls = lines();
  ls.pop_back();
  write_lines(ls);
  EXPECT_TRUE(log.verify().ok);
  EXPECT_EQ(log.read().size(), 3U);
}

TEST_F(AuditTest, RejectsWrongKeyLength) {
  EXPECT_THROW(AuditLog(file_, pq::Bytes(16)), pq::Error);
}

}  // namespace
