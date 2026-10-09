// NIST CAVP SHA3VS vectors (tests/kat/sha3).

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include "hash/sha3.hpp"
#include "hash/shake.hpp"
#include "support/kat_reader.hpp"

namespace {

using pq::test::from_hex;
using pq::test::read_rsp;
using pq::test::to_hex;

std::vector<uint8_t> message(const pq::test::KatRecord& r) {
  const size_t len_bits = std::stoul(r.fields.at("Len"));
  std::vector<uint8_t> msg = from_hex(r.fields.at("Msg"));
  msg.resize(len_bits / 8);  // Len = 0 is encoded as Msg = 00
  return msg;
}

template <typename Hash>
std::vector<uint8_t> digest(const std::vector<uint8_t>& msg) {
  std::vector<uint8_t> out(Hash::kDigestSize);
  Hash h;
  h.update(msg);
  h.finalize(std::span<uint8_t, Hash::kDigestSize>(out.data(), Hash::kDigestSize));
  return out;
}

template <typename Hash>
void run_msg_file(const std::string& file) {
  const auto records = read_rsp(file);
  ASSERT_FALSE(records.empty());
  for (const auto& r : records) {
    const auto msg = message(r);
    EXPECT_EQ(to_hex(digest<Hash>(msg)), r.fields.at("MD")) << file << " Len=" << msg.size() * 8;
  }
}

// SHA3VS, Section 6.2.3.
template <typename Hash>
void run_monte(const std::string& file) {
  const auto records = read_rsp(file);
  ASSERT_EQ(records.size(), 101U);
  std::vector<uint8_t> md = from_hex(records[0].fields.at("Seed"));
  for (size_t j = 0; j < 100; ++j) {
    for (int i = 1; i <= 1000; ++i) {
      md = digest<Hash>(md);
    }
    ASSERT_EQ(to_hex(md), records[j + 1].fields.at("MD")) << file << " COUNT=" << j;
  }
}

template <typename Xof>
std::vector<uint8_t> xof(const std::vector<uint8_t>& msg, size_t out_len) {
  std::vector<uint8_t> out(out_len);
  Xof x;
  x.absorb(msg);
  x.squeeze(out);
  return out;
}

template <typename Xof>
void run_xof_msg_file(const std::string& file) {
  const auto records = read_rsp(file);
  ASSERT_FALSE(records.empty());
  for (const auto& r : records) {
    const size_t out_bits = std::stoul(r.section.at("Outputlen"));
    const auto msg = message(r);
    EXPECT_EQ(to_hex(xof<Xof>(msg, out_bits / 8)), r.fields.at("Output"))
        << file << " Len=" << msg.size() * 8;
  }
}

template <typename Xof>
void run_xof_variable_out(const std::string& file) {
  const auto records = read_rsp(file);
  ASSERT_FALSE(records.empty());
  for (const auto& r : records) {
    const size_t out_bits = std::stoul(r.fields.at("Outputlen"));
    ASSERT_EQ(out_bits % 8, 0U);
    EXPECT_EQ(to_hex(xof<Xof>(from_hex(r.fields.at("Msg")), out_bits / 8)), r.fields.at("Output"))
        << file << " COUNT=" << r.fields.at("COUNT");
  }
}

// SHA3VS, Section 6.3.3.
template <typename Xof>
void run_xof_monte(const std::string& file) {
  const auto records = read_rsp(file);
  ASSERT_EQ(records.size(), 101U);
  const size_t min_bits = std::stoul(records[0].section.at("Minimum Output Length (bits)"));
  const size_t max_bits = std::stoul(records[0].section.at("Maximum Output Length (bits)"));
  const size_t min_bytes = (min_bits + 7) / 8;
  const size_t max_bytes = max_bits / 8;
  const size_t range = max_bytes - min_bytes + 1;

  std::vector<uint8_t> output = from_hex(records[0].fields.at("Msg"));
  size_t out_len = max_bytes;
  for (size_t j = 0; j < 100; ++j) {
    size_t recorded_len = 0;
    for (int i = 1; i <= 1000; ++i) {
      std::vector<uint8_t> msg(16, 0);
      std::copy_n(output.begin(), std::min<size_t>(16, output.size()), msg.begin());
      output = xof<Xof>(msg, out_len);
      if (i == 1000) {
        recorded_len = out_len;
      }
      const size_t rightmost =
          (static_cast<size_t>(output[out_len - 2]) << 8) | output[out_len - 1];
      out_len = min_bytes + rightmost % range;
    }
    const auto& expected = records[j + 1].fields;
    ASSERT_EQ(recorded_len * 8, std::stoul(expected.at("Outputlen"))) << file << " COUNT=" << j;
    ASSERT_EQ(to_hex(output), expected.at("Output")) << file << " COUNT=" << j;
  }
}

TEST(Sha3Kat, Sha3_256ShortMsg) { run_msg_file<pq::hash::Sha3_256>("sha3/SHA3_256ShortMsg.rsp"); }
TEST(Sha3Kat, Sha3_256LongMsg) { run_msg_file<pq::hash::Sha3_256>("sha3/SHA3_256LongMsg.rsp"); }
TEST(Sha3Kat, Sha3_256Monte) { run_monte<pq::hash::Sha3_256>("sha3/SHA3_256Monte.rsp"); }
TEST(Sha3Kat, Sha3_512ShortMsg) { run_msg_file<pq::hash::Sha3_512>("sha3/SHA3_512ShortMsg.rsp"); }
TEST(Sha3Kat, Sha3_512LongMsg) { run_msg_file<pq::hash::Sha3_512>("sha3/SHA3_512LongMsg.rsp"); }
TEST(Sha3Kat, Sha3_512Monte) { run_monte<pq::hash::Sha3_512>("sha3/SHA3_512Monte.rsp"); }

TEST(ShakeKat, Shake128ShortMsg) {
  run_xof_msg_file<pq::hash::Shake128>("sha3/SHAKE128ShortMsg.rsp");
}
TEST(ShakeKat, Shake128LongMsg) {
  run_xof_msg_file<pq::hash::Shake128>("sha3/SHAKE128LongMsg.rsp");
}
TEST(ShakeKat, Shake128VariableOut) {
  run_xof_variable_out<pq::hash::Shake128>("sha3/SHAKE128VariableOut.rsp");
}
TEST(ShakeKat, Shake128Monte) { run_xof_monte<pq::hash::Shake128>("sha3/SHAKE128Monte.rsp"); }
TEST(ShakeKat, Shake256ShortMsg) {
  run_xof_msg_file<pq::hash::Shake256>("sha3/SHAKE256ShortMsg.rsp");
}
TEST(ShakeKat, Shake256LongMsg) {
  run_xof_msg_file<pq::hash::Shake256>("sha3/SHAKE256LongMsg.rsp");
}
TEST(ShakeKat, Shake256VariableOut) {
  run_xof_variable_out<pq::hash::Shake256>("sha3/SHAKE256VariableOut.rsp");
}
TEST(ShakeKat, Shake256Monte) { run_xof_monte<pq::hash::Shake256>("sha3/SHAKE256Monte.rsp"); }

}  // namespace
