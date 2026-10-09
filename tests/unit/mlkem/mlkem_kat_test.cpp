// NIST ACVP vectors for FIPS 203 (tests/kat/mlkem).

#include <gtest/gtest.h>

#include <fstream>
#include <functional>
#include <memory>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

#include "kem/mlkem/mlkem.hpp"
#include "pq/error.hpp"
#include "support/kat_reader.hpp"

namespace {

using pq::test::from_hex;
using Json = nlohmann::json;

struct ParamSet {
  std::unique_ptr<pq::Kem> kem;
  std::function<bool(pq::ByteView)> check_ek;
  std::function<bool(pq::ByteView)> check_dk;
};

ParamSet param_set(const std::string& name) {
  if (name == "ML-KEM-512") {
    return {std::make_unique<pq::mlkem::MlKem512>(), pq::mlkem::MlKem512::check_encaps_key,
            pq::mlkem::MlKem512::check_decaps_key};
  }
  if (name == "ML-KEM-768") {
    return {std::make_unique<pq::mlkem::MlKem768>(), pq::mlkem::MlKem768::check_encaps_key,
            pq::mlkem::MlKem768::check_decaps_key};
  }
  if (name == "ML-KEM-1024") {
    return {std::make_unique<pq::mlkem::MlKem1024>(), pq::mlkem::MlKem1024::check_encaps_key,
            pq::mlkem::MlKem1024::check_decaps_key};
  }
  throw std::runtime_error("unknown parameter set " + name);
}

Json load(const std::string& file) {
  std::ifstream in(pq::test::kat_path(file));
  if (!in) {
    throw std::runtime_error("cannot open " + file);
  }
  return Json::parse(in);
}

std::vector<uint8_t> hex(const Json& v) { return from_hex(v.get<std::string>()); }

std::vector<uint8_t> bytes(pq::ByteView v) { return {v.begin(), v.end()}; }

TEST(MlKemKat, KeyGen) {
  const Json doc = load("mlkem/keyGen-internalProjection.json");
  size_t count = 0;
  for (const auto& group : doc.at("testGroups")) {
    const auto ps = param_set(group.at("parameterSet"));
    for (const auto& tc : group.at("tests")) {
      std::vector<uint8_t> seed = hex(tc.at("d"));
      const auto z = hex(tc.at("z"));
      seed.insert(seed.end(), z.begin(), z.end());
      const pq::KeyPair kp = ps.kem->keygen_derand(seed);
      EXPECT_EQ(kp.pk, hex(tc.at("ek"))) << "tcId " << tc.at("tcId");
      EXPECT_EQ(bytes(kp.sk), hex(tc.at("dk"))) << "tcId " << tc.at("tcId");
      ++count;
    }
  }
  EXPECT_EQ(count, 75U);
}

TEST(MlKemKat, EncapDecap) {
  const Json doc = load("mlkem/encapDecap-internalProjection.json");
  size_t encaps = 0;
  size_t decaps = 0;
  size_t ek_checks = 0;
  size_t dk_checks = 0;
  for (const auto& group : doc.at("testGroups")) {
    const auto ps = param_set(group.at("parameterSet"));
    const std::string function = group.at("function");
    for (const auto& tc : group.at("tests")) {
      const auto id = tc.at("tcId").get<int>();
      if (function == "encapsulation") {
        const pq::Encapsulation e = ps.kem->encaps_derand(hex(tc.at("ek")), hex(tc.at("m")));
        EXPECT_EQ(e.ct, hex(tc.at("c"))) << "tcId " << id;
        EXPECT_EQ(bytes(e.ss), hex(tc.at("k"))) << "tcId " << id;
        ++encaps;
      } else if (function == "decapsulation") {
        const pq::SecureBytes k = ps.kem->decaps(hex(tc.at("dk")), hex(tc.at("c")));
        EXPECT_EQ(bytes(k), hex(tc.at("k"))) << "tcId " << id << " (" << tc.at("reason") << ")";
        ++decaps;
      } else if (function == "encapsulationKeyCheck") {
        const auto ek = hex(tc.at("ek"));
        const bool expected = tc.at("testPassed").get<bool>();
        EXPECT_EQ(ps.check_ek(ek), expected) << "tcId " << id << " (" << tc.at("reason") << ")";
        if (!expected) {
          std::vector<uint8_t> m(32, 0);
          EXPECT_THROW((void)ps.kem->encaps_derand(ek, m), pq::Error) << "tcId " << id;
        }
        ++ek_checks;
      } else if (function == "decapsulationKeyCheck") {
        const auto dk = hex(tc.at("dk"));
        const bool expected = tc.at("testPassed").get<bool>();
        EXPECT_EQ(ps.check_dk(dk), expected) << "tcId " << id << " (" << tc.at("reason") << ")";
        if (!expected) {
          std::vector<uint8_t> c(ps.kem->sizes().ct, 0);
          EXPECT_THROW((void)ps.kem->decaps(dk, c), pq::Error) << "tcId " << id;
        }
        ++dk_checks;
      } else {
        ADD_FAILURE() << "unknown function " << function;
      }
    }
  }
  EXPECT_EQ(encaps, 75U);
  EXPECT_EQ(decaps, 30U);
  EXPECT_EQ(ek_checks, 30U);
  EXPECT_EQ(dk_checks, 30U);
}

}  // namespace
