#include "mode/ghash.hpp"

#include <gtest/gtest.h>

#include "pq/ct.hpp"
#include "pq/error.hpp"
#include "support/secret_fixture.hpp"

namespace {
TEST(Ghash, OfficialNistAes128ExamplesTwoAndThree) {
  // AES_GCM.pdf, AES-128 Examples 2 and 3: published H, C/A and S.
  const auto h = pq::test::secret_fixture("b83b533708bf535d0aa6e52980d53b78");
  const auto ct = pq::test::secret_fixture(
      "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
      "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985");
  const auto aad = pq::test::secret_fixture(
      "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf"
      "43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4");
  pq::SecureBytes out(16);
  pq::mode::detail::ghash_auth(h, {}, ct, out.span());
  EXPECT_TRUE(pq::ct_equal(out, pq::test::secret_fixture("7f1b32b81b820d02614f8895ac1d4eac")));
  pq::mode::detail::ghash_auth(h, aad, {}, out.span());
  EXPECT_TRUE(pq::ct_equal(out, pq::test::secret_fixture("6dd6cf3a1fa0371dd4c5c1ac1c3675f1")));
}

TEST(Ghash, MultiplicationIdentityZeroAndAliasingForEveryBasisVector) {
  pq::SecureBytes identity(16);
  identity[0] = 128;  // Polynomial 1 in the SP 800-38D bit convention.
  const pq::SecureBytes zero(16);
  for (uint32_t bit = 0; bit < 128; ++bit) {
    pq::SecureBytes basis(16);
    basis[bit / 8] = static_cast<uint8_t>(1U << (bit & 7U));
    pq::SecureBytes out(16);
    pq::mode::detail::ghash_multiply(basis, identity, out.span());
    EXPECT_TRUE(pq::ct_equal(out, basis));
    pq::mode::detail::ghash_multiply(identity, out, out.span());
    EXPECT_TRUE(pq::ct_equal(out, basis));
    pq::mode::detail::ghash_multiply(out, zero, out.span());
    EXPECT_TRUE(pq::ct_equal(out, zero));
  }
}

TEST(Ghash, RejectsInvalidPublicLengths) {
  pq::SecureBytes block(16);
  EXPECT_THROW(pq::mode::detail::ghash_multiply({}, block, block.span()), pq::Error);
  EXPECT_THROW(pq::mode::detail::ghash_multiply(block, {}, block.span()), pq::Error);
  EXPECT_THROW(pq::mode::detail::ghash_multiply(block, block, {}), pq::Error);
  EXPECT_THROW(pq::mode::detail::ghash_auth({}, {}, {}, block.span()), pq::Error);
}
}  // namespace
