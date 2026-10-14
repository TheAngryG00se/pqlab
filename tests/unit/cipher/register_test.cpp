#include "cipher/register.hpp"

#include <gtest/gtest.h>

TEST(CipherRegistry, AesVariantsAreIndependentAndUseFullRounds) {
  pq::Registry registry;
  pq::cipher::register_algorithms(registry);
  for (const uint32_t bits : {128U, 192U, 256U}) {
    const auto name = "AES-" + std::to_string(bits);
    const auto first = registry.cipher(name);
    const auto second = registry.cipher(name);
    EXPECT_EQ(first->name(), name);
    EXPECT_EQ(first->key_size(), bits / 8);
    EXPECT_EQ(first->rounds(), bits / 32 + 6);
    EXPECT_NE(first.get(), second.get());
  }
}
