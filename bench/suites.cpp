#include "bench/suites.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <limits>
#include <string_view>

#include "bench/measure.hpp"
#include "core/endian.hpp"
#include "hybrid/kem_dem.hpp"
#include "pq/error.hpp"
#include "pq/rng.hpp"

namespace pq::bench {
namespace {

bool selected(const RunOptions& options, std::string_view suite, const std::string& name) {
  return (options.suite == "all" || options.suite == suite) &&
         name.find(options.filter) != std::string::npos;
}

MeasureOptions bulk_options(const RunOptions& options, size_t bytes) {
  MeasureOptions out;
  out.min_iterations = 1;
  out.min_time = std::chrono::duration_cast<std::chrono::nanoseconds>(
      std::chrono::duration<double>(options.seconds));
  out.warmup = options.warmup;
  out.batch_size = bytes <= 4096 ? 64 : 1;
  return out;
}

void advance_nonce(Bytes& nonce, uint64_t& counter) {
  if (nonce.size() < 8 || counter == std::numeric_limits<uint64_t>::max()) {
    throw Error("benchmark: nonce too short or nonce counter exhausted");
  }
  store64_be(nonce.data() + nonce.size() - 8, ++counter);
}

}  // namespace

size_t run_benchmarks(const Registry& registry, const RunOptions& options,
                      const std::function<void(const Result&)>& consume) {
  size_t rows = 0;
  SystemRng rng;
  const auto emit = [&](std::string primitive, std::string param, std::string op, size_t bytes,
                        const Statistics& stats) {
    consume({std::move(primitive), std::move(param), std::move(op), bytes, stats});
    ++rows;
  };

  for (const auto& name : registry.list_kems()) {
    if (!selected(options, "kem", name)) {
      continue;
    }
    const auto kem = registry.kem(name);
    struct Input {
      SecureBytes seed;
      SecureBytes m;
      KeyPair kp;
      Encapsulation encaps;
    };
    std::array<Input, 32> inputs;
    for (auto& in : inputs) {
      in.seed = SecureBytes(kem->sizes().keygen_seed);
      in.m = SecureBytes(kem->sizes().encaps_seed);
      rng.fill(in.seed.span());
      rng.fill(in.m.span());
      in.kp = kem->keygen_derand(in.seed);
      in.encaps = kem->encaps_derand(in.kp.pk, in.m);
    }
    MeasureOptions timing;
    timing.min_iterations = options.kem_iterations;
    timing.warmup = options.warmup;
    size_t index = 0;
    emit("KEM", name, "keygen", 0,
         measure(
             [&] {
               const auto& in = inputs[index++ % inputs.size()];
               const auto out = kem->keygen_derand(in.seed);
               do_not_optimize(out);
             },
             timing));
    emit("KEM", name, "encaps", 0,
         measure(
             [&] {
               const auto& in = inputs[index++ % inputs.size()];
               const auto out = kem->encaps_derand(in.kp.pk, in.m);
               do_not_optimize(out);
             },
             timing));
    emit("KEM", name, "decaps", 0,
         measure(
             [&] {
               const auto& in = inputs[index++ % inputs.size()];
               const auto out = kem->decaps(in.kp.sk, in.encaps.ct);
               do_not_optimize(out);
             },
             timing));
  }

  for (const auto& name : registry.list_ciphers()) {
    if (selected(options, "cipher", name)) {
      const auto cipher = registry.cipher(name);
      SecureBytes key(cipher->key_size());
      rng.fill(key.span());
      const size_t block = cipher->block_size();
      if (block == 0) {
        throw Error("benchmark: cipher has zero block size");
      }
      emit("cipher", name, "set_key", 0,
           measure(
               [&] {
                 cipher->set_key(key);
                 do_not_optimize(*cipher);
               },
               bulk_options(options, 0)));
      for (size_t bytes : options.sizes) {
        if (bytes == 0 || bytes % block != 0) {
          throw Error("benchmark: cipher message size must be a positive multiple of block size");
        }
        SecureBytes input(bytes);
        SecureBytes output(bytes);
        Bytes encrypted(bytes);
        rng.fill(input.span());
        for (size_t off = 0; off < bytes; off += block) {
          cipher->encrypt_block(input.data() + off, encrypted.data() + off);
        }
        const auto timing = bulk_options(options, bytes);
        emit("cipher", name, "encrypt", bytes,
             measure(
                 [&] {
                   for (size_t off = 0; off < bytes; off += block) {
                     cipher->encrypt_block(input.data() + off, output.data() + off);
                   }
                   do_not_optimize(output);
                 },
                 timing));
        emit("cipher", name, "decrypt", bytes,
             measure(
                 [&] {
                   for (size_t off = 0; off < bytes; off += block) {
                     cipher->decrypt_block(encrypted.data() + off, output.data() + off);
                   }
                   do_not_optimize(output);
                 },
                 timing));
      }
    }

    for (const auto& mode : registry.list_modes()) {
      const std::string full_name = name + "-" + mode;
      if (selected(options, "aead", full_name)) {
        const auto aead = registry.aead(mode, name);
        SecureBytes key(aead->key_size());
        rng.fill(key.span());
        Bytes nonce(aead->nonce_size());
        rng.fill(nonce);
        uint64_t counter = 0;
        for (size_t bytes : options.sizes) {
          SecureBytes input(bytes);
          rng.fill(input.span());
          const auto timing = bulk_options(options, bytes);
          emit("AEAD", full_name, "seal", bytes,
               measure(
                   [&] {
                     advance_nonce(nonce, counter);
                     const auto out = aead->seal(key, nonce, {}, input);
                     do_not_optimize(out);
                   },
                   timing));
          advance_nonce(nonce, counter);
          const auto encrypted = aead->seal(key, nonce, {}, input);
          emit("AEAD", full_name, "open", bytes,
               measure(
                   [&] {
                     const auto out = aead->open(key, nonce, {}, encrypted);
                     if (!out) {
                       throw Error("benchmark: AEAD rejected its own ciphertext");
                     }
                     do_not_optimize(*out);
                   },
                   timing));
        }
      }

      if (mode != "GCM") {
        continue;
      }
      const hybrid::KemDem hybrid(registry);
      for (const auto& kem_name : registry.list_kems()) {
        const std::string combination = kem_name + "/" + full_name;
        if (!selected(options, "hybrid", combination)) {
          continue;
        }
        const auto kem = registry.kem(kem_name);
        const auto kp = kem->keygen(rng);
        for (size_t bytes : options.sizes) {
          SecureBytes input(bytes);
          rng.fill(input.span());
          const auto timing = bulk_options(options, bytes);
          emit("hybrid", combination, "seal", bytes,
               measure(
                   [&] {
                     const auto out = hybrid.seal(kem_name, kp.pk, name, input, rng);
                     do_not_optimize(out);
                   },
                   timing));
          const auto encrypted = hybrid.seal(kem_name, kp.pk, name, input, rng);
          emit("hybrid", combination, "open", bytes,
               measure(
                   [&] {
                     const auto out = hybrid.open(kp.sk, encrypted);
                     if (!out) {
                       throw Error("benchmark: KEM-DEM rejected its own ciphertext");
                     }
                     do_not_optimize(*out);
                   },
                   timing));
        }
      }
    }
  }
  return rows;
}

}  // namespace pq::bench
