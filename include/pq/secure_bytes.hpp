#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <utility>
#include <vector>

namespace pq {

// Public (non-secret) byte strings: public keys, ciphertexts, metadata.
using Bytes = std::vector<uint8_t>;
using ByteView = std::span<const uint8_t>;
using MutByteView = std::span<uint8_t>;

// Overwrites memory with zeros in a way the optimizer may not elide.
inline void secure_zero(void* ptr, size_t len) noexcept {
  volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
  for (size_t i = 0; i < len; ++i) {
    p[i] = 0;
  }
#if defined(__GNUC__) || defined(__clang__)
  __asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif
}

inline void secure_zero(MutByteView buf) noexcept { secure_zero(buf.data(), buf.size()); }

// Owning buffer for secrets. Zeroed on destruction and when moved from.
// Move-only: copies of secrets must be explicit (clone()).
class SecureBytes {
 public:
  SecureBytes() = default;

  explicit SecureBytes(size_t size)
      : data_(size == 0 ? nullptr : std::make_unique<uint8_t[]>(size)), size_(size) {}

  explicit SecureBytes(ByteView src) : SecureBytes(src.size()) {
    for (size_t i = 0; i < size_; ++i) {
      data_[i] = src[i];
    }
  }

  SecureBytes(const SecureBytes&) = delete;
  SecureBytes& operator=(const SecureBytes&) = delete;

  SecureBytes(SecureBytes&& other) noexcept
      : data_(std::move(other.data_)), size_(std::exchange(other.size_, 0)) {}

  SecureBytes& operator=(SecureBytes&& other) noexcept {
    if (this != &other) {
      wipe();
      data_ = std::move(other.data_);
      size_ = std::exchange(other.size_, 0);
    }
    return *this;
  }

  ~SecureBytes() { wipe(); }

  [[nodiscard]] SecureBytes clone() const { return SecureBytes(view()); }

  [[nodiscard]] uint8_t* data() noexcept { return data_.get(); }
  [[nodiscard]] const uint8_t* data() const noexcept { return data_.get(); }
  [[nodiscard]] size_t size() const noexcept { return size_; }
  [[nodiscard]] bool empty() const noexcept { return size_ == 0; }

  uint8_t& operator[](size_t i) noexcept { return data_[i]; }
  const uint8_t& operator[](size_t i) const noexcept { return data_[i]; }

  [[nodiscard]] uint8_t* begin() noexcept { return data(); }
  [[nodiscard]] uint8_t* end() noexcept { return data() + size_; }
  [[nodiscard]] const uint8_t* begin() const noexcept { return data(); }
  [[nodiscard]] const uint8_t* end() const noexcept { return data() + size_; }

  [[nodiscard]] ByteView view() const noexcept { return {data(), size_}; }
  [[nodiscard]] MutByteView span() noexcept { return {data(), size_}; }

  // NOLINTNEXTLINE(google-explicit-constructor): implicit view like std::vector
  operator ByteView() const noexcept { return view(); }

 private:
  void wipe() noexcept {
    if (data_) {
      secure_zero(data_.get(), size_);
    }
  }

  std::unique_ptr<uint8_t[]> data_;
  size_t size_ = 0;
};

}  // namespace pq
