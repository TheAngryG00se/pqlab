#include <sys/random.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>

#include "pq/error.hpp"
#include "pq/rng.hpp"

namespace pq {

// getrandom(2) with flags = 0 blocks until the kernel pool is initialised. It may
// return fewer bytes than requested (large requests, signals), so loop.
void SystemRng::fill(std::span<uint8_t> out) {
  size_t done = 0;
  while (done < out.size()) {
    const ssize_t n = ::getrandom(out.data() + done, out.size() - done, 0);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      throw Error("SystemRng: getrandom failed");
    }
    done += static_cast<size_t>(n);
  }
}

}  // namespace pq
