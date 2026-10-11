# src/core: Rng, Registry

Owner: participant 4. Namespace `pq`. Interfaces live in `include/pq/`.

| File | What |
|---|---|
| `system_rng.cpp` | `SystemRng`: `getrandom(2)`, retries on `EINTR` and short reads, throws `pq::Error` on failure. The only `Rng` allowed in `pqtool` and KEM-DEM |
| `deterministic_rng.cpp` | `DeterministicRng`: SHAKE256(seed) output stream. Tests and `pqanalyze` only |
| `registry.cpp` | `Registry`: factories by canonical name; `Registry::global()` |
| `endian.hpp` | Byte-order helpers (`load32_le`, `store64_be`, ...) |

`SecureBytes`, `secure_zero` and `ct_*` stay header-only in `include/pq/` (see AGENTS.md, section 14).

## Registry

- `Registry::global()` is built on first use by calling each module's `register_algorithms()`.
  Today that is ML-KEM only. When `src/cipher`, `src/mode` and `src/kem/hqc` land, their
  `register_algorithms()` must be added to `Registry::global()` in `registry.cpp`.
- Duplicate names and empty factories throw `pq::Error`; so do unknown names.
- `aead(mode, cipher)` builds `mode` around a fresh `cipher` instance, so
  `aead("GCM", "AES-256")->name() == "AES-256-GCM"`.
- Services (`src/hybrid`, `src/keystore`) take a `const Registry&` and default to the global one.
  Tests pass a local registry from `tests/support/test_registry.hpp`.

## Known limitations

- `Registry` is not thread-safe for registration after `global()` has been handed out.
  Registration is expected to happen once, at startup.
