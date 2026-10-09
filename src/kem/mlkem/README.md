# src/kem/mlkem: ML-KEM-512/768/1024

Owner: participant 1. Namespace `pq::mlkem` (internals in `pq::mlkem::detail`).
Standard: FIPS 203 (August 2024), https://csrc.nist.gov/pubs/fips/203/final

| File | Contents | FIPS 203 |
|---|---|---|
| `params.hpp` | Parameter sets as `constexpr` structs, byte sizes | Section 8, Tables 2-3 |
| `reduce.hpp` | Constant-time mod q: conditional subtraction, Barrett, Montgomery (R = 2^16), division by q via multiplication | Section 3.3 (no secret-dependent timing) |
| `poly.hpp`, `polyvec.hpp` | `Poly` (wiped on destruction), vector/matrix arithmetic in T_q | Sections 2.4.5-2.4.8 |
| `ntt.{hpp,cpp}` | NTT, NTT^-1, MultiplyNTTs: reference and optimized | Algorithms 9-12, Appendix A |
| `encode.hpp` | ByteEncode_d / ByteDecode_d, Compress_d / Decompress_d | Algorithms 3-6, Eq. (4.7)-(4.8) |
| `sampling.{hpp,cpp}` | SampleNTT, SamplePolyCBD, PRF | Algorithms 7-8, Eq. (4.3) |
| `kpke.{hpp,cpp}` | K-PKE KeyGen / Encrypt / Decrypt | Algorithms 13-15 |
| `mlkem.{hpp,cpp}` | `MlKem<P>` implementing `pq::Kem`, input checks | Algorithms 16-18, Section 7 |
| `register.hpp` | Registration under `ML-KEM-512`, `ML-KEM-768`, `ML-KEM-1024` | |

API notes:
- `keygen_derand(seed)` takes the 64-byte seed `d || z`; `sk` is the expanded 768k + 96
  byte decapsulation key. The keystore stores the seed and re-expands it.
- `encaps_derand(pk, m)` runs the encapsulation key check (type and modulus) and throws
  `pq::Error` if it fails. `decaps(sk, ct)` checks lengths and the hash of `ek` inside `dk`.
- An invalid ciphertext is not an error: the implicit-rejection key `J(z || c)` is returned,
  selected with `ct_equal_mask` / `ct_select`.

Two NTT implementations:
- `ntt_ref`, `inv_ntt_ref`, `multiply_ntts_ref` follow Algorithms 9-12 literally and fully
  reduce after every operation (Barrett).
- `ntt`, `inv_ntt`, `multiply_ntts` use unsigned Montgomery arithmetic with lazy reduction:
  the forward NTT does no intermediate reduction at all (bounds argued in `ntt.cpp`).
  Tests require both to agree bit for bit; the reference stays for the before/after benchmark.

Constant time:
- No `/` or `%` on secret data; Compress uses `div_q` (multiply by ceil(2^40 / q) and shift),
  checked exhaustively over its input range.
- All arithmetic is unsigned; no shifts of signed values.
- SampleNTT rejection sampling branches only on public data derived from `rho`.

Verification:
- NIST ACVP vectors (keyGen, encapsulation, decapsulation incl. modified ciphertexts,
  encapsulation and decapsulation key checks), `tests/kat/mlkem`.
- Unit tests for every layer: exhaustive reduction checks, zetas against Appendix A,
  NTT round trip, NTT product against schoolbook negacyclic multiplication, compression
  against exact rational rounding.
- Decaps(Encaps) = K on 10^4 cases per parameter set.

Known limitations:
- The matrix A is regenerated on every operation (it is not cached).
- `register.hpp` is not used until `pq::Registry` is implemented in `src/core`.
