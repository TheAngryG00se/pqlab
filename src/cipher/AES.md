# AES-128, AES-192, AES-256

`Aes(key_bits)` implements `pq::BlockCipher` with a 16-byte block and full
10/12/14-round encryption and decryption by default. The implementation follows
[FIPS 197-upd1](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf),
updated 2023-05-09, Algorithms 1–3. It is written independently from the standard,
without crypto libraries or copied reference implementation code.

The state is column-major: byte `row + 4 * column`. Key words are represented
directly as ordered bytes, with no host-endian casts. `aes_detail.hpp` provides
the elementary transformations for unit tests and S-box analysis. Expanded
keys and temporary arrays are explicitly wiped; the cipher cannot be copied or
moved. A failed key-length check preserves the existing key. A block call before
`set_key` or with a null pointer throws `pq::Error`. Both exact and partial input /
output overlap are supported. The pointer-based public interface cannot check
the allocation length: the caller must provide 16 readable/writable bytes.

`set_rounds` is the existing analysis contract: only callers in `analysis/` may
reduce the count to 1…full. The final selected round omits MixColumns, exactly as
the final full AES round. Services and registry factories use the full count;
the four-round attack setup belongs exclusively in `analysis/attacks/`.

The two S-box tables are indexed by secret bytes. This is the explicit exception
allowed by `AGENTS.md`: cache-based leakage is a known limitation, so this
implementation does **not** claim full constant-time security. Other arithmetic
uses masks and fixed loops, without secret-dependent branches or division.
No AES-NI or T-tables are used.

Tests include exhaustive field multiplication, algebraic S-box verification,
linear-transform basis vectors, the first-round trace from FIPS 197 Appendix B,
key expansion from Appendix A for each key length, and every record of twelve
unmodified NIST AESAVS ECB KAT files. Each KAT checks both cipher directions,
separate and in-place buffers; other tests cover overlap, rekeying, and misuse.
Sources and SHA-256 hashes are recorded in `tests/kat/aes/README.md`.
