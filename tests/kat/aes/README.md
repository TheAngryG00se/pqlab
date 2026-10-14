# Official AES known-answer tests

Source: [NIST CAVP block-cipher test vectors](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers).
Archive: [KAT_AES.zip](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/KAT_AES.zip).
Downloaded 2026-10-14. Archive SHA-256:
`a203b16c9246b2ebae31dee5de21a606be80cf78ceabaca37150236fa098eb60`.

The twelve ECB `.rsp` files below are complete archive members, extracted byte
for byte, including CRLF line endings and both ENCRYPT/DECRYPT sections. Nothing
has been trimmed or regenerated. They carry the CAVS 11.1 header dated 2011-04-22.
GFSbox/KeySbox, variable-key and variable-text categories cover all three AES key
lengths. ECB is used here only to test individual AES block operations. The
shared reader ignores the direction-only section headers, so the tests verify
**both** encryption and decryption for **every** record in both sections.

| File | SHA-256 |
|---|---|
| `ECBGFSbox128.rsp` | `62f17126e870b9700234cc5b592b5bb50b295320b9844f341ee58a33eae735e6` |
| `ECBGFSbox192.rsp` | `885364c3f424477e5b878b13c4b3ffcf11f4501cb1223cf25d06180915d4f070` |
| `ECBGFSbox256.rsp` | `6b0800d4d666d57abaaa4ede64c9dbdbf5ab2239a13adcac5ce516516dedf526` |
| `ECBKeySbox128.rsp` | `f23ae1259a894fcabe955c42904e0d09394dceb17b8a3dc150767fa2a6482aa7` |
| `ECBKeySbox192.rsp` | `3c3f1531fba163287b3deb001cdbf666ebc1fe70afee4a071abbefb8d4544556` |
| `ECBKeySbox256.rsp` | `010a648bfc725f0ea2bd6e9892c88498cd71d805bac84c3f93199e1d919aba03` |
| `ECBVarKey128.rsp` | `81ce3d0f80b57c4cfcacdde88e2ff9bc609050a1d80a0beb92fda30acdd98598` |
| `ECBVarKey192.rsp` | `d94b0fbedab3607bdb22d5fde635915ce5adfd97ae6da4ce136f4b2ad5b0cb6d` |
| `ECBVarKey256.rsp` | `41026476e854b2e941804726300da7222c5f7ee5b28490a1e52c4ebfbb9dfc11` |
| `ECBVarTxt128.rsp` | `447001742e5576da2213888f2187258bdd07c120106792c509786d46da2464f1` |
| `ECBVarTxt192.rsp` | `ece3fb1795a461127b4c69c8d852ec9323c88acbb037c198376b71b7d888b68f` |
| `ECBVarTxt256.rsp` | `0be3b50f6b3e28e34e16f72d1acbcea4e3c240d725a32b30917b9e560e8ef24e` |

Additional internal-transform expectations in `tests/unit/cipher/aes_test.cpp`
are transcribed directly from [FIPS 197-upd1](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf),
updated 2023-05-09: Eqs. (4.6)/(4.7), Appendix A.1–A.3 (key expansion), and
Appendix B (first-round trace). Source PDF SHA-256:
`62c86eb567f13edb8f71826e985da870b04ef6381634f303cdb16e84d47becd1`.
The code's S-box is Table 4; inverse S-box entries are obtained by inverting that
public permutation as specified in Section 5.3.2. Property-test inputs are
synthetic and are not presented as official known-answer vectors.
