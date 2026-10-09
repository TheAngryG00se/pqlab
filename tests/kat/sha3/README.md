# SHA-3 / SHAKE: NIST CAVP (SHA3VS)

Byte-oriented test vectors from the NIST Cryptographic Algorithm Validation Program,
copied without modification.

| Archive | URL | SHA-256 of the archive |
|---|---|---|
| sha-3bytetestvectors.zip | https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha-3bytetestvectors.zip | cd07701af2e47f5cc889d642528b4bf11f8b6eb55797c7307a96828ed8d8fc8c |
| shakebytetestvectors.zip | https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/shakebytetestvectors.zip | debfebc3157b3ceea002b84ca38476420389a3bf7e97dc5f53ea4689a16de4c7 |

Files are dated 2016-01-28 (CAVS 19.0). Downloaded 2026-10-09. Only the sets used by the
project are kept (SHA3-256, SHA3-512, SHAKE128, SHAKE256).

The Monte Carlo procedures are described in "The Secure Hash Algorithm 3 Validation System
(SHA3VS)", Sections 6.2.3 and 6.3.3:
https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha3vs.pdf

SHA-256 of the files:

```text
741b75d093aeb1de3536681b5e7e65090a5eca8015eb75c5f9be0feda47660d5  SHA3_256LongMsg.rsp
0b387d75eb7bb96070007ae570601675d4527f50295f41c9d0fbc6c03ec48ca4  SHA3_256Monte.rsp
e75b1ded16e9862eaaef9ad9b89402b9832f86fe818292634b2e54dc6b3540ff  SHA3_256ShortMsg.rsp
142aab2fc0fd41809b1efdf48819e4f863985fb8d5cb30694acf7c8e7080d20e  SHA3_512LongMsg.rsp
2e07ae80620d566a77f4c3cb2d5b465454100b3984e7e661030c942db9804c89  SHA3_512Monte.rsp
f73a39d8091d58c9225cfad8e6d8cfa3e8d67532c7029bf376baef0d0d86d5b6  SHA3_512ShortMsg.rsp
826b319c265448f5268c7e36f432de31315dd8155eaa038ba76d1acd0d03736f  SHAKE128LongMsg.rsp
78b0e751fd8c8eb455ec8f98debb2f2c2e39f04f5241850e190326238baf83dc  SHAKE128Monte.rsp
c7384e3f84247d90e6b0af9ac618a968bb65f5dcbe9c2ee7e8a66475c551764b  SHAKE128ShortMsg.rsp
56ac04dd47c8063bdd08fd7744aef55c22c22946d722012460703bcae0b2583f  SHAKE128VariableOut.rsp
f7881838fa013853993bf7e0814de0ab53ee93a4dbc2b7bce5bed7cc81e6985f  SHAKE256LongMsg.rsp
95e5929344f4309e70f16e42620bd393d7a69b3f2577231ff5adcda1b395c6c8  SHAKE256Monte.rsp
a21dd9180a0f0139fa8d4056919f8194ddaca2f36dc5aafa70723682099d64f5  SHAKE256ShortMsg.rsp
90fb72336900b22284477b76d0868fc2822ae42a114079c6c8a7fbda12eb52ca  SHAKE256VariableOut.rsp
```
