# S-box analysis

`analyze_sbox` exhaustively analyses a public 256-entry table. It returns the DDT,
the signed LAT (`matches - 128`, half the Walsh coefficient), differential
uniformity, vectorial nonlinearity, and whether the table is a permutation.
All nonzero output masks are considered when computing nonlinearity.

Definitions: C. Carlet, *Boolean Functions for Cryptography and Coding Theory*,
sections 2.3.6, 3.2.3 and 3.4.1,
https://www.math.univ-paris13.fr/~carlet/book-fcts-Bool-vect-crypt-codes.pdf.

The analysis consumes public mappings, not keys. DDT/LAT maxima describe one
substitution layer; they alone do not establish security or attack complexity
for a complete cipher. See `docs/analysis.md` for the conventions and methodology.
