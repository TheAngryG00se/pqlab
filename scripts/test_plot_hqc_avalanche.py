"""Parser tests with synthetic aggregate counts, not cryptographic test vectors."""

import csv
import tempfile
import unittest
from pathlib import Path

from plot_hqc_avalanche import COLUMNS, SIZES, read_distances


class HqcPlotInputTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.csv = Path(directory.name) / "summary.csv"
        self.rows = []
        for kem, (m_bits, pk_size, ct_size) in SIZES.items():
            for component, output, bits, size in (("seed_kem", "pk", 256, pk_size),
                                                  ("m", "ct", m_bits, ct_size),
                                                  ("m", "ss", m_bits, 32)):
                self.rows.append([kem, component, output, 3, bits, 8 * size, 128, 127, 129, 1])

    def read(self):
        with self.csv.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream)
            writer.writerow(COLUMNS)
            writer.writerows(self.rows)
        return read_distances(self.csv)

    def test_percent_uses_each_serialized_output_length(self):
        rows = self.read()
        self.assertEqual(len(rows), 9)
        self.assertEqual(rows["HQC-5", "ss"].percent(128), 50)
        self.assertAlmostEqual(rows["HQC-1", "ct"].percent(128), 100 * 128 / (4433 * 8))

    def test_rejects_missing_measurements_and_duplicate_outputs(self):
        self.rows.pop()
        with self.assertRaisesRegex(ValueError, "Нужны результаты"):
            self.read()
        self.rows.append(self.rows[0])
        with self.assertRaisesRegex(ValueError, "повторная"):
            self.read()

    def test_rejects_different_schema_parameter_lengths_and_bad_spread(self):
        for column, value in ((1, "z"), (4, 8), (5, 64), (6, float("nan")), (8, 20), (9, -1)):
            with self.subTest(column=column):
                original = self.rows[0][column]
                self.rows[0][column] = value
                with self.assertRaises(ValueError):
                    self.read()
                self.rows[0][column] = original

    def test_rejects_independently_aggregated_encaps_outputs(self):
        self.rows[1][3] = 5
        with self.assertRaisesRegex(ValueError, "Число пар"):
            self.read()


if __name__ == "__main__":
    unittest.main()
