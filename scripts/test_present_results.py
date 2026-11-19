"""Check presentation input handling using synthetic aggregate statistics."""

import csv
import tempfile
import unittest
from pathlib import Path

from present_results import ANALYSIS_FIELDS, KEMS, read_avalanche


class PresentationInputTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "analysis.csv"
        self.rows = [
            [kem, component, output, 5, 256, 128, "1.2"]
            for kem in KEMS for component in ("d", "z") for output in ("pk", "dk")
        ]

    def read(self):
        with self.path.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream)
            writer.writerow(ANALYSIS_FIELDS)
            writer.writerows(self.rows)
        return read_avalanche(self.path)

    def test_reads_measured_zero_and_fraction(self):
        self.rows[2][-1] = 0
        observed = self.read()
        self.assertEqual(len(observed), 12)
        self.assertEqual(observed[KEMS[0], "z", "pk"].mean, 0)
        self.assertEqual(observed[KEMS[0], "d", "dk"].mean, 1.2)

    def test_rejects_incomplete_and_repeated_measurements(self):
        self.rows.pop()
        with self.assertRaisesRegex(ValueError, "отсутствуют"):
            self.read()
        self.rows.append(self.rows[0])
        with self.assertRaisesRegex(ValueError, "повторная"):
            self.read()

    def test_rejects_invalid_average_and_mismatched_pairs(self):
        for invalid in ("nan", "inf", -1, 129):
            with self.subTest(invalid=invalid):
                self.rows[0][-1] = invalid
                with self.assertRaisesRegex(ValueError, "Хэмминга"):
                    self.read()
        self.rows[0][-1] = 1
        self.rows[0][3] = 19
        with self.assertRaisesRegex(ValueError, "Число пар"):
            self.read()


if __name__ == "__main__":
    unittest.main()
