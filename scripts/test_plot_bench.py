"""Parser/statistics tests use synthetic timings, never cryptographic test vectors."""

import csv
import tempfile
import unittest
from pathlib import Path

from plot_bench import FIELDS, load_rows, name_order, throughput_mib


class PlotBenchTest(unittest.TestCase):
    def record(self, **overrides):
        row = dict(zip(FIELDS, [
            "2026-10-11T12:00:00Z", "hash", 'CPU, "model"', "compiler", "-O3",
            "KEM", "ML-KEM-512", "encaps", "0", "10000", "200", "100", "300", "50", "3",
        ]))
        row.update(overrides)
        return row

    def read(self, rows):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "bench.csv"
            with path.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(stream, fieldnames=FIELDS)
                writer.writeheader()
                writer.writerows(rows)
            return load_rows(path)

    def test_preserves_quoted_metadata_and_handles_missing_cycles(self):
        row = self.read([self.record(median_cycles="", p5_cycles="", p95_cycles="")])[0]
        self.assertEqual(row["cpu"], 'CPU, "model"')
        self.assertIsNone(row["median_cycles"])

    def test_rejects_mixed_runs_and_duplicate_medians(self):
        with self.assertRaisesRegex(ValueError, "different runs"):
            self.read([self.record(), self.record(commit="other", op="decaps")])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.read([self.record(), self.record()])

    def test_rejects_invalid_and_nonfinite_timings(self):
        for changes in [
            {"median_ns": "0"}, {"median_ns": "nan"}, {"stddev_ns": "-1"},
            {"p95_cycles": "50"}, {"iterations": "9999"}, {"p5_cycles": ""},
            {"msg_bytes": "16"},
        ]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.read([self.record(**changes)])

    def test_throughput_has_binary_units_and_names_sort_by_parameter(self):
        self.assertEqual(throughput_mib({"msg_bytes": 1048576, "median_ns": 1e9}), 1)
        names = ["ML-KEM-1024", "ML-KEM-512", "ML-KEM-768"]
        self.assertEqual(sorted(names, key=name_order), ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"])


if __name__ == "__main__":
    unittest.main()
