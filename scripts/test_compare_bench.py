"""Test aggregation with synthetic timings, not cryptographic test vectors."""

import csv
import statistics
import tempfile
import unittest
from pathlib import Path

from compare_bench import load_series, validate_baseline, write_report
from plot_bench import FIELDS


def write_run(path, median_ns=50, **overrides):
    row = dict(zip(FIELDS, [
        "2026-10-11T12:00:00Z", "hash", "CPU", "GNU 13.4.0", "-O3",
        "KEM", "ML-KEM-512", "encaps", 0, 10000, 200, 100, 300, median_ns, 3,
    ]))
    row.update(overrides)
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerow(row)
    return path


class CompareBenchTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def run_file(self, index, **overrides):
        return write_run(self.root / f"run-{index}.csv", **overrides)

    def test_uses_median_of_run_medians_and_distinguishes_within_run_deviation(self):
        paths = [self.run_file(i, median_ns=value, timestamp=f"run-{i}")
                 for i, value in enumerate([10, 20, 90])]
        row = next(iter(load_series(paths).summary.values()))
        self.assertEqual(row["median_run_ns"], 20)
        self.assertEqual((row["min_run_ns"], row["max_run_ns"]), (10, 90))
        self.assertAlmostEqual(row["run_stddev_ns"], statistics.pstdev([10, 20, 90]))
        self.assertAlmostEqual(row["run_cv_pct"], statistics.pstdev([10, 20, 90]) / 40 * 100)
        self.assertEqual(row["median_within_run_stddev_ns"], 3)
        self.assertEqual(row["runs"], 3)

    def test_rejects_configuration_changes_within_a_series(self):
        first = self.run_file(0)
        for field in ("commit", "cpu", "compiler", "flags"):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "same commit"):
                load_series([first, self.run_file(1, **{field: "different"})])

    def test_rejects_missing_or_different_operations_and_sizes(self):
        first = self.run_file(0)
        for changes in ({"op": "decaps"}, {"param": "ML-KEM-768"}):
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, "same algorithms"):
                load_series([first, self.run_file(1, **changes)])
        cipher = {"primitive": "cipher", "param": "AES-256", "op": "encrypt"}
        with self.assertRaisesRegex(ValueError, "same algorithms"):
            load_series([self.run_file(2, msg_bytes=16, **cipher),
                         self.run_file(3, msg_bytes=32, **cipher)])

    def test_rejects_duplicate_inputs_including_symlinks(self):
        first = self.run_file(0)
        alias = self.root / "alias.csv"
        alias.symlink_to(first)
        with self.assertRaisesRegex(ValueError, "counted twice"):
            load_series([first, alias])

    def test_missing_cycles_are_preserved_and_cannot_be_mixed(self):
        first = self.run_file(0, median_cycles="", p5_cycles="", p95_cycles="")
        row = next(iter(load_series([first]).summary.values()))
        self.assertIsNone(row["median_run_cycles"])
        self.assertEqual(row["run_cv_pct"], 0)
        with self.assertRaisesRegex(ValueError, "cycle availability"):
            load_series([first, self.run_file(1)])

    def test_derived_throughput_has_binary_units(self):
        path = self.run_file(0, median_ns=1e9, primitive="cipher", param="AES-256",
                             op="encrypt", msg_bytes=2**20)
        row = next(iter(load_series([path]).summary.values()))
        self.assertEqual(row["mib_per_second"], 1)
        self.assertEqual(row["ops_per_second"], 1)

    def test_baseline_allows_another_build_but_requires_matching_hardware_and_cases(self):
        current = load_series([self.run_file(0)])
        baseline = load_series([self.run_file(1, commit="before", compiler="GNU 11.4.0")])
        validate_baseline(current, baseline)
        with self.assertRaisesRegex(ValueError, "same CPU"):
            validate_baseline(current, load_series([self.run_file(2, cpu="other CPU")]))
        with self.assertRaisesRegex(ValueError, "same algorithms"):
            validate_baseline(current, load_series([self.run_file(3, op="decaps")]))
        with self.assertRaisesRegex(ValueError, "different CSV"):
            validate_baseline(current, current)

    def test_report_computes_comparison_without_modifying_source_csv(self):
        before = self.run_file(0, median_ns=40, commit="before")
        after = self.run_file(1, median_ns=20)
        original = after.read_bytes()
        output = self.root / "report"
        report = write_report(load_series([after]), output, load_series([before]))
        with (output / "comparison.csv").open(newline="") as stream:
            row = next(csv.DictReader(stream))
        self.assertEqual(float(row["latency_ratio"]), 2)
        self.assertEqual(float(row["time_change_pct"]), -50)
        self.assertIn("медиан отдельных запусков", report.read_text())
        self.assertIn("GNU 13.4.0", report.read_text())
        self.assertEqual(after.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
