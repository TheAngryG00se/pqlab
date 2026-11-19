"""Check presentation inputs and publication using isolated temporary files."""

import csv
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from present_results import ANALYSIS_FIELDS, KEMS, ROOT, publish_pdf, read_avalanche, read_hqc_run


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


class HqcRunTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.run_dir = Path(temp.name)
        published = ROOT / "results/final/hqc-avalanche"
        for name in ("metadata.json", "summary.csv", "trials.csv"):
            shutil.copyfile(published / name, self.run_dir / name)

    def test_reads_all_outputs_from_verified_run(self):
        results = read_hqc_run(self.run_dir)
        expected = {(kem, output) for kem in ("HQC-1", "HQC-3", "HQC-5")
                    for output in ("pk", "ct", "ss")}
        self.assertEqual(set(results), expected)
        metadata = json.loads((self.run_dir / "metadata.json").read_text())
        self.assertEqual({row.samples for row in results.values()},
                         {metadata["samples_per_level_per_experiment"]})

    def test_rejects_changes_to_either_csv(self):
        for name in ("summary.csv", "trials.csv"):
            with self.subTest(name=name):
                path = self.run_dir / name
                original = path.read_bytes()
                path.write_bytes(original.replace(b"\n", b"\r\n"))
                with self.assertRaises(ValueError):
                    read_hqc_run(self.run_dir)
                path.write_bytes(original)

    def test_rejects_sample_count_mismatch(self):
        path = self.run_dir / "metadata.json"
        metadata = json.loads(path.read_text())
        metadata["samples_per_level_per_experiment"] += 1
        path.write_text(json.dumps(metadata))
        with self.assertRaises(ValueError):
            read_hqc_run(self.run_dir)

    def test_rejects_unverified_reference(self):
        path = self.run_dir / "metadata.json"
        original = path.read_text()
        for field in ("commit", "tag", "cases_passed", "rsp_sha256"):
            with self.subTest(field=field):
                metadata = json.loads(original)
                record = metadata if field in ("commit", "tag") else metadata["reference_kats"]["HQC-3"]
                record[field] = 99 if field == "cases_passed" else "different reference"
                path.write_text(json.dumps(metadata))
                with self.assertRaises(ValueError):
                    read_hqc_run(self.run_dir)


class PublishPdfTest(unittest.TestCase):
    def test_updates_existing_destination_and_preserves_it_on_error(self):
        def interrupted_copy(_source, dest):
            Path(dest).write_bytes(b"partial")
            raise OSError("interrupted copy")

        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "new.pdf"
            destination = Path(temp) / "current.pdf"
            destination.write_bytes(b"old edition")
            source.write_bytes(b"new edition")
            publish_pdf(source, destination)
            self.assertEqual(destination.read_bytes(), b"new edition")
            with patch("present_results.shutil.copyfile", side_effect=interrupted_copy):
                with self.assertRaisesRegex(OSError, "interrupted copy"):
                    publish_pdf(source, destination)
            self.assertEqual(destination.read_bytes(), b"new edition")


if __name__ == "__main__":
    unittest.main()
