"""Verify CPU selection and preservation of failed measurement series."""

import argparse
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import call, patch

from run_bench import execute, select_cpu


class RunBenchTest(unittest.TestCase):
    def test_cpu_selection_respects_available_affinity(self):
        self.assertEqual(select_cpu("auto", {2, 4}), 2)
        self.assertEqual(select_cpu("4", {2, 4}), 4)
        self.assertIsNone(select_cpu("none", {2, 4}))
        self.assertIsNone(select_cpu("auto", None))
        for requested in ("0", "bad", "-1"):
            with self.subTest(requested=requested), self.assertRaises(ValueError):
                select_cpu(requested, {2, 4})
        with self.assertRaisesRegex(ValueError, "not supported"):
            select_cpu("0", None)

    def arguments(self, root):
        binary = root / "pqbench"
        binary.write_text("test executable placeholder")
        binary.chmod(0o700)
        return argparse.Namespace(
            binary=binary, suite="kem", iterations=10000, seconds=1, warmup=100,
            sizes="16,256", filter="", repeats=2, cpu="auto", output_dir=root / "series",
            no_plots=True,
        )

    def test_existing_results_are_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temp, patch("run_bench.subprocess.run"):
            root = Path(temp)
            args = self.arguments(root)
            args.output_dir.mkdir()
            marker = args.output_dir / "existing.csv"
            marker.write_text("preserve")
            with self.assertRaises(FileExistsError):
                execute(args)
            self.assertEqual(marker.read_text(), "preserve")

    def test_failure_preserves_logs_manifest_and_restores_affinity(self):
        with tempfile.TemporaryDirectory() as temp, \
                patch("run_bench.platform.platform", return_value="test Linux"), \
                patch("run_bench.os.sched_getaffinity", return_value={2, 4}), \
                patch("run_bench.os.sched_setaffinity") as set_affinity, \
                patch("run_bench.subprocess.run", side_effect=[
                    subprocess.CompletedProcess([], 0), subprocess.CalledProcessError(1, []),
                ]):
            args = self.arguments(Path(temp))
            with self.assertRaises(subprocess.CalledProcessError):
                execute(args)
            manifest = json.loads((args.output_dir / "environment.json").read_text())
            self.assertEqual(manifest["status"], "failed")
            self.assertEqual(manifest["selected_cpu"], 2)
            self.assertEqual(len(manifest["binary_sha256"]), 64)
            self.assertTrue((args.output_dir / "run-01.log").is_file())
            self.assertEqual(set_affinity.call_args_list, [call(0, {2}), call(0, {2, 4})])

    def test_invalid_iterations_are_rejected_before_running_binary(self):
        with tempfile.TemporaryDirectory() as temp, patch("run_bench.subprocess.run") as run:
            args = self.arguments(Path(temp))
            args.iterations = 9999
            with self.assertRaisesRegex(ValueError, "iterations"):
                execute(args)
            run.assert_not_called()
            self.assertFalse(args.output_dir.exists())


if __name__ == "__main__":
    unittest.main()
