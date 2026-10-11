#!/usr/bin/env python3
"""Run pqbench repeatedly with CPU affinity and save the measurement environment."""

import argparse
import hashlib
import json
import math
import os
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from compare_bench import load_series, render_series, write_report
from plot_bench import render

ROOT = Path(__file__).resolve().parents[1]


def select_cpu(requested, allowed):
    if requested == "none":
        return None
    if allowed is None:
        if requested == "auto":
            return None
        raise ValueError("CPU affinity is not supported on this platform")
    if requested == "auto":
        return min(allowed)
    try:
        cpu = int(requested)
    except ValueError as error:
        raise ValueError("cpu must be auto, none or a logical CPU number") from error
    if cpu not in allowed:
        raise ValueError(f"CPU {cpu} is unavailable; allowed CPUs: {sorted(allowed)}")
    return cpu


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def file_sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def optional_text(path):
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except OSError:
        return None


def execute(args):
    if not 2 <= args.repeats <= 50:
        raise ValueError("repeats must be between 2 and 50")
    if args.iterations < 10000 or not math.isfinite(args.seconds) or not 1 <= args.seconds <= 3600:
        raise ValueError("require iterations >= 10000 and seconds between 1 and 3600")
    if not 0 <= args.warmup <= 2**32 - 1:
        raise ValueError("invalid warmup count")
    binary = args.binary.resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise ValueError(f"pqbench executable not found: {binary}; build the release preset")
    allowed = os.sched_getaffinity(0) if hasattr(os, "sched_getaffinity") else None
    cpu = select_cpu(args.cpu, allowed)
    # Verify arguments and the registered suite without performing any measurements.
    command = [
        str(binary), "--suite", args.suite, "--iterations", str(args.iterations),
        "--seconds", str(args.seconds), "--warmup", str(args.warmup), "--sizes", args.sizes,
    ]
    if args.filter:
        command += ["--filter", args.filter]
    subprocess.run(command + ["--list"], cwd=ROOT, check=True, capture_output=True, text=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S-%fZ")
    output = (args.output_dir or ROOT / "results" / stamp[:10] / f"series-{stamp}").resolve()
    output.mkdir(parents=True, exist_ok=False)
    manifest = {
        "schema_version": 1, "status": "running", "started_utc": utc_now(),
        "binary": str(binary), "binary_sha256": file_sha256(binary),
        "platform": platform.platform(), "python": platform.python_version(),
        "allowed_cpus": sorted(allowed) if allowed is not None else None,
        "selected_cpu": cpu, "repeats": args.repeats, "command": command,
        "governor_before": optional_text(
            f"/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_governor"
        ) if cpu is not None else None,
        "runs": [],
    }
    manifest_path = output / "environment.json"

    def save_manifest():
        manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")

    save_manifest()
    print(f"Results directory: {output}", flush=True)
    paths = []
    try:
        if cpu is not None:
            os.sched_setaffinity(0, {cpu})
        for index in range(1, args.repeats + 1):
            if file_sha256(binary) != manifest["binary_sha256"]:
                raise ValueError("pqbench binary changed during the series; rerun after rebuilding")
            path = output / f"run-{index:02d}.csv"
            print(f"Run {index}/{args.repeats}; CPU: {cpu if cpu is not None else 'unbound'}", flush=True)
            with (output / f"run-{index:02d}.log").open("w", encoding="utf-8") as log:
                subprocess.run(command + ["--output", str(path)], cwd=ROOT, check=True,
                               stdout=log, stderr=subprocess.STDOUT, text=True)
            paths.append(path)
            if file_sha256(binary) != manifest["binary_sha256"]:
                raise ValueError("pqbench binary changed during the series; rerun after rebuilding")
            manifest["runs"].append(path.name)
            save_manifest()
        series = load_series(paths)
        manifest["metadata"] = series.metadata
        manifest["status"] = "measured"
    except BaseException:
        manifest["status"] = "failed"
        raise
    finally:
        manifest["finished_utc"] = utc_now()
        try:
            save_manifest()
        finally:
            if cpu is not None:
                os.sched_setaffinity(0, allowed)
    try:
        report = write_report(series, output / "report")
        if not args.no_plots:
            render_series(series, output / "report/plots", label="серия")
            render(list(series.runs[0].values()), output / "report/plots/run-01", ("png", "svg"))
    except BaseException:
        manifest["status"] = "report_failed"
        save_manifest()
        raise
    manifest["status"] = "complete"
    save_manifest()
    print(f"Results: {output}")
    print(f"Report: {report}")
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "build/release/apps/pqbench/pqbench")
    parser.add_argument("--suite", choices=("all", "kem", "cipher", "aead", "hybrid"), default="all")
    parser.add_argument("--filter", default="")
    parser.add_argument("--iterations", type=int, default=10000)
    parser.add_argument("--seconds", type=float, default=1)
    parser.add_argument("--warmup", type=int, default=100)
    parser.add_argument("--sizes", default="16,256,4096,65536,1048576")
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--cpu", default="auto", help="auto (first allowed), none, or logical CPU number")
    parser.add_argument("--output-dir", type=Path, help="new directory; existing results are never overwritten")
    parser.add_argument("--no-plots", action="store_true", help="save CSV and Markdown without matplotlib")
    args = parser.parse_args()
    try:
        execute(args)
    except subprocess.CalledProcessError as error:
        detail = (error.stderr or "see run log in the output directory").strip()
        parser.exit(1, f"run_bench: pqbench exited with code {error.returncode}: {detail}\n")
    except (ValueError, OSError, ImportError) as error:
        parser.exit(1, f"run_bench: {error}\n")
    except KeyboardInterrupt:
        parser.exit(130, "run_bench: interrupted; completed CSV files are preserved\n")


if __name__ == "__main__":
    main()
