#!/usr/bin/env python3
"""Verify the official HQC v5.1.0 ref KATs and measure one-bit changes on synthetic inputs."""

import argparse
from collections import defaultdict
import csv
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import statistics
import subprocess
import tarfile
import tempfile


ROOT = Path(__file__).resolve().parents[1]
ADAPTER = ROOT / "tests/diff/hqc_avalanche"
COMMIT = "06567ccbad10580d78dd7863b15d23f41076d57f"
ARCHIVE_URL = f"https://gitlab.com/api/v4/projects/73349269/repository/archive.tar.gz?sha={COMMIT}"
ARCHIVE_SHA = "764316ff93c84acf9e71429b1af85a109a96d21692bb1271c392eead992a4996"
KAT_SHA = {
    1: "c3f6ce304a00685e3aa356ef7cd81dbb35d985a1ff7123610bed9582e3638c1e",
    3: "7dcb2b670d1e108c0d7dc0c88b466c63c121de5ac4f96fd2e868c7040065a4ff",
    5: "e5066df4ec3dbe012d60a4a66ce5e0c2f1996d11af8a8eb66333f15b51095edb",
}
TRIAL_FIELDS = "kem trial component output flipped_bit input_bits output_bits changed_bits".split()
SUMMARY_FIELDS = ("kem component output samples input_bits output_bits mean_changed_bits "
                  "min_changed_bits max_changed_bits sample_sd_changed_bits").split()


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def verified_archive(cache, provided):
    path = provided or cache / f"hqc-{COMMIT}.tar.gz"
    if not path.exists() and provided is None:
        with tempfile.TemporaryDirectory(dir=cache) as tmp:
            download = Path(tmp) / "archive"
            subprocess.run(["curl", "--fail", "--silent", "--show-error", "--location",
                            "--retry", "2", "--max-time", "180", ARCHIVE_URL, "-o", download],
                           check=True)
            if sha256(download) != ARCHIVE_SHA:
                raise ValueError("downloaded HQC archive SHA-256 differs from the pinned release")
            download.replace(path)
    if sha256(path) != ARCHIVE_SHA:
        raise ValueError("HQC archive SHA-256 differs from the pinned release")
    return path


def extract_sources(archive, directory):
    with tarfile.open(archive, "r:gz") as package:
        for item in package:
            parts = PurePosixPath(item.name).parts
            if (len(parts) < 3 or parts[1] not in ("src", "lib", "kats")
                    or (parts[1] == "kats" and parts[2] != "ref") or item.isdir()):
                continue
            if not item.isfile() or ".." in parts or item.name.startswith("/"):
                raise ValueError("unexpected member in pinned HQC archive")
            path = directory.joinpath(*parts[1:])
            path.parent.mkdir(parents=True, exist_ok=True)
            with package.extractfile(item) as source, path.open("xb") as output:
                shutil.copyfileobj(source, output)


def kat_bytes(path, level):
    if sha256(path) != KAT_SHA[level]:
        raise ValueError(f"HQC-{level} official KAT SHA-256 mismatch")
    records = path.read_text(encoding="ascii").strip().split("\n\n")[1:]
    if len(records) != 100:
        raise ValueError(f"HQC-{level} requires all 100 official KAT records")
    data = bytearray()
    for count, record in enumerate(records):
        fields = dict(line.split(" = ", 1) for line in record.splitlines())
        if fields["count"] != str(count):
            raise ValueError(f"HQC-{level} unexpected KAT index")
        for field in ("seed", "pk", "sk", "ct", "ss"):
            data.extend(bytes.fromhex(fields[field]))
    return data


def write_results(directory, trials, samples, provenance):
    groups = defaultdict(list)
    with (directory / "trials.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=TRIAL_FIELDS, lineterminator="\n")
        writer.writeheader()
        for row in trials:
            writer.writerow(row)
            rows = groups[row["kem"], row["component"], row["output"]]
            trial, bit = int(row["trial"]), int(row["flipped_bit"])
            n_in, n_out, d = (int(row[k]) for k in ("input_bits", "output_bits", "changed_bits"))
            if trial != len(rows) or bit != trial % n_in or not 0 <= d <= n_out:
                raise ValueError("invalid trial order, input bit or distance")
            rows.append((n_in, n_out, d))

    expected = {(f"HQC-{v}", x, y) for v in KAT_SHA
                for x, y in (("seed_kem", "pk"), ("m", "ct"), ("m", "ss"))}
    if set(groups) != expected:
        raise ValueError("one or more expected HQC experiment groups are missing")
    with (directory / "summary.csv").open("w", newline="") as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(SUMMARY_FIELDS)
        for key, rows in sorted(groups.items()):
            n_in, n_out = rows[0][:2]
            if len(rows) != samples or any(row[:2] != (n_in, n_out) for row in rows):
                raise ValueError("inconsistent number of trials or dimensions")
            distances = [row[2] for row in rows]
            writer.writerow([*key, samples, n_in, n_out, f"{statistics.mean(distances):.9f}",
                             min(distances), max(distances), f"{statistics.stdev(distances):.9f}"])
    provenance["output_sha256"] = {name: sha256(directory / name)
                                   for name in ("summary.csv", "trials.csv")}
    (directory / "metadata.json").write_text(json.dumps(provenance, indent=2) + "\n")


def run(args):
    if not 2 <= args.samples <= 100000:
        raise ValueError("--samples must be between 2 and 100000")
    output = args.output_dir.resolve()
    if output.exists():
        raise ValueError("output directory already exists; choose a new directory")
    cache = ROOT / "build/hqc-avalanche"
    cache.mkdir(parents=True, exist_ok=True)
    archive = verified_archive(cache, args.archive)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=cache) as tmp, \
            tempfile.TemporaryDirectory(dir=output.parent) as stage:
        source, build = Path(tmp) / "source", Path(tmp) / "build"
        extract_sources(archive, source)
        subprocess.run(["cmake", "-S", ADAPTER, "-B", build, "-G", "Ninja",
                        f"-DHQC_SOURCE={source}", "-DPQ_WITH_REFERENCE=ON",
                        "-DCMAKE_BUILD_TYPE=Release"], check=True)
        subprocess.run(["cmake", "--build", build, "--parallel", "4"], check=True)
        trials = []
        for level in KAT_SHA:
            exe = build / f"avalanche_{level}"
            kat = source / f"kats/ref/hqc-{level}/PQCkemKAT_32.rsp"
            subprocess.run([exe, "kat"], input=kat_bytes(kat, level), check=True)
            print(f"HQC-{level}: 100 official KATs passed; measuring {args.samples} pairs",
                  flush=True)
            result = subprocess.run([exe, "measure", str(args.samples)], text=True,
                                    stdout=subprocess.PIPE, check=True)
            trials.extend(csv.DictReader(result.stdout.splitlines(), fieldnames=TRIAL_FIELDS))
        provenance = {
            "implementation": "official HQC portable C reference (ref)",
            "upstream": "https://gitlab.com/pqc-hqc/hqc", "tag": "v5.1.0", "commit": COMMIT,
            "specification_date": "2026-11-09",
            "specification_url": "https://pqc-hqc.org/doc/hqc_specifications_v5.1.pdf",
            "specification_sha256": "45be0bc16b6a44836a5f6d9f7bafbaf39e368d0bceac6aa1fea64d1320471b2f",
            "archive_url": ARCHIVE_URL, "archive_sha256": ARCHIVE_SHA,
            "reference_kats": {f"HQC-{k}": {"cases_passed": 100, "rsp_sha256": v}
                               for k, v in KAT_SHA.items()},
            "samples_per_level_per_experiment": args.samples,
            "inputs": "SHAKE256(ASCII('pqlab/hqc-avalanche/v1/HQC-{level}/{trial}')), "
                      "split as seed_kem[32] || m[16/24/32] || salt[16]; trial is zero-based",
            "flipped_bit": "trial modulo input_bits; bit zero is the LSB of the first byte",
            "keygen_pair": "flip one seed_kem bit; observe serialized public key",
            "encapsulation_pair": "flip one m bit, fix pk and salt within pair; observe "
                                  "serialized ciphertext including fixed salt, and shared secret",
            "controls": "exact coin-request lengths; all KAT pk,sk,ct,ss; baseline replay on "
                        "first trial of each level; one-bit input check; salt equality and "
                        "Decaps on both ciphertexts of every experimental pair",
            "method_sha256": {str(p.relative_to(ROOT)): sha256(p) for p in
                              (Path(__file__).resolve(), ADAPTER / "adapter.cpp", ADAPTER / "CMakeLists.txt")},
        }
        staging = Path(stage) / "verified"
        staging.mkdir()
        write_results(staging, trials, args.samples, provenance)
        staging.rename(output)
    print(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=768, help="pairs per level and input (default 768)")
    parser.add_argument("--archive", type=Path, help="use an offline copy of the pinned .tar.gz")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "results/hqc-avalanche")
    args = parser.parse_args()
    try:
        run(args)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"run_hqc_avalanche: {error}\n")


if __name__ == "__main__":
    main()
