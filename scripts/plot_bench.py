#!/usr/bin/env python3
"""Plot measured pqbench CSV data; never generate benchmark values."""

import argparse
import csv
import math
import re
from collections import defaultdict
from pathlib import Path

FIELDS = (
    "timestamp,commit,cpu,compiler,flags,primitive,param,op,msg_bytes,iterations,"
    "median_cycles,p5_cycles,p95_cycles,median_ns,stddev_ns"
).split(",")
OPS = {
    "KEM": {"keygen", "encaps", "decaps"},
    "cipher": {"set_key", "encrypt", "decrypt"},
    "AEAD": {"seal", "open"},
    "hybrid": {"seal", "open"},
}
COLORS = ("#2563eb", "#16a085", "#e18b26", "#934fc2", "#da5475", "#64748b")

def name_order(name):
    return tuple(int(part) if part.isdecimal() else part for part in re.split(r"(\d+)", name))


def load_rows(path):
    with Path(path).open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames != FIELDS:
            raise ValueError("CSV columns must match the pqbench schema")
        rows = list(reader)
    if not rows:
        raise ValueError("CSV contains no measurements")
    metadata = None
    seen = set()
    for line, row in enumerate(rows, 2):
        try:
            if None in row or any(value is None for value in row.values()):
                raise ValueError("wrong number of fields")
            identity = tuple(row[key] for key in ("timestamp", "commit", "cpu", "compiler", "flags"))
            if metadata is not None and identity != metadata:
                raise ValueError("different runs must not be mixed into one comparison")
            metadata = identity
            if row["primitive"] not in OPS or row["op"] not in OPS[row["primitive"]]:
                raise ValueError("unsupported primitive/operation")
            if not row["param"]:
                raise ValueError("missing algorithm name")
            for key in ("msg_bytes", "iterations"):
                row[key] = int(row[key])
            if row["msg_bytes"] < 0 or row["iterations"] <= 0:
                raise ValueError("invalid size or iteration count")
            if row["primitive"] == "KEM" and row["iterations"] < 10000:
                raise ValueError("KEM measurements need at least 10000 iterations")
            for key in ("median_ns", "stddev_ns"):
                row[key] = float(row[key])
                if not math.isfinite(row[key]):
                    raise ValueError("non-finite timing")
            if row["median_ns"] <= 0 or row["stddev_ns"] < 0:
                raise ValueError("invalid timing")
            cycle_keys = ("median_cycles", "p5_cycles", "p95_cycles")
            present = [bool(row[key]) for key in cycle_keys]
            if any(present) and not all(present):
                raise ValueError("incomplete cycle statistics")
            for key in cycle_keys:
                row[key] = float(row[key]) if row[key] else None
            if all(present):
                values = [row[key] for key in cycle_keys]
                if any(not math.isfinite(v) or v <= 0 for v in values):
                    raise ValueError("invalid cycle statistics")
                if not row["p5_cycles"] <= row["median_cycles"] <= row["p95_cycles"]:
                    raise ValueError("percentiles are out of order")
            key = tuple(row[k] for k in ("primitive", "param", "op", "msg_bytes"))
            if key in seen:
                raise ValueError("duplicate measurement; do not average medians")
            seen.add(key)
        except (ValueError, TypeError) as error:
            raise ValueError(f"CSV line {line}: {error}") from error
    return rows


def throughput_mib(row):
    return row["msg_bytes"] * 1e9 / row["median_ns"] / (1024 * 1024)


def render(rows, output_dir, formats):
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.ticker import FuncFormatter

    plt.rcParams.update({
        "font.family": "DejaVu Sans", "font.size": 10,
        "axes.spines.top": False, "axes.spines.right": False,
        "axes.titleweight": "bold", "figure.facecolor": "white",
        "axes.prop_cycle": plt.cycler(color=COLORS), "svg.fonttype": "none",
    })
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    meta = rows[0]
    footer = (
        f"{meta['cpu']} · {meta['compiler']}\n"
        f"{meta['commit']} · {meta['timestamp']} · только измеренные значения"
    )
    paths = []

    def save(fig, name):
        fig.text(0.07, 0.02, footer, fontsize=8, color="#64748b")
        fig.subplots_adjust(bottom=0.19, top=0.88, left=0.10, right=0.97)
        for extension in formats:
            path = output_dir / f"{name}.{extension}"
            fig.savefig(path, dpi=180, facecolor="white")
            paths.append(path)
        plt.close(fig)

    kem = [r for r in rows if r["primitive"] == "KEM"]
    operations = ("keygen", "encaps", "decaps")
    if kem:
        names = sorted({r["param"] for r in kem}, key=name_order)
        fig, ax = plt.subplots(figsize=(max(9, len(names) * 1.8), 5.6))
        width = 0.23
        for index, op in enumerate(operations):
            data = {r["param"]: r for r in kem if r["op"] == op}
            positions = [i + (index - 1) * width for i, name in enumerate(names) if name in data]
            values = [data[name]["median_ns"] / 1000 for name in names if name in data]
            bars = ax.bar(positions, values, width, label=op, color=COLORS[index])
            ax.bar_label(bars, labels=[f"{v:.1f}" for v in values], padding=4, fontsize=8)
        ax.set_xticks(range(len(names)), names)
        ax.set_ylabel("Медиана времени, мкс · меньше — быстрее")
        ax.set_title("KEM: создание ключей, инкапсуляция и декапсуляция", pad=18)
        ax.set_ylim(bottom=0)
        ax.margins(y=0.18)
        ax.set_axisbelow(True)
        ax.grid(axis="y", alpha=0.18)
        ax.legend(ncol=3, frameon=False)
        save(fig, "kem_latency")

        if all(r["median_cycles"] is not None for r in kem):
            fig, axes = plt.subplots(1, 3, figsize=(13, 5.6), sharey=True)
            for index, (ax, op) in enumerate(zip(axes, operations)):
                data = {r["param"]: r for r in kem if r["op"] == op}
                points = [(i, data[name]) for i, name in enumerate(names) if name in data]
                ax.errorbar(
                    [r["median_cycles"] for _, r in points], [i for i, _ in points],
                    xerr=[
                        [r["median_cycles"] - r["p5_cycles"] for _, r in points],
                        [r["p95_cycles"] - r["median_cycles"] for _, r in points],
                    ],
                    fmt="o", capsize=5, color=COLORS[index],
                )
                ax.set_title(op)
                ax.set_xlabel("Тысячи тактов TSC")
                ax.xaxis.set_major_formatter(FuncFormatter(lambda value, _: f"{value / 1000:g}"))
                ax.set_xlim(left=0)
                ax.grid(axis="x", alpha=0.18)
            axes[0].set_yticks(range(len(names)), names)
            axes[0].invert_yaxis()
            fig.suptitle("KEM: медиана и диапазон p5–p95")
            fig.subplots_adjust(wspace=0.22)
            save(fig, "kem_cycles")

    for primitive in ("cipher", "AEAD", "hybrid"):
        for op in sorted(OPS[primitive] - {"set_key"}):
            data = [
                r for r in rows
                if r["primitive"] == primitive and r["op"] == op and r["msg_bytes"] > 0
            ]
            if not data:
                continue
            groups = defaultdict(list)
            for row in data:
                groups[row["param"]].append(row)
            fig, ax = plt.subplots(figsize=(10, 6))
            for name, group in sorted(groups.items(), key=lambda item: name_order(item[0])):
                group.sort(key=lambda r: r["msg_bytes"])
                values = [
                    r["median_ns"] / 1e6 if primitive == "hybrid" else throughput_mib(r)
                    for r in group
                ]
                ax.plot([r["msg_bytes"] for r in group], values, "o-", label=name, linewidth=2)
            ax.set_xscale("log", base=2)
            ax.set_xlabel("Размер сообщения, байт")
            ylabel = "Медиана времени, мс" if primitive == "hybrid" else "Скорость, МиБ/с"
            ax.set_ylabel(ylabel)
            if primitive == "hybrid":
                ax.set_yscale("log")
            else:
                ax.set_ylim(bottom=0)
            ax.set_title(f"{primitive}: {op} на разных размерах сообщений", pad=18)
            ax.grid(alpha=0.18, which="both")
            ax.legend(frameon=False, fontsize=8)
            metric = "latency" if primitive == "hybrid" else "throughput"
            save(fig, f"{primitive.lower()}_{op}_{metric}")
    if not paths:
        raise ValueError("CSV contains no supported plottable measurements")
    return paths


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--formats", default="png,svg")
    args = parser.parse_args()
    formats = args.formats.split(",")
    if not formats or any(fmt not in {"png", "svg", "pdf"} for fmt in formats):
        parser.error("formats must be a comma-separated selection of png,svg,pdf")
    try:
        rows = load_rows(args.csv)
        output = args.output_dir or args.csv.parent / "plots"
        for path in render(rows, output, formats):
            print(path)
    except (ValueError, OSError, ImportError) as error:
        parser.exit(1, f"plot_bench: {error}\n")


if __name__ == "__main__":
    main()
