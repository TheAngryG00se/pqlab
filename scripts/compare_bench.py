#!/usr/bin/env python3
"""Summarize independent pqbench runs and optionally compare them with a baseline."""

import argparse
import csv
import statistics
from dataclasses import dataclass
from pathlib import Path

from plot_bench import COLORS, load_rows, name_order

CONFIG_FIELDS = ("commit", "cpu", "compiler", "flags")
KEY_FIELDS = ("primitive", "param", "op", "msg_bytes")
SUMMARY_FIELDS = list(CONFIG_FIELDS + KEY_FIELDS) + [
    "runs", "median_run_ns", "min_run_ns", "max_run_ns", "run_stddev_ns", "run_cv_pct",
    "ops_per_second", "mib_per_second", "median_run_cycles", "median_run_p5_cycles",
    "median_run_p95_cycles", "median_within_run_stddev_ns",
]


@dataclass
class Series:
    paths: list
    runs: list
    metadata: dict
    summary: dict


def row_key(row):
    return tuple(row[field] for field in KEY_FIELDS)


def key_order(key):
    return key[0], name_order(key[1]), key[2], key[3]


def summarize(rows):
    """Statistics of run medians; these are never pooled operation quantiles."""
    times = [row["median_ns"] for row in rows]
    median = statistics.median(times)
    deviation = statistics.pstdev(times)
    cycles = [row["median_cycles"] is not None for row in rows]
    if any(cycles) and not all(cycles):
        raise ValueError("cycle availability differs between runs")
    result = {field: rows[0][field] for field in CONFIG_FIELDS + KEY_FIELDS}
    result.update({
        "runs": len(rows), "median_run_ns": median,
        "min_run_ns": min(times), "max_run_ns": max(times),
        "run_stddev_ns": deviation,
        "run_cv_pct": deviation / statistics.mean(times) * 100,
        "ops_per_second": 1e9 / median,
        "mib_per_second": rows[0]["msg_bytes"] * 1e9 / median / 2**20
        if rows[0]["msg_bytes"] else None,
        "median_within_run_stddev_ns": statistics.median(row["stddev_ns"] for row in rows),
    })
    for source, target in (
        ("median_cycles", "median_run_cycles"),
        ("p5_cycles", "median_run_p5_cycles"),
        ("p95_cycles", "median_run_p95_cycles"),
    ):
        result[target] = statistics.median(row[source] for row in rows) if all(cycles) else None
    return result


def load_series(paths):
    paths = [Path(path).resolve() for path in paths]
    if not paths:
        raise ValueError("at least one CSV is required")
    if len(set(paths)) != len(paths):
        raise ValueError("the same CSV must not be counted twice")
    runs = []
    metadata = None
    expected_keys = None
    for path in paths:
        rows = load_rows(path)
        identity = {field: rows[0][field] for field in CONFIG_FIELDS}
        if metadata is not None and identity != metadata:
            raise ValueError("a series must use the same commit, CPU, compiler and flags")
        metadata = identity
        run = {row_key(row): row for row in rows}
        if expected_keys is not None and run.keys() != expected_keys:
            raise ValueError("every run must contain the same algorithms, operations and sizes")
        expected_keys = run.keys()
        runs.append(run)
    summary = {
        key: summarize([run[key] for run in runs]) for key in sorted(expected_keys, key=key_order)
    }
    return Series(paths, runs, metadata, summary)


def validate_baseline(current, baseline):
    if current.summary.keys() != baseline.summary.keys():
        raise ValueError("baseline must contain the same algorithms, operations and sizes")
    if current.metadata["cpu"] != baseline.metadata["cpu"]:
        raise ValueError("baseline comparison requires the same CPU model")
    if set(current.paths) & set(baseline.paths):
        raise ValueError("current series and baseline must use different CSV files")


def markdown(value):
    return str(value).replace("\n", " ").replace("|", "\\|")


def write_report(current, output_dir, baseline=None, label="current", baseline_label="baseline"):
    if baseline is not None:
        validate_baseline(current, baseline)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = output_dir / "summary.csv"
    with summary_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=SUMMARY_FIELDS)
        writer.writeheader()
        writer.writerows(current.summary.values())

    lines = [
        "# Измеренная производительность", "",
        "Центральное значение — медиана **медиан отдельных запусков**. "
        "Min–max и CV описывают разброс этих медиан; это не p5–p95 отдельных операций "
        "и не доверительный интервал. CV = stddev / среднее × 100%.", "",
        "p5/p95 и stddev внутри запусков сохранены в исходных CSV. "
        "Поля median_run_p5/p95_cycles в summary.csv — медианы перцентилей запусков, "
        "а не перцентили объединённой выборки. Такты обозначают TSC.", "",
    ]
    for title, series in ((label, current), (baseline_label, baseline)):
        if series is None:
            continue
        lines += [f"## {markdown(title)} · запусков: {len(series.runs)}", ""]
        lines += [f"- {field}: {markdown(series.metadata[field])}" for field in CONFIG_FIELDS]
        lines += ["", "Исходные CSV:", ""]
        for path, run in zip(series.paths, series.runs):
            first = next(iter(run.values()))
            counts = [row["iterations"] for row in run.values()]
            lines.append(
                f"- {markdown(path)} · {first['timestamp']} · "
                f"вызовов на измерение: {min(counts)}–{max(counts)}"
            )
        lines.append("")
    lines += [
        "## Результаты текущей серии", "",
        "| Алгоритм / операция | Байт | Медиана, мкс | Min–max, мкс | CV, % | Оп/с | МиБ/с |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for row in current.summary.values():
        throughput = "—" if row["mib_per_second"] is None else f"{row['mib_per_second']:.3f}"
        lines.append(
            f"| {markdown(row['param'])} / {row['op']} | {row['msg_bytes']} | "
            f"{row['median_run_ns'] / 1000:.3f} | "
            f"{row['min_run_ns'] / 1000:.3f}–{row['max_run_ns'] / 1000:.3f} | "
            f"{row['run_cv_pct']:.2f} | {row['ops_per_second']:.1f} | {throughput} |"
        )
    if baseline is not None:
        lines += [
            "", "## Сравнение с базовой серией", "",
            "Отношение времени = медиана базовой серии / медиана текущей. "
            "Значение > 1 означает меньшее время в текущей серии. "
            "Изменение времени < 0 означает ускорение. "
            "Различия компилятора и флагов видны в метаданных; "
            "сравнение само по себе не устанавливает причину изменения скорости.", "",
            "| Алгоритм / операция | Байт | Базовая, мкс | Текущая, мкс | Отношение времени | Изменение, % |",
            "|---|---:|---:|---:|---:|---:|",
        ]
        comparison_path = output_dir / "comparison.csv"
        with comparison_path.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream)
            writer.writerow(list(KEY_FIELDS) + [
                "baseline_median_run_ns", "current_median_run_ns", "latency_ratio",
                "time_change_pct",
            ])
            for key, row in current.summary.items():
                before = baseline.summary[key]["median_run_ns"]
                after = row["median_run_ns"]
                ratio = before / after
                change = (after / before - 1) * 100
                writer.writerow(list(key) + [before, after, ratio, change])
                lines.append(
                    f"| {markdown(row['param'])} / {row['op']} | {row['msg_bytes']} | "
                    f"{before / 1000:.3f} | {after / 1000:.3f} | {ratio:.3f} | {change:+.2f} |"
                )
    report_path = output_dir / "report.md"
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return report_path


def render_series(current, output_dir, baseline=None, label="current", baseline_label="baseline",
                  formats=("png", "svg")):
    if baseline is not None:
        validate_baseline(current, baseline)
    if not formats or any(fmt not in {"png", "svg", "pdf"} for fmt in formats):
        raise ValueError("formats must be a selection of png,svg,pdf")
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams.update({
        "font.family": "DejaVu Sans", "font.size": 10, "svg.fonttype": "none",
        "axes.spines.top": False, "axes.spines.right": False,
        "axes.titleweight": "bold", "figure.facecolor": "white",
    })
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    groups = [(label, current)]
    if baseline is not None:
        groups.append((baseline_label, baseline))
    footer = current.metadata["cpu"] + "\n" + "\n".join(
        f"{title}: {series.metadata['compiler']} · {series.metadata['commit']} · "
        f"{len(series.runs)} запусков" for title, series in groups
    )
    footer += "\nДиапазон min–max медиан запусков; это не доверительный интервал."
    paths = []

    def save(fig, name):
        fig.text(0.07, 0.015, footer, fontsize=8, color="#64748b")
        fig.subplots_adjust(bottom=0.25, top=0.85, left=0.08, right=0.97)
        for extension in formats:
            path = output_dir / f"{name}.{extension}"
            fig.savefig(path, dpi=180, facecolor="white")
            paths.append(path)
        plt.close(fig)

    kem_keys = [key for key in current.summary if key[0] == "KEM"]
    if kem_keys:
        operations = [op for op in ("keygen", "encaps", "decaps")
                      if any(key[2] == op for key in kem_keys)]
        names = sorted({key[1] for key in kem_keys}, key=name_order)
        fig, axes = plt.subplots(1, len(operations), squeeze=False,
                                 figsize=(max(9, len(operations) * len(names) * 1.55), 6))
        width = 0.34 if baseline else 0.55
        for ax, op in zip(axes[0], operations):
            for group_index, (title, series) in enumerate(groups):
                positions, values, low, high = [], [], [], []
                for index, name in enumerate(names):
                    key = ("KEM", name, op, 0)
                    if key not in series.summary:
                        continue
                    row = series.summary[key]
                    position = index + (group_index - (len(groups) - 1) / 2) * width
                    value = row["median_run_ns"] / 1000
                    positions.append(position)
                    values.append(value)
                    low.append(value - row["min_run_ns"] / 1000)
                    high.append(row["max_run_ns"] / 1000 - value)
                    samples = [run[key]["median_ns"] / 1000 for run in series.runs]
                    jitter = [position + (i - (len(samples) - 1) / 2) * width / max(len(samples), 1)
                              for i in range(len(samples))]
                    ax.scatter(jitter, samples, color="#0f172a", s=12, alpha=0.6, zorder=4)
                ax.bar(positions, values, width, yerr=[low, high], capsize=4,
                       color=COLORS[group_index], alpha=0.8,
                       label=f"{title} ({len(series.runs)})")
            ax.set_xticks(range(len(names)), names, rotation=15)
            ax.set_title(op)
            ax.set_ylim(bottom=0)
            ax.set_ylabel("Время операции, мкс")
            ax.set_axisbelow(True)
            ax.grid(axis="y", alpha=0.18)
        axes[0][0].legend(frameon=False, fontsize=9)
        fig.suptitle("KEM: медианы независимых запусков и диапазон min–max", fontweight="bold")
        save(fig, "kem_repeated_latency")

    for primitive in ("cipher", "AEAD", "hybrid"):
        operations = sorted({key[2] for key in current.summary if key[0] == primitive})
        for op in operations:
            keys = [key for key in current.summary if key[0] == primitive and key[2] == op
                    and (key[3] > 0 or op == "set_key")]
            if not keys:
                continue
            names = sorted({key[1] for key in keys}, key=name_order)
            fig, ax = plt.subplots(figsize=(11, 6))
            latency = primitive == "hybrid" or op == "set_key"
            for name_index, name in enumerate(names):
                name_keys = [key for key in keys if key[1] == name]
                name_keys.sort(key=lambda key: key[3])
                for group_index, (title, series) in enumerate(groups):
                    rows = [series.summary[key] for key in name_keys]
                    sizes = [row["msg_bytes"] for row in rows]
                    if op == "set_key":
                        row = rows[0]
                        position = name_index + (group_index - (len(groups) - 1) / 2) * 0.3
                        value = row["median_run_ns"] / 1000
                        ax.errorbar(position, value,
                                    yerr=[[value - row['min_run_ns'] / 1000],
                                          [row['max_run_ns'] / 1000 - value]],
                                    fmt="o", capsize=4, color=COLORS[group_index],
                                    label=title if name_index == 0 else None)
                        continue
                    if latency:
                        values = [row["median_run_ns"] / 1e6 for row in rows]
                        low = [row["min_run_ns"] / 1e6 for row in rows]
                        high = [row["max_run_ns"] / 1e6 for row in rows]
                    else:
                        values = [row["mib_per_second"] for row in rows]
                        low = [row["msg_bytes"] * 1e9 / row["max_run_ns"] / 2**20 for row in rows]
                        high = [row["msg_bytes"] * 1e9 / row["min_run_ns"] / 2**20 for row in rows]
                    color = COLORS[name_index % len(COLORS)]
                    ax.plot(sizes, values, "o-" if group_index == 0 else "s--", color=color,
                            label=f"{name} · {title}")
                    ax.fill_between(sizes, low, high, color=color, alpha=0.12)
            if op == "set_key":
                ax.set_xticks(range(len(names)), names)
                ax.set_ylabel("Время настройки ключа, мкс")
            else:
                ax.set_xscale("log", base=2)
                ax.set_xlabel("Размер сообщения, байт")
                ax.set_ylabel("Время операции, мс" if latency else "Скорость, МиБ/с")
            ax.set_ylim(bottom=0)
            ax.set_title(f"{primitive}: {op} · медианы запусков и диапазон min–max", pad=18)
            ax.grid(alpha=0.18, which="both")
            ax.legend(frameon=False, fontsize=8)
            save(fig, f"{primitive.lower()}_{op}_repeated")
    return paths


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv", nargs="+", type=Path)
    parser.add_argument("--baseline", nargs="+", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--label", default="current")
    parser.add_argument("--baseline-label", default="baseline")
    parser.add_argument("--formats", default="png,svg")
    parser.add_argument("--no-plots", action="store_true")
    args = parser.parse_args()
    try:
        current = load_series(args.csv)
        baseline = load_series(args.baseline) if args.baseline else None
        print(write_report(current, args.output_dir, baseline, args.label, args.baseline_label))
        if not args.no_plots:
            for path in render_series(current, args.output_dir / "plots", baseline,
                                      args.label, args.baseline_label, args.formats.split(",")):
                print(path)
    except (ValueError, OSError, ImportError) as error:
        parser.exit(1, f"compare_bench: {error}\n")


if __name__ == "__main__":
    main()
