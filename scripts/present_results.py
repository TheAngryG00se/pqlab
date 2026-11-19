#!/usr/bin/env python3
"""Build the pqlab presentation from ML-KEM and HQC experiments."""

import argparse
import csv
import json
import math
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from compare_bench import load_series
from kem_assessment_figure import assessment_figure
from plot_hqc_avalanche import hqc_avalanche_figure, read_distances
from presentation_style import BLUE, FIGURE_STYLE, GRID, INK, MUTED, ORANGE, TEAL, number, slide, span
from run_hqc_avalanche import COMMIT as HQC_COMMIT, KAT_SHA, sha256


ROOT = Path(__file__).resolve().parents[1]
KEMS = ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024")
OPERATIONS = {"keygen": "Генерация ключей", "encaps": "Инкапсуляция", "decaps": "Декапсуляция"}
ANALYSIS_FIELDS = "kem,component,output,samples,input_bits,output_bits,mean_changed_bits".split(",")
LATEST_PDF = ROOT / "output/pdf/pqlab.pdf"


@dataclass(frozen=True)
class Change:
    samples: int
    output_bits: int
    mean: float


def read_avalanche(path):
    expected = {(kem, part, output) for kem in KEMS for part in ("d", "z") for output in ("pk", "dk")}
    observed = {}
    with Path(path).open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames != ANALYSIS_FIELDS:
            raise ValueError("Неверный заголовок CSV pqanalyze")
        for line, row in enumerate(reader, 2):
            try:
                if None in row or None in row.values():
                    raise ValueError("неверное число полей")
                key = (row["kem"], row["component"], row["output"])
                if key not in expected or key in observed:
                    raise ValueError(f"неизвестная или повторная комбинация {key}")
                entry = Change(int(row["samples"]), int(row["output_bits"]), float(row["mean_changed_bits"]))
                if int(row["input_bits"]) != 256 or entry.output_bits <= 0 or entry.samples <= 0:
                    raise ValueError("недопустимое число наблюдений или длина входа/выхода")
                if not math.isfinite(entry.mean) or not 0 <= entry.mean <= entry.output_bits:
                    raise ValueError("расстояние Хэмминга вне диапазона")
                observed[key] = entry
            except ValueError as error:
                raise ValueError(f"{path}, строка {line}: {error}") from error
    if observed.keys() != expected:
        raise ValueError("В CSV отсутствуют результаты для одной или нескольких комбинаций ML-KEM")
    for kem in KEMS:
        for output in ("pk", "dk"):
            if observed[kem, "d", output].output_bits != observed[kem, "z", output].output_bits:
                raise ValueError(f"Длина {kem} {output} различается между опытами")
        for part in ("d", "z"):
            if observed[kem, part, "pk"].samples != observed[kem, part, "dk"].samples:
                raise ValueError(f"Число пар {kem} {part} различается для pk и dk")
    return observed


def read_hqc_run(directory):
    metadata_path = directory / "metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    expected_kats = {f"HQC-{level}": {"cases_passed": 100, "rsp_sha256": checksum}
                     for level, checksum in KAT_SHA.items()}
    if (not isinstance(metadata, dict) or metadata.get("tag") != "v5.1.0"
            or metadata.get("commit") != HQC_COMMIT or metadata.get("reference_kats") != expected_kats):
        raise ValueError(f"{metadata_path}: ожидались HQC v5.1.0 и 300 подтверждённых KAT")
    hashes = metadata.get("output_sha256")
    for name in ("summary.csv", "trials.csv"):
        path = directory / name
        if not isinstance(hashes, dict) or sha256(path) != hashes.get(name):
            raise ValueError(f"{path}: SHA-256 расходится с metadata.json")
    rows = read_distances(directory / "summary.csv")
    if any(row.samples != metadata.get("samples_per_level_per_experiment") for row in rows.values()):
        raise ValueError(f"{metadata_path}: число пар расходится с summary.csv")
    return rows


def publish_pdf(source_pdf, destination_pdf):
    destination_pdf.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=destination_pdf.parent) as tmp:
        staged = Path(tmp) / destination_pdf.name
        shutil.copyfile(source_pdf, staged)
        staged.replace(destination_pdf)


def horizontal_axis(ax, centers, labels, xlabel):
    from matplotlib.ticker import FuncFormatter

    ax.set_yticks(centers, labels=labels, size=17, weight="medium", color=INK)
    ax.set_xlabel(xlabel, size=15, color=MUTED, labelpad=12)
    ax.tick_params(axis="x", labelsize=13, colors=MUTED, length=0, pad=8)
    ax.tick_params(axis="y", length=0, pad=12)
    ax.spines[:].set_visible(False)
    ax.grid(axis="x", color=GRID, linewidth=.9)
    ax.set_axisbelow(True)
    ax.xaxis.set_major_formatter(FuncFormatter(lambda value, _: number(value, 2)))


def legend(fig, columns, y):
    from matplotlib.patches import Patch

    fig.legend(handles=[Patch(color=color, label=label) for label, color in columns],
               loc="center left", bbox_to_anchor=(.057, y), ncol=len(columns),
               borderaxespad=0, frameon=False, labelcolor=INK, fontsize=15,
               handlelength=1.0, columnspacing=2.2)


def footer(fig, line):
    fig.text(.057, .045, line, size=12, color=MUTED)


def latency_figure(plt, series):
    wanted = [("KEM", kem, op, 0) for kem in KEMS for op in OPERATIONS]
    if any(key not in series.summary for key in wanted):
        raise ValueError("Нужны три операции для всех трёх наборов ML-KEM")
    iterations = span([run[key]["iterations"] for run in series.runs for key in wanted])
    n = len(series.runs)
    description = "Медиана одного прогона" if n == 1 else (
        f"Медиана медиан по прогонам ({n}). Отрезки показывают минимум и максимум медиан"
    )
    fig = slide(plt, "Время операций ML-KEM", description)
    ax = fig.add_axes([.212, .23, .722, .48])
    centers = [2.3, 1.15, 0]
    horizontal_axis(ax, centers, list(OPERATIONS.values()), "Время одной операции, мкс")
    colors = (BLUE, TEAL, ORANGE)
    legend(fig, list(zip(KEMS, colors)), .766)
    highest = max(series.summary[key]["max_run_ns"] for key in wanted) / 1000
    for kem, color, offset in zip(KEMS, colors, (.26, 0, -.26)):
        for center, op in zip(centers, OPERATIONS):
            values = series.summary["KEM", kem, op, 0]
            y = center + offset
            v = values["median_run_ns"] / 1000
            low, high = values["min_run_ns"] / 1000, values["max_run_ns"] / 1000
            ax.barh(y, v, height=.185, color=color)
            if n > 1:
                ax.errorbar(v, y, xerr=[[v-low], [high-v]], fmt="none", ecolor=INK, capsize=3)
            ax.text(high + highest * .014, y, number(v), va="center", fontsize=13, color=INK)
    ax.set_xlim(0, highest * 1.16)
    ax.set_ylim(-.51, 2.81)
    meta = series.metadata
    fig.text(.057, .105, "Случайные входы подготовлены до начала замера.", size=14, color=MUTED)
    footer(fig, f"{meta['cpu']}  ·  {meta['compiler']}  ·  {meta['commit']}  ·  "
                f"Вызовов на операцию за прогон — {iterations}")
    return fig


def avalanche_figure(plt, rows):
    fig = slide(plt, "Лавинный эффект при генерации ключей",
                "В каждой паре входов меняли один бит в одной из двух 256-битных частей seed.")
    legend(fig, [("Открытый ключ (pk)", BLUE), ("Закрытый ключ (dk)", TEAL)], .77)
    centers = [2, 1, 0]
    for part, left in (("d", .172), ("z", .633)):
        ax = fig.add_axes([left, .24, .305, .405])
        ax.set_title(f"Изменение бита в {part}", loc="left", size=21, weight="bold", color=INK, pad=18)
        units = "Доля изменившихся битов, %" if part == "d" else "Изменившихся битов, среднее"
        horizontal_axis(ax, centers, KEMS, units)
        values = {}
        for kem in KEMS:
            for output in ("pk", "dk"):
                item = rows[kem, part, output]
                values[kem, output] = 100 * item.mean / item.output_bits if part == "d" else item.mean
        # One-bit changes in a full secret key would round to 0% on the left-hand scale.
        limit = max(1, max(values.values()) * 1.23)
        for kem, center in zip(KEMS, centers):
            for output, color, offset in (("pk", BLUE, .16), ("dk", TEAL, -.16)):
                v, y = values[kem, output], center + offset
                if v == 0:
                    ax.plot(0, y, marker="o", markersize=6, color=color, clip_on=False)
                else:
                    ax.barh(y, v, height=.22, color=color)
                label = number(v, 2) if part == "z" else f"{number(v)} %"
                ax.text(v + limit * .025, y, label, va="center", size=14, color=INK)
        ax.set_xlim(0, limit)
        ax.set_ylim(-.55, 2.55)
    samples = span([item.samples for item in rows.values()])
    fig.text(.057, .105, "d участвует в создании ключевой пары. z хранится в закрытом ключе для неявного отказа.",
             size=15, color=INK)
    footer(fig, f"pqanalyze  ·  Число пар входов на компоненту — {samples}  ·  "
                "Оба ключа измерены на одних и тех же парах.")
    return fig


def envelope_figure(plt):
    from matplotlib.patches import Rectangle

    fig = slide(plt, "Смена получателя в конверте PQL1",
                "Для каждого файла создаётся случайный ключ данных DEK длиной 32 байта.")
    diagram = fig.add_axes([0, 0, 1, 1])
    diagram.set(xlim=(0, 1), ylim=(0, 1))
    diagram.axis("off")

    def cell(x, width, y, label, background, edge, textcolor=INK):
        height = .091
        diagram.add_patch(Rectangle((x, y), width, height, facecolor=background,
                                    edgecolor=edge, linewidth=1.3))
        diagram.text(x + width / 2, y + height / 2, label, fontsize=14, color=textcolor,
                     ha="center", va="center", linespacing=1.5)

    columns = ((.183, "A", "Параметры"), (.375, "B", "Упаковка ключа"),
               (.632, "", "Зашифрованные данные и теги"))
    for x, part, title in columns:
        diagram.text(x, .731, f"{part}  {title}".strip(), fontsize=18, color=INK, weight="bold")

    for y, recipient, kek, edge, tint in (
        (.585, "Старый", "старым", BLUE, "#ebf2fa"),
        (.355, "Новый", "новым", ORANGE, "#fbefe6"),
    ):
        diagram.text(.057, y + .045, f"{recipient}\nполучатель", fontsize=18,
                     weight="medium", va="center", color=INK)
        cell(.183, .183, y, "Версия, шифр,\nпрефикс nonce", "#f1f5f6", "#9ab0b8")
        cell(.375, .248, y, f"ID ключа и капсула KEM\nDEK под {kek} KEK + тег", tint, edge)
        cell(.632, .114, y, "Фрагмент 1", "#eef7f5", "#88b5aa")
        cell(.746, .047, y, "Тег", "#d2e9e3", "#88b5aa")
        cell(.793, .032, y, "…", "white", "#88b5aa")
        cell(.825, .085, y, "Последний", "#eef7f5", "#88b5aa")
        cell(.910, .041, y, "Тег", "#d2e9e3", "#88b5aa")

    for x, action, color in ((.196, "Те же байты", MUTED), (.39, "Новая упаковка DEK", ORANGE),
                             (.646, "Те же фрагменты и теги", MUTED)):
        diagram.annotate("", xy=(x, .462), xytext=(x, .566),
                         arrowprops={"arrowstyle": "-|>", "color": color, "lw": 1.8})
        diagram.text(x + .014, .51, action, va="center", fontsize=14, color=color)

    def note(y, label, detail):
        diagram.text(.057, y, label, weight="bold", fontsize=15, color=INK, va="top")
        diagram.text(.207, y, detail, fontsize=15, color=INK, va="top", linespacing=1.4)

    note(.276, "Шифрование", "GCM использует ключ данных и шифрует фрагменты до 64 КиБ. У каждого — тег 16 байт.")
    note(.211, "Ротация ключа", "Старый закрытый ключ позволяет открыть DEK. Новый открытый ключ через KEM и HKDF\n"
         "даёт ключ упаковки KEK, которым защищают тот же DEK.")
    note(.113, "Копирование", "Криптография обрабатывает заголовок. Копирование файла в новый буфер\n"
         "занимает O(N) времени и памяти, где N — размер конверта.")
    return fig


def render(bench_paths, avalanche_path, output, hqc_rows):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_pdf import PdfPages

    series = load_series(bench_paths)
    changes = read_avalanche(avalanche_path)
    figures = (("pql1_rotation", envelope_figure, ()),
               ("mlkem_latency", latency_figure, (series,)),
               ("mlkem_avalanche", avalanche_figure, (changes,)),
               ("hqc_avalanche", hqc_avalanche_figure, (hqc_rows,)),
               ("kem_attack_assessment", assessment_figure, ()))
    style = {**FIGURE_STYLE, "pdf.fonttype": 42}
    with plt.rc_context(style), PdfPages(output / "pqlab.pdf", metadata={"Title": "Стенд pqlab"}) as pdf:
        for name, draw, inputs in figures:
            fig = draw(plt, *inputs)
            try:
                pdf.savefig(fig, facecolor="white")
                for extension in ("png", "svg"):
                    fig.savefig(output / f"{name}.{extension}", dpi=120, facecolor="white")
            finally:
                plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description="Презентация PQL1, экспериментов ML-KEM и HQC и оценки атак (PDF, PNG, SVG).")
    parser.add_argument("--bench-csv", type=Path, nargs="+", help="один или несколько CSV pqbench")
    parser.add_argument("--analysis-csv", type=Path, help="CSV эксперимента d/z из pqanalyze")
    parser.add_argument("--hqc-dir", type=Path, help="каталог готового опыта HQC с CSV и metadata.json")
    parser.add_argument("--output-dir", type=Path, help="новый каталог для результатов")
    args = parser.parse_args()
    if bool(args.bench_csv) != bool(args.analysis_csv):
        parser.error("укажите оба источника CSV или запустите без них для новых измерений")
    now = datetime.now(timezone.utc)
    output = args.output_dir or ROOT / "results" / now.strftime("%Y-%m-%d/presentation-%H%M%S-%fZ")
    try:
        output.mkdir(exist_ok=False, parents=True)
        bench_paths, avalanche_path = args.bench_csv, args.analysis_csv
        hqc_dir = args.hqc_dir
        if hqc_dir is None:
            standard_hqc = ROOT / "results/hqc-avalanche"
            if standard_hqc.exists():
                hqc_dir = standard_hqc
            elif bench_paths:
                hqc_dir = ROOT / "results/final/hqc-avalanche"
            else:
                hqc_dir = output.resolve() / "hqc"
                subprocess.run([sys.executable, ROOT / "scripts/run_hqc_avalanche.py",
                                "--output-dir", hqc_dir], cwd=ROOT, check=True)
        hqc_rows = read_hqc_run(hqc_dir)
        print(f"HQC: {hqc_dir.resolve()}", flush=True)
        if not bench_paths:
            subprocess.run(["cmake", "--preset", "release"], cwd=ROOT, check=True)
            subprocess.run(["cmake", "--build", "--preset", "release", "--target", "pqbench", "pqanalyze",
                            "--parallel", "4"], cwd=ROOT, check=True)
            apps = ROOT / "build/release/apps"
            series_dir, avalanche_path = output.resolve() / "bench", output / "avalanche.csv"
            subprocess.run([sys.executable, ROOT / "scripts/run_bench.py", "--suite", "kem",
                            "--filter", "ML-KEM-", "--repeats", "5", "--no-plots",
                            "--output-dir", series_dir], cwd=ROOT, check=True)
            bench_paths = sorted(series_dir.glob("run-*.csv"))
            subprocess.run([apps / "pqanalyze/pqanalyze", "--samples", "256", "--output", avalanche_path],
                           check=True)
        render(bench_paths, avalanche_path, output, hqc_rows)
        if args.output_dir is None:
            publish_pdf(output / "pqlab.pdf", LATEST_PDF)
            print(LATEST_PDF)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"present_results: {error}\n")
    print(output.resolve())


if __name__ == "__main__":
    main()
