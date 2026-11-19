#!/usr/bin/env python3
"""Plot measured distances for the HQC v5.1.0 reference implementation."""

import argparse
import csv
import math
from dataclasses import dataclass
from pathlib import Path

from present_results import BLUE, GRID, INK, MUTED, ORANGE, TEAL, number, slide, span


COLUMNS = ("kem,component,output,samples,input_bits,output_bits,mean_changed_bits,"
           "min_changed_bits,max_changed_bits,sample_sd_changed_bits").split(",")
# m bits, serialized public key bytes, serialized ciphertext bytes in HQC v5.1.0.
SIZES = {"HQC-1": (128, 2241, 4433), "HQC-3": (192, 4514, 8978), "HQC-5": (256, 7237, 14421)}
PANELS = (("pk", "Открытый ключ", "Генерация ключей · seed → pk", BLUE),
          ("ct", "Шифротекст", "Инкапсуляция · m → ct", TEAL),
          ("ss", "Общий секрет", "Инкапсуляция · m → K", ORANGE))


@dataclass(frozen=True)
class Distance:
    samples: int
    bits: int
    mean: float
    minimum: int
    maximum: int
    sd: float

    def percent(self, distance):
        return 100 * distance / self.bits


def read_distances(path):
    rows = {}
    with Path(path).open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames != COLUMNS:
            raise ValueError("Ожидается заголовок summary.csv для эксперимента HQC v5.1.0")
        for row in reader:
            try:
                if None in row or None in row.values():
                    raise ValueError("неверное число полей")
                kem, output = row["kem"], row["output"]
                if kem not in SIZES or output not in ("pk", "ct", "ss") or (kem, output) in rows:
                    raise ValueError("неизвестная или повторная комбинация набора и выхода")
                message_bits, pk_bytes, ct_bytes = SIZES[kem]
                component = "seed_kem" if output == "pk" else "m"
                input_bits = 256 if output == "pk" else message_bits
                sizes = {"pk": 8 * pk_bytes, "ct": 8 * ct_bytes, "ss": 256}
                if (row["component"] != component or int(row["input_bits"]) != input_bits
                        or int(row["output_bits"]) != sizes[output]):
                    raise ValueError("компонента входа или длина не соответствует HQC v5.1.0")
                d = Distance(int(row["samples"]), int(row["output_bits"]), float(row["mean_changed_bits"]),
                             int(row["min_changed_bits"]), int(row["max_changed_bits"]),
                             float(row["sample_sd_changed_bits"]))
                if not (d.samples >= 2 and 0 <= d.minimum <= d.mean <= d.maximum <= d.bits
                        and math.isfinite(d.sd) and 0 <= d.sd <= d.maximum - d.minimum):
                    raise ValueError("недопустимая статистика расстояний Хэмминга")
                rows[kem, output] = d
            except ValueError as error:
                raise ValueError(f"{path}, строка {reader.line_num}: {error}") from error
    if len(rows) != len(PANELS) * len(SIZES):
        raise ValueError("Нужны результаты для каждого из трёх выходов каждого набора HQC")
    for kem in SIZES:
        if rows[kem, "ct"].samples != rows[kem, "ss"].samples:
            raise ValueError(f"Число пар для ct и K у {kem} различается")
    return rows


def render(rows, output_dir, extension):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.ticker import FuncFormatter, MaxNLocator

    shares = [d.percent(d.mean) for d in rows.values()]
    # Keep the same scale on every panel, including the 50% reference and the plotted intervals.
    low = min(50, *(d.percent(min(d.minimum, d.mean - d.sd)) for d in rows.values()))
    high = max(50, *(d.percent(max(d.maximum, d.mean + d.sd)) for d in rows.values()))
    pad = max(1, .09 * (high - low))
    limits = (max(0, low - pad), min(100, high + pad))
    with plt.rc_context({"font.family": "DejaVu Sans", "axes.unicode_minus": False,
                         "svg.hashsalt": "pqlab-hqc-avalanche"}):
        fig = slide(plt, "Лавинный эффект в HQC",
                    f"При изменении одного входного бита средняя доля изменившихся битов "
                    f"составила {number(min(shares), 2)}–{number(max(shares), 2)} %.")
        for index, (output, title, mapping, color) in enumerate(PANELS):
            left = .13 + index * .286
            fig.text(left, .732, title, fontsize=21, weight="bold", color=INK)
            fig.text(left, .681, mapping, fontsize=13.5, color=MUTED)
            ax = fig.add_axes([left, .295, .237, .347])
            positions = [2, 1, 0]
            ax.set_yticks(positions, list(SIZES) if index == 0 else [""] * len(SIZES))
            ax.tick_params(axis="y", length=0, pad=12, labelsize=15, colors=INK)
            ax.tick_params(axis="x", length=0, pad=7, labelsize=12, colors=MUTED)
            ax.xaxis.set_major_locator(MaxNLocator(nbins=4, steps=[1, 2, 5, 10]))
            ax.xaxis.set_major_formatter(FuncFormatter(lambda x, _: number(x, 2)))
            ax.set(xlim=limits, ylim=(-.4, 2.55))
            ax.spines[:].set_visible(False)
            ax.set_axisbelow(True)
            ax.grid(axis="x", color=GRID, linewidth=.8)
            ax.axvline(50, color=MUTED, linestyle="--", linewidth=1, zorder=1)
            for kem, y in zip(SIZES, positions):
                d = rows[kem, output]
                mean = d.percent(d.mean)
                ax.hlines(y, d.percent(d.minimum), d.percent(d.maximum), color=color, linewidth=1.6)
                ax.hlines(y, mean-d.percent(d.sd), mean+d.percent(d.sd), color=color, linewidth=6)
                ax.plot(mean, y, "o", markeredgecolor=color, markerfacecolor="white",
                        markersize=7, markeredgewidth=1.8, zorder=3)
                bits = f"{d.mean:,.1f}".replace(",", " ").replace(".", ",")
                percent = f"{mean:.2f}".replace(".", ",")
                ax.text(.5, y + .19, f"{percent} %   ·   {bits} бит", ha="center",
                        fontsize=13, color=INK, transform=ax.get_yaxis_transform(),
                        bbox={"facecolor": "white", "edgecolor": "none", "pad": 1})
        fig.text(.513, .208, "Доля изменившихся битов от полной длины выхода, %", ha="center",
                 fontsize=16, color=INK)
        fig.text(.057, .127, "Точка — среднее. Толстая линия — ±1 выборочное стандартное отклонение,"
                 " тонкая — минимум и максимум.", fontsize=14, color=INK)
        count = span([d.samples for d in rows.values()])
        fig.text(.057, .061, f"HQC v5.1.0 · эталонная реализация · Пар на комбинацию — {count}. "
                 "Соль фиксирована внутри пары и входит в длину шифротекста.", fontsize=12, color=MUTED)
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
            path = output_dir / f"hqc_avalanche.{extension}"
            fig.savefig(path, dpi=120, facecolor="white",
                        metadata={"Date": None} if extension == "svg" else None)
            if extension == "svg":
                # Matplotlib leaves a trailing space on each line of an SVG path.
                lines = path.read_text(encoding="utf-8").splitlines()
                path.write_text("\n".join(line.rstrip() for line in lines) + "\n", encoding="utf-8")
        finally:
            plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description="Построить научную фигуру HQC из измеренных расстояний.")
    parser.add_argument("csv", type=Path, help="summary.csv эксперимента HQC v5.1.0")
    parser.add_argument("--output-dir", type=Path, help="по умолчанию рядом с CSV")
    parser.add_argument("--format", choices=("svg", "png"), default="svg", help="по умолчанию SVG")
    args = parser.parse_args()
    try:
        render(read_distances(args.csv), args.output_dir or args.csv.parent, args.format)
    except (OSError, ValueError) as error:
        parser.exit(1, f"plot_hqc_avalanche: {error}\n")


if __name__ == "__main__":
    main()
