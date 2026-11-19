"""Shared colors, labels and canvas for the 16:9 presentation figures."""

INK, MUTED, GRID = "#142e3d", "#466371", "#d9e3e5"
BLUE, TEAL, ORANGE = "#2866a9", "#007867", "#b6501b"
FIGURE_STYLE = {"font.family": "DejaVu Sans", "axes.unicode_minus": False}


def number(value, digits=1):
    if digits == 0:
        return f"{value:.0f}"
    return f"{value:.{digits}f}".rstrip("0").rstrip(".").replace(".", ",")


def span(values):
    low, high = min(values), max(values)
    return (f"{low:,}" if low == high else f"{low:,}–{high:,}").replace(",", " ")


def slide(plt, title, subtitle):
    fig = plt.figure(figsize=(16, 9), facecolor="white")
    fig.text(.055, .91, title, size=37, weight="bold", color=INK)
    fig.text(.057, .849, subtitle, size=18, color=MUTED)
    return fig
