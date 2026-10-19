"""Plot normalized Modbus feature distributions as a standalone SVG."""
import argparse
import html
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from apt_detection.physical_sensor.preprocessing import (  # noqa: E402
    FEATURE_COLUMNS,
    chronological_split,
    load_modbus_csv,
)

COLORS = ["#2457A7", "#D04A35", "#E49B24", "#2C8C62", "#8754A1", "#168A9C", "#B34E83"]


def text(x, y, value, size=12, anchor="start", weight="normal"):
    return '<text x="{}" y="{}" font-family="Arial,sans-serif" font-size="{}" text-anchor="{}" font-weight="{}">{}</text>'.format(
        x, y, size, anchor, weight, html.escape(str(value))
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=Path("data/raw/ton_iot/IoT_Modbus.csv"))
    parser.add_argument("--cutoff", default="2019-04-25")
    parser.add_argument("--output", type=Path, default=Path("docs/results/modbus_feature_distributions.svg"))
    args = parser.parse_args()

    train, test = chronological_split(load_modbus_csv(args.data), args.cutoff)
    series = []
    for period, frame in (("train", train), ("test", test)):
        normal = frame.loc[frame["label"] == 0]
        series.append(("{} normal".format(period), normal))
        attacks = frame.loc[frame["label"] == 1]
        series.extend(
            ("{} {}".format(period, kind), group)
            for kind, group in attacks.groupby("type", sort=True)
        )

    width, height = 1260, 890
    panels = [(35, 35), (650, 35), (35, 410), (650, 410)]
    parts = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="{}" height="{}" viewBox="0 0 {} {}">'.format(width, height, width, height),
        '<rect width="100%" height="100%" fill="white"/>',
        text(width / 2, 24, "TON_IoT Modbus feature distributions by split and class", 19, "middle", "bold"),
    ]

    bins = 32
    for feature, (panel_x, panel_y) in zip(FEATURE_COLUMNS, panels):
        plot_x, plot_y = panel_x + 68, panel_y + 42
        plot_w, plot_h = 520, 250
        histograms = []
        for name, frame in series:
            values = frame[feature].to_numpy(dtype=float)
            counts, edges = np.histogram(values, bins=bins, range=(0, 65536))
            percent = counts / max(len(values), 1) * 100
            histograms.append((name, len(values), percent))
        max_percent = max(float(values.max()) for _, _, values in histograms)
        y_max = max(2, int(np.ceil(max_percent / 2) * 2))

        parts.append(text(panel_x + 5, panel_y + 20, feature, 14, "start", "bold"))
        for tick in range(0, y_max + 1, max(1, y_max // 2)):
            y = plot_y + plot_h - tick / y_max * plot_h
            parts.append('<line x1="{}" y1="{}" x2="{}" y2="{}" stroke="#dddddd"/>'.format(plot_x, y, plot_x + plot_w, y))
            parts.append(text(plot_x - 9, y + 4, "{}%".format(tick), 10, "end"))
        parts.append('<line x1="{}" y1="{}" x2="{}" y2="{}" stroke="#333333"/>'.format(plot_x, plot_y, plot_x, plot_y + plot_h))
        parts.append('<line x1="{}" y1="{}" x2="{}" y2="{}" stroke="#333333"/>'.format(plot_x, plot_y + plot_h, plot_x + plot_w, plot_y + plot_h))

        for tick in (0, 16384, 32768, 49152, 65535):
            x = plot_x + tick / 65535 * plot_w
            parts.append('<line x1="{}" y1="{}" x2="{}" y2="{}" stroke="#999999"/>'.format(x, plot_y + plot_h, x, plot_y + plot_h + 5))
            parts.append(text(x, plot_y + plot_h + 18, tick, 9, "middle"))

        for index, (name, _, percent) in enumerate(histograms):
            points = []
            for bin_index, value in enumerate(percent):
                x = plot_x + (bin_index + 0.5) / bins * plot_w
                y = plot_y + plot_h - value / y_max * plot_h
                points.append("{:.1f},{:.1f}".format(x, y))
            parts.append('<polyline fill="none" stroke="{}" stroke-width="2" opacity="0.82" points="{}"/>'.format(
                COLORS[index], " ".join(points)
            ))
        parts.append(text(plot_x + plot_w / 2, plot_y + plot_h + 35, "Register value", 10, "middle"))

    legend_y = 805
    for index, (name, frame) in enumerate(series):
        column, row = index % 4, index // 4
        x, y = 50 + column * 300, legend_y + row * 24
        parts.append('<line x1="{}" y1="{}" x2="{}" y2="{}" stroke="{}" stroke-width="3"/>'.format(x, y - 4, x + 24, y - 4, COLORS[index]))
        parts.append(text(x + 32, y, "{} (n={:,})".format(name, len(frame)), 11))
    parts.append(text(width / 2, 875, "Each line is normalized to its group's percentage per 2,048-value bin.", 11, "middle"))
    parts.append("</svg>")

    output = args.output if args.output.is_absolute() else ROOT / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(parts), encoding="utf-8")
    print("Saved distribution plot to {}".format(output))
    print("Attack type is used only to group the curves, not as a model feature.")


if __name__ == "__main__":
    main()
