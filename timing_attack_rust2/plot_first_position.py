import argparse
import csv
import statistics
from pathlib import Path


def median_by_candidate(measurements_path: Path, run_id: int) -> list[tuple[str, int]]:
    timings: dict[str, list[int]] = {}
    with measurements_path.open(newline="") as csv_file:
        for row in csv.DictReader(csv_file):
            if int(row["run"]) != run_id:
                continue
            if int(row["position"]) != 0 or row["phase"] != "measured":
                continue
            timings.setdefault(row["candidate"], []).append(int(row["elapsed_ns"]))
    return [(candidate, int(statistics.median(values))) for candidate, values in timings.items()]


def write_svg(points: list[tuple[str, int]], output_path: Path) -> None:
    width = 980
    height = 420
    margin_left = 55
    margin_right = 20
    margin_top = 35
    margin_bottom = 60
    plot_width = width - margin_left - margin_right
    plot_height = height - margin_top - margin_bottom
    max_value = max(value for _, value in points)
    bar_width = plot_width / len(points)
    correct_candidate = "P"

    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="white"/>',
        '<text x="490" y="22" text-anchor="middle" font-family="Arial" font-size="18">Position 0 median response time by candidate</text>',
        f'<line x1="{margin_left}" y1="{height - margin_bottom}" x2="{width - margin_right}" y2="{height - margin_bottom}" stroke="#333"/>',
        f'<line x1="{margin_left}" y1="{margin_top}" x2="{margin_left}" y2="{height - margin_bottom}" stroke="#333"/>',
        f'<text x="16" y="{margin_top + 8}" font-family="Arial" font-size="12">{max_value / 1_000_000:.1f} ms</text>',
        f'<text x="20" y="{height - margin_bottom}" font-family="Arial" font-size="12">0</text>',
        f'<text x="500" y="{height - 12}" text-anchor="middle" font-family="Arial" font-size="13">Candidate character</text>',
        '<text x="14" y="220" transform="rotate(-90 14 220)" text-anchor="middle" font-family="Arial" font-size="13">Median elapsed time</text>',
    ]

    for index, (candidate, value) in enumerate(points):
        x = margin_left + index * bar_width
        bar_height = (value / max_value) * plot_height
        y = height - margin_bottom - bar_height
        fill = "#cc4c02" if candidate == correct_candidate else "#7aa6c2"
        lines.append(
            f'<rect x="{x + 1:.2f}" y="{y:.2f}" width="{max(bar_width - 2, 1):.2f}" '
            f'height="{bar_height:.2f}" fill="{fill}"/>'
        )
        if candidate == correct_candidate or index % 3 == 0:
            lines.append(
                f'<text x="{x + bar_width / 2:.2f}" y="{height - margin_bottom + 16}" '
                f'text-anchor="middle" font-family="Arial" font-size="10">{candidate}</text>'
            )

    best_candidate, best_value = max(points, key=lambda item: item[1])
    lines.append(
        f'<text x="{width - 25}" y="46" text-anchor="end" font-family="Arial" font-size="13">'
        f'Best: {best_candidate} ({best_value / 1_000_000:.2f} ms)</text>'
    )
    lines.append("</svg>")
    output_path.write_text("\n".join(lines) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("results_dir", type=Path)
    parser.add_argument("--run", type=int, default=1)
    args = parser.parse_args()
    points = median_by_candidate(args.results_dir / "measurements.csv", args.run)
    if not points:
        raise SystemExit("no measurements found for requested run and position")
    write_svg(points, args.results_dir / f"position0_run{args.run}_medians.svg")


if __name__ == "__main__":
    main()
