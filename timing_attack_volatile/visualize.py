"""
Timing Attack Statistical Visualizer
Reads timing_data.csv produced by the Rust attacker and generates
presentation-quality charts showing the side-channel leakage.

Usage:
    python visualize.py                  # uses timing_data.csv in current dir
    python visualize.py path/to/data.csv
"""

import sys
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

CSV_PATH = sys.argv[1] if len(sys.argv) > 1 else "timing_data.csv"

# ------- LOAD DATA ------
df = pd.read_csv(CSV_PATH)
positions = sorted(df["position"].unique())

# Per-position summary: one row per (position, character) with the trimmed mean
summary = (
    df.groupby(["position", "character"])["trimmed_mean_ns"]
    .first()
    .reset_index()
)

# Identify the winner (highest trimmed mean) at each position
winners = (
    summary.loc[summary.groupby("position")["trimmed_mean_ns"].idxmax()]
    .set_index("position")
)
recovered_password = "".join(winners["character"].values)

print(f"Recovered password: {recovered_password}")
print(f"Password length:    {len(recovered_password)}")


# ── Figure 1: Per-position bar chart (top-10 candidates) ────────────
fig1, axes = plt.subplots(
    nrows=2,
    ncols=int(np.ceil(len(positions) / 2)),
    figsize=(3.2 * int(np.ceil(len(positions) / 2)), 8),
    constrained_layout=True,
)
axes = axes.flatten()

for idx, pos in enumerate(positions):
    ax = axes[idx]
    pos_data = summary[summary["position"] == pos].copy()
    pos_data = pos_data.sort_values("trimmed_mean_ns", ascending=False).head(10)

    colors = [
        "#d62728" if c == winners.loc[pos, "character"] else "#1f77b4"
        for c in pos_data["character"]
    ]
    ax.barh(
        pos_data["character"].values[::-1],
        pos_data["trimmed_mean_ns"].values[::-1] / 1e6,  # convert to ms
        color=colors[::-1],
    )
    ax.set_title(
        f"Position {pos}  (winner: '{winners.loc[pos, 'character']}')",
        fontsize=10,
        fontweight="bold",
    )
    ax.set_xlabel("Trimmed mean (ms)", fontsize=8)
    ax.tick_params(labelsize=8)

# Hide unused subplots
for idx in range(len(positions), len(axes)):
    axes[idx].set_visible(False)

fig1.suptitle(
    f"Top-10 Candidate Timings Per Position   |   Recovered: \"{recovered_password}\"",
    fontsize=13,
    fontweight="bold",
)
fig1.savefig("fig1_bar_chart.png", dpi=180)
print("Saved fig1_bar_chart.png")


# ── Figure 2: Winner vs. runner-up distributions (box plots) ────────
fig2, axes2 = plt.subplots(
    nrows=2,
    ncols=int(np.ceil(len(positions) / 2)),
    figsize=(3.2 * int(np.ceil(len(positions) / 2)), 8),
    constrained_layout=True,
)
axes2 = axes2.flatten()

for idx, pos in enumerate(positions):
    ax = axes2[idx]

    # Get the top-2 characters by trimmed mean
    pos_summary = summary[summary["position"] == pos].sort_values(
        "trimmed_mean_ns", ascending=False
    )
    top2 = pos_summary.head(2)["character"].values  # [winner, runner_up]

    # Gather all raw samples for just those two
    winner_samples = df[
        (df["position"] == pos) & (df["character"] == top2[0])
    ]["raw_time_ns"].values / 1e6

    runner_samples = df[
        (df["position"] == pos) & (df["character"] == top2[1])
    ]["raw_time_ns"].values / 1e6

    bp = ax.boxplot(
        [runner_samples, winner_samples],
        labels=[f"'{top2[1]}' (2nd)", f"'{top2[0]}' (1st)"],
        patch_artist=True,
        widths=0.5,
    )
    bp["boxes"][0].set_facecolor("#1f77b4")
    bp["boxes"][1].set_facecolor("#d62728")

    ax.set_title(f"Position {pos}", fontsize=10, fontweight="bold")
    ax.set_ylabel("Time (ms)", fontsize=8)
    ax.tick_params(labelsize=8)

for idx in range(len(positions), len(axes2)):
    axes2[idx].set_visible(False)

fig2.suptitle(
    "Winner vs. Runner-Up Distributions (all 201 samples)",
    fontsize=13,
    fontweight="bold",
)
fig2.savefig("fig2_distributions.png", dpi=180)
print("Saved fig2_distributions.png")


# ── Figure 3: Confidence gap across positions ───────────────────────
gaps = []
for pos in positions:
    pos_summary = summary[summary["position"] == pos].sort_values(
        "trimmed_mean_ns", ascending=False
    )
    vals = pos_summary["trimmed_mean_ns"].values
    gaps.append(vals[0] - vals[1])

gaps_ms = np.array(gaps) / 1e6

fig3, ax3 = plt.subplots(figsize=(max(6, len(positions) * 0.8), 4), constrained_layout=True)
bars = ax3.bar(
    [str(p) for p in positions],
    gaps_ms,
    color=["#2ca02c" if g > np.median(gaps_ms) else "#ff7f0e" for g in gaps_ms],
)
ax3.axhline(np.median(gaps_ms), ls="--", color="gray", label=f"Median gap: {np.median(gaps_ms):.3f} ms")
ax3.set_xlabel("Password position", fontsize=10)
ax3.set_ylabel("Gap between 1st and 2nd candidate (ms)", fontsize=10)
ax3.set_title("Confidence Gap Per Position", fontsize=13, fontweight="bold")
ax3.legend()

# Annotate winner character on each bar
for i, pos in enumerate(positions):
    ax3.text(
        i, gaps_ms[i] + gaps_ms.max() * 0.02,
        f"'{winners.loc[pos, 'character']}'",
        ha="center", fontsize=9, fontweight="bold",
    )

fig3.savefig("fig3_confidence_gap.png", dpi=180)
print("Saved fig3_confidence_gap.png")


# ── Figure 4: Cumulative timing shows staircase pattern ─────────────
fig4, ax4 = plt.subplots(figsize=(max(6, len(positions) * 0.8), 4), constrained_layout=True)

winner_means = [winners.loc[p, "trimmed_mean_ns"] / 1e6 for p in positions]
ax4.plot(positions, winner_means, "o-", color="#d62728", linewidth=2, markersize=8)
for i, pos in enumerate(positions):
    ax4.annotate(
        f"'{winners.loc[pos, 'character']}'",
        (pos, winner_means[i]),
        textcoords="offset points",
        xytext=(0, 10),
        ha="center",
        fontsize=9,
        fontweight="bold",
    )

ax4.set_xlabel("Password position", fontsize=10)
ax4.set_ylabel("Winner trimmed mean (ms)", fontsize=10)
ax4.set_title(
    "Cumulative Timing Staircase",
    fontsize=12,
    fontweight="bold",
)
ax4.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))

fig4.savefig("fig4_staircase.png", dpi=180)
print("Saved fig4_staircase.png")


# ── Summary stats table (printed to terminal) ───────────────────────
print("\n" + "=" * 70)
print(f"  RECOVERED PASSWORD: {recovered_password}")
print("=" * 70)
print(f"{'Pos':<5} {'Char':<6} {'Trimmed Mean (ms)':<20} {'Gap (ms)':<15} {'Samples'}")
print("-" * 70)
for i, pos in enumerate(positions):
    char = winners.loc[pos, "character"]
    mean_ms = winners.loc[pos, "trimmed_mean_ns"] / 1e6
    n_samples = len(df[(df["position"] == pos) & (df["character"] == char)])
    print(f"{pos:<5} '{char}'   {mean_ms:<20.3f} {gaps_ms[i]:<15.3f} {n_samples}")
print("-" * 70)

plt.show()
