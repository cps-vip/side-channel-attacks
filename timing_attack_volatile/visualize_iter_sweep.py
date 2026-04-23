import pandas as pd
import matplotlib.pyplot as plt

stats = pd.read_csv("iter_sweep_stats.csv")
pos_stats = pd.read_csv("iter_sweep_position_stats.csv")

# convert success to bool in case it's a string
stats["success"] = stats["success"].astype(str).str.lower() == "true"
pos_stats["was_correct"] = pos_stats["was_correct"].astype(str).str.lower() == "true"

iter_order = sorted(stats["iters"].unique())

# --- fig 1: success rate vs iterations ---
success_rate = stats.groupby("iters")["success"].mean() * 100
avg_runtime = stats.groupby("iters")["runtime_ns"].mean() / 1e9  # seconds

fig, ax = plt.subplots()
ax.bar([str(i) for i in iter_order], [success_rate[i] for i in iter_order], color="steelblue")
ax.set_xlabel("iterations (do_per_char_work)")
ax.set_ylabel("full password recovery rate (%)")
ax.set_title("success rate vs iterations (samples=101, runs=20)")
ax.set_ylim(0, 105)
for i, v in enumerate([success_rate[it] for it in iter_order]):
    ax.text(i, v + 1, f"{v:.0f}%", ha="center", fontsize=9)
plt.tight_layout()
plt.savefig("fig_iters_success_rate.png", dpi=150)
plt.close()
print("saved fig_iters_success_rate.png")

# --- fig 2: avg runtime vs iterations ---
fig, ax = plt.subplots()
ax.bar([str(i) for i in iter_order], [avg_runtime[i] for i in iter_order], color="seagreen")
ax.set_xlabel("iterations (do_per_char_work)")
ax.set_ylabel("average runtime per run (s)")
ax.set_title("runtime vs iterations (samples=101, runs=20)")
plt.tight_layout()
plt.savefig("fig_iters_runtime.png", dpi=150)
plt.close()
print("saved fig_iters_runtime.png")

# --- fig 3: per-character accuracy vs iterations ---
char_acc = pos_stats.groupby("iters")["was_correct"].mean() * 100

fig, ax = plt.subplots()
ax.bar([str(i) for i in iter_order], [char_acc[i] for i in iter_order], color="steelblue")
ax.set_xlabel("iterations (do_per_char_work)")
ax.set_ylabel("per-character accuracy (%)")
ax.set_title("per-character accuracy vs iterations")
ax.set_ylim(0, 105)
for i, v in enumerate([char_acc[it] for it in iter_order]):
    ax.text(i, v + 1, f"{v:.1f}%", ha="center", fontsize=9)
plt.tight_layout()
plt.savefig("fig_iters_char_accuracy.png", dpi=150)
plt.close()
print("saved fig_iters_char_accuracy.png")

# --- fig 4: avg gap_ns vs iterations (signal strength) ---
avg_gap = pos_stats.groupby("iters")["gap_ns"].mean()

fig, ax = plt.subplots()
ax.bar([str(i) for i in iter_order], [avg_gap[i] for i in iter_order], color="coral")
ax.set_xlabel("iterations (do_per_char_work)")
ax.set_ylabel("average gap (ns)")
ax.set_title("timing signal strength vs iterations")
plt.tight_layout()
plt.savefig("fig_iters_gap.png", dpi=150)
plt.close()
print("saved fig_iters_gap.png")

# --- fig 5: staircase plot for one successful run at 50000 iters ---
run1 = pos_stats[(pos_stats["iters"] == 50000) & (pos_stats["run"] == 1)].sort_values("position")
fig, ax = plt.subplots()
ax.plot(run1["position"], run1["chosen_score_ns"] / 1e6, marker="o", label="chosen char score")
ax.set_xlabel("position")
ax.set_ylabel("trimmed mean time (ms)")
ax.set_title("staircase: timing grows with each correct character (iters=50000)")
ax.set_xticks(run1["position"])
plt.tight_layout()
plt.savefig("fig_staircase.png", dpi=150)
plt.close()
print("saved fig_staircase.png")

print("\nsummary table:")
summary = pd.DataFrame({
    "iters": iter_order,
    "success_rate_%": [round(success_rate[i], 1) for i in iter_order],
    "char_accuracy_%": [round(char_acc[i], 1) for i in iter_order],
    "avg_runtime_s": [round(avg_runtime[i], 2) for i in iter_order],
    "avg_gap_ns": [round(avg_gap[i], 1) for i in iter_order],
})
print(summary.to_string(index=False))