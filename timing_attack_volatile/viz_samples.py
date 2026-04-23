import pandas as pd
import matplotlib.pyplot as plt

stats = pd.read_csv("sample_sweep_stats.csv")
pos_stats = pd.read_csv("sample_sweep_position_stats.csv")

stats["success"] = stats["success"].astype(str).str.lower() == "true"
pos_stats["was_correct"] = pos_stats["was_correct"].astype(str).str.lower() == "true"

sample_order = sorted(stats["samples"].unique())

success_rate = stats.groupby("samples")["success"].mean() * 100
char_acc = pos_stats.groupby("samples")["was_correct"].mean() * 100
avg_runtime = stats.groupby("samples")["runtime_ns"].mean() / 1e9
avg_gap = pos_stats.groupby("samples")["gap_ns"].mean()

# --- fig 1: success rate vs samples ---
fig, ax = plt.subplots()
ax.bar([str(s) for s in sample_order], [success_rate[s] for s in sample_order], color="steelblue")
ax.set_xlabel("samples")
ax.set_ylabel("full password recovery rate (%)")
ax.set_title("success rate vs samples (iters=10000, runs=50)")
ax.set_ylim(0, 105)
for i, v in enumerate([success_rate[s] for s in sample_order]):
    ax.text(i, v + 1, f"{v:.0f}%", ha="center", fontsize=9)
plt.tight_layout()
plt.savefig("fig_samples_success_rate.png", dpi=150)
plt.close()
print("saved fig_samples_success_rate.png")

# --- fig 2: per-character accuracy vs samples ---
fig, ax = plt.subplots()
ax.bar([str(s) for s in sample_order], [char_acc[s] for s in sample_order], color="steelblue")
ax.set_xlabel("samples")
ax.set_ylabel("per-character accuracy (%)")
ax.set_title("per-character accuracy vs samples (iters=10000, runs=50)")
ax.set_ylim(0, 105)
for i, v in enumerate([char_acc[s] for s in sample_order]):
    ax.text(i, v + 1, f"{v:.1f}%", ha="center", fontsize=9)
plt.tight_layout()
plt.savefig("fig_samples_char_accuracy.png", dpi=150)
plt.close()
print("saved fig_samples_char_accuracy.png")

# --- fig 3: runtime vs samples ---
fig, ax = plt.subplots()
ax.bar([str(s) for s in sample_order], [avg_runtime[s] for s in sample_order], color="seagreen")
ax.set_xlabel("samples")
ax.set_ylabel("average runtime per run (s)")
ax.set_title("runtime vs samples (iters=10000, runs=50)")
plt.tight_layout()
plt.savefig("fig_samples_runtime.png", dpi=150)
plt.close()
print("saved fig_samples_runtime.png")

# --- fig 4: avg gap vs samples ---
fig, ax = plt.subplots()
ax.bar([str(s) for s in sample_order], [avg_gap[s] for s in sample_order], color="coral")
ax.set_xlabel("samples")
ax.set_ylabel("average gap (ns)")
ax.set_title("timing signal strength vs samples (iters=10000, runs=50)")
plt.tight_layout()
plt.savefig("fig_samples_gap.png", dpi=150)
plt.close()
print("saved fig_samples_gap.png")

print("\nsummary table:")
summary = pd.DataFrame({
    "samples": sample_order,
    "success_rate_%": [round(success_rate[s], 1) for s in sample_order],
    "char_accuracy_%": [round(char_acc[s], 1) for s in sample_order],
    "avg_runtime_s": [round(avg_runtime[s], 2) for s in sample_order],
    "avg_gap_ns": [round(avg_gap[s], 1) for s in sample_order],
})
print(summary.to_string(index=False))