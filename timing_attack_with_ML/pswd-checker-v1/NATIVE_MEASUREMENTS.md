# Native Windows timing experiment

Use this implementation for counter measurements. The earlier `timing_lab.py` is only a portable teaching baseline. All checker calls and the timed batch execute in compiled C; Python orchestrates experiments and writes results outside the timed region.

## Build and run

Requires Windows x64 with MSVC C++ Build Tools and an x86-64 processor exposing RDTSCP and invariant TSC. Initialization rejects unsupported processors. The local machine has the required compiler; no installation was performed.

```powershell
.\build_native.ps1
python -m unittest -v
python native_attack.py --cpu 0 --samples 400 --batch 1000 --output results/native-natural
python native_attack.py --cpu 0 --mode constant --samples 400 --batch 1000 --output results/native-control
```

`--cpu 0` pins the calling thread to logical CPU 0 in its current processor group, if allowed. Choose another allowed CPU as necessary. This does not identify whether a core is a performance or efficiency core. On machines with processor groups, this is not a global CPU index. Python and native code run sequentially on the same calling thread. Avoid concurrent callers: the native lab has process-global state.

Default `--work 0` means **no artificial amplification**. For an explicit teaching experiment use `--work 2000` with a smaller batch such as `--batch 10`. The fixed-work comparison performs the same amplification for every character. It is an experimental mitigation control, not a vetted production constant-time authentication function. Its equal-length loop reads every byte; input length remains observable. Inspect generated assembly when changing compilers or optimization options. The native checker uses volatile secret reads, noinline functions, and an observable accumulator to preserve benchmark execution. Those choices are part of the experiment and may differ from a production checker.

## What the columns mean

| CSV field | Meaning |
| --- | --- |
| `tsc_ticks_total` | Timestamp counter difference around the native batch, including timestamp boundary overhead. **Not actual core execution cycles.** |
| `thread_cycles_total` | Windows `QueryThreadCycleTime` difference; thread cycle accounting, including user/kernel execution and measurement overhead. Do not convert it into elapsed seconds. |
| `wall_ns_total` | QPC elapsed time, converted with QPC frequency. Includes thread-cycle queries and TSC boundaries as well as the batch. |
| `aux_start`, `aux_end` | RDTSCP auxiliary signatures at the two endpoints. Interpretation depends on the OS/hypervisor. |
| `endpoint_migration` | Different auxiliary signatures; sample is retained in CSV but excluded from ranking. Equal signatures do not prove there was no migration away and back. |

CSV values are **batch totals**. Rankings divide by batch size. Normalizing does not create individual-call measurements or improve the timer's physical resolution. Repeated candidates in a batch change cache and branch predictor state; repeat experiments at multiple batch sizes and report this limitation.

The TSC boundaries use compiler barriers and LFENCE/RDTSCP/LFENCE. CPU capability checks establish availability, not a universal precision guarantee under every hypervisor or processor implementation. Thread cycle accounting can have insufficient granularity for small batches. The three counters bracket different nested regions, so their differences are not an exact context-switch correction.

The summary saves 100 empty-check baseline samples. This baseline includes a loop and a function call; it is not pure timestamp overhead. Baselines are reported separately rather than subtracted from each measurement. Candidate collection is interleaved in randomized order, with warmup before each position. All raw samples, including endpoint migration flags, are retained.

## Accuracy and experimental interpretation

An invariant TSC runs at a fixed reference rate even when CPU execution frequency changes. Thus TSC ticks cannot be interpreted as actual core cycles. QPC is the Windows API for elapsed-time measurements. `QueryThreadCycleTime` is a separate accounting metric. Keep each metric separately labeled, and use `--metric wall_ns` or `--metric thread_cycles` to compare attack rankings.

Affinity reduces migration but does not prevent preemption, interrupts, SMT sibling interference, power/thermal changes, or virtualization noise. A TSC delta includes time while the thread is descheduled. This implementation **does not collect context-switch counts**. Use Windows Performance Recorder/Analyzer or another validated profiler in a subsequent experiment. Do not silently remove outliers until you have a predeclared filtering rule; retaining raw distributions is essential.

The attacker knows password length and alphabet. The victim is loaded in the same process for the lab; this does not establish a process isolation security boundary. Recovery receives measurements, not secret bytes. Greedy prefix ranking can propagate a single error. Success on one synthetic password is proof of a detectable local timing signal for that setup, not a general success rate or a trained ML result. Compare multiple secrets and sessions and a matched fixed-candidate detector benchmark before drawing stronger conclusions.

## Teammates on Mac and WSL2

This DLL backend is Windows x64 only. Apple Silicon cannot execute x86 RDTSCP natively. Apple documents CPU Counters and CPU Profiler in Instruments for hardware profiling. A native macOS backend or a validated mperf integration must be developed separately; do not call Mach timer ticks CPU cycles. Intel Macs also need a macOS build/backend. Keep distributions and recovery rates separate by machine, architecture, and counter type.

No mperf dependency has been added: the exact project/version intended by the instructor has not been identified. WSL2 access was denied in this session. Guest counter availability, physical core placement, and hypervisor behavior remain unverified. The native Windows experiment runs without WSL2.

## References

- [Microsoft: acquiring high-resolution time stamps](https://learn.microsoft.com/en-us/windows/win32/sysinfo/acquiring-high-resolution-time-stamps)
- [Microsoft: QueryThreadCycleTime](https://learn.microsoft.com/en-us/windows/win32/api/realtimeapiset/nf-realtimeapiset-querythreadcycletime)
- [Microsoft: RDTSCP intrinsic](https://learn.microsoft.com/en-us/cpp/intrinsics/rdtscp)
- [Intel manual: invariant TSC and RDTSCP](https://cdrdv2-public.intel.com/858456/253669-088-sdm-vol-3b.pdf)
- [Apple: optimize CPU performance with Instruments](https://developer.apple.com/videos/play/wwdc2025/308/)
