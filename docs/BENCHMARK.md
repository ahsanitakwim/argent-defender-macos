# Performance Benchmark

All numbers below are **measured**, not estimated. They come from `argent-engine scan`, which returns a benchmark with every scan (also shown in the app's "Performance benchmark" panel and stored in `scan.bench_json`).

## Run 1 — build host (Linux x86_64 VM, 2 vCPU, 8 GB RAM) — 10 Nov 2026

Corpus: 18,036 files / 340 MB (Rust crate sources incl. binary test fixtures and archives).

| Mode | Files scanned | Data | Duration | Throughput | CPU util. | Peak RAM | Findings |
|---|---|---|---|---|---|---|---|
| Quick (high-risk types) | 1,790 | 6.3 MB | 1.06 s | 5.7 MiB/s | 32 % | 35.5 MiB | 0 |
| Full (cold cache) | 18,036 | 296 MB | 6.98 s | 40.5 MiB/s | 53 % | 63.5 MiB | 0 |
| Incremental (unchanged) | 0 (18,036 cached) | 0 | 0.08 s | — | — | 49.5 MiB | 0 |
| Deep (warm OS cache) | 18,036 | 296 MB | 1.51 s | 186.9 MiB/s | 156 % | 63.5 MiB | 2 (both INFO/LOW, from an APK-shaped test fixture correctly identified by content) |

Single-sample timings: EICAR + 15 MB real APK + text file, Full mode: **234 ms**, 21 archive entries, 92 % CPU, 47 MiB peak RAM. APK static analysis (`apk`): **248 ms** for the 15 MB PCAPdroid APK. YARA-X rule compilation (9 bundled rules): 8 ms.

Observations: Quick mode is dominated by directory walking (filesystem metadata), Full-cold by disk I/O; the warm Deep run shows the CPU-bound ceiling on 2 vCPUs. No false-positive malware detections across 18k files.

## Still to measure on target hardware

The product targets MacBooks; these numbers are **not** MacBook numbers. Re-run on Intel and Apple Silicon:

```bash
ARGENT_DB=/tmp/bench.db argent-engine scan ~/Downloads --mode full --pretty | jq .data.bench
```

Record `duration_ms`, `throughput_mib_s`, `cpu_utilization_pct`, `peak_rss_mib`, `applications_inspected`. AI inference: the Isolation Forest (200 trees) runs inside `android audit`; time it from the `duration_ms` difference with/without ≥8 user apps. LLM latency depends on the chosen local model.
