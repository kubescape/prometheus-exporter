# Summary-read baseline

Measured on 1 November 2026 with Go 1.26.9, darwin/arm64, Apple M4 (`GOMAXPROCS=10`). Each value is the median of three benchmark runs with a one-second target per case.

Baseline: upstream `9faa9cf4a7d0be562136cfe108f80856cbdc8361`. The same benchmark was copied into an isolated baseline checkout with only its two method calls adapted to the old context-free signatures. The branch measurement uses the implementation in this change. The metric-schema fixture also passes against that unchanged upstream implementation.

## Workload reads over loopback HTTP

| Source / records | Baseline ms/read | Branch ms/read | Requests/read | Response bytes/read | Baseline bytes allocated/read | Branch bytes allocated/read |
|---|---:|---:|---:|---:|---:|---:|
| workload_configuration / 100 | 0.97 | 0.97 | 1 | 36,932 | 279,119 | 278,912 |
| workload_configuration / 1,000 | 8.64 | 8.59 | 2 | 368,278 | 2,903,233 | 2,902,535 |
| workload_configuration / 10,000 | 86.03 | 86.51 | 20 | 3,682,916 | 40,048,405 | 40,052,779 |
| workload_vulnerability / 100 | 1.50 | 1.51 | 1 | 55,528 | 358,920 | 359,128 |
| workload_vulnerability / 1,000 | 13.63 | 13.71 | 2 | 554,270 | 3,752,652 | 3,750,770 |
| workload_vulnerability / 10,000 | 139.40 | 139.81 | 20 | 5,542,836 | 53,113,659 | 53,110,914 |

The fixture serves 500 items per page. Responses include workload labels and severity data, are prepared outside the timed region, and are decoded by the generated storage client. Client-side QPS throttling is disabled. Each case measures one source; enabling both workload sources would read both inventories.

These small timing differences are descriptive measurements, not a statistically established speedup or regression. Request counts and response payload sizes are unchanged. This change adds cancellation checks and continuation-token tracking; its purpose is correctness and a reusable baseline.

The benchmark does not run Storage or measure its aggregation, disk access, server CPU, realistic network conditions, peak process heap, or concurrent scrapes. It is not sufficient evidence to choose production polling defaults. A real Storage/Prometheus comparison remains part of the recovery implementation.

## Reproduce

```sh
go test ./api -run '^$' -bench '^BenchmarkSummaryReads$' -benchmem -benchtime=1s -count=3
```

Compare on the same host with identical fixtures and no simultaneous test or benchmark run. `B/op` is cumulative allocation per read, not peak memory use.
