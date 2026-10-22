# v1.5 Performance Audit

**Baseline:** `dev` at `8562b23f0da21fe9f6c17f8367a30171b72b635b`, 2026-10-18.

## Measurement quality

The existing full local test gate passed once, but it runs active browser, streaming, firewall and container scenarios; its container snapshots are not an idle benchmark. No comparable idle CPU/memory sample, long-duration memory-growth run, browser heap profile, or history-scale query benchmark was captured. Therefore no absolute idle resource claim is made. `build.ps1 release`/Docker-based repeat measurements are blocked while Docker Desktop's Linux engine is unavailable.

The current implementation does provide a deterministic structural baseline in code: authenticated Statistics SSE is bounded to 16 subscribers (`internal/monitoring/feed.go`); each subscriber sends an initial health snapshot and reevaluates health on a 15-second tick (`internal/admin/server.go:statisticsEvents`); the SPA separately refreshes the full initial API every 30 seconds (`internal/admin/frontend/src/main.tsx`). Four SSE evaluations per minute per connected browser plus two redundant bootstrap refreshes yields approximately 6 evaluations per steady browser-minute, or 96 evaluations/minute at 16 browsers (ignoring connection starts/retries). Health evaluation fans out to several probes and writes health-state JSON even when the observed state has not changed. This is a source-derived request/write count, not a CPU measurement.

## Bottlenecks and correctness affecting metrics

| Area | Evidence | Planned measurable improvement |
| --- | --- | --- |
| Repeated health work | 15-second health evaluation is performed once per SSE client; initial poll repeats much of that data. | Produce one shared bounded sample per interval, serve it to all subscribers, and remove redundant 30-second bootstrap polling while keeping initial fetch/reconnect snapshots. Assert probe count across 1 and max subscribers. |
| Persistent writes | Each evaluation records health and the current path writes the state file even when unchanged. | Compare canonical state first and avoid unchanged disk syncs. Test exact writes and ensure real transitions remain durable. |
| CPU accounting | `readCPU` totals guest counters twice. | Correct the denominator and verify known counter deltas including guest time. |
| Historical error rate | Per-interval percentages are averaged equally by `aggregateProxy`. | Retain request/error denominators and test unequal request volumes; report a weighted result. |
| Frontend polling/rendering | Full `/api/initial` polling runs every 30 seconds despite SSE; security ban countdown refreshes the full panel every five seconds. | Remove duplicate polling and isolate countdown updates to their small display; check network request count and browser interactions. |
| Charts | Charts use simplistic per-series maximum scaling, have sparse axis context/tooltips and independent range controls; history can be large. | Share range/time cursor, label units and time axes, preserve unavailable-vs-zero semantics, and measure render time with 90-day fixture data. |

## Before/after plan

Use a repeatable isolated fixture, same host and browser, same container limits, and report warm-up plus sample duration. Record idle and one-browser resource values before and after, then run a bounded 16-subscriber health-stream test and compare health probe count, file sync count, server CPU/memory, browser request count and reconnect behavior. Use a fixed large history fixture for chart render timing and browser heap. Report raw conditions/results; if Docker remains unavailable, leave these as blocked and do not infer a gain from code structure alone.

### Candidate implementation result

The working tree now shares component-health observations for 15 seconds
across callers, skips persistence when health state is unchanged, and no longer
polls the full initial API every 30 seconds. Unit tests cover health sampling,
state transitions and persistence behavior. Historical error-rate aggregation
is request weighted, and CPU guest counters are no longer double-counted.
These are code/test-backed reductions and correctness fixes; they are not
measured CPU, memory, or latency improvements.

For the same 16-browser cap used above, code structure changes steady-state
health work from up to 64 SSE-triggered observations per minute to at most 4
shared observations per minute (one per 15-second cache window), a 93.75%
reduction in health observation calls. It also removes up to 32 periodic full
bootstrap requests per minute. Unchanged health state now causes no durable
state-file rewrite. These are derived upper bounds, not load-test measurements;
connection starts, retries and actual resource use are excluded.

### Baseline result

No comparable before/after measurement exists. The baseline structural rates
above and candidate test assertions are the only quantitative evidence. Active
integration-run figures are intentionally excluded because concurrent tests
make them incomparable to idle operation. A fixed-fixture comparison of idle
CPU/RSS, SSE fan-out/probe/write counts, browser requests, and large-history
render/heap remains a release blocker; no performance gain is claimed.
