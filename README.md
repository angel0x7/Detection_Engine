# Tetragon + Sigma Detection Engine

A learning-oriented detection engine that streams events from Tetragon's gRPC
API, normalizes them into a single flat schema, and evaluates them against
Sigma rules - including single-shot rules, multi-step correlation
(sequence) rules, and count/threshold aggregation rules.

Built incrementally as a study project on top of Tetragon
(https://github.com/cilium/tetragon) and pySigma. **This is educational /
prototype-grade code**, not a production detection pipeline - see
"Known limitations" below before relying on it for anything real.

## Architecture

```
Tetragon daemon (eBPF)
      |
   gRPC GetEvents stream (unix socket)
      |
tetragon_normalize.py       -> UnifiedEvent (flat dataclass, all 10 event types)
      |
      |-- tetragon_pipeline.py + tetragon_backend.py
      |        -> single-shot Sigma rule matching (sigma_rules/*.yml)
      |
      |-- correlation_engine.py
      |        -> multi-step sequence detection, keyed by exec_id / lineage
      |
      |-- aggregation_engine.py
      |        -> count()-style threshold detection, keyed by group-by field
      |
      |-- sigma_correlation_compiler.py
               -> bridges native Sigma "correlation:" YAML onto the two engines above
```

## Folder contents

| File | Purpose |
|---|---|
| `tetragon_normalize.py` | Converts any raw `GetEventsResponse` (all 10 oneof event types) into one flat `UnifiedEvent` dataclass. Also contains `stream_events()`: the live gRPC generator with automatic reconnect (exponential backoff, gap tracking, fatal-code handling). |
| `schema_explorer.py` | Static reference tool: walks the compiled protobuf descriptors and prints every event type's fields (number, name, readable type, `repeated`). Modes: no args (all events), `<event_name>` (one), `--args` (adds the `KprobeArgument` oneof). No daemon needed. |
| `tests/test_resilience.py` | 16 tests using a real, killable in-process gRPC daemon: reconnect, backoff, give-up, fatal codes, health alerts, CLI exit codes. |
| `tests/test_smoke.py` | 25 offline tests (real protobuf messages through the whole pipeline). Run: `python3 -m unittest discover -s tests -v` |
| `tetragon_pipeline.py` | pySigma `ProcessingPipeline` mapping generic Sigma field names (`Image`, `CommandLine`, ...) onto `UnifiedEvent` dotted paths. |
| `tetragon_backend.py` | Compiles a parsed Sigma rule's condition tree into a Python predicate function (`UnifiedEvent -> bool`), since we're matching against live objects, not emitting a query string. |
| `detection_engine.py` | Minimal entrypoint: loads only single-shot Sigma rules from `sigma_rules/` and evaluates them against the live stream. |
| `correlation_engine.py` | Stateful engine for multi-step sequence detections (e.g. "credential read, then network connect, within 30s"). Maintains a `ProcessStore` keyed by `exec_id`, with ancestry-chain (`lineage`) support and TTL eviction. |
| `aggregation_engine.py` | Sliding-window threshold detection (e.g. "5+ setuid execs by the same UID within 60s"). |
| `sigma_correlation_compiler.py` | Compiles pySigma's native `SigmaCorrelationRule` objects (the official `correlation:` YAML spec) into `CorrelationRule` / `AggregationRule` instances so you can write standard Sigma correlation YAML instead of hand-building Python objects. |
| `main.py` | **The entrypoint.** CLI (`--socket`, `--rules-dir`, `--max-retries`, backoff flags), health routing, single-shot + correlation + aggregation, clean exit codes. |
| `health.py` | `HealthMonitor`: turns `process_throttle`, `rate_limit_info`, connection loss/regain and skipped events into `[HEALTH]` alerts, with a summary on exit. |
| `sigma_rules/*.yml` | Example Sigma rules used to validate the pipeline. |
| `tracingpolicies/*.yaml` | Example Tetragon TracingPolicies (ptrace injection / T1055, setuid credential changes / T1548) to generate real `process_kprobe` / `process_lsm` traffic for testing. |
| `proto/generate_stubs.sh` | Clones the Tetragon repo and compiles its `.proto` files into the Python stubs this project imports (`tetragon.tetragon_pb2`, etc). |
| `requirements.txt` | Python dependencies. |

## Setup

### 1. Prerequisites

- Tetragon already installed and running on this VM (per the official docs:
  https://tetragon.io/docs/), exposing its gRPC socket at
  `/var/run/tetragon/tetragon.sock` (default).
- Python 3.10+ (uses `list[...]`/`dict[...]` generics and `X | None` style
  typing in places, and dataclasses).

### 2. Install Python dependencies

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Generate the gRPC Python stubs

The project imports `from tetragon.tetragon_pb2 import ...` and
`from tetragon.tetragon_pb2_grpc import ...` - these are generated files, not
included here (they're large, versioned to whatever Tetragon release you're
running, and easy to regenerate).

```bash
cd proto
chmod +x generate_stubs.sh
./generate_stubs.sh ..     # generates into the project root
cd ..
```

This clones `cilium/tetragon` (shallow) and runs `grpc_tools.protoc` against
`api/v1/tetragon/*.proto`, producing a `tetragon/` package next to this
README with `tetragon_pb2.py`, `tetragon_pb2_grpc.py`, `events_pb2.py`, etc.

**Pinned to Tetragon v1.7.1** (the stubs in this folder were generated from that release tag; the daemon binary itself could not be run in the test sandbox, only its proto files were checked). To match a different daemon, run `TETRAGON_REF=<tag> ./generate_stubs.sh ..`.

**Version note:** the exact proto schema (field names, which event types
exist) depends on which Tetragon version you cloned. If you're running an
older or newer Tetragon daemon than `main`, consider cloning a matching tag
instead of `main` in `generate_stubs.sh`, to avoid client/server schema
drift.

### 4. Load the example TracingPolicies (optional, for live testing)

```bash
tetra tracingpolicy add tracingpolicies/ptrace-injection.yaml
tetra tracingpolicy add tracingpolicies/credential-changes.yaml
tetra tracingpolicy list   # confirm both are loaded/enabled
```

Check your running kernel actually exposes the hooked functions before
loading (signatures/availability vary by kernel version):

```bash
sudo cat /sys/kernel/debug/tracing/available_filter_functions | grep -E "ptrace|fix_setuid"
```

## Running it

**Static schema reference** (no daemon needed):
```bash
python3 schema_explorer.py
```

**Just print normalized events** (sanity check the normalization layer):
```bash
python3 tetragon_normalize.py
```

**Single-shot Sigma rules only**:
```bash
python3 detection_engine.py
```

**Full pipeline** (single-shot + correlation + aggregation + health):
```bash
sudo python3 main.py                       # the Tetragon socket is usually root-only
sudo python3 main.py --socket unix:///run/tetragon/tetragon.sock --rules-dir /path/to/rules
```
Run from any directory: the rules default to the `sigma_rules/` folder next to `main.py`. Exit codes: `0` Ctrl-C, `1` stream failed (fatal error or `--max-retries` exhausted), `2` bad config.

Then, in another terminal, generate some traffic to trigger the example
rules/policies, e.g.:
```bash
su root
strace -p <some_pid>
```

## Writing rules for hook events (kprobe / LSM / tracepoint)

Sigma has no notion of syscall arguments, so `tetragon_pipeline.py` maps a
readable rule-side field name onto an address into the event's `args` list:

| Address | Meaning | Example mapping |
|---|---|---|
| `args.<arg_type>.<field>` | **any** argument of that type | `TargetFilename` -> `args.path_arg.path` |
| `args.<N>.<arg_type>[.<field>]` | **only** the Nth argument (0-based) | `PtraceRequest` -> `args.0.int_arg` |

Use the positional form whenever a hook has several arguments of the same type.
`sys_ptrace(request, pid)` has two `int_arg`s, and the type-only form would match
`16` in either. `N` is the position in the **event's** `args` list, i.e. the
order arguments are declared in your TracingPolicy's `args:` section. A rule
whose position doesn't exist in the event simply doesn't match. Any Sigma field
that is *not* in the pipeline mapping resolves to nothing and silently never
matches, so add a mapping for every field name your rules use.

Numeric comparisons are coerced (protobuf renders 64-bit ints as strings), so
`PtraceRequest: 16` matches both `16` and `"16"`.

`sigma_rules/ptrace_injection.yml` + `tracingpolicies/ptrace-injection.yaml` are a
worked example (T1055.008). The policy's ptrace constants were corrected in this
version (`POKETEXT`=4, `POKEDATA`=5, `POKEUSER`=6, `ATTACH`=16, `SEIZE`=16902);
earlier versions mislabeled 4 and 6 and omitted `SEIZE`.

**Correlations and `generate`.** Following the Sigma spec, a rule that is
referenced by a correlation is a building block and does **not** alert on its
own unless the correlation sets `generate: true`; otherwise every event feeding
a correlation would also raise a separate alert. A startup `[info]` line lists
the rules that are being kept quiet. Rules are referenced by their `name:` (or
`id:`), and a correlation may reference a rule in a **different file**: all
files in `--rules-dir` load as one collection. A syntax error is reported with
the offending file name, and a bad rules directory exits with code 2.

## Operational behaviour

**Reconnect.** If the daemon is down, restarts, crashes (stale socket file) or drops the stream, the engine keeps retrying with exponential backoff (`--initial-backoff` 1s, doubling, capped by `--max-backoff` 30s) instead of crashing. A missing socket is detected instantly; a permission problem is diagnosed in the message ("run with sudo"). `--max-retries N` makes it give up (exit 1) after N consecutive failures; the default is forever. gRPC statuses that retrying can't fix (`UNIMPLEMENTED`, `INVALID_ARGUMENT`, `UNAUTHENTICATED`, `PERMISSION_DENIED`) stop immediately. One event that fails to normalize is skipped and reported, not fatal.

**Health alerts** (printed as `[HEALTH][level] ...`, separate from `[ALERT]`):

| Condition | Level | Meaning |
|---|---|---|
| `process_throttle` START/STOP | high / info | Tetragon is dropping a cgroup's events; activity there is invisible |
| `rate_limit_info` with drops | high | Tetragon dropped process events; alerts are batched (10s cooldown) so a storm doesn't flood the console |
| connection lost | high | no detection until reconnect |
| reconnected after Ns | high | events during those N seconds were **not seen**: a detection blind spot |
| cannot reach Tetragon at startup | warning | waiting for the daemon; not counted as a blind spot |
| event skipped | warning | normalization failed for one event |

On exit, a summary line reports disconnects, blind seconds, dropped events and throttles.

**Important:** events generated while disconnected are lost, not replayed. Long-lived correlation state (`ProcessStore`) survives a reconnect, but sequences that straddle the gap can be missed.

## Known limitations (read before extending)

- **Correlation matching is "in-order subsequence within a window", not
  general CEP.** Fine for a handful of hand-rolled rules; if you need
  `count()`/`near`/negative-sequence logic at scale, you'll want a proper
  compiler for Sigma's full correlation spec rather than continuing to
  extend `correlation_engine.py` by hand.
- **`sigma_correlation_compiler.py` only handles `gte`/`gt` for event-count
  correlations** and raises `NotImplementedError` for other operators or
  types (`value_count`, etc.) rather than silently mis-compiling them.
- **No persistence.** `ProcessStore` and the aggregation windows are
  in-memory only; restarting the engine loses all state (in-flight
  correlations reset).
- **Single daemon/node only.** No multi-node aggregation - each Tetragon
  daemon's `node_name` is captured in `UnifiedEvent` but not currently used
  to partition state, so if you fan this out across a fleet you'll need to
  key state by `(node_name, exec_id)`, not `exec_id` alone.
- **This is not doing TracingPolicy authoring validation.** Kernel function
  signatures vary by kernel version; the two example policies were written
  against a specific field layout and may need adjusting for your kernel
  (see the `available_filter_functions` check above).


## What has been tested (and what hasn't)

Tested offline (41 tests) against a fresh clone of `cilium/tetragon` (protoc-generated
stubs) and `pysigma==1.5.1`: normalization of all event branches, Sigma rule
matching (positive + negative), the `auid` filter-exclusion regression,
lineage correlation, aggregation de-dup, native Sigma `event_count`
correlation YAML round-trip, and `schema_explorer.py` in all modes.

The resilience features were tested against a real gRPC server (the generated `FineGuidanceSensors` servicer) on a unix socket that the tests stop and restart, and by hand with real processes including `kill -9` on the server (stale socket). Each fix was also mutation-checked: deliberately breaking it makes a test fail (a watchdog turns any hang into a failure).

**Not tested: a live connection to a running Tetragon daemon**, real kernel
events, or the TracingPolicies loading on a real kernel. `stream_events()`,
the two TracingPolicies, and the `arg` shapes real kprobes produce are
unverified until you run them on your VM. Also untested: `temporal`
correlation YAML (only the hand-built `CorrelationRule` path is covered).

### Verified proto quirks (differ from what you might assume)

- `GetEventsResponse` / `GetEventsRequest` are in `events_pb2`; the event
  message types (`Process`, `ProcessKprobe`, ...) are in `tetragon_pb2`.
- The `FineGuidanceSensors` stub is in `sensors_pb2_grpc`;
  `tetragon_pb2_grpc.py` is empty.
- `ProcessThrottle` carries `type` and `cgroup` only - no `process`.
- `MessageToDict` must use `preserving_proto_field_name=True` or keys become
  camelCase and silently break `arg_type` matching.
- Any Sigma field not listed in `tetragon_pipeline.py` resolves to `None`,
  which makes `not filter` conditions always true. Map every field you use.
- `KprobeArgument` has no `index` field, so `index` is always `None` in
  normalized args. Positional matching uses the argument's position in the
  event's `args` list instead (see "Writing rules for hook events").
- Run `python3 schema_explorer.py` on your build for the authoritative schema.

## Suggested next steps

1. Validate the two example TracingPolicies actually produce the expected
   `process_kprobe`/`process_lsm` shape on your kernel (`schema_explorer.py`
   + `tetragon_normalize.py` together are your inspection tools).
2. Extend `tetragon_pipeline.py`'s field mappings as you write more
   TracingPolicies with new argument shapes.
3. Write a scripted attack simulation (e.g. read `/etc/shadow` then open a
   socket) to exercise `correlation_engine.py`'s example rule end-to-end.
4. If you use a pysigma version other than 1.5.1, re-verify
   `sigma_correlation_compiler.py` (see the inspection snippet in its
   docstring) - the correlation API has changed across releases.
