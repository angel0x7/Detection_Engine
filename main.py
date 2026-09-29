"""
main.py

Full pipeline entrypoint:
  gRPC stream (auto-reconnecting) -> normalize
      -> health monitor      (throttle / rate-limit / connection gaps)
      -> single-shot Sigma rules
      -> temporal correlation rules
      -> event-count aggregation rules

Usage:
  sudo python3 main.py [--socket unix:///var/run/tetragon/tetragon.sock]
                       [--rules-dir ./sigma_rules] [--max-retries N]

Exit codes: 0 = stopped with Ctrl-C, 1 = stream failed (fatal or retries
exhausted), 2 = bad configuration (e.g. rules directory missing).
"""

import argparse
import sys
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.exceptions import SigmaRuleNotFoundError

from tetragon_pipeline import tetragon_pipeline
from tetragon_backend import compile_rule
from sigma_correlation_compiler import compile_correlation
from correlation_engine import CorrelationEngine
from aggregation_engine import AggregationEngine
from health import HealthMonitor
from tetragon_normalize import stream_events, StreamError, DEFAULT_SOCKET

DEFAULT_RULES_DIR = Path(__file__).resolve().parent / "sigma_rules"


def _load_collection(paths):
    """
    Load every rule file as ONE SigmaCollection, so a correlation may reference
    a base rule that lives in a different file (pySigma resolves references
    within a single collection only; loading file-by-file raises
    SigmaRuleNotFoundError for such rules - verified on pysigma 1.5.1).

    On failure, re-parse each file alone to name the broken one. A file that
    fails ONLY because its references live elsewhere is not the culprit.
    """
    texts = [(p, p.read_text()) for p in paths]
    try:
        return SigmaCollection.from_yaml("\n---\n".join(t for _, t in texts))
    except Exception as exc:
        for path, text in texts:
            try:
                SigmaCollection.from_yaml(text)
            except SigmaRuleNotFoundError:
                continue
            except Exception as inner:
                raise ValueError(f"{path.name}: {inner}") from inner
        raise ValueError(str(exc)) from exc


def load_everything(rules_dir):
    """
    Returns (single_shot, temporal_rules, agg_rules). single_shot excludes rules
    that only exist to feed a correlation (see `generate` below).

    Verified against pysigma==1.5.1: SigmaCollection.rules is a single mixed
    list containing both plain SigmaRule and SigmaCorrelationRule instances -
    there is no separate `.correlations` attribute. Split them with isinstance.

    compiled_by_ref is keyed by each rule's `name:` field if set, else its
    `id:` - this is how a correlation's `rules:` list (SigmaRuleReference
    objects, via `.reference`) resolves back to a base rule at runtime.
    """
    pipeline = tetragon_pipeline()
    single_shot, compiled_by_ref, correlations = [], {}, []

    rules_dir = Path(rules_dir)
    paths = sorted(list(rules_dir.glob("*.yml")) + list(rules_dir.glob("*.yaml")))
    collection = _load_collection(paths)
    for item in collection.rules:
        if isinstance(item, SigmaCorrelationRule):
            correlations.append(item)
            continue

        pipeline.apply(item)
        compiled = compile_rule(item)
        single_shot.append(compiled)
        ref_key = item.name or (str(item.id) if item.id else None)
        if ref_key:
            compiled_by_ref[ref_key] = compiled

    temporal_rules, agg_rules = [], []
    keep_alert = set()          # ids of base rules that must keep alerting on their own
    referenced = set()
    for corr in correlations:
        result = compile_correlation(corr, compiled_by_ref)
        (temporal_rules if hasattr(result, "steps") else agg_rules).append(result)
        for ref in corr.rules:
            base = compiled_by_ref[ref.reference]
            referenced.add(id(base))
            if corr.generate:
                keep_alert.add(id(base))

    # Sigma spec: rules referenced by a correlation are building blocks and do
    # NOT alert on their own unless the correlation sets `generate: true`.
    # (Without this, every event feeding a correlation also fired its own alert.)
    quiet = [r for r in single_shot if id(r) in referenced and id(r) not in keep_alert]
    for r in quiet:
        print(f"[info] rule '{r.title}' only feeds a correlation and will not alert "
              f"on its own (set `generate: true` in the correlation to change this)",
              file=sys.stderr)
    single_shot = [r for r in single_shot if r not in quiet]

    return single_shot, temporal_rules, agg_rules


def run(single_shot, temporal_rules, agg_rules, events, health):
    """Feed an iterable of UnifiedEvents through health + all detectors."""
    corr_engine = CorrelationEngine(correlation_rules=temporal_rules)
    agg_engine = AggregationEngine(rules=agg_rules)

    for event in events:
        if health.process(event):        # throttle / rate-limit: not detection input
            continue

        for rule in single_shot:
            if rule.matches(event):
                print(f"[ALERT][{rule.level}] {rule.title}", flush=True)

        corr_engine.process(event)
        agg_engine.process(event)


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Tetragon + Sigma detection engine")
    p.add_argument("--socket", default=DEFAULT_SOCKET,
                   help="Tetragon gRPC address (default: %(default)s)")
    p.add_argument("--rules-dir", default=str(DEFAULT_RULES_DIR),
                   help="directory of Sigma .yml/.yaml files (default: %(default)s)")
    p.add_argument("--max-retries", type=int, default=None,
                   help="give up after N consecutive failed reconnects "
                        "(default: retry forever)")
    p.add_argument("--initial-backoff", type=float, default=1.0,
                   help="first reconnect delay in seconds; doubles each failure")
    p.add_argument("--max-backoff", type=float, default=30.0,
                   help="cap on the reconnect delay in seconds")
    p.add_argument("--connect-timeout", type=float, default=5.0,
                   help="seconds to wait for the socket to accept a connection")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        sys.stdout.reconfigure(line_buffering=True)   # alerts appear immediately when piped
    except Exception:
        pass

    rules_dir = Path(args.rules_dir)
    if not rules_dir.is_dir():
        print(f"[FATAL] rules directory not found: {rules_dir}", file=sys.stderr)
        return 2

    try:
        single_shot, temporal_rules, agg_rules = load_everything(rules_dir)
    except Exception as exc:            # bad YAML, unknown correlation reference, ...
        print(f"[FATAL] could not load rules from {rules_dir}: "
              f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(f"Loaded {len(single_shot)} single-shot rules, "
          f"{len(temporal_rules)} temporal correlations, "
          f"{len(agg_rules)} aggregation rules from {rules_dir}", flush=True)
    if not single_shot:
        print(f"[WARN] no Sigma rules found in {rules_dir}: nothing will ever alert",
              file=sys.stderr)

    health = HealthMonitor()
    events = stream_events(
        socket_path=args.socket,
        on_status=health.on_status,
        max_retries=args.max_retries,
        initial_backoff=args.initial_backoff,
        max_backoff=args.max_backoff,
        connect_timeout=args.connect_timeout,
    )
    try:
        run(single_shot, temporal_rules, agg_rules, events, health)
    except StreamError as exc:
        print(f"[FATAL] {exc}", file=sys.stderr)
        print(health.summary(), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nStopped.", file=sys.stderr)
        print(health.summary(), file=sys.stderr)
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
