"""
aggregation_engine.py

Threshold/count-based detections: N matching events per group-by key
within a rolling time window.
"""

import time
from dataclasses import dataclass, field
from collections import defaultdict, deque
from typing import Callable, Optional

from tetragon_normalize import UnifiedEvent


@dataclass
class AggregationRule:
    title: str
    predicate: Callable[[UnifiedEvent], bool]          # which events count toward the threshold
    group_by: Callable[[UnifiedEvent], Optional[str]]  # e.g. lambda e: e.process.uid
    threshold: int
    window_seconds: float
    level: str = "medium"


class AggregationEngine:
    def __init__(self, rules: list):
        self.rules = rules
        # per rule, per group-key: deque of timestamps
        self._windows = {r.title: defaultdict(deque) for r in rules}
        self._alerted_recently = {r.title: {} for r in rules}

    def process(self, event: UnifiedEvent):
        now = time.time()
        for rule in self.rules:
            if not rule.predicate(event):
                continue

            key = rule.group_by(event)
            if key is None:
                continue

            dq = self._windows[rule.title][key]
            dq.append(now)

            # drop timestamps outside the window
            cutoff = now - rule.window_seconds
            while dq and dq[0] < cutoff:
                dq.popleft()

            if len(dq) >= rule.threshold:
                self._maybe_alert(rule, key, len(dq), now)

    def _maybe_alert(self, rule: AggregationRule, key: str, count: int, now: float):
        # simple de-dup: don't re-fire the same group-key alert more than once per window
        last = self._alerted_recently[rule.title].get(key, 0)
        if now - last < rule.window_seconds:
            return
        self._alerted_recently[rule.title][key] = now
        print(f"[AGG ALERT][{rule.level}] {rule.title} "
              f"key={key} count={count} in {rule.window_seconds}s")


# --- Example: >5 exec attempts of setuid binaries by the same UID in 60s ---

def build_example_agg_rules() -> list:
    def setuid_exec(e: UnifiedEvent) -> bool:
        return e.event_type == "process_exec" and e.process is not None and \
               e.process.binary in ("/usr/bin/sudo", "/usr/bin/su", "/usr/bin/pkexec")

    return [
        AggregationRule(
            title="Repeated privilege-escalation binary execution",
            predicate=setuid_exec,
            group_by=lambda e: str(e.process.uid),
            threshold=5,
            window_seconds=60,
            level="high",
        ),
    ]
