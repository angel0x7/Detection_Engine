"""
correlation_engine.py

Stateful sequence/threshold detection keyed by exec_id lineage.
"""

import time
import threading
from dataclasses import dataclass, field
from typing import Callable, Optional

from tetragon_normalize import UnifiedEvent


# ---------------------------------------------------------------------------
# 1. Process state store - the "memory" of the engine
# ---------------------------------------------------------------------------

@dataclass
class ProcessState:
    exec_id: str
    parent_exec_id: Optional[str] = None
    binary: Optional[str] = None
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    # timestamped log of every rule-tagged "step" this process has hit
    matched_steps: list = field(default_factory=list)
    exited: bool = False


class ProcessStore:
    """Thread-safe exec_id -> ProcessState table with TTL eviction."""

    def __init__(self, ttl_seconds: int = 600):
        self._lock = threading.Lock()
        self._states: dict = {}
        self.ttl_seconds = ttl_seconds

    def get_or_create(self, exec_id: str, parent_exec_id: str, binary: str) -> ProcessState:
        with self._lock:
            st = self._states.get(exec_id)
            if st is None:
                st = ProcessState(exec_id=exec_id, parent_exec_id=parent_exec_id, binary=binary)
                self._states[exec_id] = st
            st.last_seen = time.time()
            return st

    def mark_exited(self, exec_id: str):
        with self._lock:
            if exec_id in self._states:
                self._states[exec_id].exited = True

    def record_step(self, exec_id: str, step_name: str):
        with self._lock:
            st = self._states.get(exec_id)
            if st:
                st.matched_steps.append((time.time(), step_name))

    def ancestry_chain(self, exec_id: str) -> list:
        """Walk up parent_exec_id links to build the lineage."""
        chain = []
        with self._lock:
            current = self._states.get(exec_id)
            seen = set()
            while current and current.exec_id not in seen:
                chain.append(current)
                seen.add(current.exec_id)
                current = self._states.get(current.parent_exec_id)
        return chain

    def sweep_expired(self):
        """Call periodically to evict old, exited processes and cap memory growth."""
        cutoff = time.time() - self.ttl_seconds
        with self._lock:
            dead = [
                eid for eid, st in self._states.items()
                if st.exited and st.last_seen < cutoff
            ]
            for eid in dead:
                del self._states[eid]


# ---------------------------------------------------------------------------
# 2. Correlation rule definition
# ---------------------------------------------------------------------------

@dataclass
class CorrelationStep:
    name: str
    predicate: Callable[[UnifiedEvent], bool]


@dataclass
class CorrelationRule:
    title: str
    steps: list                          # list[CorrelationStep], ordered sequence required
    window_seconds: float                # max time span across all steps
    scope: str = "exec_id"               # "exec_id" (same process) or "lineage" (ancestry chain)
    level: str = "high"

    def check(self, store: ProcessStore, exec_id: str) -> bool:
        if self.scope == "exec_id":
            state = store._states.get(exec_id)
            steps_log = state.matched_steps if state else []
        else:  # lineage: flatten steps across the whole ancestry chain
            steps_log = []
            for st in store.ancestry_chain(exec_id):
                steps_log.extend(st.matched_steps)
            steps_log.sort(key=lambda x: x[0])

        required = [s.name for s in self.steps]
        return _subsequence_within_window(steps_log, required, self.window_seconds)


def _subsequence_within_window(steps_log: list, required: list, window: float) -> bool:
    """Check whether `required` appears as an in-order subsequence in steps_log
    (by name), with first-to-last timestamp span <= window."""
    idx = 0
    start_ts = None
    for ts, name in steps_log:
        if idx < len(required) and name == required[idx]:
            if idx == 0:
                start_ts = ts
            idx += 1
            if idx == len(required):
                return (ts - start_ts) <= window
    return False


# ---------------------------------------------------------------------------
# 3. The engine
# ---------------------------------------------------------------------------

class CorrelationEngine:
    def __init__(self, correlation_rules: list, ttl_seconds: int = 600):
        self.store = ProcessStore(ttl_seconds=ttl_seconds)
        self.rules = correlation_rules
        self._last_sweep = time.time()

    def process(self, event: UnifiedEvent):
        if event.event_type == "process_exit" and event.process:
            self.store.mark_exited(event.process.exec_id)
            return

        if not event.process:
            return

        exec_id = event.process.exec_id
        self.store.get_or_create(
            exec_id, event.process.parent_exec_id, event.process.binary
        )

        # Tag this event against each correlation rule's per-step predicates
        for rule in self.rules:
            for step in rule.steps:
                if step.predicate(event):
                    self.store.record_step(exec_id, step.name)

            if rule.check(self.store, exec_id):
                self._alert(rule, exec_id)

        # Periodic cleanup so memory doesn't grow unbounded
        if time.time() - self._last_sweep > 60:
            self.store.sweep_expired()
            self._last_sweep = time.time()

    def _alert(self, rule: CorrelationRule, exec_id: str):
        print(f"[CORRELATION ALERT][{rule.level}] {rule.title} "
              f"(exec_id={exec_id})")


# ---------------------------------------------------------------------------
# 4. Example: credential access -> outbound network exfil, same lineage
# ---------------------------------------------------------------------------

def build_example_rules() -> list:
    def reads_shadow(e: UnifiedEvent) -> bool:
        return (e.event_type == "process_kprobe"
                and e.function_name == "security_file_open"
                and any(a["arg_type"] == "path_arg"
                        and "/etc/shadow" in str(a["value"].get("path", ""))
                        for a in e.args))

    def outbound_connect(e: UnifiedEvent) -> bool:
        return (e.event_type == "process_kprobe"
                and e.function_name in ("tcp_connect", "__x64_sys_connect")
                and any(a["arg_type"] == "sock_arg" for a in e.args))

    return [
        CorrelationRule(
            title="Shadow file read followed by outbound connection",
            steps=[
                CorrelationStep("read_shadow", reads_shadow),
                CorrelationStep("net_connect", outbound_connect),
            ],
            window_seconds=30,
            scope="lineage",   # allow parent reads shadow, child process exfils
            level="critical",
        ),
    ]


if __name__ == "__main__":
    from tetragon_normalize import stream_events

    engine = CorrelationEngine(correlation_rules=build_example_rules())
    for event in stream_events():
        engine.process(event)
