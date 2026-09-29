"""
health.py

Engine-health signals. A detection engine that doesn't know it is blind is
worse than one that says so, so these conditions are surfaced as alerts
instead of being silently ignored:

  * process_throttle  - Tetragon began/stopped throttling a cgroup's events
  * rate_limit_info   - Tetragon dropped process events (rate limiting)
  * connection state  - lost/regained the gRPC stream (a visibility gap)
  * event_error       - an event failed to normalize and was skipped
"""

import time
from typing import Callable, Optional


def _default_emit(level: str, message: str):
    print(f"[HEALTH][{level}] {message}", flush=True)


class HealthMonitor:
    def __init__(self,
                 emit: Optional[Callable[[str, str], None]] = None,
                 rate_limit_cooldown: float = 10.0,
                 clock: Callable[[], float] = time.monotonic):
        self._emit = emit or _default_emit
        self._cooldown = rate_limit_cooldown
        self._clock = clock
        self._last_rl_emit: Optional[float] = None
        self._pending_dropped = 0

        # counters, reported by summary()
        self.dropped_total = 0
        self.throttle_starts = 0
        self.active_throttles: set = set()
        self.disconnects = 0
        self.blind_seconds_total = 0.0
        self.bad_events = 0
        self._connected_once = False

    # -- events from the stream ------------------------------------------
    def process(self, event) -> bool:
        """Handle health events. Returns True if `event` was one (the caller
        should not feed it to the detection engines)."""
        if event.event_type == "process_throttle":
            self._throttle(event)
            return True
        if event.event_type == "rate_limit_info":
            self._rate_limit(event)
            return True
        return False

    def _throttle(self, event):
        cgroup = event.throttle_cgroup or "unknown"
        if event.throttle_type == "THROTTLE_START":
            self.throttle_starts += 1
            self.active_throttles.add(cgroup)
            self._emit("high", f"Tetragon started throttling events from cgroup "
                               f"{cgroup}: activity there is NOT being reported")
        elif event.throttle_type == "THROTTLE_STOP":
            self.active_throttles.discard(cgroup)
            self._emit("info", f"Tetragon stopped throttling cgroup {cgroup}")

    def _rate_limit(self, event):
        n = event.dropped_events or 0
        if n <= 0:
            return
        self.dropped_total += n
        self._pending_dropped += n
        now = self._clock()
        if self._last_rl_emit is None or now - self._last_rl_emit >= self._cooldown:
            self._flush_rate_limit(now)

    def _flush_rate_limit(self, now: Optional[float] = None):
        if not self._pending_dropped:
            return
        self._emit("high", f"Tetragon reports {self._pending_dropped} dropped "
                           f"process event(s) (rate limiting) - detections may "
                           f"have been missed")
        self._pending_dropped = 0
        self._last_rl_emit = self._clock() if now is None else now

    # -- connection state, wired to stream_events(on_status=...) ----------
    def on_status(self, state: str, **info):
        if state == "connected":
            gap = info.get("blind_seconds")
            first = not self._connected_once
            self._connected_once = True
            if first:
                # Detection had not started yet, so waiting for the daemon is
                # not a blind spot - just report it.
                waited = f" after waiting {gap:.1f}s for the daemon" if gap else ""
                self._emit("info", f"connected to Tetragon at {info.get('socket')}{waited}")
            elif gap is None:
                self._emit("info", f"connected to Tetragon at {info.get('socket')}")
            else:
                self.blind_seconds_total += gap
                self._emit("high", f"reconnected after {gap:.1f}s - events during "
                                   f"this gap were NOT seen (detection blind spot)")
        elif state == "disconnected":
            if not self._connected_once:
                self._emit("warning", f"cannot reach Tetragon yet ({info.get('reason')}); "
                                      f"waiting for it")
            else:
                self.disconnects += 1
                self._emit("high", f"lost connection to Tetragon ({info.get('reason')}); "
                                   f"no detection until it reconnects")
        elif state == "reconnecting":
            self._emit("info", f"reconnect attempt #{info.get('attempt')} "
                               f"in {info.get('delay')}s")
        elif state == "fatal":
            self._emit("critical", f"giving up: {info.get('reason')}")
        elif state == "event_error":
            self.bad_events += 1
            self._emit("warning", f"skipped an event that failed to normalize: "
                                  f"{info.get('error')}")

    # -- shutdown ---------------------------------------------------------
    def summary(self) -> str:
        self._flush_rate_limit()
        return (f"health summary: {self.disconnects} disconnect(s), "
                f"{self.blind_seconds_total:.1f}s blind, "
                f"{self.dropped_total} dropped event(s) reported, "
                f"{self.throttle_starts} throttle start(s), "
                f"{self.bad_events} event(s) skipped")
