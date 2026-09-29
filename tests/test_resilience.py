"""
tests/test_resilience.py

Tests for the two operational gaps: (1) reconnect when the daemon goes away,
(2) health alerts for throttling / rate limiting / visibility gaps.

A real gRPC server (the generated FineGuidanceSensors servicer) on a unix
socket stands in for the Tetragon daemon, so the tests can stop and restart
it mid-stream - no eBPF or root needed.

Run from the project root:
    python3 -m unittest discover -s tests -v
"""

import faulthandler
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from concurrent import futures
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import grpc  # noqa: E402

import tetragon_normalize as tn  # noqa: E402
from health import HealthMonitor  # noqa: E402
from tetragon.events_pb2 import GetEventsResponse  # noqa: E402
from tetragon.sensors_pb2_grpc import (  # noqa: E402
    FineGuidanceSensorsServicer,
    add_FineGuidanceSensorsServicer_to_server,
)

FAST = dict(initial_backoff=0.05, max_backoff=0.1, connect_timeout=0.3)


def exec_event(binary, args=""):
    r = GetEventsResponse()
    r.process_exec.process.binary = binary
    r.process_exec.process.arguments = args
    r.process_exec.process.exec_id = binary
    return r


class FakeDaemon:
    """A killable stand-in for the Tetragon gRPC server."""

    def __init__(self, sock_path, events=(), abort_with=None, stop_after=None):
        self.sock_path = sock_path
        self.events = list(events)
        self.abort_with = abort_with        # grpc.StatusCode to fail every stream with
        self.stop_after = stop_after        # seconds after events are sent -> stop daemon
        self.server = None

    def start(self):
        if os.path.exists(self.sock_path):
            os.remove(self.sock_path)
        daemon = self

        class Servicer(FineGuidanceSensorsServicer):
            def GetEvents(self, request, context):
                if daemon.abort_with is not None:
                    context.abort(daemon.abort_with, "injected failure")
                for e in daemon.events:
                    yield e
                if daemon.stop_after is not None:
                    threading.Timer(daemon.stop_after, daemon.stop).start()
                while context.is_active():      # live stream: stay open
                    time.sleep(0.02)

        self.server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
        add_FineGuidanceSensorsServicer_to_server(Servicer(), self.server)
        self.server.add_insecure_port(f"unix://{self.sock_path}")
        self.server.start()
        return self

    def stop(self):
        if self.server is not None:
            self.server.stop(0).wait()
            self.server = None
        if os.path.exists(self.sock_path):      # a real daemon removes its socket on exit
            os.remove(self.sock_path)


class SocketTestCase(unittest.TestCase):
    def setUp(self):
        # Watchdog: a regression that makes the client retry/block forever must
        # FAIL the run (with a traceback), not hang CI. Kills the process at 30s.
        faulthandler.dump_traceback_later(30, exit=True)
        self.dir = tempfile.mkdtemp(prefix="tgtest")
        self.sock = os.path.join(self.dir, "t.sock")
        self.target = f"unix://{self.sock}"
        self.daemons = []
        self.timers = []
        self.statuses = []

    def tearDown(self):
        faulthandler.cancel_dump_traceback_later()
        for tm in self.timers:                   # never let a timer outlive its test
            tm.cancel()
        for d in self.daemons:
            d.stop()
        shutil.rmtree(self.dir, ignore_errors=True)

    def daemon(self, *a, **kw):
        d = FakeDaemon(self.sock, *a, **kw)
        self.daemons.append(d)
        return d

    def later(self, delay, fn):
        tm = threading.Timer(delay, fn)
        tm.daemon = True
        self.timers.append(tm)
        tm.start()

    def on_status(self, state, **info):
        self.statuses.append((state, info))

    def states(self):
        return [s for s, _ in self.statuses]


class TestHealthMonitor(unittest.TestCase):
    def setUp(self):
        self.out = []
        self.now = [0.0]
        self.h = HealthMonitor(emit=lambda lvl, msg: self.out.append((lvl, msg)),
                               rate_limit_cooldown=10, clock=lambda: self.now[0])

    def _event(self, build):
        r = GetEventsResponse()
        build(r)
        return tn.normalize(r)

    def test_throttle_start_and_stop(self):
        def start(r):
            r.process_throttle.type = 1          # THROTTLE_START
            r.process_throttle.cgroup = "pod-abc"

        def stop(r):
            r.process_throttle.type = 2          # THROTTLE_STOP
            r.process_throttle.cgroup = "pod-abc"

        self.assertTrue(self.h.process(self._event(start)))
        self.assertEqual(self.h.active_throttles, {"pod-abc"})
        self.assertEqual(self.out[-1][0], "high")
        self.assertIn("pod-abc", self.out[-1][1])
        self.assertTrue(self.h.process(self._event(stop)))
        self.assertEqual(self.h.active_throttles, set())

    def test_rate_limit_alerts_then_cools_down_then_flushes(self):
        def drop(n):
            return self._event(lambda r: setattr(r.rate_limit_info,
                                                 "number_of_dropped_process_events", n))
        self.h.process(drop(5))                  # first report: alerts immediately
        self.assertEqual(len(self.out), 1)
        self.assertIn("5 dropped", self.out[0][1])
        self.now[0] = 3
        self.h.process(drop(2))                  # inside cooldown: suppressed
        self.now[0] = 6
        self.h.process(drop(4))
        self.assertEqual(len(self.out), 1)
        self.now[0] = 11                         # cooldown over: reports everything accumulated
        self.h.process(drop(1))
        self.assertEqual(len(self.out), 2)
        self.assertIn("7 dropped", self.out[1][1])   # 2 + 4 + 1
        self.assertEqual(self.h.dropped_total, 12)

    def test_summary_flushes_pending_drops(self):
        drop = lambda n: self._event(lambda r: setattr(  # noqa: E731
            r.rate_limit_info, "number_of_dropped_process_events", n))
        self.h.process(drop(1))
        self.now[0] = 1
        self.h.process(drop(9))                  # suppressed
        self.assertEqual(len(self.out), 1)
        summary = self.h.summary()
        self.assertEqual(len(self.out), 2)       # flushed on shutdown
        self.assertIn("10 dropped", summary)

    def test_zero_drop_report_is_silent_and_normal_events_pass_through(self):
        self.h.process(self._event(lambda r: setattr(
            r.rate_limit_info, "number_of_dropped_process_events", 0)))
        self.assertEqual(self.out, [])
        self.assertFalse(self.h.process(tn.normalize(exec_event("/bin/ls"))))

    def test_startup_wait_is_not_a_blind_spot(self):
        self.h.on_status("disconnected", reason="socket missing")   # daemon not up yet
        self.assertEqual(self.out[-1][0], "warning")
        self.assertIn("cannot reach", self.out[-1][1])
        self.h.on_status("connected", socket="unix:///x", blind_seconds=2.0)
        self.assertEqual(self.out[-1][0], "info")                   # not "high"
        self.assertIn("after waiting 2.0s", self.out[-1][1])
        self.assertEqual((self.h.disconnects, self.h.blind_seconds_total), (0, 0.0))

    def test_connection_status_messages(self):
        self.h.on_status("connected", socket="unix:///x", blind_seconds=None)
        self.assertEqual(self.out[-1][0], "info")
        self.h.on_status("disconnected", reason="boom")
        self.assertEqual(self.out[-1][0], "high")
        self.h.on_status("connected", socket="unix:///x", blind_seconds=4.2)
        self.assertIn("4.2s", self.out[-1][1])
        self.assertIn("NOT seen", self.out[-1][1])
        self.assertEqual((self.h.disconnects, round(self.h.blind_seconds_total, 1)), (1, 4.2))


class TestStreamReconnect(SocketTestCase):
    def stream(self, **kw):
        return tn.stream_events(self.target, on_status=self.on_status, **{**FAST, **kw})

    def test_waits_for_a_daemon_that_starts_late(self):
        d = self.daemon(events=[exec_event("/bin/a")])
        self.later(0.4, d.start)
        gen = self.stream()
        try:
            evt = next(gen)
        finally:
            gen.close()
        self.assertEqual(evt.process.binary, "/bin/a")
        self.assertEqual(self.states()[0], "disconnected")
        self.assertIn("reconnecting", self.states())
        connected = [i for s, i in self.statuses if s == "connected"]
        self.assertGreater(connected[0]["blind_seconds"], 0)

    def test_reconnects_after_the_daemon_restarts_mid_stream(self):
        d1 = self.daemon(events=[exec_event("/bin/a")]).start()
        gen = self.stream()
        try:
            self.assertEqual(next(gen).process.binary, "/bin/a")
            d1.stop()                                            # daemon dies mid-stream
            d2 = self.daemon(events=[exec_event("/bin/b")])
            self.later(0.4, d2.start)                            # ...and comes back
            self.assertEqual(next(gen).process.binary, "/bin/b")
        finally:
            gen.close()
        self.assertEqual([s for s in self.states() if s in ("connected", "disconnected")],
                         ["connected", "disconnected", "connected"])
        blind = [i["blind_seconds"] for s, i in self.statuses if s == "connected"]
        self.assertIsNone(blind[0])
        self.assertGreater(blind[1], 0)

    def test_gives_up_after_max_retries(self):
        with self.assertRaises(tn.StreamError) as cm:
            next(self.stream(max_retries=2))
        self.assertIn("giving up after 2 retries", str(cm.exception))
        self.assertEqual(self.states().count("reconnecting"), 2)
        self.assertEqual(self.states()[-1], "fatal")

    def test_fatal_grpc_status_is_not_retried(self):
        self.daemon(abort_with=grpc.StatusCode.UNIMPLEMENTED).start()
        with self.assertRaises(tn.StreamError):
            next(self.stream())
        self.assertNotIn("reconnecting", self.states())
        self.assertEqual(self.states()[-1], "fatal")

    def test_one_bad_event_is_skipped_not_fatal(self):
        self.daemon(events=[exec_event("/bin/a"), exec_event("/bin/b")]).start()
        real, calls = tn.normalize, []

        def flaky(resp):
            calls.append(1)
            if len(calls) == 1:
                raise ValueError("boom")
            return real(resp)

        gen = self.stream()
        try:
            with mock.patch.object(tn, "normalize", flaky):
                evt = next(gen)
        finally:
            gen.close()
        self.assertEqual(evt.process.binary, "/bin/b")          # /bin/a was skipped
        self.assertIn("event_error", self.states())

    def test_missing_socket_fails_fast_with_a_useful_reason(self):
        t0 = time.monotonic()
        with self.assertRaises(tn.StreamError) as cm:
            next(self.stream(max_retries=0, connect_timeout=5))
        self.assertLess(time.monotonic() - t0, 2)               # no 5s connect wait
        self.assertIn("does not exist", str(cm.exception))


class TestMainCli(SocketTestCase):
    def run_main(self, *extra):
        cmd = [sys.executable, str(ROOT / "main.py"), "--socket", self.target,
               "--initial-backoff", "0.05", "--max-backoff", "0.1",
               "--connect-timeout", "0.3", *extra]
        return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=60)

    def test_no_daemon_exits_cleanly_without_a_traceback(self):
        p = self.run_main("--max-retries", "1")
        self.assertEqual(p.returncode, 1)
        self.assertNotIn("Traceback", p.stderr)
        self.assertIn("[FATAL]", p.stderr)
        self.assertIn("health summary", p.stderr)

    def test_broken_rule_file_exits_2_without_traceback(self):
        rules = os.path.join(self.dir, "rules"); os.makedirs(rules)
        with open(os.path.join(rules, "bad.yml"), "w") as f:
            f.write("title: bad\ncorrelation:\n  type: event_count\n  rules: [nope]\n"
                    "  group-by: [process.uid]\n  timespan: 60s\n  condition: {gte: 2}\n")
        p = self.run_main("--rules-dir", rules)
        self.assertEqual(p.returncode, 2)
        self.assertNotIn("Traceback", p.stderr)
        self.assertIn("could not load rules", p.stderr)

    def test_bad_rules_dir_exits_2(self):
        p = self.run_main("--rules-dir", os.path.join(self.dir, "nope"))
        self.assertEqual(p.returncode, 2)
        self.assertIn("rules directory not found", p.stderr)

    def test_alerts_health_and_daemon_loss_end_to_end(self):
        def build():
            evs = [exec_event("/bin/su", "root")]
            r = GetEventsResponse()
            r.process_lsm.function_name = "security_task_fix_setuid"
            r.process_lsm.process.auid.value = 1000
            evs.append(r)                                        # -> alert
            r = GetEventsResponse()
            r.process_lsm.function_name = "security_task_fix_setuid"
            r.process_lsm.process.auid.value = 0
            evs.append(r)                                        # filtered by the rule
            r = GetEventsResponse()
            r.process_throttle.type = 1
            r.process_throttle.cgroup = "noisy-cgroup"
            evs.append(r)
            r = GetEventsResponse()
            r.rate_limit_info.number_of_dropped_process_events = 7
            evs.append(r)
            return evs

        self.daemon(events=build(), stop_after=0.5).start()      # daemon dies after sending
        p = self.run_main("--max-retries", "2")
        out = p.stdout
        self.assertEqual(p.returncode, 1, p.stderr)
        self.assertNotIn("Traceback", p.stderr)
        self.assertIn("[ALERT][medium] Suspicious su/sudo to root", out)
        self.assertEqual(out.count("Setuid to root from non-root login session"), 1)
        self.assertIn("throttling events from cgroup noisy-cgroup", out)
        self.assertIn("7 dropped process event(s)", out)
        self.assertIn("lost connection to Tetragon", out)
        self.assertIn("giving up", out)                          # 'fatal' health line
        self.assertIn("[FATAL]", p.stderr)


if __name__ == "__main__":
    unittest.main()
