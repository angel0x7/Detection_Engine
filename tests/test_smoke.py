"""
tests/test_smoke.py

Offline smoke tests - no Tetragon daemon needed. They build real protobuf
messages from the generated stubs and push them through the whole pipeline.

Run from the project root:
    python3 -m unittest discover -s tests -v
"""

import contextlib
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sigma.collection import SigmaCollection  # noqa: E402

import tetragon_normalize as tn  # noqa: E402
from tetragon.events_pb2 import GetEventsResponse  # noqa: E402
from tetragon_backend import compile_rule  # noqa: E402
from tetragon_pipeline import tetragon_pipeline  # noqa: E402
from correlation_engine import CorrelationEngine, build_example_rules  # noqa: E402
from aggregation_engine import AggregationEngine, build_example_agg_rules  # noqa: E402
from main import load_everything  # noqa: E402


def compile_yaml_file(name):
    rule = SigmaCollection.from_yaml((ROOT / "sigma_rules" / name).read_text()).rules[0]
    tetragon_pipeline().apply(rule)
    return compile_rule(rule)


class TestNormalize(unittest.TestCase):
    def test_kprobe_fields_and_snake_case_arg_type(self):
        r = GetEventsResponse()
        k = r.process_kprobe
        k.process.exec_id = "abc"
        k.process.binary = "/bin/su"
        k.process.arguments = "root"
        k.function_name = "security_file_open"
        k.args.add().string_arg = "/etc/shadow"
        e = tn.normalize(r)
        self.assertEqual(e.event_type, "process_kprobe")
        self.assertEqual(e.process.command_line, "/bin/su root")
        self.assertEqual(e.args[0]["arg_type"], "string_arg")  # not "stringArg"

    def test_throttle_has_no_process(self):
        r = GetEventsResponse()
        r.process_throttle.type = 1
        e = tn.normalize(r)
        self.assertIsNone(e.process)
        self.assertEqual(e.throttle_type, "THROTTLE_START")

    def test_rate_limit_info(self):
        r = GetEventsResponse()
        r.rate_limit_info.number_of_dropped_process_events = 42
        self.assertEqual(tn.normalize(r).dropped_events, 42)

    def test_unknown_event_type_falls_back(self):
        r = GetEventsResponse()
        r.test.arg0 = 1
        self.assertEqual(tn.normalize(r).event_type, "test")


class TestSigmaRules(unittest.TestCase):
    def test_su_root_positive_and_negative(self):
        rule = compile_yaml_file("su_root.yml")
        hit, miss = GetEventsResponse(), GetEventsResponse()
        hit.process_exec.process.binary = "/bin/su"
        hit.process_exec.process.arguments = "root"
        miss.process_exec.process.binary = "/bin/ls"
        self.assertTrue(rule.matches(tn.normalize(hit)))
        self.assertFalse(rule.matches(tn.normalize(miss)))

    def test_filter_exclusion_on_auid(self):
        # Regression: unmapped 'auid' used to make "not filter" always True.
        rule = compile_yaml_file("setuid_root.yml")
        for auid, expected in ((0, False), (1000, True)):
            r = GetEventsResponse()
            r.process_lsm.function_name = "security_task_fix_setuid"
            r.process_lsm.process.auid.value = auid
            self.assertEqual(rule.matches(tn.normalize(r)), expected, f"auid={auid}")


class TestEngines(unittest.TestCase):
    def test_correlation_across_lineage(self):
        engine = CorrelationEngine(build_example_rules())
        a = GetEventsResponse()
        a.process_kprobe.process.exec_id = "A"
        a.process_kprobe.function_name = "security_file_open"
        a.process_kprobe.args.add().path_arg.path = "/etc/shadow"
        b = GetEventsResponse()
        b.process_kprobe.process.exec_id = "B"
        b.process_kprobe.process.parent_exec_id = "A"
        b.process_kprobe.function_name = "tcp_connect"
        b.process_kprobe.args.add().sock_arg.daddr = "1.2.3.4"
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            engine.process(tn.normalize(a))
            engine.process(tn.normalize(b))
        self.assertIn("CORRELATION ALERT", buf.getvalue())

    def test_aggregation_fires_once_at_threshold(self):
        engine = AggregationEngine(build_example_agg_rules())
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            for _ in range(6):
                r = GetEventsResponse()
                r.process_exec.process.binary = "/usr/bin/sudo"
                r.process_exec.process.uid.value = 1000
                engine.process(tn.normalize(r))
        self.assertEqual(buf.getvalue().count("AGG ALERT"), 1)


CORRELATION_YAML = """\
title: base rule
name: setuid_exec_rule
status: experimental
logsource:
  product: tetragon
detection:
  selection:
    function_name: security_task_fix_setuid
  condition: selection
level: medium
---
title: Repeated setuid
correlation:
  type: event_count
  rules:
    - setuid_exec_rule
  group-by:
    - process.uid
  timespan: 60s
  condition:
    gte: 3
"""


class TestSigmaCorrelationYaml(unittest.TestCase):
    def test_event_count_yaml_round_trip(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "c.yml").write_text(CORRELATION_YAML)
            single, temporal, agg = load_everything(d)
        # the base rule only feeds the correlation, so it must NOT alert by itself
        self.assertEqual((len(single), len(temporal), len(agg)), (0, 0, 1))
        self.assertEqual((agg[0].threshold, agg[0].window_seconds), (3, 60))

        engine = AggregationEngine(agg)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            for _ in range(4):
                r = GetEventsResponse()
                r.process_lsm.function_name = "security_task_fix_setuid"
                r.process_lsm.process.uid.value = 1000
                engine.process(tn.normalize(r))
        self.assertIn("AGG ALERT", buf.getvalue())



def compile_ptrace():
    return compile_yaml_file("ptrace_injection.yml")


def ptrace_event(request, pid, fn="__x64_sys_ptrace"):
    r = GetEventsResponse()
    r.process_kprobe.function_name = fn
    r.process_kprobe.args.add().int_arg = request
    r.process_kprobe.args.add().int_arg = pid
    return tn.normalize(r)


class TestPositionalArgs(unittest.TestCase):
    def test_ptrace_matches_on_request_code(self):
        rule = compile_ptrace()
        for request in (4, 5, 6, 16, 16902):          # POKETEXT/DATA/USER, ATTACH, SEIZE
            self.assertTrue(rule.matches(ptrace_event(request, 1234)), request)

    def test_read_only_request_does_not_match(self):
        self.assertFalse(compile_ptrace().matches(ptrace_event(2, 1234)))   # PEEKDATA

    def test_swapped_arguments_do_not_match(self):
        # Regression: type-only matching found "16" in ANY int_arg. Positional
        # matching must only look at args[0] (the request), not args[1] (the pid).
        self.assertFalse(compile_ptrace().matches(ptrace_event(1234, 16)))

    def test_other_syscall_does_not_match(self):
        self.assertFalse(compile_ptrace().matches(ptrace_event(16, 1, fn="__x64_sys_kill")))

    def test_missing_position_is_a_clean_non_match(self):
        r = GetEventsResponse()
        r.process_kprobe.function_name = "__x64_sys_ptrace"
        r.process_kprobe.args.add().int_arg = 16          # only ONE arg emitted
        from tetragon_backend import _match_args_list
        self.assertFalse(_match_args_list(tn.normalize(r).args, "1.int_arg", lambda v: True))

    def test_type_only_form_still_works(self):
        from tetragon_backend import _match_args_list
        r = GetEventsResponse()
        r.process_kprobe.args.add().path_arg.path = "/etc/shadow"
        args = tn.normalize(r).args
        self.assertTrue(_match_args_list(args, "path_arg.path", lambda v: v == "/etc/shadow"))
        self.assertTrue(_match_args_list(args, "0.path_arg.path", lambda v: v == "/etc/shadow"))

    def test_64bit_ints_rendered_as_strings_still_match_numbers(self):
        # protobuf JSON renders int64 as "16"; a plain == against 16 never matched.
        from tetragon_backend import _build_value_matcher
        from sigma.types import SigmaNumber
        m = _build_value_matcher(SigmaNumber(16))
        self.assertTrue(m("16"))
        self.assertTrue(m(16))
        self.assertFalse(m("17"))
        self.assertFalse(m(None))
        self.assertFalse(m("abc"))


CORR_TEMPLATE = """\
title: base rule
name: setuid_exec_rule
status: experimental
logsource:
  product: tetragon
detection:
  selection:
    function_name: security_task_fix_setuid
  condition: selection
level: medium
---
title: Repeated setuid
correlation:
  type: event_count
  rules:
    - {ref}
  group-by:
    - process.uid
  timespan: 60s
  condition:
    gte: 3
{extra}"""


class TestGenerateSemantics(unittest.TestCase):
    def load(self, ref="setuid_exec_rule", extra=""):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "c.yml").write_text(CORR_TEMPLATE.format(ref=ref, extra=extra))
            return load_everything(d)

    def test_base_rule_is_quiet_by_default(self):
        single, _, agg = self.load()
        self.assertEqual((len(single), len(agg)), (0, 1))

    def test_generate_false_is_quiet(self):
        self.assertEqual(len(self.load(extra="  generate: false\n")[0]), 0)

    def test_generate_true_keeps_the_base_rule_alerting(self):
        single, _, agg = self.load(extra="  generate: true\n")
        self.assertEqual((len(single), len(agg)), (1, 1))

    def test_no_duplicate_alerts_end_to_end(self):
        # 3 matching events: the correlation must fire ONCE and the base rule NOT AT ALL.
        single, _, agg = self.load()
        engine = AggregationEngine(agg)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            for _ in range(3):
                r = GetEventsResponse()
                r.process_lsm.function_name = "security_task_fix_setuid"
                r.process_lsm.process.uid.value = 1000
                e = tn.normalize(r)
                for rule in single:
                    if rule.matches(e):
                        print("[ALERT] base")
                engine.process(e)
        self.assertEqual(buf.getvalue().count("[ALERT] base"), 0)
        self.assertEqual(buf.getvalue().count("AGG ALERT"), 1)

    def test_unknown_reference_gives_a_clear_error(self):
        with self.assertRaises(ValueError) as cm:
            self.load(ref="typo_rule")
        self.assertIn("typo_rule", str(cm.exception))

    def test_compiler_rejects_unknown_reference_defensively(self):
        from sigma_correlation_compiler import compile_correlation
        col = SigmaCollection.from_yaml(CORR_TEMPLATE.format(ref="setuid_exec_rule", extra=""))
        corr = [r for r in col.rules if hasattr(r, "timespan")][0]
        with self.assertRaises(ValueError) as cm:
            compile_correlation(corr, {"other_rule": None})
        self.assertIn("setuid_exec_rule", str(cm.exception))
        self.assertIn("other_rule", str(cm.exception))          # lists what IS known

    def test_correlation_may_reference_a_rule_in_another_file(self):
        base, corr = CORR_TEMPLATE.split("---\n")
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "a_base.yml").write_text(base)
            (Path(d) / "b_corr.yml").write_text("title: Repeated setuid\n" + corr.split("title: Repeated setuid\n")[1].format(ref="setuid_exec_rule", extra=""))
            single, _, agg = load_everything(d)
        self.assertEqual((len(single), len(agg)), (0, 1))

    def test_broken_file_is_named_in_the_error(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "good.yml").write_text((ROOT / "sigma_rules" / "su_root.yml").read_text())
            (Path(d) / "broken.yml").write_text("title: x\ndetection: [unclosed\n")
            with self.assertRaises(ValueError) as cm:
                load_everything(d)
        self.assertIn("broken.yml", str(cm.exception))
        self.assertNotIn("good.yml", str(cm.exception))


class TestSchemaExplorer(unittest.TestCase):
    def test_all_modes_exit_cleanly(self):
        import subprocess
        script = str(ROOT / "schema_explorer.py")
        for argv, code in (([], 0), (["process_lsm"], 0), (["--args"], 0), (["nope"], 1)):
            p = subprocess.run([sys.executable, script, *argv], cwd=ROOT,
                               capture_output=True, text=True)
            self.assertEqual(p.returncode, code, f"{argv}: {p.stderr}")


if __name__ == "__main__":
    unittest.main()
