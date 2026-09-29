"""
tetragon_backend.py

Compiles a parsed Sigma rule into a Python predicate: UnifiedEvent -> bool
"""

import re
from typing import Callable, Any
from sigma.rule import SigmaRule
from sigma.conditions import (
    ConditionOR,
    ConditionAND,
    ConditionNOT,
    ConditionFieldEqualsValueExpression,
)
from sigma.types import SigmaNumber, SigmaRegularExpression

Predicate = Callable[[Any], bool]


def _resolve_field(event, dotted_path: str):
    """Walk 'process.binary' or 'args.path_arg.path' against a UnifiedEvent."""
    parts = dotted_path.split(".")
    obj = event
    for p in parts:
        if obj is None:
            return None
        if p == "args" and hasattr(obj, "args"):
            # special-case: search across all normalized KprobeArguments
            return obj.args
        if isinstance(obj, dict):
            obj = obj.get(p)
        else:
            obj = getattr(obj, p, None)
    return obj


def _match_args_list(args_list, sub_path: str, matcher: Callable[[Any], bool]) -> bool:
    """
    Match a field under 'args.*' against the event's normalized argument list.

    Two addressing forms (the part after 'args.'):

      <arg_type>[.<subfield>...]           any argument of that type
            e.g. 'path_arg.path', 'sock_arg.daddr'

      <position>.<arg_type>[.<subfield>...]   ONLY the argument at that position
            e.g. '0.int_arg' (first arg), '1.int_arg' (second arg)

    Use the positional form whenever a hook has several arguments of the same
    type - e.g. sys_ptrace(request, pid, ...) has two int_args, and the
    type-only form cannot tell them apart.

    <position> is the argument's index in the EVENT's `args` list, i.e. the
    order the arguments are declared in your TracingPolicy's `args:` section
    (KprobeArgument has no index field of its own). It is not necessarily the
    kernel function's argument number if you skipped or reordered arguments.
    """
    parts = sub_path.split(".")
    position = None
    if parts[0].isdigit():
        position, parts = int(parts[0]), parts[1:]
    if not parts:
        return False
    arg_type, subfields = parts[0], parts[1:]

    if position is None:
        candidates = args_list or []
    elif args_list and position < len(args_list):
        candidates = [args_list[position]]
    else:
        return False                      # hook emitted fewer args than the rule expects

    for a in candidates:
        if a.get("arg_type") != arg_type:
            continue
        value = a.get("value")
        for key in subfields:
            value = value.get(key) if isinstance(value, dict) else None
        if matcher(value):
            return True
    return False


def _build_value_matcher(sigma_value) -> Callable[[Any], bool]:
    """Translate a SigmaString (with wildcards) / SigmaRegularExpression / SigmaNumber
    into a Python matcher function."""
    if isinstance(sigma_value, SigmaRegularExpression):
        pattern = re.compile(sigma_value.regexp)
        return lambda v: v is not None and pattern.search(str(v)) is not None

    if isinstance(sigma_value, SigmaNumber):
        target = sigma_value.number

        def numeric_match(v):
            # protobuf's JSON mapping renders 64-bit ints (long_arg, size_arg, ...)
            # as STRINGS, so a plain `v == 16` would silently never match "16".
            try:
                return float(v) == float(target)
            except (TypeError, ValueError):
                return False
        return numeric_match

    # SigmaString: handle Sigma's wildcard semantics (*  and  ?)
    raw = str(sigma_value)
    if raw.startswith("*") and raw.endswith("*") and len(raw) > 1:
        needle = raw.strip("*").lower()
        return lambda v: v is not None and needle in str(v).lower()
    if raw.startswith("*"):
        suffix = raw.lstrip("*").lower()
        return lambda v: v is not None and str(v).lower().endswith(suffix)
    if raw.endswith("*"):
        prefix = raw.rstrip("*").lower()
        return lambda v: v is not None and str(v).lower().startswith(prefix)
    exact = raw.lower()
    return lambda v: v is not None and str(v).lower() == exact


def compile_field_equals(expr: ConditionFieldEqualsValueExpression) -> Predicate:
    field = expr.field
    matcher = _build_value_matcher(expr.value)

    def predicate(event) -> bool:
        if field.startswith("args."):
            args_list = _resolve_field(event, "args")
            return _match_args_list(args_list, field[len("args."):], matcher)
        value = _resolve_field(event, field)
        return matcher(value)

    return predicate


def compile_condition(node) -> Predicate:
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return compile_field_equals(node)

    if isinstance(node, ConditionAND):
        sub = [compile_condition(c) for c in node.args]
        return lambda e: all(p(e) for p in sub)

    if isinstance(node, ConditionOR):
        sub = [compile_condition(c) for c in node.args]
        return lambda e: any(p(e) for p in sub)

    if isinstance(node, ConditionNOT):
        sub = compile_condition(node.args[0])
        return lambda e: not sub(e)

    raise NotImplementedError(f"Unsupported condition node: {type(node)}")


class CompiledSigmaRule:
    def __init__(self, rule: SigmaRule, predicate: Predicate):
        self.rule = rule
        self.predicate = predicate

    def matches(self, event) -> bool:
        return self.predicate(event)

    @property
    def title(self) -> str:
        return self.rule.title

    @property
    def level(self) -> str:
        return str(self.rule.level) if self.rule.level else "medium"


def compile_rule(rule: SigmaRule) -> CompiledSigmaRule:
    """Compile every detection block's condition, OR them together
    (mirrors how a Sigma rule's top-level 'condition:' combines named blocks)."""
    predicates = []
    for condition in rule.detection.parsed_condition:
        node = condition.parsed
        predicates.append(compile_condition(node))
    combined = lambda e: any(p(e) for p in predicates)
    return CompiledSigmaRule(rule, combined)
