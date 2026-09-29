"""
sigma_correlation_compiler.py

Reads pySigma SigmaCorrelationRule objects and produces our engine's
CorrelationRule / AggregationRule instances.

Verified against pysigma==1.5.1 by parsing real correlation YAML and
inspecting the runtime objects (previous version of this file was written
from the spec/docs and had several wrong assumptions - see the corrections
noted inline below). If you're on a different pysigma version, re-run the
same kind of inspection before trusting this file:

    from sigma.collection import SigmaCollection
    col = SigmaCollection.from_yaml(open("some_correlation.yml").read())
    for item in col.rules:
        if hasattr(item, "timespan"):
            print(item.type, item.condition, item.rules, item.group_by)
"""

from sigma.correlations import SigmaCorrelationRule, SigmaCorrelationType, SigmaCorrelationConditionOperator
from tetragon_backend import CompiledSigmaRule
from correlation_engine import CorrelationRule, CorrelationStep
from aggregation_engine import AggregationRule


def _resolve_group_by(field_paths: list):
    """Build a group-by key function from Sigma's group-by field list.
    corr.group_by is a plain list[str] of dotted paths (e.g. 'process.uid'),
    not field-mapped objects - confirmed at runtime."""
    def group_by(event) -> str:
        parts = []
        for path in field_paths:
            obj = event
            for p in path.split("."):
                obj = getattr(obj, p, None) if obj is not None else None
            parts.append(str(obj))
        return "|".join(parts)
    return group_by


def compile_correlation(corr: SigmaCorrelationRule, compiled_rules_by_ref: dict):
    """
    compiled_rules_by_ref must be keyed by whatever string the correlation's
    `rules:` list uses to refer to base rules - this is the base rule's
    `name:` field if set, else its `id:`. corr.rules is a list of
    SigmaRuleReference objects, NOT plain strings - use `.reference` to get
    the string (confirmed at runtime; a naive `compiled_rules_by_ref[r]`
    with r being the SigmaRuleReference object itself will KeyError).
    """
    referenced = []
    for ref in corr.rules:
        if ref.reference not in compiled_rules_by_ref:
            known = ", ".join(sorted(compiled_rules_by_ref)) or "(none)"
            raise ValueError(
                f"correlation '{corr.title}' references unknown rule "
                f"'{ref.reference}'. Rules are matched by their `name:` or `id:` "
                f"field. Known: {known}"
            )
        referenced.append(compiled_rules_by_ref[ref.reference])

    # corr.timespan.seconds is correct (SigmaCorrelationTimespan.seconds is
    # already normalized to seconds regardless of the "30s"/"5m" spec used).
    window_seconds = corr.timespan.seconds
    group_by = _resolve_group_by([str(f) for f in corr.group_by])

    # corr.type is a SigmaCorrelationType enum instance, NOT
    # SigmaCorrelationTypeLiteral (that's a typing.Literal alias, not an
    # enum with class attributes - using it as one raises AttributeError).
    if corr.type in (SigmaCorrelationType.TEMPORAL, SigmaCorrelationType.TEMPORAL_ORDERED):
        steps = [
            CorrelationStep(name=ref.reference, predicate=rule.matches)
            for ref, rule in zip(corr.rules, referenced)
        ]
        return CorrelationRule(
            title=corr.title,
            steps=steps,
            window_seconds=window_seconds,
            scope="lineage",   # safest default; tighten to "exec_id" if group-by implies it
            level=str(corr.level) if corr.level else "medium",
        )

    if corr.type == SigmaCorrelationType.EVENT_COUNT:
        # event_count correlations reference exactly one underlying rule.
        # corr.condition is a SigmaCorrelationCondition with .op (a
        # SigmaCorrelationConditionOperator enum) and .count (int) -
        # NOT .gte/.gt attributes as an earlier draft of this file assumed.
        base_rule = referenced[0]
        if corr.condition.op not in (
            SigmaCorrelationConditionOperator.GTE,
            SigmaCorrelationConditionOperator.GT,
        ):
            raise NotImplementedError(
                f"Only gte/gt event_count conditions are wired up to "
                f"AggregationRule's threshold semantics; got {corr.condition.op}. "
                f"Extend AggregationRule if you need lt/lte/eq/neq."
            )
        threshold = corr.condition.count
        return AggregationRule(
            title=corr.title,
            predicate=base_rule.matches,
            group_by=group_by,
            threshold=threshold,
            window_seconds=window_seconds,
            level=str(corr.level) if corr.level else "medium",
        )

    raise NotImplementedError(f"Correlation type {corr.type} not yet supported")
