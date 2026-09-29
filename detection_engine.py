"""
detection_engine.py

Simple entrypoint: load single-shot Sigma rules only (no correlation/aggregation)
and evaluate them against the live Tetragon event stream.

For the full pipeline (single-shot + correlation + aggregation), use main.py instead.
"""

from pathlib import Path
from sigma.collection import SigmaCollection

from tetragon_pipeline import tetragon_pipeline
from tetragon_backend import compile_rule, CompiledSigmaRule
from tetragon_normalize import stream_events


def load_rules(rules_dir: str) -> list:
    pipeline = tetragon_pipeline()
    compiled = []

    for path in Path(rules_dir).glob("*.yml"):
        collection = SigmaCollection.from_yaml(path.read_text())
        for rule in collection.rules:
            pipeline.apply(rule)          # applies the field mapping in-place
            compiled.append(compile_rule(rule))

    return compiled


def main():
    rules = load_rules("./sigma_rules")
    print(f"Loaded {len(rules)} rules")

    for event in stream_events():
        for rule in rules:
            if rule.matches(event):
                print(f"[ALERT][{rule.level}] {rule.title} "
                      f"-> pid={event.process.pid if event.process else None} "
                      f"cmd={event.process.command_line if event.process else None}")


if __name__ == "__main__":
    main()
