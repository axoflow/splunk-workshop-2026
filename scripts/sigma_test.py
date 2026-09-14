#!/usr/bin/env python3
"""Evaluate Sigma rules against their TP/TN samples, offline.

    scripts/sigma_test.py --pipeline pipelines/workshop_sysmon.yml \
                          --rules rules/ --tests tests/

    scripts/sigma_test.py --pipeline solution/pipelines/workshop_sysmon.yml \
                          --rules rules/ --tests tests/

Note: `sigma test` is NOT a sigma-cli subcommand -- sigma-cli ships convert,
check, list and plugin. This is the workshop's harness. It needs no Splunk
instance, which is what makes it usable as a CI merge gate.

What it does, and why it is honest:

  1. Parses the rule with pySigma.
  2. Applies the SAME processing pipeline the Splunk conversion uses, so
     field mappings, added conditions and dropped detection items all take
     effect exactly as they do in the generated SPL.
  3. Evaluates the resulting detection tree directly against each JSON
     sample.

Step 3 is an approximation of Splunk, not Splunk. It implements Sigma's
matching semantics (case-insensitive, wildcards, AND/OR/NOT), which is
enough to catch a broken field mapping or an inverted filter. It does NOT
reproduce SPL quirks -- backslash escaping in particular. A rule that passes
here can still return zero rows in Splunk -- which is the whole point of the
workshop. It also cannot know whether a field is extracted in your Splunk at
all, or whether your `source` string is right, because those are properties of
an environment rather than of a rule.

Harness for logic, Splunk for reality, always both. Use scripts/ingest.py +
scripts/query.sh for the end-to-end check.

Exit status: 0 if every sample matched its expectation, 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

try:
    from sigma.collection import SigmaCollection
    from sigma.conditions import (
        ConditionAND,
        ConditionFieldEqualsValueExpression,
        ConditionNOT,
        ConditionOR,
        ConditionValueExpression,
    )
    from sigma.processing.pipeline import ProcessingPipeline
    from sigma.types import (
        SigmaBool,
        SigmaNull,
        SigmaNumber,
        SigmaRegularExpression,
        SigmaString,
        SpecialChars,
    )
except ImportError as exc:  # pragma: no cover
    sys.exit(
        f"error: {exc}\n"
        "Install the workshop dependencies first:\n"
        "  python3 -m venv .venv && source .venv/bin/activate\n"
        "  pip install -r requirements.txt"
    )


class Unsupported(Exception):
    """The rule uses a construct this harness cannot evaluate offline."""


# --------------------------------------------------------------------------
# Sigma value -> matcher
# --------------------------------------------------------------------------

def sigma_string_to_regex(value: SigmaString) -> re.Pattern[str]:
    """Translate a SigmaString (with * and ? wildcards) into a regex.

    Modifiers are already baked in by the time we get here: `|contains: foo`
    has become the SigmaString `*foo*`, `|endswith: bar` has become `*bar`.
    That is why this function is the only place wildcard semantics live.
    """
    parts: list[str] = []
    for chunk in value.s:
        if isinstance(chunk, str):
            parts.append(re.escape(chunk))
        elif chunk is SpecialChars.WILDCARD_MULTI:
            parts.append(".*")
        elif chunk is SpecialChars.WILDCARD_SINGLE:
            parts.append(".")
        else:
            raise Unsupported(f"unhandled SigmaString component {chunk!r}")
    return re.compile("^" + "".join(parts) + "$", re.IGNORECASE | re.DOTALL)


def value_matches(sigma_value, observed) -> bool:
    """Does a single observed event value satisfy a single Sigma value?"""
    if isinstance(sigma_value, SigmaNull):
        return observed is None or observed == ""

    if observed is None:
        return False

    if isinstance(sigma_value, SigmaString):
        return bool(sigma_string_to_regex(sigma_value).match(str(observed)))

    if isinstance(sigma_value, SigmaRegularExpression):
        flags = re.IGNORECASE if getattr(sigma_value, "case_insensitive", False) else 0
        return bool(re.search(sigma_value.regexp, str(observed), flags))

    if isinstance(sigma_value, (SigmaNumber, SigmaBool)):
        # Splunk is loose about numeric-vs-string; 4688 and "4688" are the
        # same event. Compare on the string form so a quoted EventCode in a
        # test sample does not produce a spurious failure.
        return str(sigma_value.number if isinstance(sigma_value, SigmaNumber)
                   else sigma_value.boolean).lower() == str(observed).lower()

    raise Unsupported(f"unhandled Sigma value type {type(sigma_value).__name__}")


# --------------------------------------------------------------------------
# Condition tree -> boolean
# --------------------------------------------------------------------------

def lookup(event: dict, field_name: str):
    """Case-insensitive field lookup, because Splunk field names are not
    reliably cased the same way across sourcetypes."""
    if field_name in event:
        return event[field_name]
    lowered = field_name.lower()
    for key, value in event.items():
        if key.lower() == lowered:
            return value
    return None


def evaluate(node, event: dict) -> bool:
    if isinstance(node, ConditionAND):
        return all(evaluate(arg, event) for arg in node.args)
    if isinstance(node, ConditionOR):
        return any(evaluate(arg, event) for arg in node.args)
    if isinstance(node, ConditionNOT):
        return not evaluate(node.args[0], event)

    if isinstance(node, ConditionFieldEqualsValueExpression):
        observed = lookup(event, node.field)
        # A list value in the event (multivalue field) matches if any element does.
        if isinstance(observed, list):
            return any(value_matches(node.value, item) for item in observed)
        return value_matches(node.value, observed)

    if isinstance(node, ConditionValueExpression):
        # Keyword search with no field: Sigma searches the whole event.
        for observed in event.values():
            candidates = observed if isinstance(observed, list) else [observed]
            for item in candidates:
                if value_matches(node.value, item):
                    return True
        return False

    raise Unsupported(f"unhandled condition node {type(node).__name__}")


# --------------------------------------------------------------------------
# Test discovery and execution
# --------------------------------------------------------------------------

@dataclass
class Result:
    rule_id: str
    rule_title: str
    rule_path: Path
    samples: list[tuple[str, str, bool, bool]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors and all(fired == expected
                                       for _, _, expected, fired in self.samples)

    @property
    def true_positives(self) -> int:
        return sum(1 for _, _, expected, fired in self.samples if expected and fired)

    @property
    def expected_positives(self) -> int:
        return sum(1 for _, _, expected, _ in self.samples if expected)

    @property
    def false_positives(self) -> int:
        return sum(1 for _, _, expected, fired in self.samples if not expected and fired)


def load_samples(tests_root: Path, rule_path: Path, rules_root: Path) -> list[Path]:
    """tests/ mirrors rules/: rules/execution/foo.yml -> tests/execution/foo/*.json"""
    relative = rule_path.relative_to(rules_root).with_suffix("")
    directory = tests_root / relative
    if not directory.is_dir():
        return []
    return sorted(directory.glob("*.json"))


def run_rule(rule_path: Path, pipeline: ProcessingPipeline | None,
             tests_root: Path, rules_root: Path) -> Result:
    collection = SigmaCollection.from_yaml(rule_path.read_text())
    rule = collection.rules[0]
    result = Result(rule_id=str(rule.id), rule_title=rule.title, rule_path=rule_path)

    if pipeline is not None:
        pipeline.apply(rule)

    samples = load_samples(tests_root, rule_path, rules_root)
    if not samples:
        result.errors.append(
            "no test samples found -- expected "
            f"{tests_root / rule_path.relative_to(rules_root).with_suffix('')}/*.json"
        )
        return result

    try:
        conditions = [c.parse() for c in rule.detection.parsed_condition]
    except Exception as exc:
        result.errors.append(f"could not parse rule condition: {exc}")
        return result

    for sample_path in samples:
        try:
            doc = json.loads(sample_path.read_text())
        except json.JSONDecodeError as exc:
            result.errors.append(f"{sample_path.name}: invalid JSON: {exc}")
            continue

        meta = doc.get("_meta", {})
        event = doc.get("event")
        if not isinstance(event, dict):
            result.errors.append(f"{sample_path.name}: missing top-level 'event' object")
            continue

        expect = meta.get("expect")
        if expect not in ("fire", "no_fire"):
            result.errors.append(
                f"{sample_path.name}: _meta.expect must be 'fire' or 'no_fire', got {expect!r}"
            )
            continue

        # source/sourcetype live in _meta because scripts/ingest.py sends them
        # as Splunk metadata rather than event fields -- but the pipeline adds
        # them as SPL constraints, so the matcher has to see them too.
        enriched = dict(event)
        enriched.setdefault("source", meta.get("source", "WinEventLog:Security"))
        enriched.setdefault("sourcetype", meta.get("sourcetype", "WinEventLog:Security"))

        try:
            fired = any(evaluate(condition, enriched) for condition in conditions)
        except Unsupported as exc:
            result.errors.append(f"{sample_path.name}: {exc}")
            continue

        result.samples.append((sample_path.name,
                               meta.get("description", ""),
                               expect == "fire",
                               fired))

    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate Sigma rules against their TP/TN samples, offline.")
    parser.add_argument("--rules", default="rules",
                        help="rule file or directory (default: rules)")
    parser.add_argument("--tests", default="tests",
                        help="tests directory, mirroring rules/ (default: tests)")
    parser.add_argument("--pipeline", action="append", default=[],
                        help="processing pipeline YAML; repeatable")
    parser.add_argument("--rules-root", default=None,
                        help="root used to map rules to tests "
                             "(default: --rules if it is a directory, else its parent chain)")
    args = parser.parse_args()

    rules_arg = Path(args.rules)
    tests_root = Path(args.tests)

    if rules_arg.is_dir():
        rule_paths = sorted(p for p in rules_arg.rglob("*.yml"))
        rules_root = rules_arg
    elif rules_arg.is_file():
        rule_paths = [rules_arg]
        # A single rule still needs a root to compute the tests/ mirror path.
        rules_root = Path(args.rules_root) if args.rules_root else Path("rules")
        if not rules_root.is_dir():
            rules_root = rules_arg.parent
    else:
        return _fail(f"no such rule path: {rules_arg}")

    if not rule_paths:
        return _fail(f"no .yml rules under {rules_arg}")
    if not tests_root.is_dir():
        return _fail(f"no such tests directory: {tests_root}")

    pipeline = None
    for path in args.pipeline:
        p = Path(path)
        if not p.is_file():
            return _fail(f"no such pipeline: {p}")
        # A malformed pipeline is a normal thing to hit while editing one.
        # Report it as an error with the file name, not as a traceback.
        try:
            loaded = ProcessingPipeline.from_yaml(p.read_text())
        except Exception as exc:
            return _fail(
                f"could not load pipeline {p}:\n"
                f"       {type(exc).__name__}: {exc}\n\n"
                "       Common causes:\n"
                "         * 'transformations:' present but empty -- write "
                "'transformations: []'\n"
                "         * a TODO block left half-uncommented\n"
                "         * indentation: list items under 'transformations' need '- '"
            )
        pipeline = loaded if pipeline is None else pipeline + loaded

    if pipeline is None:
        print("warning: no --pipeline given. Sigma's abstract field names will be")
        print("         matched literally against the samples -- which is the")
        print("         Stage 1 failure, reproduced offline.")
        print()
    elif not pipeline.items:
        print("note: the pipeline loaded but contains no transformations, so it")
        print("      changes nothing. If you are on Stage 4, that is expected --")
        print("      the TODO block is still commented out.")
        print()

    results = [run_rule(p, pipeline, tests_root, rules_root) for p in rule_paths]

    failed = 0
    for r in results:
        status = "PASS" if r.ok else "FAIL"
        print(f"[{status}] {r.rule_title}")
        print(f"        {r.rule_path}")
        for name, description, expected, fired in r.samples:
            mark = "ok  " if expected == fired else "FAIL"
            want = "fire" if expected else "no fire"
            got = "fired" if fired else "did not fire"
            print(f"        {mark} {name:<24} expected {want:<8} -> {got}"
                  + (f"   ({description})" if description else ""))
        for err in r.errors:
            print(f"        FAIL {err}")
        if not r.ok:
            failed += 1
        print()

    tp, exp = sum(r.true_positives for r in results), sum(r.expected_positives for r in results)
    fp = sum(r.false_positives for r in results)
    rate = (100.0 * tp / exp) if exp else 0.0
    print(f"{len(results) - failed}/{len(results)} rules passed | "
          f"true-positive rate {tp}/{exp} ({rate:.0f}%) | false positives {fp}")

    if failed:
        print()
        print("Before editing the rule, ask which layer is actually broken:")
        print("  * field name in the SPL not present in the data -> pipelines/")
        print("  * field present but always empty                -> collection/")
        print("  * fields fine, logic too broad or too narrow     -> rules/")
    return 1 if failed else 0


def _fail(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
