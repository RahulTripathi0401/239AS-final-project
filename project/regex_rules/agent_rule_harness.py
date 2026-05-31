#!/usr/bin/env python3
"""LLM-guided rule-discovery harness for CSIC 2010.

This script turns the manual/Codex rule-iteration process into a reproducible
agent loop. The LLM does not execute detection logic. It sees metric summaries
and sampled errors, chooses a candidate rule group from a fixed safe catalog,
and the deterministic evaluator decides whether that candidate is accepted.

The fixed catalog keeps the experiment auditable: the model can guide search,
but it cannot inject arbitrary Python or regexes into the runtime path.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

from sklearn.model_selection import train_test_split

from evaluate_rules import (
    ROUND_1,
    ROUND_2,
    ROUND_3,
    ROUND_4,
    ROUND_7,
    ROUND_10,
    DATA_PATH,
    Request,
    Rule,
    button_value_anomaly,
    contact_and_location_field_anomaly,
    credential_value_anomaly,
    endpoint_keyset_anomaly,
    endpoint_value_anomaly,
    evaluate_with_callbacks,
    field_format_anomaly,
    load_requests,
    person_name_field_anomaly,
    product_value_anomaly,
    register_business_anomaly,
    stable_value_anomaly,
    strict_identity_field_anomaly,
    stricter_path_or_method_anomaly,
)


Callback = Callable[[Request], bool]
OUT_DIR = Path(__file__).resolve().parent / "outputs"


@dataclass(frozen=True)
class Candidate:
    candidate_id: str
    description: str
    rules: tuple[Rule, ...] = ()
    callbacks: tuple[Callback, ...] = ()


@dataclass
class State:
    rules: list[Rule] = field(default_factory=list)
    callbacks: list[Callback] = field(default_factory=list)
    accepted_ids: list[str] = field(default_factory=list)
    rejected_ids: list[str] = field(default_factory=list)


def rule_delta(newer: list[Rule], older: list[Rule]) -> tuple[Rule, ...]:
    old_names = {rule.name for rule in older}
    return tuple(rule for rule in newer if rule.name not in old_names)


CATALOG: list[Candidate] = [
    Candidate(
        "seed_obvious_attacks",
        "Generic SQL, script, /etc/passwd, and null-byte signatures.",
        tuple(ROUND_1),
    ),
    Candidate(
        "injection_and_path_rules",
        "Tautologies, HTML injection, traversal, shell metacharacters, and backup suffixes.",
        rule_delta(ROUND_2, ROUND_1),
    ),
    Candidate(
        "encoding_and_file_probe_rules",
        "Suspicious quote punctuation, Windows/Unix file probes, and absolute URL parameters.",
        rule_delta(ROUND_3, ROUND_2),
    ),
    Candidate(
        "resource_and_markup_rules",
        "Known invalid resources, angle brackets, and SQL function probes.",
        rule_delta(ROUND_4, ROUND_3),
    ),
    Candidate(
        "endpoint_value_callbacks",
        "Endpoint-aware numeric-field and registration-field checks.",
        callbacks=(endpoint_value_anomaly, register_business_anomaly),
    ),
    Candidate(
        "endpoint_schema_callbacks",
        "Expected endpoint parameter keysets and strict known-path checks.",
        callbacks=(endpoint_keyset_anomaly, stricter_path_or_method_anomaly, button_value_anomaly),
    ),
    Candidate(
        "encoded_payload_rules",
        "Encoded XSS, CRLF, encoded shell/metacharacter, and encoded null-byte signatures.",
        rule_delta(ROUND_7, ROUND_4),
    ),
    Candidate(
        "value_constraint_rules",
        "Regex metacharacter, login/password slash, and stable short-field mutation signatures.",
        rule_delta(ROUND_10, ROUND_7),
        callbacks=(stable_value_anomaly, product_value_anomaly, field_format_anomaly),
    ),
    Candidate(
        "identity_field_callbacks",
        "Login, password, credit-card-like number, postal-code, and person-name shape checks.",
        callbacks=(strict_identity_field_anomaly, person_name_field_anomaly),
    ),
    Candidate(
        "contact_location_credential_callbacks",
        "Email, city, province, and credential-value shape checks.",
        callbacks=(contact_and_location_field_anomaly, credential_value_anomaly),
    ),
]


REPLAY_PLAN = [candidate.candidate_id for candidate in CATALOG]


def metrics_line(metrics: dict[str, float | int]) -> str:
    return (
        f"accuracy={metrics['accuracy']:.4f} precision={metrics['precision']:.4f} "
        f"recall={metrics['recall']:.4f} f1={metrics['f1']:.4f} "
        f"tp={metrics['tp']} fp={metrics['fp']} tn={metrics['tn']} fn={metrics['fn']}"
    )


def predict(request: Request, rules: list[Rule], callbacks: list[Callback]) -> int:
    compiled = [(rule, rule.compile()) for rule in rules]
    for rule, pattern in compiled:
        if pattern.search(getattr(request, rule.field)):
            return 1
    return int(any(callback(request) for callback in callbacks))


def sample_errors(
    requests: Iterable[Request],
    rules: list[Rule],
    callbacks: list[Callback],
    limit: int = 4,
) -> dict[str, list[dict[str, str | int]]]:
    errors = {"false_positives": [], "false_negatives": []}
    for request in requests:
        pred = predict(request, rules, callbacks)
        if pred == 1 and request.label == 0 and len(errors["false_positives"]) < limit:
            errors["false_positives"].append(example_dict(request))
        elif pred == 0 and request.label == 1 and len(errors["false_negatives"]) < limit:
            errors["false_negatives"].append(example_dict(request))
        if all(len(values) >= limit for values in errors.values()):
            break
    return errors


def example_dict(request: Request) -> dict[str, str | int]:
    return {
        "label": request.label,
        "method": request.method,
        "path": request.path_decoded,
        "url": request.url_decoded[:220],
        "body": request.content_decoded[:180],
        "params": ",".join(sorted(request.params_decoded))[:180],
    }


def candidate_by_id(candidate_id: str) -> Candidate | None:
    for candidate in CATALOG:
        if candidate.candidate_id == candidate_id:
            return candidate
    return None


def add_unique(state: State, candidate: Candidate) -> State:
    rule_names = {rule.name for rule in state.rules}
    callback_names = {callback.__name__ for callback in state.callbacks}
    return State(
        rules=state.rules + [rule for rule in candidate.rules if rule.name not in rule_names],
        callbacks=state.callbacks
        + [callback for callback in candidate.callbacks if callback.__name__ not in callback_names],
        accepted_ids=list(state.accepted_ids),
        rejected_ids=list(state.rejected_ids),
    )


class Planner:
    def choose(
        self,
        round_number: int,
        state: State,
        dev_metrics: dict[str, float | int],
        errors: dict[str, list[dict[str, str | int]]],
    ) -> tuple[str, str]:
        raise NotImplementedError


class ReplayPlanner(Planner):
    def choose(
        self,
        round_number: int,
        state: State,
        dev_metrics: dict[str, float | int],
        errors: dict[str, list[dict[str, str | int]]],
    ) -> tuple[str, str]:
        remaining = [candidate_id for candidate_id in REPLAY_PLAN if candidate_id not in state.accepted_ids]
        if not remaining:
            return "stop", "All replay candidates have already been accepted."
        return remaining[0], "Replay planner follows the retained rule-family order from the report."


class OpenAIPlanner(Planner):
    def __init__(self, model: str, api_key_file: str | None = None, temperature: float = 0.0) -> None:
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise SystemExit(
                "Missing dependency: install openai with `uv pip install openai`."
            ) from exc
        if api_key_file and not os.environ.get("OPENAI_API_KEY"):
            key = Path(api_key_file).read_text().strip()
            if key:
                os.environ["OPENAI_API_KEY"] = key
        if not os.environ.get("OPENAI_API_KEY"):
            raise SystemExit(
                "OPENAI_API_KEY is not set. Export it or pass --api-key-file before using "
                "--planner openai."
            )
        self.client = OpenAI()
        self.model = model
        self.temperature = temperature

    def choose(
        self,
        round_number: int,
        state: State,
        dev_metrics: dict[str, float | int],
        errors: dict[str, list[dict[str, str | int]]],
    ) -> tuple[str, str]:
        remaining = [
            {
                "candidate_id": candidate.candidate_id,
                "description": candidate.description,
                "regex_rules": [rule.name for rule in candidate.rules],
                "callbacks": [callback.__name__ for callback in candidate.callbacks],
            }
            for candidate in CATALOG
            if candidate.candidate_id not in state.accepted_ids
            and candidate.candidate_id not in state.rejected_ids
        ]
        if not remaining:
            return "stop", "No remaining candidates."
        payload = {
            "round": round_number,
            "accepted": state.accepted_ids,
            "rejected": state.rejected_ids,
            "dev_metrics": dev_metrics,
            "sampled_errors": errors,
            "remaining_candidates": remaining,
        }
        prompt = (
            "You are guiding an offline web-attack rule-discovery harness. "
            "Choose exactly one candidate_id from remaining_candidates, or choose stop. "
            "Prefer candidates that should improve recall while keeping precision high. "
            "Return only JSON with keys candidate_id and rationale.\n\n"
            f"{json.dumps(payload, indent=2)}"
        )
        response = self.client.responses.create(
            model=self.model,
            input=[
                {
                    "role": "system",
                    "content": (
                        "You are an LLM agent planner. You do not write executable code. "
                        "You choose from a fixed safe catalog, then a deterministic tool evaluates it."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            text={
                "format": {
                    "type": "json_schema",
                    "name": "candidate_choice",
                    "schema": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "candidate_id": {"type": "string"},
                            "rationale": {"type": "string"},
                        },
                        "required": ["candidate_id", "rationale"],
                    },
                }
            },
            temperature=self.temperature,
        )
        raw = response.output_text
        try:
            choice = json.loads(raw)
        except json.JSONDecodeError:
            match = re.search(r"\{.*\}", raw, flags=re.S)
            if not match:
                raise RuntimeError(f"Model did not return JSON: {raw!r}")
            choice = json.loads(match.group(0))
        return str(choice["candidate_id"]), str(choice["rationale"])


def run_agent(args: argparse.Namespace) -> list[dict[str, str | int | float]]:
    requests = load_requests()
    labels = [request.label for request in requests]
    indices = list(range(len(requests)))
    train_dev_idx, test_idx = train_test_split(
        indices, test_size=0.2, random_state=args.seed, stratify=labels
    )
    train_dev_labels = [labels[i] for i in train_dev_idx]
    train_idx, dev_idx = train_test_split(
        train_dev_idx,
        test_size=args.dev_size,
        random_state=args.seed,
        stratify=train_dev_labels,
    )
    train_requests = [requests[i] for i in train_idx]
    dev_requests = [requests[i] for i in dev_idx]
    test_requests = [requests[i] for i in test_idx]

    if args.planner == "openai":
        planner: Planner = OpenAIPlanner(args.model, args.api_key_file, args.temperature)
    else:
        planner = ReplayPlanner()

    state = State()
    rows: list[dict[str, str | int | float]] = []
    start = time.perf_counter()

    print(f"dataset={DATA_PATH}")
    print(
        f"split=random_state={args.seed} train={len(train_requests)} "
        f"dev={len(dev_requests)} test={len(test_requests)}"
    )
    print(f"planner={args.planner} model={args.model if args.planner == 'openai' else 'n/a'}")

    for round_number in range(1, args.max_rounds + 1):
        current_dev = evaluate_with_callbacks(dev_requests, state.rules, state.callbacks)
        current_test = evaluate_with_callbacks(test_requests, state.rules, state.callbacks)
        errors = sample_errors(dev_requests, state.rules, state.callbacks, args.error_examples)
        candidate_id, rationale = planner.choose(round_number, state, current_dev, errors)
        if candidate_id == "stop":
            print(f"round={round_number} planner_stop rationale={rationale}")
            break
        candidate = candidate_by_id(candidate_id)
        if candidate is None:
            print(f"round={round_number} invalid_candidate={candidate_id} rationale={rationale}")
            state.rejected_ids.append(candidate_id)
            continue

        candidate_state = add_unique(state, candidate)
        candidate_dev = evaluate_with_callbacks(
            dev_requests, candidate_state.rules, candidate_state.callbacks
        )
        candidate_test = evaluate_with_callbacks(
            test_requests, candidate_state.rules, candidate_state.callbacks
        )
        accepted = (
            candidate_dev["precision"] >= args.min_precision
            and candidate_dev[args.objective] > current_dev[args.objective] + args.min_delta
        )
        if accepted:
            state = candidate_state
            state.accepted_ids.append(candidate.candidate_id)
        else:
            state.rejected_ids.append(candidate.candidate_id)

        row = {
            "round": round_number,
            "candidate_id": candidate.candidate_id,
            "accepted": int(accepted),
            "rationale": rationale,
            "dev_accuracy_before": f"{current_dev['accuracy']:.6f}",
            "dev_f1_before": f"{current_dev['f1']:.6f}",
            "dev_accuracy_after": f"{candidate_dev['accuracy']:.6f}",
            "dev_precision_after": f"{candidate_dev['precision']:.6f}",
            "dev_recall_after": f"{candidate_dev['recall']:.6f}",
            "dev_f1_after": f"{candidate_dev['f1']:.6f}",
            "test_accuracy_after": f"{candidate_test['accuracy']:.6f}",
            "test_precision_after": f"{candidate_test['precision']:.6f}",
            "test_recall_after": f"{candidate_test['recall']:.6f}",
            "test_f1_after": f"{candidate_test['f1']:.6f}",
            "test_tp_after": candidate_test["tp"],
            "test_fp_after": candidate_test["fp"],
            "test_tn_after": candidate_test["tn"],
            "test_fn_after": candidate_test["fn"],
            "regex_rules": len(candidate_state.rules),
            "callbacks": len(candidate_state.callbacks),
        }
        rows.append(row)
        print(
            f"round={round_number} candidate={candidate.candidate_id} accepted={accepted} "
            f"dev_before=({metrics_line(current_dev)}) dev_after=({metrics_line(candidate_dev)}) "
            f"test_after=({metrics_line(candidate_test)})"
        )
        print(f"  rationale={rationale}")
        if accepted and candidate_test["accuracy"] >= args.target_accuracy:
            print(f"target_reached test_accuracy={candidate_test['accuracy']:.4f}")
            if args.stop_at_target:
                break

    final_train = evaluate_with_callbacks(train_requests, state.rules, state.callbacks)
    final_dev = evaluate_with_callbacks(dev_requests, state.rules, state.callbacks)
    final_test = evaluate_with_callbacks(test_requests, state.rules, state.callbacks)
    elapsed = time.perf_counter() - start
    print(f"accepted={state.accepted_ids}")
    print(f"rejected={state.rejected_ids}")
    print(f"final_train={metrics_line(final_train)}")
    print(f"final_dev={metrics_line(final_dev)}")
    print(f"final_test={metrics_line(final_test)}")
    print(f"elapsed_seconds={elapsed:.2f}")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / args.output
    if rows:
        with out_path.open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
        print(f"wrote={out_path}")
    return rows


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--planner", choices=["openai", "replay"], default="openai")
    parser.add_argument("--model", default="gpt-5.2")
    parser.add_argument("--api-key-file", help="Optional file containing an OpenAI API key.")
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--dev-size", type=float, default=0.1875, help="Fraction of train-dev split used as dev. 0.1875 yields a 65/15/20 train/dev/test split.")
    parser.add_argument("--max-rounds", type=int, default=12)
    parser.add_argument("--min-precision", type=float, default=0.995)
    parser.add_argument("--objective", choices=["accuracy", "recall", "f1"], default="f1")
    parser.add_argument("--min-delta", type=float, default=1e-6)
    parser.add_argument("--target-accuracy", type=float, default=0.99)
    parser.add_argument("--stop-at-target", action="store_true")
    parser.add_argument("--error-examples", type=int, default=4)
    parser.add_argument("--output", default="agent_rule_harness_rounds.csv")
    return parser.parse_args()


if __name__ == "__main__":
    run_agent(parse_args())
