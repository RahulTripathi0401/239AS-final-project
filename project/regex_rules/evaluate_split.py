#!/usr/bin/env python3
import csv
import sys
import time
from pathlib import Path

from sklearn.model_selection import train_test_split

from evaluate_rules import (
    DATA_PATH,
    ROUND_1,
    ROUND_2,
    ROUND_3,
    ROUND_4,
    ROUND_7,
    ROUND_10,
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
    put_method_anomaly,
    register_business_anomaly,
    stable_value_anomaly,
    strict_identity_field_anomaly,
    stricter_path_or_method_anomaly,
    unexpected_path_or_host_anomaly,
)


OUT_DIR = Path(__file__).resolve().parent / "outputs"


def rule_rounds():
    return [
        ("round_1_seed_obvious_attacks", ROUND_1, []),
        ("round_2_add_injection_and_path_rules", ROUND_2, []),
        ("round_3_add_encoding_and_file_probe_rules", ROUND_3, []),
        ("round_4_add_resource_and_broad_markup_rules", ROUND_4, []),
        (
            "round_5_add_endpoint_value_callbacks",
            ROUND_4,
            [endpoint_value_anomaly, register_business_anomaly],
        ),
        (
            "round_6_add_endpoint_schema_callbacks",
            ROUND_4,
            [
                endpoint_value_anomaly,
                register_business_anomaly,
                endpoint_keyset_anomaly,
                unexpected_path_or_host_anomaly,
            ],
        ),
        (
            "round_7_encoded_payloads_and_strict_paths",
            ROUND_7,
            [
                endpoint_value_anomaly,
                register_business_anomaly,
                endpoint_keyset_anomaly,
                stricter_path_or_method_anomaly,
                button_value_anomaly,
            ],
        ),
        (
            "round_8_encoded_payloads_conservative_paths",
            ROUND_7,
            [
                endpoint_value_anomaly,
                register_business_anomaly,
                endpoint_keyset_anomaly,
                unexpected_path_or_host_anomaly,
                button_value_anomaly,
                put_method_anomaly,
            ],
        ),
        (
            "round_9_full_static_whitelist_and_put",
            ROUND_7,
            [
                endpoint_value_anomaly,
                register_business_anomaly,
                endpoint_keyset_anomaly,
                stricter_path_or_method_anomaly,
                button_value_anomaly,
            ],
        ),
        (
            "round_10_value_constraints_no_asterisk",
            ROUND_10,
            [
                endpoint_value_anomaly,
                register_business_anomaly,
                endpoint_keyset_anomaly,
                stricter_path_or_method_anomaly,
                button_value_anomaly,
                stable_value_anomaly,
                product_value_anomaly,
                field_format_anomaly,
            ],
        ),
        (
            "round_11_identity_field_shapes",
            ROUND_10,
            [
                endpoint_value_anomaly,
                register_business_anomaly,
                endpoint_keyset_anomaly,
                stricter_path_or_method_anomaly,
                button_value_anomaly,
                stable_value_anomaly,
                product_value_anomaly,
                field_format_anomaly,
                strict_identity_field_anomaly,
                person_name_field_anomaly,
            ],
        ),
        (
            "round_12_contact_location_credentials",
            ROUND_10,
            [
                endpoint_value_anomaly,
                register_business_anomaly,
                endpoint_keyset_anomaly,
                stricter_path_or_method_anomaly,
                button_value_anomaly,
                stable_value_anomaly,
                product_value_anomaly,
                field_format_anomaly,
                strict_identity_field_anomaly,
                person_name_field_anomaly,
                contact_and_location_field_anomaly,
                credential_value_anomaly,
            ],
        ),
    ]


def write_csv(path: Path, rows: list[dict[str, str | int | float]]) -> None:
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def fmt(metrics: dict[str, float | int]) -> str:
    return (
        f"accuracy={metrics['accuracy']:.4f} precision={metrics['precision']:.4f} "
        f"recall={metrics['recall']:.4f} f1={metrics['f1']:.4f} "
        f"tp={metrics['tp']} fp={metrics['fp']} tn={metrics['tn']} fn={metrics['fn']}"
    )


def main() -> None:
    load_start = time.perf_counter()
    requests = load_requests()
    load_seconds = time.perf_counter() - load_start
    labels = [request.label for request in requests]
    indices = list(range(len(requests)))
    train_idx, test_idx = train_test_split(
        indices,
        test_size=0.2,
        random_state=42,
        stratify=labels,
    )
    train_requests = [requests[i] for i in train_idx]
    test_requests = [requests[i] for i in test_idx]

    print(f"dataset={DATA_PATH}")
    print(
        f"split=random_state=42 stratified 80/20 "
        f"train={len(train_requests)} test={len(test_requests)}"
    )
    print(
        f"train_positives={sum(r.label for r in train_requests)} "
        f"train_negatives={sum(1 - r.label for r in train_requests)} "
        f"test_positives={sum(r.label for r in test_requests)} "
        f"test_negatives={sum(1 - r.label for r in test_requests)}"
    )
    print(f"load_seconds={load_seconds:.4f}")

    rows = []
    test_eval_start = time.perf_counter()
    final_test_metrics = None
    for round_number, (name, rules, callbacks) in enumerate(rule_rounds(), start=1):
        train_metrics = evaluate_with_callbacks(train_requests, rules, callbacks)
        test_metrics = evaluate_with_callbacks(test_requests, rules, callbacks)
        if name == "round_12_contact_location_credentials":
            final_test_metrics = test_metrics
        rows.append(
            {
                "round_number": round_number,
                "round_name": name,
                "regex_rules": len(rules),
                "callbacks": len(callbacks),
                "train_accuracy": f"{train_metrics['accuracy']:.6f}",
                "train_precision": f"{train_metrics['precision']:.6f}",
                "train_recall": f"{train_metrics['recall']:.6f}",
                "train_f1": f"{train_metrics['f1']:.6f}",
                "test_accuracy": f"{test_metrics['accuracy']:.6f}",
                "test_precision": f"{test_metrics['precision']:.6f}",
                "test_recall": f"{test_metrics['recall']:.6f}",
                "test_f1": f"{test_metrics['f1']:.6f}",
                "train_tp": train_metrics["tp"],
                "train_fp": train_metrics["fp"],
                "train_tn": train_metrics["tn"],
                "train_fn": train_metrics["fn"],
                "test_tp": test_metrics["tp"],
                "test_fp": test_metrics["fp"],
                "test_tn": test_metrics["tn"],
                "test_fn": test_metrics["fn"],
            }
        )
        print(f"{name}: train {fmt(train_metrics)}")
        print(f"{name}: test  {fmt(test_metrics)}")
    test_eval_seconds = time.perf_counter() - test_eval_start

    write_csv(OUT_DIR / "regex_split_round_metrics.csv", rows)

    if final_test_metrics is None:
        print("missing final round", file=sys.stderr)
        raise SystemExit(1)
    print(f"test_eval_seconds_all_rounds={test_eval_seconds:.4f}")
    print(f"final_round_test={fmt(final_test_metrics)}")
    print(f"wrote={OUT_DIR / 'regex_split_round_metrics.csv'}")


if __name__ == "__main__":
    main()
