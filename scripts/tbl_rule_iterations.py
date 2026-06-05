#!/usr/bin/env python3
from artifact_utils import FIGURES, REGEX_ROUNDS, read_csv, write_csv, write_tex_table


SELECTED = {
    "round_1_seed_obvious_attacks": "Seed rules",
    "round_6_add_endpoint_schema_callbacks": "Schemas",
    "round_9_full_static_whitelist_and_put": "Encoded",
    "round_10_value_constraints_no_asterisk": "Values",
    "round_12_contact_location_credentials": "Final rules",
}


def fmt(value: str) -> str:
    return f"{float(value):.4f}"


def main() -> None:
    source = read_csv(REGEX_ROUNDS)
    rows = []
    for row in source:
        if row["round_name"] in SELECTED:
            rows.append(
                {
                    "Round": SELECTED[row["round_name"]],
                    "Acc.": fmt(row["test_accuracy"]),
                    "Prec.": fmt(row["test_precision"]),
                    "Rec.": fmt(row["test_recall"]),
                    "F1": fmt(row["test_f1"]),
                }
            )
    write_csv(FIGURES / "tbl_rule_iterations.csv", rows)
    write_tex_table(FIGURES / "tbl_rule_iterations.tex", list(rows[0]), [[r[k] for k in rows[0]] for r in rows])


if __name__ == "__main__":
    main()
