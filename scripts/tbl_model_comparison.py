#!/usr/bin/env python3
from artifact_utils import FIGURES, ML_METRICS, final_regex_row, read_csv, write_csv, write_tex_table


def fmt(value: str) -> str:
    return f"{float(value):.4f}"


def main() -> None:
    rule = final_regex_row()
    ml = read_csv(ML_METRICS)[0]
    rows = [
        {"Detector": "Random forest", "Eval.": "20% test", "Acc.": fmt(ml["accuracy"]), "F1": fmt(ml["f1"])},
        {"Detector": "Regex harness", "Eval.": "20% test", "Acc.": fmt(rule["test_accuracy"]), "F1": fmt(rule["test_f1"])},
    ]
    write_csv(FIGURES / "tbl_model_comparison.csv", rows)
    write_tex_table(FIGURES / "tbl_model_comparison.tex", list(rows[0]), [[r[k] for k in rows[0]] for r in rows])


if __name__ == "__main__":
    main()
