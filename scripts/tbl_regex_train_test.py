#!/usr/bin/env python3
from artifact_utils import FIGURES, final_regex_row, write_csv, write_tex_table


def fmt(value: str) -> str:
    return f"{float(value):.4f}"


def main() -> None:
    row = final_regex_row()
    rows = [
        {
            "Split": "Train",
            "Acc.": fmt(row["train_accuracy"]),
            "Prec.": fmt(row["train_precision"]),
            "Rec.": fmt(row["train_recall"]),
            "F1": fmt(row["train_f1"]),
            "FP": row["train_fp"],
            "FN": row["train_fn"],
        },
        {
            "Split": "Test",
            "Acc.": fmt(row["test_accuracy"]),
            "Prec.": fmt(row["test_precision"]),
            "Rec.": fmt(row["test_recall"]),
            "F1": fmt(row["test_f1"]),
            "FP": row["test_fp"],
            "FN": row["test_fn"],
        },
    ]
    write_csv(FIGURES / "tbl_regex_train_test.csv", rows)
    write_tex_table(FIGURES / "tbl_regex_train_test.tex", list(rows[0]), [[r[k] for k in rows[0]] for r in rows])


if __name__ == "__main__":
    main()
