#!/usr/bin/env python3
from artifact_utils import FIGURES, final_regex_row, write_csv, write_tex_table


def main() -> None:
    row = final_regex_row()
    rows = [
        {
            "Actual": "Actual normal",
            "Predicted normal": row["test_tn"],
            "Predicted attack": row["test_fp"],
        },
        {
            "Actual": "Actual attack",
            "Predicted normal": row["test_fn"],
            "Predicted attack": row["test_tp"],
        },
    ]
    write_csv(FIGURES / "tbl_regex_confusion.csv", rows)
    write_tex_table(
        FIGURES / "tbl_regex_confusion.tex",
        ["", "Predicted normal", "Predicted attack"],
        [[r["Actual"], f"{int(r['Predicted normal']):,}", f"{int(r['Predicted attack']):,}"] for r in rows],
    )


if __name__ == "__main__":
    main()
