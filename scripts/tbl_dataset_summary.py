#!/usr/bin/env python3
from __future__ import annotations

import csv
from collections import Counter

from artifact_utils import DATASET, FIGURES, write_csv, write_tex_table


def main() -> None:
    counts = Counter()
    with DATASET.open(newline="", encoding="latin-1") as f:
        for row in csv.DictReader(f):
            counts["Total requests"] += 1
            if row["classification"] == "0":
                counts["Normal requests"] += 1
            else:
                counts["Anomalous requests"] += 1
            counts[f"{row['Method']} requests"] += 1
            if row["URL"]:
                counts["Rows with non-empty URL"] += 1
            if row["content"]:
                counts["Rows with non-empty body"] += 1

    order = [
        "Total requests",
        "Normal requests",
        "Anomalous requests",
        "GET requests",
        "POST requests",
        "PUT requests",
        "Rows with non-empty URL",
        "Rows with non-empty body",
    ]
    rows = [{"Property": key, "Count": counts[key]} for key in order]
    write_csv(FIGURES / "tbl_dataset_summary.csv", rows)
    write_tex_table(FIGURES / "tbl_dataset_summary.tex", ["Property", "Count"], [[r["Property"], f"{r['Count']:,}"] for r in rows])


if __name__ == "__main__":
    main()
