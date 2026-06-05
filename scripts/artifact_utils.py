#!/usr/bin/env python3
from __future__ import annotations

import csv
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIGURES = ROOT / "figures"
REGEX_ROUNDS = ROOT / "project" / "regex_rules" / "outputs" / "regex_split_round_metrics.csv"
ML_METRICS = ROOT / "project" / "kaggle_kernel" / "outputs" / "binary_metrics.csv"
ML_RUNTIME = ROOT / "project" / "kaggle_kernel" / "outputs" / "runtime_summary.csv"
DATASET = ROOT / "data" / "raw" / "csic_database.csv"


def ensure_figures() -> None:
    FIGURES.mkdir(parents=True, exist_ok=True)


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    ensure_figures()
    if not rows:
        raise ValueError(f"no rows to write: {path}")
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def write_tex_table(path: Path, headers: list[str], rows: list[list[object]]) -> None:
    ensure_figures()
    colspec = "l" + "r" * (len(headers) - 1)
    lines = [
        "\\begin{tabular}{" + colspec + "}",
        "\\toprule",
        " & ".join(headers) + " \\\\",
        "\\midrule",
    ]
    for row in rows:
        lines.append(" & ".join(str(item) for item in row) + " \\\\")
    lines.extend(["\\bottomrule", "\\end{tabular}", ""])
    path.write_text("\n".join(lines))


def final_regex_row() -> dict[str, str]:
    rows = read_csv(REGEX_ROUNDS)
    return rows[-1]
