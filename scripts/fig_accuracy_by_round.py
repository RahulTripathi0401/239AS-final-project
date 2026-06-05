#!/usr/bin/env python3
from __future__ import annotations

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from artifact_utils import FIGURES, REGEX_ROUNDS, read_csv


def main() -> None:
    rows = read_csv(REGEX_ROUNDS)
    x = list(range(1, len(rows) + 1))
    y = [float(row["test_accuracy"]) for row in rows]
    labels = [f"R{row['round_number']}" for row in rows]

    FIGURES.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(6.2, 3.4))
    ax.plot(x, y, marker="o", color="blue", linewidth=1.8)
    ax.set_xticks(x, labels, rotation=45, ha="right")
    ax.set_ylabel("Accuracy")
    ax.set_xlabel("Rule-discovery round")
    ax.set_ylim(0.58, 1.01)
    ax.grid(True, alpha=0.25)
    fig.tight_layout()
    fig.savefig(FIGURES / "fig_accuracy_by_round.pdf")
    fig.savefig(FIGURES / "fig_accuracy_by_round.png", dpi=200)
    plt.close(fig)


if __name__ == "__main__":
    main()
