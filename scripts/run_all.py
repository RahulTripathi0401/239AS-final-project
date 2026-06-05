#!/usr/bin/env python3
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run(cmd: list[str]) -> None:
    print("+", " ".join(cmd))
    subprocess.run(cmd, cwd=ROOT, check=True)


def main() -> None:
    run([sys.executable, "project/regex_rules/evaluate_split.py"])
    run([sys.executable, "project/regex_rules/agent_rule_harness.py", "--planner", "replay"])
    run([sys.executable, "project/kaggle_kernel/run_notebook25d16fa6ba_local.py"])
    for script in [
        "tbl_dataset_summary.py",
        "tbl_experimental_configs.py",
        "tbl_regex_confusion.py",
        "tbl_regex_train_test.py",
        "fig_accuracy_by_round.py",
        "tbl_rule_iterations.py",
        "tbl_model_comparison.py",
        "tbl_runtime.py",
    ]:
        run([sys.executable, f"scripts/{script}"])
    run(["latexmk", "-pdf", "-interaction=nonstopmode", "-halt-on-error", "usenix.tex"])
    shutil.copy2(ROOT / "usenix.pdf", ROOT / "paper_final.pdf")
    print("wrote paper_final.pdf and reproducibility artifacts under figures/")


if __name__ == "__main__":
    main()
