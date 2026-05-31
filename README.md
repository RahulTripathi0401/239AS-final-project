# LLM-Guided Rule Discovery for Web Attack Detection

This repository contains the final paper draft, presentation materials, CSIC 2010 dataset copy, rule-harness code, and reproduced machine-learning baseline for the ECE239AS Network Security research project.

## Main Files

- `usenix.tex`: final paper source.
- `usenix.pdf`: compiled paper PDF.
- `sample.bib`: bibliography entries.
- `project/REPRODUCIBILITY.md`: step-by-step instructions for reproducing the reported experiments.
- `project/csic_database.csv`: local CSIC 2010 dataset used by the scripts.
- `project/regex_rules/evaluate_split.py`: split-based evaluation of the rule harness.
- `project/regex_rules/agent_rule_harness.py`: LLM-guided agent loop over a safe catalog of candidate rule groups.
- `project/kaggle_kernel/run_notebook25d16fa6ba_local.py`: reproduced machine-learning baseline.

## Quick Reproduction

```bash
uv sync
uv run python project/regex_rules/evaluate_split.py
uv run python project/regex_rules/agent_rule_harness.py --planner replay
uv run python project/kaggle_kernel/run_notebook25d16fa6ba_local.py
latexmk -pdf -interaction=nonstopmode -halt-on-error usenix.tex
```

See `project/REPRODUCIBILITY.md` for expected outputs and caveats.
