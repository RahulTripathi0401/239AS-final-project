# LLM-Guided Rule Discovery for Web Attack Detection

## Paper

*"LLM-Guided Rule Discovery for Web Attack Detection,"* submitted to ECE239AS
Network Security (June 2026).

**PDF:** [`./paper_final.pdf`](paper_final.pdf)

**GitHub:** <https://github.com/RahulTripathi0401/239AS-final-project>

## Directory Guide

| Path | Purpose |
| --- | --- |
| `data/raw/` | Small, open dataset committed for reproducibility. |
| `data/sql/` | Empty placeholder; no SQL or BigQuery is required. |
| `figures/` | Auto-generated CSV/TeX/PDF/PNG artifacts used to reproduce paper figures and tables. |
| `notebooks/` | Placeholder for notebook workflows; this artifact uses scripts instead. |
| `scripts/` | One clearly labeled reproducibility script per paper figure/table, plus `run_all.py`. |
| `project/regex_rules/` | Deterministic rule definitions, split evaluation, and the agent rule-discovery harness. |
| `project/kaggle_kernel/` | Reproduced Kaggle machine-learning baseline and generated ML outputs. |
| `usenix.tex`, `sample.bib`, `usenix.sty` | Paper source files. |

## Data

The project uses the CSIC 2010 web-application attack dataset from Kaggle:

<https://www.kaggle.com/datasets/ispangler/csic-2010-web-application-attacks>

A local copy is committed at `data/raw/csic_database.csv`. The original scripts
also keep a compatibility copy at `project/csic_database.csv`. See
[`data/README_DATA.md`](data/README_DATA.md) for provenance and replacement
instructions.

## Environment

Install the Python environment with `uv`:

```bash
uv sync
```

The lockfile `uv.lock` records the resolved environment used for the checked
run. The paper build requires a LaTeX distribution with `latexmk`.

## Reproduce Everything

Run the full artifact pipeline from the repository root:

```bash
uv run python scripts/run_all.py
```

This command:

1. Re-runs the split-based regex rule evaluation.
2. Replays the deterministic agent harness.
3. Re-runs the reproduced machine-learning baseline.
4. Regenerates paper table/figure artifacts under `figures/`.
5. Rebuilds `usenix.pdf` and copies it to `paper_final.pdf`.

The machine-learning baseline can take about a minute on a laptop because it
extracts TF-IDF features, trains models, evaluates them, and saves plots.

## Agent Harness

The agent code is:

```text
project/regex_rules/agent_rule_harness.py
```

For deterministic replay without an API key:

```bash
uv run python project/regex_rules/agent_rule_harness.py --planner replay
```

For an LLM-guided run, provide an OpenAI API key through the environment or an
uncommitted local file:

```bash
export OPENAI_API_KEY="..."
uv run python project/regex_rules/agent_rule_harness.py --planner openai --model gpt-5.2
```

The model is allowed to choose only from a fixed safe catalog of candidate rule
groups. It cannot write arbitrary detector code into the runtime path.

## Figure and Table Scripts

Each script below regenerates the artifact named in the paper. Table scripts
write both `.csv` and `.tex` files to `figures/`; figure scripts write `.pdf`
and `.png` files.

| Paper artifact | Reproducibility script | Output |
| --- | --- | --- |
| Table: CSIC 2010 dataset summary | `scripts/tbl_dataset_summary.py` | `figures/tbl_dataset_summary.*` |
| Table: detector configurations | `scripts/tbl_experimental_configs.py` | `figures/tbl_experimental_configs.*` |
| Table: final rule confusion matrix | `scripts/tbl_regex_confusion.py` | `figures/tbl_regex_confusion.*` |
| Table: train/test rule performance | `scripts/tbl_regex_train_test.py` | `figures/tbl_regex_train_test.*` |
| Figure: accuracy by rule round | `scripts/fig_accuracy_by_round.py` | `figures/fig_accuracy_by_round.*` |
| Table: selected rule iterations | `scripts/tbl_rule_iterations.py` | `figures/tbl_rule_iterations.*` |
| Table: ML comparison | `scripts/tbl_model_comparison.py` | `figures/tbl_model_comparison.*` |
| Table: runtime comparison | `scripts/tbl_runtime.py` | `figures/tbl_runtime.*` |

The methodology diagrams and algorithm are TikZ/LaTeX artifacts embedded
directly in `usenix.tex`; rebuilding the paper regenerates them.

## Expected Main Results

The final regex and heuristic rule set should report approximately:

```text
accuracy=0.9921 precision=0.9992 recall=0.9816 f1=0.9903
tp=4921 fp=4 tn=7196 fn=92
```

The reproduced random-forest baseline should report approximately:

```text
Accuracy : 0.9763
F1 Score : 0.9712
ROC-AUC  : 0.9973
```

Small runtime differences are expected across machines.

## Notes

The final rule set is evaluated on the same held-out 20% test split as the
machine-learning baseline. The paper explicitly notes that the rule families
were developed through earlier dataset inspection before the split-based
reporting pass, so the result is a held-out evaluation of a frozen detector
rather than a fully blinded train-only discovery study.
