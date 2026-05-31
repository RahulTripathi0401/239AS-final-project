# Reproducibility Instructions

This directory contains the data and scripts needed to reproduce the main results in the paper, "LLM-Guided Rule Discovery for Web Attack Detection."

## Artifact Layout

- `csic_database.csv`: local CSIC 2010 HTTP request dataset used in all experiments.
- `regex_rules/evaluate_rules.py`: deterministic rule definitions, request parser, metrics helpers, and full-dataset rule evaluation utilities.
- `regex_rules/evaluate_split.py`: stratified 80/20 train/test evaluation for the rule-discovery rounds reported in the paper.
- `regex_rules/agent_rule_harness.py`: an agent-loop implementation that asks an LLM to choose candidate rule groups from a safe catalog, evaluates each candidate deterministically, and accepts only metric-improving candidates.
- `kaggle_kernel/notebook25d16fa6ba.ipynb`: pulled Kaggle notebook for the CSIC 2010 machine-learning baseline.
- `kaggle_kernel/notebook25d16fa6ba.py`: notebook converted to Python.
- `kaggle_kernel/run_notebook25d16fa6ba_local.py`: local runner that reproduces the random-forest baseline with the same dataset copy.
- `experiment_log.md`: historical notes from dataset inspection, rule iteration, runtime measurement, and notebook reproduction.

## Environment

The experiments were run locally on macOS using Python through `uv`. Run all commands below from the repository root.

Install runtime dependencies into a local `uv` environment:

```bash
uv sync
```

The rule harness uses only the Python standard library plus scikit-learn for the stratified split in `evaluate_split.py`. The LLM-guided agent loop additionally uses the OpenAI Python SDK when run with `--planner openai`. The reproduced machine-learning baseline uses Pandas, NumPy, SciPy, scikit-learn, Matplotlib, Seaborn, and Joblib. Direct dependencies are listed in `pyproject.toml`, and the full resolved environment is recorded in `uv.lock`.

## Reproduce Rule-Harness Results

Run the split-based rule evaluation:

```bash
uv run python project/regex_rules/evaluate_split.py
```

This command:

1. Loads `project/csic_database.csv`.
2. Builds a stratified 80/20 train/test split with `random_state=42`.
3. Evaluates each retained rule-discovery round on both train and test partitions.
4. Writes per-round metrics to `project/regex_rules/outputs/regex_split_round_metrics.csv`.

The final round should report approximately:

```text
accuracy=0.9921 precision=0.9992 recall=0.9816 f1=0.9903
tp=4921 fp=4 tn=7196 fn=92
```

The expected split sizes are:

```text
train=48852
test=12213
test_positives=5013
test_negatives=7200
```

## Reproduce the Agent Loop

The agent-loop script follows the pattern of a tool-using agent: the model sees state, metrics, sampled errors, and available actions; it chooses one candidate rule group; the deterministic harness evaluates that candidate and returns the result. The model never writes executable detection code.

For a deterministic reproduction of the accepted rule-family sequence, run:

```bash
uv run python project/regex_rules/agent_rule_harness.py --planner replay
```

This should end with approximately:

```text
final_test=accuracy=0.9921 precision=0.9992 recall=0.9816 f1=0.9903 tp=4921 fp=4 tn=7196 fn=92
```

To run the LLM-guided planner, set an API key in the environment and choose an available OpenAI model:

```bash
export OPENAI_API_KEY="..."
uv run python project/regex_rules/agent_rule_harness.py --planner openai --model gpt-5.2
```

Alternatively, place the key in a local file that is not committed and pass:

```bash
uv run python project/regex_rules/agent_rule_harness.py --planner openai --model gpt-5.2 --api-key-file /path/to/openai_key.txt
```

The model name is configurable. The public OpenAI model list currently documents GPT-5.2, GPT-5.1, and GPT-5 model families; if an account has a newer or private alias, pass it with `--model`.

## Reproduce Machine-Learning Baseline

Run the local notebook reproduction:

```bash
uv run python project/kaggle_kernel/run_notebook25d16fa6ba_local.py
```

This command:

1. Loads the same `project/csic_database.csv`.
2. Extracts 18 numeric URL/body/method/content-length features.
3. Builds character TF-IDF features over URL and body text.
4. Trains the binary random-forest baseline on the same stratified 80/20 split with `random_state=42`.
5. Writes plots and artifacts to `project/kaggle_kernel/outputs/`.

The binary random-forest result should report approximately:

```text
Accuracy : 0.9763
F1 Score : 0.9712
ROC-AUC  : 0.9973
```

The local script timer reported about 32.97 seconds in the checked run, while an earlier shell wall-clock runtime through `uv` was about 63.52 seconds. Exact timing will vary by machine.

## Rebuild the Paper

Compile the paper from the project root:

```bash
latexmk -pdf -interaction=nonstopmode -halt-on-error usenix.tex
```

The compiled PDF is `usenix.pdf`. The paper uses vector TikZ/PGFPlots figures embedded directly in `usenix.tex`, so no external figure files are required for the main manuscript.

## Notes and Caveats

The final rule set is evaluated on the same held-out 20% test split as the reproduced random-forest baseline. The rule families were developed through earlier dataset inspection before this split-based reporting pass, so the paper treats the result as a held-out evaluation of a frozen detector rather than as proof of a fully blinded train-only discovery process.
