# Project Context Handoff

Date: 2026-05-16  
Workspace: `/Users/rahul/code/phd/courses/239AS`

This file summarizes the work completed so far so the project can continue cleanly if the chat context is compacted.

## Current Project Direction

The paper is now about LLM-guided discovery of simple, auditable HTTP attack detection rules.

Core framing:

- Web attacks often leave visible clues in HTTP request text.
- Runtime defenses such as WAFs and IDSs need fast, predictable logic because they inspect traffic on the request path.
- Dense ML models can classify attacks well, but they do not naturally produce compact deployable rules.
- LLM-as-detector systems keep the LLM in the runtime path, which raises cost, latency, reproducibility, and auditability concerns.
- LLM rule-generation systems often target complex production grammars such as Suricata, ModSecurity, or KQL.
- Our work asks a smaller question: can an LLM-guided offline loop discover simple regexes and endpoint heuristics that recover much of the performance of statistical models?

Important wording/style constraint from the user:

- Match the tone of the IPHints introduction the user pasted.
- Each paragraph should have a takeaway topic sentence.
- Paragraphs should be compact, roughly 5-6 sentences max.
- Tone should be measured, empirical, and careful, not hype-heavy.
- Claims should use careful language where needed: “may,” “can,” “not proof,” “appears,” etc.

## Data

Local dataset:

- `project/csic_database.csv`
- Source: <https://www.kaggle.com/datasets/ispangler/csic-2010-web-application-attacks>

Inspected shape:

```text
Rows:    61,065 data rows
Size:    about 28 MB
Columns: 17
Labels:  36,000 normal, 25,065 anomalous
Methods: GET 43,088; POST 17,580; PUT 397
```

Important dataset quirks:

- First CSV column is unnamed and contains string labels: `Normal` or `Anomalous`.
- `classification` is the numeric target: `0` normal, `1` anomalous.
- `lenght` is misspelled in the CSV.
- GET request payloads are usually in `URL`.
- POST request payloads are usually in `content`.
- Many header fields are constant or nearly constant.
- Useful fields are `Method`, `URL`, `content`, decoded URL/content, path, parsed query/body parameters, endpoint-specific parameter structure.

## Regex Rule Harness

Main file:

- `project/regex_rules/evaluate_rules.py`

What it does:

- Loads `project/csic_database.csv`.
- Builds a `Request` dataclass with:
  - raw URL
  - decoded URL
  - raw content
  - decoded content
  - raw/decoded path
  - decoded query
  - combined raw request text
  - combined decoded request text
  - parsed decoded parameters
- Defines regex `Rule` objects with:
  - `name`
  - `field`
  - `pattern`
  - regex flags
- Evaluates rules and callback heuristics.
- Reports accuracy, precision, recall, F1, TP, FP, TN, FN.
- Prints example false positives and false negatives.

Run command:

```bash
cd /Users/rahul/code/phd/courses/239AS
python3 project/regex_rules/evaluate_rules.py
```

## Regex Rule Iterations

The harness currently contains multiple rounds of increasing sophistication:

- Round 1: obvious attack signatures such as script tags, SQL clusters, `/etc/passwd`, null byte.
- Round 2: SQL comments, tautologies, HTML injection, traversal, shell/meta characters, backup suffixes.
- Round 3/4: encoded/file probes, invalid resources, broad markup rules.
- Round 5/6: endpoint value callbacks and endpoint schema callbacks.
- Round 7/8/9: encoded payloads, path/method handling, full static whitelist, `PUT` handling.
- Round 10: stable values, product constraints, DNI checks, regex meta payloads, mutated short fields.
- Round 11: identity field shapes.
- Round 12: contact/location/credential checks.

Best exploratory full-dataset result:

```text
round_12_contact_location_credentials
accuracy  = 0.9921
precision = 0.9991
recall    = 0.9815
f1        = 0.9902
tp=24602 fp=22 tn=35978 fn=463
```

Important caveat:

- This is not a fair generalization result.
- These rules were developed after inspecting the full dataset.
- Treat this as evidence of feasibility only.
- The paper should emphasize the need for train/dev/test evaluation.

Final-rule runtime from timing:

```text
Rows: 61,065
Load CSV + parse requests: about 0.86 sec
Apply final rules:         about 1.92 sec
Total:                     about 2.78 sec
Throughput:                about 21,963 rows/sec
```

## Kaggle Notebook Baseline

The user asked to pull and run:

```bash
kaggle kernels pull mustafa818/notebook25d16fa6ba
```

The machine initially lacked Kaggle auth. User logged in, then this worked:

```bash
uvx kaggle kernels pull mustafa818/notebook25d16fa6ba -p project/kaggle_kernel -m
```

Downloaded files:

- `project/kaggle_kernel/kernel-metadata.json`
- `project/kaggle_kernel/notebook25d16fa6ba.ipynb`
- `project/kaggle_kernel/notebook25d16fa6ba.py`

Converted with:

```bash
uvx jupyter nbconvert --to script project/kaggle_kernel/notebook25d16fa6ba.ipynb \
  --output notebook25d16fa6ba \
  --output-dir project/kaggle_kernel
```

A local runner was created because the original notebook hardcoded Kaggle paths:

- `project/kaggle_kernel/run_notebook25d16fa6ba_local.py`

Run command used:

```bash
uv run --with pandas --with numpy --with matplotlib --with seaborn \
  --with scikit-learn --with scipy --with joblib \
  python project/kaggle_kernel/run_notebook25d16fa6ba_local.py
```

Run log:

- `project/kaggle_kernel/run_notebook25d16fa6ba_local.log`

Generated outputs:

- `project/kaggle_kernel/outputs/binary_confusion_matrix.png`
- `project/kaggle_kernel/outputs/binary_roc_curve.png`
- `project/kaggle_kernel/outputs/class_and_method_distribution.png`
- `project/kaggle_kernel/outputs/feature_importance.png`
- `project/kaggle_kernel/outputs/model_comparison.png`
- `project/kaggle_kernel/outputs/multiclass_confusion_matrix.png`
- `project/kaggle_kernel/outputs/rf_binary_model.pkl`
- `project/kaggle_kernel/outputs/gb_multiclass_model.pkl`
- `project/kaggle_kernel/outputs/tfidf_vectorizer.pkl`
- `project/kaggle_kernel/outputs/label_encoder.pkl`

Binary Random Forest result from local notebook run:

```text
Accuracy : 0.9763
F1 Score : 0.9712
ROC-AUC  : 0.9973
```

Binary classification report:

```text
              precision    recall  f1-score   support

      Normal       0.98      0.98      0.98      7200
      Attack       0.97      0.97      0.97      5013

    accuracy                           0.98     12213
   macro avg       0.98      0.98      0.98     12213
weighted avg       0.98      0.98      0.98     12213
```

Multi-class inferred attack-type result:

```text
Classes: Normal, SQLi, SSRF
Accuracy:      0.8967
Weighted F1:   0.8960
```

Runtime:

```text
Script-reported runtime: 30.42 sec
Shell wall time:         63.52 sec
User CPU time:           95.33 sec
System CPU time:          4.42 sec
```

Comparison framing:

- Regex round 12 on full dataset: 0.9921 accuracy, but contaminated by full-dataset tuning.
- Kaggle Random Forest on 20% split: 0.9763 accuracy, cleaner held-out split.
- Do not claim regex is better unless/until train/dev/test evaluation is done.
- Current honest claim: compact rules appear feasible and fast; fair evaluation remains next.

## Experiment Log

A fuller retrospective log already exists:

- `project/experiment_log.md`

That file summarizes:

- dataset inspection
- regex harness
- rule iterations
- runtime analysis
- Kaggle notebook pull/run
- comparison
- recommended train/dev/test next step

This handoff file is more focused on current state and paper writing.

## LaTeX Template and Build

User moved and unzipped:

- `~/Downloads/USENIX_2023.zip`

Now in the root workspace:

- `USENIX_2023.zip`
- `acm.bst`
- `sample.bib`
- `usenix.sty`
- `usenix.tex`
- `usenix.png`

Build command:

```bash
latexmk -pdf -interaction=nonstopmode -halt-on-error usenix.tex
```

Output:

- `usenix.pdf`

TeX tooling found:

- `/Library/TeX/texbin/latexmk`
- `/Library/TeX/texbin/pdflatex`
- `/Library/TeX/texbin/xelatex`

## Current Paper State

Current main paper file:

- `usenix.tex`

The old content was stripped and the paper currently has:

- Abstract header only, empty.
- Introduction written.
- Background and Related Work written, with citation TODOs.
- Methodology empty.
- Data / Experimental Setup empty.
- Discussion / Limitations empty.
- Conclusion empty.

Current title:

```latex
\title{\Large \bf Agent-Guided Rule Discovery for Internet Measurement}
```

This title is now stale because the project shifted to web-attack rule discovery. Consider changing it soon.

Current authors:

```latex
Rahul Tripathi, Armaan Oberai, Justine Ellery
```

## Current Introduction

The introduction was rewritten to more closely match the IPHints example style.

Current structure:

1. Web attacks reveal clues in HTTP request text.
2. Rules matter because WAFs/IDSs sit on the request path and need cheap deterministic logic.
3. ML models show attacks are learnable but do not produce deployable detection logic.
4. Manual rule writing does not scale and can overfit or miss endpoint-specific variation.
5. This paper uses an LLM as an offline proposal mechanism, not as the detector.
6. Evaluation on CSIC 2010 and exploratory feasibility result.
7. Contribution: controlled methodology for LLM-guided rule discovery.

References added to intro:

- `OWASPModSecurity`
- `OWASPCoreRuleSet`
- `Adnan2021IoTIDSReview`

These were added to `sample.bib`.

## Current Background and Related Work

This section was shortened after the user said it was too long for an academic paper.

Current structure:

1. CSIC 2010 and web-attack benchmark context.
2. ML/deep-learning models classify accurately but do not produce simple detection logic.
3. LLM-based IDS mostly uses LLMs as classifiers/payload interpreters.
4. LLM-assisted rule generation targets complex rule languages and operational frameworks.
5. Our work is smaller and controlled: Python regexes and endpoint heuristics.
6. Harness treats LLM as offline proposer; deterministic evaluator accepts/rejects rules.

Still has `\todo{cite ...}` placeholders for:

- CSIC 2010 and DARPA critiques.
- Sarvari et al.
- Zhang et al.
- Deep-learning HTTP injection work.
- Kaggle/reproduced baseline.
- LLM IDS.
- Al-Hammouri et al.
- Moreno et al.
- GridAI.
- VibeWAF.
- UniRule.
- RulePilot.
- EDR KQL work.

## Reviewer Feedback on Intro

User asked:

> if you were to read the intro from a reviewers perspective what would you think

Response summary:

- Previous intro had the right ingredients but sounded too much like a project report.
- It named CSIC and methods too early.
- It did not build enough pressure around operational need for cheap request-path logic.
- It needed to distinguish from ML/LLM detectors more clearly.

Then the intro was rewritten to follow the IPHints-like structure.

## Methodology Section: Planned Content

User asked to write methodology, but then interrupted to request this handoff first.

When continuing, write `\section{Methodology}` in the same style.

Suggested methodology structure:

1. **Overview paragraph**  
   Takeaway: The harness separates rule proposal from rule execution. LLM proposes, deterministic code validates/evaluates, final detector is rule-only.

2. **Request representation paragraph**  
   Takeaway: Each HTTP request is represented in both raw and decoded forms. Fields include method, URL, content, path, query/body params, combined raw/decoded request text.

3. **Rule language paragraph**  
   Takeaway: The rule language is intentionally small. Rules are regexes over named fields plus scalar/endpoint callbacks. This keeps output auditable and avoids production IDS grammar.

4. **Proposal loop paragraph**  
   Takeaway: The LLM receives summaries of train/dev errors and proposes a small batch of rules. It should not see the held-out test set.

5. **Validation and acceptance paragraph**  
   Takeaway: Candidate rules are executed before acceptance. Accept only if they improve development-set F1/recall under precision constraints or reduce errors without introducing unacceptable false positives.

6. **Final evaluation paragraph**  
   Takeaway: Final retained rules are frozen and evaluated once on test. Runtime is measured separately from model/rule discovery.

7. **Implementation paragraph**  
   Takeaway: The prototype is implemented in Python using `csv`, `urllib.parse`, and `re`. The final detector uses no LLM calls and compiles regexes.

Important: Current code does not yet implement train/dev/test split. The paper should describe it as the intended methodology only if we implement it, or say the current full-dataset result is exploratory. Better next engineering step is to implement `evaluate_split.py`.

## Proposed Next Engineering Step

Implement a fair split-based evaluator.

Suggested files:

- `project/regex_rules/evaluate_split.py`
- optionally `project/regex_rules/rules.yaml`

Suggested split:

```text
train: 70%
dev:   15%
test:  15%
```

Important discipline:

- Train: examples and initial pattern discovery.
- Dev: rule acceptance and iteration.
- Test: final once-only evaluation.

Because existing rules were developed on full data, a clean test result requires either:

- rebuilding rules using only train/dev visibility, or
- clearly labeling any split evaluation of current rules as contaminated.

## Citation / BibTeX Status

Added in `sample.bib`:

- `OWASPModSecurity`
- `OWASPCoreRuleSet`
- `Adnan2021IoTIDSReview`

Need BibTeX:

1. DARPA intrusion detection dataset critique / limitations.
2. CSIC 2010 dataset paper/source.
3. Kaggle notebook baseline or cite our reproduced local baseline in text instead.
4. Sarvari et al. online variable-order Markov model for HTTP anomaly detection.
5. Zhang et al. ensemble/tree-rule IDS work using RF/AdaBoost/XGBoost/CIC-IDS2017.
6. Deep-learning HTTP injection detection with character embeddings.
7. Chen et al. Convolutional Channel-BiLSTM-Attention for web command injection.
8. LLM-integrated NetFlow IDS paper.
9. Al-Hammouri et al. hybrid signature IDS with GPT-2.
10. Moreno et al. automated Suricata rule generation with LLMs.
11. GridAI multi-agent Suricata rule generation/repair.
12. VibeWAF LLM + ModSecurity prototype.
13. UniRule unified detection-rule generation.
14. RulePilot LLM-powered detection-rule generation.
15. LLM-augmented EDR rule generation from OpenCTI to Microsoft Defender/KQL.

Potential supporting citations:

- CIC-IDS2017 dataset.
- SR-BH 2020 dataset used by VibeWAF.
- Suricata.
- Snort.
- ModSecurity.
- Kusto Query Language / Microsoft Defender for Endpoint.

## Current Commands to Know

Build paper:

```bash
cd /Users/rahul/code/phd/courses/239AS
latexmk -pdf -interaction=nonstopmode -halt-on-error usenix.tex
```

Run regex harness:

```bash
cd /Users/rahul/code/phd/courses/239AS
python3 project/regex_rules/evaluate_rules.py
```

Run Kaggle local baseline:

```bash
cd /Users/rahul/code/phd/courses/239AS
uv run --with pandas --with numpy --with matplotlib --with seaborn \
  --with scikit-learn --with scipy --with joblib \
  python project/kaggle_kernel/run_notebook25d16fa6ba_local.py
```

## Notes and Warnings

- There may be TeX auxiliary files in the root folder: `usenix.aux`, `usenix.bbl`, `usenix.blg`, `usenix.fdb_latexmk`, `usenix.fls`, `usenix.log`, `usenix.out`.
- Do not delete source files unless asked.
- `project/experiment_log.md` is already a good detailed experiment record.
- `project/context_handoff.md` is this handoff note.
- The title should likely be revised before final writing continues.
- Be careful not to overclaim the 99.2% regex result; it is full-dataset-tuned and exploratory.
- The user values the IPHints writing style and will likely push back on prose that reads like a generic survey or project report.
