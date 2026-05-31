# CSIC 2010 Regex Rules and Kaggle Notebook Experiment Log

Date written: 2026-05-16  
Workspace: `/Users/rahul/code/phd/courses/239AS`

## Goal

Explore whether a lightweight agent-style harness can produce regex and schema-based rules to classify the CSIC 2010 web application attack dataset, then compare that approach with an existing Kaggle machine-learning notebook for the same dataset.

Dataset:

- Local file: `project/csic_database.csv`
- Source: `https://www.kaggle.com/datasets/ispangler/csic-2010-web-application-attacks`

## Dataset Inspection

The CSV was inspected locally.

Basic shape:

```text
Rows:    61,065 data rows
Size:    about 28 MB
Columns: 17
Labels:  36,000 normal, 25,065 anomalous
Methods: GET 43,088; POST 17,580; PUT 397
```

Columns:

```text
'', Method, User-Agent, Pragma, Cache-Control, Accept,
Accept-encoding, Accept-charset, language, host, cookie,
content-type, connection, lenght, content, classification, URL
```

Important quirks:

- The first column is unnamed in the CSV and contains `Normal` or `Anomalous`.
- `classification` is the numeric target: `0` for normal, `1` for anomalous.
- The `lenght` column is misspelled in the source data.
- GET requests generally carry payloads in `URL`.
- POST requests generally carry payloads in `content`.
- Many header columns are constant or near-constant, so they are weak modeling signals.
- Useful fields are mainly `Method`, `URL`, `content`, endpoint path, parsed parameters, and decoded payload text.

The attack data includes SQL injection, XSS, malformed parameters, encoded payloads, suspicious paths, invalid HTTP methods, and endpoint-specific value violations.

## Regex Rule Harness

Created:

- `project/regex_rules/evaluate_rules.py`

The harness:

- Loads `project/csic_database.csv`.
- Parses URL, path, query, and request body.
- Builds both raw and URL-decoded request views.
- Applies named regex rules.
- Applies endpoint/schema callbacks for cases that are easier to express as structured checks.
- Reports accuracy, precision, recall, F1, and confusion matrix counts for each round.
- Prints representative false positives and false negatives.

Run command:

```bash
cd /Users/rahul/code/phd/courses/239AS
python3 project/regex_rules/evaluate_rules.py
```

## Regex Rule Iterations

The rule set was built iteratively.

Early rounds focused on obvious attack signatures:

- SQL keywords and SQL comment patterns.
- XSS tags and `alert(...)`.
- Path traversal.
- Encoded null bytes.
- Suspicious shell/meta characters.
- Invalid backup/temp resource suffixes.

Later rounds added endpoint-aware checks:

- Expected parameter keysets per endpoint.
- Numeric field constraints for `id`, `precio`, `cantidad`, `cp`, `ntc`, etc.
- Stable button/action values such as `B1=Entrar`, `B2=Vaciar carrito`, `modo=registro`.
- Product value constraints for `anadir.jsp`.
- Known normal static paths and image paths.
- Detection of `PUT` requests.
- Field-shape checks for login, DNI, credit-card-like `ntc`, postal code, names, email, city, province, and credentials.

Final best round:

```text
round_12_contact_location_credentials
accuracy  = 0.9921
precision = 0.9991
recall    = 0.9815
f1        = 0.9902

tp=24602 fp=22 tn=35978 fn=463
```

Important caveat:

This result was obtained after inspecting and iterating on the full dataset. It is a strong proof of concept, but not a clean generalization estimate. A proper next step is a train/dev/test split where rules are tuned only on train/dev and evaluated once on held-out test.

## Regex Runtime Analysis

Earlier final-rule runtime:

```text
Rows: 61,065
Load CSV + parse requests: about 0.87 sec
Apply rules only:          about 1.58 sec
Total:                     about 2.45 sec
Throughput eval only:      about 38,594 rows/sec
Throughput load + eval:    about 24,909 rows/sec
```

After adding more final rules in round 12:

```text
Rows: 61,065
Load CSV + parse requests: about 0.86 sec
Apply final rules:         about 1.92 sec
Total:                     about 2.78 sec
Throughput load + eval:    about 21,963 rows/sec
```

So even the expanded rule set remains very fast.

## Kaggle Notebook Pull and Run

Pulled Kaggle kernel:

```bash
uvx kaggle kernels pull mustafa818/notebook25d16fa6ba -p project/kaggle_kernel -m
```

Downloaded files:

- `project/kaggle_kernel/kernel-metadata.json`
- `project/kaggle_kernel/notebook25d16fa6ba.ipynb`
- `project/kaggle_kernel/notebook25d16fa6ba.py`

The notebook was converted to Python with:

```bash
uvx jupyter nbconvert --to script project/kaggle_kernel/notebook25d16fa6ba.ipynb \
  --output notebook25d16fa6ba \
  --output-dir project/kaggle_kernel
```

The original notebook used Kaggle-only paths such as:

```text
/kaggle/input/...
/kaggle/working/...
```

So a local runner was created:

- `project/kaggle_kernel/run_notebook25d16fa6ba_local.py`

It preserves the notebook's core modeling logic while:

- Reading `project/csic_database.csv`.
- Using a noninteractive Matplotlib backend.
- Saving plots and models under `project/kaggle_kernel/outputs`.
- Running locally via `uv`.

Run command:

```bash
cd /Users/rahul/code/phd/courses/239AS
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

## Kaggle Notebook Results

The notebook trains:

- Binary Random Forest classifier using numeric features plus character TF-IDF.
- Multi-class Gradient Boosting classifier on inferred attack types.
- Several numeric-only model comparisons.
- 5-fold cross-validation on numeric features.

Binary Random Forest results on the notebook's 20% test split:

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

Inferred multi-class results:

```text
Classes: Normal, SQLi, SSRF
Accuracy:      0.8967
Weighted F1:   0.8960
```

5-fold cross-validation on numeric-only features:

```text
CV F1 Scores: [0.8730, 0.8755, 0.8751, 0.8750, 0.8783]
Mean F1: 0.8754 +/- 0.0017
```

Numeric-only model comparison:

```text
Random Forest:       Accuracy=0.8931 | F1=0.8691
Gradient Boosting:   Accuracy=0.8544 | F1=0.8117
Logistic Regression: Accuracy=0.7372 | F1=0.6496
```

Kaggle local runner runtime:

```text
Script-reported runtime: 32.97 sec
Shell wall time:         63.52 sec
User CPU time:           95.33 sec
System CPU time:          4.42 sec
```

## Comparison

Accuracy comparison from the latest runs:

```text
Regex round 12, full dataset:
Accuracy  = 0.9921
Precision = 0.9991
Recall    = 0.9815
F1        = 0.9902

Kaggle Random Forest, 20% test split:
Accuracy  = 0.9763
F1        = 0.9712
ROC-AUC   = 0.9973
```

Runtime comparison:

```text
Regex round 12:
Total runtime on full data: about 2.78 sec

Kaggle notebook local runner:
Script runtime: about 32.97 sec
Shell wall time: about 63.52 sec
```

The regex approach is much faster and, after tuning on the full dataset, reached higher measured accuracy. However, that comparison is not fully fair because:

- The regex rules were iterated using knowledge from the full dataset.
- The Kaggle notebook reports a held-out 20% test split.
- The regex system needs a clean train/dev/test evaluation to estimate generalization.

## Recommended Next Step

Build a fair split-based regex experiment:

```text
train: 70%
dev:   15%
test:  15%
```

Workflow:

```text
1. Use train to inspect examples and propose rules.
2. Use dev to accept, reject, and tune rules.
3. Evaluate test only once at the end.
```

This would allow an apples-to-apples comparison with the Kaggle notebook's machine-learning result.

Potential files:

```text
project/regex_rules/split_data.py
project/regex_rules/evaluate_split.py
project/regex_rules/rules.yaml
```

This would also make it easier to build an actual agent harness where the agent proposes rule edits and the evaluator accepts them only if they improve development-set metrics.
