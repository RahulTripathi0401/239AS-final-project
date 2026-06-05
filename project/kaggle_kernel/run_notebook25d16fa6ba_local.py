#!/usr/bin/env python3
import os
import re
import time
import warnings
from pathlib import Path

import joblib
import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from scipy.sparse import csr_matrix, hstack
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    accuracy_score,
    auc,
    classification_report,
    confusion_matrix,
    f1_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.preprocessing import LabelEncoder


warnings.filterwarnings("ignore")

HERE = Path(__file__).resolve().parent
PROJECT_DIR = HERE.parent
DATA_PATH = PROJECT_DIR / "csic_database.csv"
OUTPUT_DIR = HERE / "outputs"
OUTPUT_DIR.mkdir(exist_ok=True)


def savefig(name: str) -> None:
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / name, dpi=150, bbox_inches="tight")
    plt.close()


def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    feat = pd.DataFrame()

    url = df["URL"].fillna("")
    body = df["content"].fillna("")
    payload = url + " " + body

    feat["url_length"] = url.str.len()
    feat["url_depth"] = url.str.count("/")
    feat["url_param_count"] = url.str.count(r"[?&]")
    feat["url_has_sql"] = url.str.contains(
        r"(?i)(select|union|insert|drop|exec|cast|'|--|;)", regex=True
    ).astype(int)
    feat["url_has_xss"] = url.str.contains(
        r"(?i)(<script|onerror|onload|javascript:|alert\()", regex=True
    ).astype(int)
    feat["url_has_ssrf"] = url.str.contains(
        r"(?i)(127\.0\.0\.1|localhost|169\.254|file://|gopher://|dict://)",
        regex=True,
    ).astype(int)
    feat["url_has_traversal"] = url.str.contains(
        r"(?i)(\.\.\/|%2e%2e)", regex=True
    ).astype(int)
    feat["url_special_chars"] = url.str.count(r"[<>'\"%;()&+]")
    feat["url_encoded_chars"] = url.str.count(r"%[0-9a-fA-F]{2}")

    feat["body_length"] = body.str.len()
    feat["body_has_sql"] = body.str.contains(
        r"(?i)(select|union|insert|drop|exec|cast|'|--|;)", regex=True
    ).astype(int)
    feat["body_has_xss"] = body.str.contains(
        r"(?i)(<script|onerror|onload|javascript:|alert\()", regex=True
    ).astype(int)
    feat["body_special_chars"] = body.str.count(r"[<>'\"%;()&+]")
    feat["body_encoded_chars"] = body.str.count(r"%[0-9a-fA-F]{2}")

    feat["method_is_post"] = (df["Method"].fillna("") == "POST").astype(int)
    feat["method_is_get"] = (df["Method"].fillna("") == "GET").astype(int)
    feat["method_is_other"] = (~df["Method"].fillna("").isin(["GET", "POST"])).astype(
        int
    )

    feat["content_length"] = pd.to_numeric(
        df["lenght"].fillna("0").astype(str).str.extract(r"(\d+)")[0],
        errors="coerce",
    ).fillna(0)

    feat["payload"] = payload
    return feat


def infer_attack_type(row: pd.Series) -> str:
    if row["classification"] == 0:
        return "Normal"
    payload = (str(row.get("URL", "")) + " " + str(row.get("content", ""))).lower()
    if re.search(r"select|union|insert|drop|exec|cast|--|'\s*or|'\s*and", payload):
        return "SQLi"
    if re.search(r"<script|onerror|onload|javascript:|alert\(|<img.*src", payload):
        return "XSS"
    if re.search(r"127\.0\.0\.1|localhost|169\.254|file://|gopher://|dict://", payload):
        return "SSRF"
    if re.search(r"\.\./|%2e%2e|%252e|/etc/passwd|/proc/", payload):
        return "PathTraversal"
    if re.search(r"cmd=|exec=|system\(|passthru\(|shell_exec", payload):
        return "CommandInjection"
    return "OtherAttack"


def main() -> None:
    t0 = time.perf_counter()
    print("All libraries loaded successfully")
    print(f"Using data: {DATA_PATH}")

    df = pd.read_csv(DATA_PATH)
    print(f"Shape: {df.shape}")
    print(f"Columns: {list(df.columns)}")
    print(f"\nLabel distribution:\n{df['classification'].value_counts()}")
    print(f"\nHTTP methods:\n{df['Method'].value_counts()}")

    fig, axes = plt.subplots(1, 2, figsize=(12, 4))
    counts = df["classification"].value_counts()
    axes[0].bar(["Normal", "Attack"], counts.values, color=["#4CAF50", "#F44336"])
    axes[0].set_title("Class Distribution")
    method_counts = df["Method"].value_counts().head(5)
    axes[1].bar(method_counts.index, method_counts.values, color="#2196F3")
    axes[1].set_title("HTTP Methods")
    savefig("class_and_method_distribution.png")

    features_df = extract_features(df)
    print(f"Features extracted: {features_df.shape[1] - 1} numeric + 1 text column")

    df["attack_type"] = df.apply(infer_attack_type, axis=1)
    print("\n=== Attack Type Distribution ===")
    print(df["attack_type"].value_counts())

    numeric_cols = [
        "url_length",
        "url_depth",
        "url_param_count",
        "url_has_sql",
        "url_has_xss",
        "url_has_ssrf",
        "url_has_traversal",
        "url_special_chars",
        "url_encoded_chars",
        "body_length",
        "body_has_sql",
        "body_has_xss",
        "body_special_chars",
        "body_encoded_chars",
        "method_is_post",
        "method_is_get",
        "method_is_other",
        "content_length",
    ]

    X_numeric = features_df[numeric_cols].fillna(0).values
    tfidf = TfidfVectorizer(
        analyzer="char_wb", ngram_range=(2, 4), max_features=3000, sublinear_tf=True
    )
    X_text = tfidf.fit_transform(features_df["payload"].fillna(""))
    X = hstack([csr_matrix(X_numeric), X_text])
    y_binary = df["classification"].values

    le = LabelEncoder()
    y_multi = le.fit_transform(df["attack_type"].values)
    print("Multi-class labels:", dict(enumerate(le.classes_)))

    X_train, X_test, yb_train, yb_test, ym_train, ym_test = train_test_split(
        X, y_binary, y_multi, test_size=0.2, random_state=42, stratify=y_binary
    )
    print(f"\nTrain size: {X_train.shape[0]:,} | Test size: {X_test.shape[0]:,}")
    print(f"Feature dimensions: {X_train.shape[1]:,}")

    print("\nTraining Binary Classifier (Random Forest)...")
    rf_binary = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        min_samples_leaf=2,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42,
    )
    rf_binary.fit(X_train, yb_train)
    yb_pred = rf_binary.predict(X_test)
    yb_prob = rf_binary.predict_proba(X_test)[:, 1]

    print("\n=== Binary Classification Report ===")
    print(classification_report(yb_test, yb_pred, target_names=["Normal", "Attack"]))
    binary_accuracy = accuracy_score(yb_test, yb_pred)
    binary_f1 = f1_score(yb_test, yb_pred)
    binary_roc_auc = roc_auc_score(yb_test, yb_prob)
    print(f"Accuracy : {binary_accuracy:.4f}")
    print(f"F1 Score : {binary_f1:.4f}")
    print(f"ROC-AUC  : {binary_roc_auc:.4f}")

    fig, ax = plt.subplots(figsize=(6, 5))
    cm = confusion_matrix(yb_test, yb_pred)
    pd.DataFrame(
        [
            {
                "model": "Random forest",
                "split": "20% test",
                "accuracy": binary_accuracy,
                "f1": binary_f1,
                "roc_auc": binary_roc_auc,
                "tn": int(cm[0, 0]),
                "fp": int(cm[0, 1]),
                "fn": int(cm[1, 0]),
                "tp": int(cm[1, 1]),
            }
        ]
    ).to_csv(OUTPUT_DIR / "binary_metrics.csv", index=False)
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["Normal", "Attack"])
    disp.plot(ax=ax, colorbar=False, cmap="Blues")
    ax.set_title("Binary Classification Confusion Matrix")
    savefig("binary_confusion_matrix.png")

    fpr, tpr, _ = roc_curve(yb_test, yb_prob)
    roc_auc = auc(fpr, tpr)
    plt.figure(figsize=(6, 5))
    plt.plot(fpr, tpr, color="#2196F3", lw=2, label=f"ROC Curve (AUC = {roc_auc:.4f})")
    plt.plot([0, 1], [0, 1], "k--", lw=1)
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title("ROC Curve Binary Classifier")
    plt.legend(loc="lower right")
    savefig("binary_roc_curve.png")

    print("\nTraining Multi-Class Classifier (Gradient Boosting)...")
    print("Classes:", list(le.classes_))
    X_train_num = X_train[:, : len(numeric_cols)].toarray()
    X_test_num = X_test[:, : len(numeric_cols)].toarray()
    gb_multi = GradientBoostingClassifier(
        n_estimators=150, learning_rate=0.1, max_depth=5, subsample=0.8, random_state=42
    )
    gb_multi.fit(X_train_num, ym_train)
    ym_pred = gb_multi.predict(X_test_num)

    print("\n=== Multi-Class Classification Report ===")
    print(classification_report(ym_test, ym_pred, target_names=le.classes_))
    print(f"Accuracy: {accuracy_score(ym_test, ym_pred):.4f}")
    print(f"F1 (weighted): {f1_score(ym_test, ym_pred, average='weighted'):.4f}")

    fig, ax = plt.subplots(figsize=(8, 6))
    cm_multi = confusion_matrix(ym_test, ym_pred)
    sns.heatmap(
        cm_multi,
        annot=True,
        fmt="d",
        cmap="Blues",
        xticklabels=le.classes_,
        yticklabels=le.classes_,
        ax=ax,
    )
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title("Multi-Class Confusion Matrix")
    savefig("multiclass_confusion_matrix.png")

    importances = rf_binary.feature_importances_[: len(numeric_cols)]
    importance_df = pd.DataFrame(
        {"Feature": numeric_cols, "Importance": importances}
    ).sort_values("Importance", ascending=True).tail(15)
    plt.figure(figsize=(8, 6))
    plt.barh(importance_df["Feature"], importance_df["Importance"], color="#2196F3")
    plt.xlabel("Feature Importance (Gini)")
    plt.title("Top Feature Importances Random Forest")
    savefig("feature_importance.png")
    print("\nTop 5 most important features:")
    print(importance_df.sort_values("Importance", ascending=False).head(5).to_string(index=False))

    print("\nRunning 5-Fold Cross Validation on Binary Classifier...")
    X_num_all = features_df[numeric_cols].fillna(0).values
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    rf_cv = RandomForestClassifier(
        n_estimators=100, max_depth=15, class_weight="balanced", n_jobs=-1, random_state=42
    )
    cv_scores = cross_val_score(rf_cv, X_num_all, y_binary, cv=cv, scoring="f1", n_jobs=-1)
    print(f"\nCV F1 Scores: {cv_scores.round(4)}")
    print(f"Mean F1: {cv_scores.mean():.4f} +/- {cv_scores.std():.4f}")

    print("\nComparing models on Binary Classification (numeric features only)...")
    models = {
        "Random Forest": RandomForestClassifier(
            n_estimators=100, class_weight="balanced", n_jobs=-1, random_state=42
        ),
        "Gradient Boosting": GradientBoostingClassifier(n_estimators=100, random_state=42),
        "Logistic Regression": LogisticRegression(
            class_weight="balanced", max_iter=500, random_state=42
        ),
    }

    results = []
    for name, model in models.items():
        model.fit(X_train_num, yb_train)
        pred = model.predict(X_test_num)
        results.append(
            {
                "Model": name,
                "Accuracy": round(accuracy_score(yb_test, pred), 4),
                "F1": round(f1_score(yb_test, pred), 4),
            }
        )
        print(f"{name}: Accuracy={results[-1]['Accuracy']} | F1={results[-1]['F1']}")

    results_df = pd.DataFrame(results)
    results_df.to_csv(OUTPUT_DIR / "numeric_model_comparison.csv", index=False)
    x = np.arange(len(results_df))
    w = 0.35
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.bar(x - w / 2, results_df["Accuracy"], w, label="Accuracy", color="#2196F3")
    ax.bar(x + w / 2, results_df["F1"], w, label="F1 Score", color="#4CAF50")
    ax.set_xticks(x)
    ax.set_xticklabels(results_df["Model"])
    ax.set_ylim([0.5, 1.02])
    ax.set_title("Model Comparison Binary Classification")
    ax.legend()
    savefig("model_comparison.png")

    joblib.dump(rf_binary, OUTPUT_DIR / "rf_binary_model.pkl")
    joblib.dump(gb_multi, OUTPUT_DIR / "gb_multiclass_model.pkl")
    joblib.dump(tfidf, OUTPUT_DIR / "tfidf_vectorizer.pkl")
    joblib.dump(le, OUTPUT_DIR / "label_encoder.pkl")

    total_runtime = time.perf_counter() - t0
    pd.DataFrame(
        [{"pipeline": "Reproduced ML baseline", "runtime_seconds": total_runtime}]
    ).to_csv(OUTPUT_DIR / "runtime_summary.csv", index=False)
    print(f"\nModels and plots saved to {OUTPUT_DIR}")
    print(f"Total runtime seconds: {total_runtime:.2f}")


if __name__ == "__main__":
    main()
