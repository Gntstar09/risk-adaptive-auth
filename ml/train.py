"""Train and compare four risk detectors on the synthetic login data."""
from pathlib import Path

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (confusion_matrix, f1_score, precision_score,
                             recall_score, roc_auc_score, roc_curve)
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parent
DATA = ROOT.parent / "datasets"
MODELS = ROOT / "models"
RESULTS = ROOT / "results"
MODELS.mkdir(exist_ok=True)
RESULTS.mkdir(exist_ok=True)

FEATURES = ["first_login", "new_device", "new_country", "unusual_hour",
            "failed_by_email", "failed_by_ip", "hour_sin", "hour_cos", "is_weekend"]
THRESHOLD = 30        # same boundary as the Java PolicyEngine: score > 30 means "not ALLOW"
RULE_WEIGHT = 0.6     # hybrid = max(rule, 0.6*rule + 0.4*ml)


def add_features(df):
    df = df.copy()
    df["hour_sin"] = np.sin(2 * np.pi * df["hour"] / 24)
    df["hour_cos"] = np.cos(2 * np.pi * df["hour"] / 24)
    return df


def rule_score(df):
    """Exactly the weights used by RuleBasedRiskEngine in Java."""
    s = (35 * df["new_device"] + 40 * df["new_country"] + 10 * df["unusual_hour"]
         + 8 * np.minimum(df["failed_by_email"], 3)
         + 20 * (df["failed_by_ip"] >= 5).astype(int))
    return np.minimum(s, 100).to_numpy(dtype=float)


def evaluate(y, score, flagged):
    flagged = np.asarray(flagged).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, flagged, labels=[0, 1]).ravel()
    return {
        "precision": precision_score(y, flagged, zero_division=0),
        "recall": recall_score(y, flagged, zero_division=0),
        "f1": f1_score(y, flagged, zero_division=0),
        "roc_auc": roc_auc_score(y, score),
        "false_positive_rate": fp / (fp + tn),
        "TP": int(tp), "FP": int(fp), "FN": int(fn), "TN": int(tn),
    }


def main():
    std = add_features(pd.read_csv(DATA / "logins.csv"))
    hard = add_features(pd.read_csv(DATA / "logins_hard.csv"))
    train, test = train_test_split(std, test_size=0.2, stratify=std["is_attack"], random_state=42)

    rf = RandomForestClassifier(n_estimators=150, max_depth=10, min_samples_leaf=5,
                                class_weight="balanced", random_state=42, n_jobs=1)
    rf.fit(train[FEATURES], train["is_attack"])

    # Isolation Forest learns what NORMAL looks like, so it trains on genuine logins only
    legit_train = train[train["is_attack"] == 0]
    iso = IsolationForest(n_estimators=150, random_state=42, n_jobs=1).fit(legit_train[FEATURES])
    iso_threshold = np.percentile(-iso.decision_function(legit_train[FEATURES]), 95)

    def detectors(df):
        rule = rule_score(df)
        ml = rf.predict_proba(df[FEATURES])[:, 1] * 100
        hybrid = np.maximum(rule, RULE_WEIGHT * rule + (1 - RULE_WEIGHT) * ml)
        anomaly = -iso.decision_function(df[FEATURES])
        return {
            "Rule-based": (rule, rule > THRESHOLD),
            "Random Forest": (ml, ml > THRESHOLD),
            "Isolation Forest": (anomaly, anomaly > iso_threshold),
            "Hybrid (rules + RF)": (hybrid, hybrid > THRESHOLD),
        }

    sets = {"Standard test set": test, "Hard set (sophisticated attackers)": hard}
    rows, curves = [], {}
    for set_name, df in sets.items():
        y = df["is_attack"].to_numpy()
        det = detectors(df)
        curves[set_name] = (y, det)
        for method, (score, flagged) in det.items():
            rows.append({"dataset": set_name, "method": method, **evaluate(y, score, flagged)})

    results = pd.DataFrame(rows)
    results.to_csv(RESULTS / "metrics.csv", index=False)
    pd.set_option("display.width", 200)
    show = results.drop(columns=["TP", "FP", "FN", "TN"]).round(3)
    for set_name in sets:
        print(f"\n=== {set_name} ===")
        print(show[show["dataset"] == set_name].drop(columns="dataset").to_string(index=False))

    # ROC curves
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.8))
    for ax, (set_name, (y, det)) in zip(axes, curves.items()):
        for method, (score, _) in det.items():
            fpr, tpr, _ = roc_curve(y, score)
            ax.plot(fpr, tpr, label=f"{method} (AUC {roc_auc_score(y, score):.3f})")
        ax.plot([0, 1], [0, 1], "k--", linewidth=0.8)
        ax.set_title(set_name)
        ax.set_xlabel("False positive rate")
        ax.set_ylabel("True positive rate")
        ax.legend(loc="lower right", fontsize=8)
    fig.tight_layout()
    fig.savefig(RESULTS / "roc.png", dpi=150)

    # Feature importance
    imp = pd.Series(rf.feature_importances_, index=FEATURES).sort_values()
    fig2, ax2 = plt.subplots(figsize=(6, 4))
    imp.plot.barh(ax=ax2)
    ax2.set_title("Random Forest feature importance")
    fig2.tight_layout()
    fig2.savefig(RESULTS / "feature_importance.png", dpi=150)

    joblib.dump({"model": rf, "features": FEATURES}, MODELS / "rf.joblib")
    print("\nSaved: models/rf.joblib, results/metrics.csv, results/roc.png, results/feature_importance.png")


if __name__ == "__main__":
    main()