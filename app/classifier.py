"""classifier.py
Trains two Gradient Boosting Classifiers:
-gbc_rules: using only rule features
-gbc_full: using all feature vectors
Uses the merged dataset and also evaluates a rule gated gbc_rules
detector where normal is assigned if no rule flags fire."""

from pathlib import Path
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import train_test_split, GridSearchCV

DATASET = Path("merged_dataset.csv")
MODELS_DIR = Path("models")
MODELS_DIR.mkdir(exist_ok=True)

LABEL_MAP = {
    "normal": 0,
    "no_pkce_accepted": 1,
    "no_pkce_rejected": 2,
    "pkce_downgrade": 3,
    "redirect_flaw_strict": 4,
    "redirect_flaw_misconfig": 5,
    "refresh_misuse_rejected": 6,
    "refresh_misuse_stolen": 7,
}
INV_LABEL_MAP = {v: k for k, v in LABEL_MAP.items()}

def load_data():
    df = pd.read_csv(DATASET)
    #Making sure run is int
    df["run"] = df["run"].astype(int)
    rule_cols = [c for c in df.columns if c.startswith("rule_") and c != "rule_label"]
    df[rule_cols] = df[rule_cols].apply(pd.to_numeric, errors = "raise")
    return df

def train_gbc(X, y, name: str, inv_label_map=None):
    print(f"\n[train] {name}")
    #Make sure features are numeric, else it fails if string
    X = X.apply(pd.to_numeric, errors="raise")
    #1.70% train, 30% temp(tune + test)
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, 
        y,
        test_size=0.30,
        random_state=42,
        stratify=y,
    )

    #2.From the 30%, split into 20% test and 10% tune overall
    #30% of data in X_temp. This is to get 2/3 test, 1/3 tune (20%+30%)
    X_test, X_tune, y_test, y_tune = train_test_split(
        X_temp,
        y_temp,
        test_size=1/3,
        random_state=43,
        stratify=y_temp,
    )

    base = GradientBoostingClassifier(random_state=42)
    param_grid = {
        "n_estimators": [50, 100],
        "learning_rate": [0.05, 0.1],
        "max_depth": [3, 4],
    }

    #Use the 10% tuning set for GridSearchCV
    grid = GridSearchCV(
        base,
        param_grid,
        cv=3,
        n_jobs=-1,
        scoring="f1_macro",
    )
    grid.fit(X_tune, y_tune)
    best = grid.best_estimator_

    print(f"[{name}] best params (from 10% tuning set): {grid.best_params_}")

    #Final evaluation on the 20% test set
    y_pred = best.predict(X_test)
    print(f"[{name}] confusion matrix:\n{confusion_matrix(y_test, y_pred)}")
    
    if inv_label_map is not None:
        labels = sorted(inv_label_map) #label mismatch fix
        target_names = [inv_label_map[i] for i in labels]
        cr = classification_report(y_test, y_pred, labels=labels, target_names=target_names, zero_division=0)
    else:
        cr = classification_report(y_test, y_pred, zero_division=0)
    
    print(f"[{name}] classification report:\n{cr}")

    #Macro AUROC (one vs rest) on the test set
    try:
        y_proba = best.predict_proba(X_test)
        auroc_macro = roc_auc_score(
            y_test, y_proba, multi_class="ovr", average="macro"
        )
        print(f"[{name}] macro AUROC (test set): {auroc_macro:.4f}")
    except Exception as e:
        print(f"[{name}] AUROC calculation failed: {e} ")
    
    model_path = MODELS_DIR / f"{name}.joblib"
    joblib.dump(best, model_path)
    print(f"[{name}] model saved to {model_path}")

    return best

def main():
    df = load_data()

    #Target labels
    y = df["label"]

    #Full feature set (x1 through x37)
    full_features = [c for c in df.columns if c.startswith("x")]
    X_full = df[full_features]

    #Rule-based features
    rule_features = [
        c 
        for c in df.columns
        if c.startswith("rule_") and c != "rule_label"
    ]
    if not rule_features:
        raise ValueError("No rule features found in merged_dataset.csv")
    X_rules = df[rule_features]

    #Train gradient bossting on rule features only (multiclass)
    gbc_rules = train_gbc(X_rules, y, name="gbc_rules", inv_label_map=INV_LABEL_MAP)

    #Train gradient boosting on full feature vector (multiclass)
    gbc_full = train_gbc(X_full, y, name="gbc_full", inv_label_map=INV_LABEL_MAP)

    #Rule gated evaluation. Normal=no rule flags, flaws using gbc_rules
    print(f"Rule gated evaluation with gbc_rules (normal = no rule flags)")
    y_true = df["label"]
    rule_sum = X_rules.sum(axis=1)
    NORMAL_LABEL = LABEL_MAP["normal"]

    #Predicitons and probabilities from gbc_rules on full dataset
    y_pred_flaw = gbc_rules.predict(X_rules)
    try:
        y_proba_flaw = gbc_rules.predict_proba(X_rules)
    except Exception:
        y_proba_flaw = None
    
    #Force normal if no rule is fired, else use model prediction
    y_pred = np.where(rule_sum == 0, NORMAL_LABEL, y_pred_flaw)

    #Build probability matrix
    proba = None
    if y_proba_flaw is not None:
        k = len(LABEL_MAP)
        rows = []
        for rs, ml_probs in zip(rule_sum, y_proba_flaw):
            if rs == 0:
                p = [0.0] * k
                p[NORMAL_LABEL] = 1.0
                rows.append(p)
            else:
                rows.append(list(ml_probs))
        proba = np.array(rows)
    
    print("Confusion matrix:")
    print(confusion_matrix(y_true, y_pred))
    print("\nClassification report:")
    #label mismatch fix
    labels = sorted(INV_LABEL_MAP)
    target_names = [INV_LABEL_MAP[i] for i in labels]
    print(
        classification_report(
            y_true,
            y_pred,
            labels=labels,
            target_names=target_names,
            zero_division=0,
        )
    )
    if proba is not None:
        try:
            auroc_macro = roc_auc_score(
                y_true, proba, multi_class="ovr", average="macro"
            )
            print(f"Macro AUROC (rule gated gbc_rules): {auroc_macro:.4f}")
        except Exception as e:
            print(f"Rule gated AUROC calculation failed: {e}")

if __name__ == "__main__":
    main()