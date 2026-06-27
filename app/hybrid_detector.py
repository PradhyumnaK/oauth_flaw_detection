"""hybrid_detector.py
Hybrid OAuth/OIDC detector:
-Rule fires (if rule sum > 0): use gbc rules prediction
-Rule silent (if rule sum is 0): defer to gbc full prediction"""

from pathlib import Path
from typing import Tuple, List
import joblib
import numpy as np
import pandas as pd

#Paths
DATASET = Path("merged_dataset.csv")
MODELS_DIR = Path("models")
GBC_RULES_PATH = MODELS_DIR / "gbc_rules.joblib"
GBC_FULL_PATH = MODELS_DIR / "gbc_full.joblib"

#Label maps
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
NORMAL_LABEL = LABEL_MAP["normal"]

def load_rule_features(df: pd.DataFrame) -> pd.DataFrame:
    rule_columns = [c for c in df.columns if c.startswith("rule_") and c!="rule_label"]
    if not rule_columns:
        raise ValueError("No rule columns found in merged_dataset.csv")
    return df[rule_columns]

def load_dull_features(df):
    columns = [c for c in df.columns if c.startswith("x")]
    if not columns:
        raise ValueError("No x feature columns found")
    return df[columns]

def load_hybrid_components() -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, np.ndarray]:
    #Load merged dataset, extract rule feature matrix and return labels
    #Returns: df (full dataframe), X_rules (rule feature subset), and y_true (label vector)
    df = pd.read_csv(DATASET)
    df["run"] = df["run"].astype(int)

    X_rules = load_rule_features(df)
    x_full = load_dull_features(df)
    y_true = df["label"].to_numpy()
    return df, X_rules, x_full, y_true

def load_models():
    for p in (GBC_RULES_PATH, GBC_FULL_PATH):
        if not p.exists():
            raise FileNotFoundError(f"Model not found: {p}")
    return joblib.load(GBC_RULES_PATH), joblib.load(GBC_FULL_PATH)

def hybrid_predict(X_rules, X_full, gbc_rules=None, gbc_full=None):
    if gbc_rules is None or gbc_full is None:
        gbc_rules, gbc_full = load_models()
    X_rules = X_rules.apply(pd.to_numeric, errors="raise")
    X_full  = X_full.apply(pd.to_numeric, errors="raise")

    y_proba_rules = gbc_rules.predict_proba(X_rules)
    y_proba_full  = gbc_full.predict_proba(X_full)

    # Weighted ensemble
    combined = 0.4 * y_proba_rules + 0.6 * y_proba_full
    return np.argmax(combined, axis=1)

def hybrid_predict_proba(X_rules, X_full, gbc_rules=None, gbc_full=None):
    if gbc_rules is None or gbc_full is None:
        gbc_rules, gbc_full = load_models()
    X_rules = X_rules.apply(pd.to_numeric, errors="raise")
    X_full  = X_full.apply(pd.to_numeric, errors="raise")

    y_proba_rules = gbc_rules.predict_proba(X_rules)
    y_proba_full  = gbc_full.predict_proba(X_full)

    return 0.4 * y_proba_rules + 0.6 * y_proba_full