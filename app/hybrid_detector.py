"""hybrid_detector.py
Hybrid OAuth/OIDC detector:
-Uses rule features + gbc_rules model
-Applies a rule gated fallback: if no rule flags fire, classified as normal"""

from pathlib import Path
from typing import Tuple, List
import joblib
import numpy as np
import pandas as pd

#Paths
DATASET = Path("merged_dataset.csv")
MODELS_DIR = Path("models")
GBC_RULES_PATH = MODELS_DIR / "gbc_rules.joblib"

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

def load_hybrid_components() -> Tuple[pd.DataFrame, pd.DataFrame, np.ndarray]:
    #Load merged dataset, extract rule feature matrix and return labels
    #Returns: df (full dataframe), X_rules (rule feature subset), and y_true (label vector)
    df = pd.read_csv(DATASET)
    df["run"] = df["run"].astype(int)

    X_rules = load_rule_features(df)
    y_true = df["label"].to_numpy()
    return df, X_rules, y_true

def load_gbc_rules():
    #Loading the trained gbc rules model
    if not GBC_RULES_PATH.exists():
        raise FileNotFoundError(f"Model not found: {GBC_RULES_PATH}")
    return joblib.load(GBC_RULES_PATH)

def hybrid_predict(X_rules: pd.DataFrame, model=None) -> np.ndarray:
    #Hybrid prediction
    #Use gbc_rules for flaws
    #Force normal when no rule flags fire using rule_sum == 0
    if model is None:
        model = load_gbc_rules()
    
    #Making sure it is numeric
    X_rules = X_rules.apply(pd.to_numeric, errors="raise")

    rule_sum = X_rules.sum(axis=1).to_numpy()
    y_pred_flaw = model.predict(X_rules)

    y_pred = y_pred_flaw.copy()
    normal_mask = (rule_sum == 0)
    y_pred[normal_mask] = NORMAL_LABEL
    return y_pred

def hybrid_predict_proba(X_rules: pd.DataFrame, model=None) -> np.ndarray:
    #Hybrid probability matrix
    #For rule sum 0, normal
    #Else, use gbc rules predicted probability
    if model is None:
        model = load_gbc_rules()
    
    #Making sure its numeric
    X_rules = X_rules.apply(pd.to_numeric, errors="raise")

    rule_sum = X_rules.sum(axis=1).to_numpy()
    try:
        y_proba_flaw = model.predic_proba(X_rules)
    except Exception:
        return None
    
    k=len(LABEL_MAP)
    rows: List[List[float]] = []
    for rs, ml_probs in zip(rule_sum, y_proba_flaw):
        if rs == 0:
            p = [0.0] * k
            p[NORMAL_LABEL] = 1.0
            rows.append(p)
        else:
            rows.append(list(ml_probs))
    
    return np.array(rows)