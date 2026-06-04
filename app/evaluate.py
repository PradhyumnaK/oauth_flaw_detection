"""evaluate.py
Evaluate the hybrid rule + ML detector on the merged dataset
Uses:
-rule based features + gbc rules
-rule gated normal fallback (normal when there are no rule flags)"""

from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, classification_report, roc_auc_score
from hybrid_detector import load_hybrid_components, load_gbc_rules, hybrid_predict, hybrid_predict_proba, INV_LABEL_MAP

def main():
    #Load data and model
    df, X_rules, y_true = load_hybrid_components()
    gbc_rules = load_gbc_rules()
    
    print(f"Hybrid rule gated evaluation\n")

    #Prediction
    y_pred = hybrid_predict(X_rules, model=gbc_rules)
    proba = hybrid_predict_proba(X_rules, model=gbc_rules)

    #Confusion matrix
    print(f"Confusion matrix:\n {confusion_matrix(y_true, y_pred)}")

    #Classification report
    target_names = [INV_LABEL_MAP[i] for i in sorted(INV_LABEL_MAP)]
    print("Classification report:")
    print(
        classification_report(
            y_true, 
            y_pred,
            target_names=target_names,
        )
    )

    #Macro AUROC (one vs rest)
    if proba is not None:
        try:
            auroc_macro = roc_auc_score(
                y_true,
                proba,
                multi_class="ovr",
                average="macro",
            )
            print(f"Macro AUROC (hybrid rule gated): {auroc_macro:.4f}")
        except Exception as e:
            print(f"Hybrid AUROC calculation failed: {e}")

if __name__ == "__main__":
    main()