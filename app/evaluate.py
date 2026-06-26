"""evaluate.py
Evaluate the hybrid rule + ML detector on the merged dataset
Uses:
-rule based features + gbc rules
-rule gated normal fallback (normal when there are no rule flags)"""

from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, classification_report, roc_auc_score
from hybrid_detector import load_hybrid_components, load_models, hybrid_predict, hybrid_predict_proba, INV_LABEL_MAP
import shap
import matplotlib.pyplot as plt
import joblib #To load gbc_32

def explain_with_shap(model, X, feature_names, model_name: str):
    """Generate SHAP feature importance for a trained GBC model"""
    print(f"\n[SHAP] Generating explanations for {model_name}...")
    explainer = shap.Explainer(model.predict_proba, X)
    shap_values = explainer(X)

    plt.figure()
    shap.summary_plot(shap_values, X, feature_names=feature_names, show=False, plot_type="bar")
    plt.title(f"SHAP Feature Importance: {model_name}")
    plt.savefig(f"shap_{model_name}_summary.png", dpi=150)
    plt.close()
    print(f"[SHAP] Saved shap_{model_name}_summary.png")

def main():
    #Load data and model
    df, X_rules, x_full, y_true = load_hybrid_components()
    gbc_rules, gbc_full = load_models()
    MODELS_DIR = Path("models")
    gbc_32 = joblib.load(MODELS_DIR / "gbc_32_munonye.joblib")
    
    print(f"Hybrid evaluation\n")

    #Prediction
    y_pred = hybrid_predict(X_rules, x_full, gbc_rules, gbc_full)
    proba = hybrid_predict_proba(X_rules, x_full, gbc_rules, gbc_full)

    labels = sorted(INV_LABEL_MAP)
    target_names = [INV_LABEL_MAP[i] for i in labels]

    #Confusion matrix and classification report
    print(f"COnfusion matrix:\n{confusion_matrix(y_true, y_pred)}")
    print(f"Classification report:")
    print(classification_report(y_true, y_pred, labels=labels, target_names=target_names, zero_division=0))

    #Macro AUROC
    if proba is not None:
        try:
            auroc = roc_auc_score(y_true, proba, multi_class="ovr", average="macro")
            print(f"Macro AUROC (hybrid): {auroc:.4f}")
        except Exception as e:
            print(f"AUROC failed: {e}")
    
    #SHAP explanation for gbc_full
    full_features = [c for c in df.columns if c.startswith("x")]
    explain_with_shap(gbc_full, df[full_features], full_features, "gbc_full")
    #For gbc_32_munonye
    munonye_features = [f"x{i}" for i in range(1, 33)]
    explain_with_shap(gbc_32, df[munonye_features], munonye_features, "gbc_32_munonye")

if __name__ == "__main__":
    main()