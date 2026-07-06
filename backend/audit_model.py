import pandas as pd
import numpy as np
import joblib
import json
import os
import lightgbm as lgb
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support, roc_auc_score
import shap

def run_model_audit():
    print("Loading test data...")
    test_df = pd.read_csv('data/test.csv')
    
    # Load model and encoders
    model = joblib.load('models/model_lightgbm.pkl')
    vec = joblib.load('models/vectorizer_lightgbm.pkl')
    sec = joblib.load('models/preprocessor_lightgbm.pkl')
    le = joblib.load('models/label_encoder_lightgbm.pkl')
    
    print("Extracting features...")
    Xt = vec.transform(test_df['payload'].fillna(''))
    Xs = sec.transform(test_df['payload'].fillna(''))
    from scipy.sparse import hstack
    X = hstack([Xt, Xs]).astype(np.float32)
    y_true = le.transform(test_df['label'])
    
    print("Predicting probabilities...")
    probas = model.predict_proba(X)
    
    report = {}
    classes = list(le.classes_)
    report['classes'] = classes
    
    # 1. Confusion Matrix (default argmax)
    y_pred_default = np.argmax(probas, axis=1)
    cm = confusion_matrix(y_true, y_pred_default)
    report['default_cm'] = cm.tolist()
    
    # 2. Prec, Rec, F1 per class (default)
    p, r, f1, s = precision_recall_fscore_support(y_true, y_pred_default)
    report['default_metrics'] = {classes[i]: {"precision": float(p[i]), "recall": float(r[i]), "f1": float(f1[i]), "support": int(s[i])} for i in range(len(classes))}
    
    # 3. False Positives / 4. False Negatives Analysis
    # We can infer from CM.
    
    # 5. ROC AUC (OVR)
    try:
        report['macro_roc_auc'] = float(roc_auc_score(y_true, probas, multi_class='ovr', average='macro'))
        # per-class roc
        per_class_roc = {}
        for i, cls in enumerate(classes):
            y_bin = (y_true == i).astype(int)
            per_class_roc[cls] = float(roc_auc_score(y_bin, probas[:, i]))
        report['per_class_roc'] = per_class_roc
    except Exception as e:
        report['macro_roc_auc'] = str(e)
    
    # 7. Calibration
    # We can check Brier score or just mean proba vs true frequency
    brier_scores = {}
    for i, cls in enumerate(classes):
        y_bin = (y_true == i).astype(int)
        brier = np.mean((probas[:, i] - y_bin)**2)
        brier_scores[cls] = float(brier)
    report['brier_scores'] = brier_scores
    
    # 8. Threshold Analysis (0.1 to 0.95)
    print("Simulating thresholds...")
    thresholds = [0.10, 0.20, 0.30, 0.40, 0.50, 0.60, 0.70, 0.80, 0.90, 0.95]
    thresh_report = {cls: [] for cls in classes}
    
    for th in thresholds:
        for i, cls in enumerate(classes):
            if cls == "normal": continue # normal doesn't have a blocking threshold usually
            # Binary decision: proba >= th
            y_pred_bin = (probas[:, i] >= th).astype(int)
            y_true_bin = (y_true == i).astype(int)
            bp, br, bf1, bs = precision_recall_fscore_support(y_true_bin, y_pred_bin, average='binary', zero_division=0)
            thresh_report[cls].append({"threshold": th, "precision": float(bp), "recall": float(br), "f1": float(bf1)})
    
    report['threshold_analysis'] = thresh_report
    
    # 9. SHAP Analysis
    print("Running SHAP...")
    try:
        # We need a sample because SHAP on 30k x 3000 features takes too long
        # X is sparse, TreeExplainer supports sparse but let's be careful
        explainer = shap.TreeExplainer(model)
        # Sample 500
        X_sample = X[:500]
        shap_values = explainer.shap_values(X_sample)
        
        # Get feature names
        try:
            tfidf_names = vec.get_feature_names_out().tolist()
            sec_names = sec.feature_names
            feature_names = tfidf_names + sec_names
        except:
            feature_names = [f"f_{i}" for i in range(X.shape[1])]
            
        # Global mean absolute shap
        # shap_values is a list of arrays (one per class)
        mean_abs_shap = np.mean([np.abs(sv).mean(axis=0) for sv in shap_values], axis=0)
        top_idx = np.argsort(mean_abs_shap)[::-1][:20]
        
        top_shap_features = []
        for idx in top_idx:
            top_shap_features.append({"feature": feature_names[idx], "shap_importance": float(mean_abs_shap[idx])})
        report['shap_top_20'] = top_shap_features
    except Exception as e:
        print("SHAP failed:", e)
        report['shap_top_20'] = str(e)
        
    with open('model_audit_results.json', 'w') as f:
        json.dump(report, f, indent=2)

if __name__ == "__main__":
    run_model_audit()
