import pandas as pd
import numpy as np
import joblib
import urllib.parse
import html
import re
from sklearn.metrics import precision_recall_fscore_support

def normalize_payload(text_str):
    text_str = str(text_str)
    
    # 1. Unicode escape decoding (safe regex replacement to avoid warnings on invalid escapes)
    # This replaces \uXXXX and \UXXXXXXXX with their characters
    try:
        text_str = re.sub(
            r'\\u([0-9a-fA-F]{4})',
            lambda m: chr(int(m.group(1), 16)),
            text_str
        )
        text_str = re.sub(
            r'\\U([0-9a-fA-F]{8})',
            lambda m: chr(int(m.group(1), 16)),
            text_str
        )
    except Exception:
        pass
        
    # 2. HTML unescape
    text_str = html.unescape(text_str)
    
    # 3. URL unquote (double)
    text_str = urllib.parse.unquote_plus(text_str)
    text_str = urllib.parse.unquote_plus(text_str)
    
    return text_str

def run_experiment():
    print("Loading test data (subset)...")
    # Take 5000 random samples to make it fast
    test_df = pd.read_csv('data/test.csv').sample(5000, random_state=42)
    
    model = joblib.load('models/model_lightgbm.pkl')
    vec = joblib.load('models/vectorizer_lightgbm.pkl')
    sec = joblib.load('models/preprocessor_lightgbm.pkl')
    le = joblib.load('models/label_encoder_lightgbm.pkl')
    
    # 1. Baseline Predictions
    print("Running Baseline...")
    Xt = vec.transform(test_df['payload'].fillna(''))
    Xs = sec.transform(test_df['payload'].fillna(''))
    from scipy.sparse import hstack
    X_base = hstack([Xt, Xs]).astype(np.float32)
    y_pred_base = np.argmax(model.predict_proba(X_base), axis=1)
    
    # 2. Normalized Predictions
    print("Running Normalized...")
    norm_payloads = test_df['payload'].fillna('').apply(normalize_payload)
    Xt_norm = vec.transform(norm_payloads)
    Xs_norm = sec.transform(norm_payloads)
    X_norm = hstack([Xt_norm, Xs_norm]).astype(np.float32)
    y_pred_norm = np.argmax(model.predict_proba(X_norm), axis=1)
    
    y_true = le.transform(test_df['label'])
    
    print("\n--- BASELINE METRICS ---")
    p, r, f, s = precision_recall_fscore_support(y_true, y_pred_base, average='macro', zero_division=0)
    print(f"Macro P: {p:.4f}, R: {r:.4f}, F1: {f:.4f}")
    
    print("\n--- NORMALIZED METRICS ---")
    p_n, r_n, f_n, s_n = precision_recall_fscore_support(y_true, y_pred_norm, average='macro', zero_division=0)
    print(f"Macro P: {p_n:.4f}, R: {r_n:.4f}, F1: {f_n:.4f}")
    
    classes = list(le.classes_)
    p, r, f, _ = precision_recall_fscore_support(y_true, y_pred_base, zero_division=0)
    p_n, r_n, f_n, _ = precision_recall_fscore_support(y_true, y_pred_norm, zero_division=0)
    
    print("\nClass-level F1 Comparison:")
    for i, cls in enumerate(classes):
        print(f"{cls:15s} | Base: {f[i]:.4f} | Norm: {f_n[i]:.4f} | Diff: {f_n[i]-f[i]:.4f}")

if __name__ == "__main__":
    run_experiment()
