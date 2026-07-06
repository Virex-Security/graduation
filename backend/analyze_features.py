import pandas as pd
import numpy as np
import joblib
import json

def analyze_features():
    print("Loading test data...")
    test_df = pd.read_csv('data/test.csv')
    
    print("Loading SecurityFeatureExtractor...")
    sec = joblib.load('models/preprocessor_lightgbm.pkl')
    
    print("Extracting features...")
    # Extract features using transform
    X_sec = sec.transform(test_df['payload'].fillna(''))
    
    # Try to get feature names
    feature_names = sec.feature_names
    
    print("Computing correlation matrix...")
    df_sec = pd.DataFrame(X_sec.toarray() if hasattr(X_sec, 'toarray') else X_sec, columns=feature_names)
    
    corr_matrix = df_sec.corr()
    
    high_corr_pairs = []
    
    for i in range(len(corr_matrix.columns)):
        for j in range(i+1, len(corr_matrix.columns)):
            col1 = corr_matrix.columns[i]
            col2 = corr_matrix.columns[j]
            corr_val = corr_matrix.iloc[i, j]
            
            if abs(corr_val) > 0.95:
                high_corr_pairs.append({
                    "feature_1": col1,
                    "feature_2": col2,
                    "correlation": float(corr_val)
                })
                
    # Now check TF-IDF
    vec = joblib.load('models/vectorizer_lightgbm.pkl')
    tfidf_config = {
        "analyzer": vec.analyzer,
        "ngram_range": vec.ngram_range,
        "max_features": vec.max_features,
        "min_df": vec.min_df,
        "max_df": vec.max_df
    }
    
    report = {
        "high_correlation_pairs": high_corr_pairs,
        "tfidf_config": tfidf_config
    }
    
    with open('feature_analysis.json', 'w') as f:
        json.dump(report, f, indent=2)
        
    print("Analysis complete.")

if __name__ == "__main__":
    analyze_features()
