import pandas as pd
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix, roc_auc_score, precision_recall_fscore_support
import joblib
import numpy as np
from pathlib import Path
import warnings

warnings.filterwarnings('ignore')

DATA_DIR = Path("data")
MODEL_PATH = DATA_DIR / "model_pipeline.pkl"  # Save as pipeline


def train_and_evaluate():
    """Train ML model with proper pipeline and validation"""
    
    # Load training data
    train_data = pd.read_csv(DATA_DIR / "ml_training_data.csv")

    print("="*60)
    print("  ML Model Training - Virex Security")
    print("="*60)
    print(f"\n Training samples: {len(train_data)}")
    print(f"   Normal:  {(train_data['label']==0).sum()} ({(train_data['label']==0).sum()/len(train_data)*100:.1f}%)")
    print(f"   Attacks: {(train_data['label']==1).sum()} ({(train_data['label']==1).sum()/len(train_data)*100:.1f}%)")
    
    # Check class balance
    attack_ratio = (train_data['label']==1).sum() / len(train_data)
    if attack_ratio < 0.3 or attack_ratio > 0.7:
        print(f"\n⚠️  WARNING: Imbalanced dataset (attacks: {attack_ratio*100:.1f}%)")
        print("   Consider balancing classes for better performance")

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        train_data["text"],
        train_data["label"],
        test_size=0.2,
        random_state=42,
        stratify=train_data["label"],
    )

    print(f"\n Split: {len(X_train)} train, {len(X_test)} test")

    # Create Pipeline (prevents data leakage)
    print("\n Building ML Pipeline...")
    pipeline = Pipeline([
        ('vectorizer', TfidfVectorizer(
            ngram_range=(1, 4),  # Increased to 4 to capture longer attack sequences
            max_features=2500,  # Reduced from 5000 to prevent overfitting and memorizing noise
            lowercase=True,
            strip_accents="unicode",
            sublinear_tf=True,
            min_df=5,  # Increased from 3 to ignore highly rare synthetic tokens
            max_df=0.7,  # Ignore words in >70% of docs
        )),
        ('classifier', RandomForestClassifier(
            n_estimators=100,  # Reduced from 200
            max_depth=15,  # Reduced from 25 to prevent overfitting
            min_samples_split=10,  # Increased
            min_samples_leaf=5,  # Increased from 2
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        ))
    ])

    # Calculate sample weights to rebalance Command Injection
    print("\n Weighting Command Injection samples...")
    cmd_pattern = re.compile(r"(;|\|\||\||&&|\$(?:@|\*|\$|\?|#|-|!|\{IFS\}|\{PATH\})|`|\$\(|base64\s*-d|awk|sed|sudo|cat|wget|curl|nc|bash|sh|php|perl|ruby|powershell)", re.I)
    
    sample_weights = []
    for text, label in zip(X_train, y_train):
        if label == 1 and cmd_pattern.search(str(text)):
            sample_weights.append(3.0)  # Boost Command Injection importance
        else:
            sample_weights.append(1.0)
            
    # Train model
    print(" Training Random Forest with sample weights...")
    pipeline.fit(X_train, y_train, classifier__sample_weight=sample_weights)

    # Cross-validation on training set
    print("\n Running 5-fold cross-validation...")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(
        pipeline, X_train, y_train,
        cv=cv, scoring="f1", n_jobs=-1
    )

    print(f"   CV F1 Score: {cv_scores.mean():.3f} ± {cv_scores.std():.3f}")
    
    if cv_scores.std() > 0.08:
        print("   ⚠️  High variance - model may be unstable")
    else:
        print("    Low variance - model is stable")

    # Evaluate on test set
    print("\n Test Set Evaluation:")
    y_pred = pipeline.predict(X_test)
    y_prob = pipeline.predict_proba(X_test)[:, 1]

    test_accuracy = accuracy_score(y_test, y_pred)
    test_auc = roc_auc_score(y_test, y_prob)
    
    print(f"   Accuracy: {test_accuracy*100:.2f}%")
    print(f"   ROC-AUC:  {test_auc:.4f}")
    
    # Detailed metrics
    precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='binary')
    print(f"   Precision: {precision:.3f}")
    print(f"   Recall:    {recall:.3f}")
    print(f"   F1-Score:  {f1:.3f}")
    
    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    print(f"\n   Confusion Matrix:")
    print(f"   TN: {tn:4d}  FP: {fp:4d}")
    print(f"   FN: {fn:4d}  TP: {tp:4d}")
    
    # False positive rate (important for security)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    print(f"\n   False Positive Rate: {fpr*100:.2f}%")
    if fpr > 0.05:
        print("   ⚠️  High FPR - may block legitimate requests")
    else:
        print("    Low FPR - good for production")
    
    # Overfitting check
    train_pred = pipeline.predict(X_train)
    train_accuracy = accuracy_score(y_train, train_pred)
    gap = train_accuracy - test_accuracy
    
    print(f"\n Overfitting Analysis:")
    print(f"   Train Accuracy: {train_accuracy*100:.2f}%")
    print(f"   Test Accuracy:  {test_accuracy*100:.2f}%")
    print(f"   Gap:            {gap*100:.2f}%")
    
    if gap > 0.10:
        print("   ⚠️  OVERFITTING DETECTED!")
        print("   Model memorized training data")
        print("   Recommendation: Use more diverse data or reduce model complexity")
    elif gap > 0.05:
        print("   ⚠️  Slight overfitting")
        print("   Model may not generalize well")
    else:
        print("    Good generalization")
    
    # Realistic accuracy check
    if test_accuracy > 0.95:
        print(f"\n⚠️  WARNING: Test accuracy ({test_accuracy*100:.1f}%) is suspiciously high")
        print("   This may indicate:")
        print("   - Data leakage")
        print("   - Overly simple patterns")
        print("   - Not enough diversity in data")
        print("\n   Recommendation: Test on real-world data")

    # Classification report
    print(f"\n Detailed Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['Normal', 'Attack'], digits=3))

    # Save pipeline
    DATA_DIR.mkdir(exist_ok=True)
    joblib.dump(pipeline, MODEL_PATH)
    print(f"\n Model pipeline saved to: {MODEL_PATH}")
    print(f"   Size: {MODEL_PATH.stat().st_size / 1024:.1f} KB")
    
    # Feature importance (top 20)
    print(f"\n Top 20 Important Features:")
    vectorizer = pipeline.named_steps['vectorizer']
    classifier = pipeline.named_steps['classifier']
    feature_names = vectorizer.get_feature_names_out()
    importances = classifier.feature_importances_
    
    top_indices = np.argsort(importances)[-20:][::-1]
    for i, idx in enumerate(top_indices, 1):
        print(f"   {i:2d}. {feature_names[idx]:30s} ({importances[idx]:.4f})")

    print("\n" + "="*60)
    print(" Training Complete!")
    print("="*60)
    print("\n Next steps:")
    print("   1. Test model: python -c \"from app.ml.inference import ml_analyze; print(ml_analyze('SELECT * FROM users'))\"")
    print("   2. Start dashboard: python run_dashboard.py")
    print("   3. Monitor false positives in production")
    
    return pipeline


if __name__ == "__main__":
    train_and_evaluate()
