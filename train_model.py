import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix, roc_auc_score
import joblib
import numpy as np
from pathlib import Path

DATA_DIR = Path("data")
MODEL_PATH = DATA_DIR / "model.pkl"
VECTORIZER_PATH = DATA_DIR / "vectorizer.pkl"


def train_and_evaluate():
    train_data = pd.read_csv(DATA_DIR / "ml_training_data.csv")

    val_path = DATA_DIR / "ml_validation_data.csv"
    has_validation = val_path.exists()

    print(f"Training samples: {len(train_data)}")
    print(f"Normal:  {(train_data['label']==0).sum()}")
    print(f"Attacks: {(train_data['label']==1).sum()}")

    X_train, X_dev, y_train, y_dev = train_test_split(
        train_data["text"],
        train_data["label"],
        test_size=0.15,
        random_state=None,
        stratify=train_data["label"],
    )

    print("\nVectorizing...")
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 3),
        max_features=8000,
        lowercase=True,
        strip_accents="unicode",
        sublinear_tf=True,
        min_df=2,
    )

    X_train_vec = vectorizer.fit_transform(X_train)
    X_dev_vec = vectorizer.transform(X_dev)

    print("Training Random Forest...")
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=25,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train_vec, y_train)

    print("\nRunning 5-fold cross-validation...")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=None)
    X_all_vec = vectorizer.transform(train_data["text"])
    cv_scores = cross_val_score(
        model, X_all_vec, train_data["label"],
        cv=cv, scoring="f1", n_jobs=-1
    )

    print(f"CV F1: {cv_scores.mean():.3f} +/- {cv_scores.std():.3f}")
    if cv_scores.std() > 0.05:
        print("WARNING: High variance detected - model may be overfitting")

    y_pred = model.predict(X_dev_vec)
    y_prob = model.predict_proba(X_dev_vec)[:, 1]

    dev_accuracy = accuracy_score(y_dev, y_pred)
    dev_auc = roc_auc_score(y_dev, y_prob)
    cm = confusion_matrix(y_dev, y_pred)

    print(f"\nDev Set Results:")
    print(f"  Accuracy: {dev_accuracy*100:.2f}%")
    print(f"  ROC-AUC:  {dev_auc:.4f}")
    print(f"\n{classification_report(y_dev, y_pred, target_names=['Normal', 'Attack'])}")

    if dev_accuracy > 0.98:
        print("WARNING: Accuracy > 98% on dev set.")
        print("   This may indicate overfitting or data leakage.")

    if has_validation:
        print("\n--- Validation Set (unseen data) ---")
        val_data = pd.read_csv(val_path)
        X_val_vec = vectorizer.transform(val_data["text"])
        y_val_pred = model.predict(X_val_vec)
        y_val_prob = model.predict_proba(X_val_vec)[:, 1]

        val_accuracy = accuracy_score(val_data["label"], y_val_pred)
        val_auc = roc_auc_score(val_data["label"], y_val_prob)

        print(f"  Accuracy: {val_accuracy*100:.2f}%")
        print(f"  ROC-AUC:  {val_auc:.4f}")
        print(f"\n{classification_report(val_data['label'], y_val_pred, target_names=['Normal', 'Attack'])}")

        gap = dev_accuracy - val_accuracy
        if gap > 0.05:
            print(f"WARNING: Generalization gap: {gap*100:.1f}%")
            print("   Model performs significantly worse on unseen data.")
    else:
        print("\nNo validation set found at data/ml_validation_data.csv")
        print("   Run: python scripts/generate_real_training_data.py")

    DATA_DIR.mkdir(exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    joblib.dump(vectorizer, VECTORIZER_PATH)
    print(f"\nModel saved to {MODEL_PATH}")
    print(f"Vectorizer saved to {VECTORIZER_PATH}")

    return model, vectorizer


if __name__ == "__main__":
    train_and_evaluate()
