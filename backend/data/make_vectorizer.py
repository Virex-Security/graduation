import pandas as pd
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer

print("Loading training data...")
df = pd.read_csv("data/ml_training_data_v2.csv")
X  = df["text"].values
print(f"Samples: {len(X):,}")

vec = TfidfVectorizer(
    ngram_range=(1, 2),
    max_features=10_000,
    analyzer="char_wb",
    sublinear_tf=True
)
vec.fit(X)
print(f"Vocab size: {len(vec.vocabulary_)}")

joblib.dump(vec, "data/vectorizer_v2.pkl")
print("Done — data/vectorizer_v2.pkl saved!")