import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib

data = pd.read_csv("ml_training_data.csv")

print("إحصائيات البيانات:")
print(f"إجمالي الصفوف: {len(data)}")
print(f"الطلبات الطبيعية: {len(data[data['label'] == 0])}")
print(f"الهجمات: {len(data[data['label'] == 1])}")
print()

X_train, X_test, y_train, y_test = train_test_split(
    data['text'], 
    data['label'], 
    test_size=0.2, 
    random_state=42
)

vectorizer = TfidfVectorizer(
    ngram_range=(1, 2),
    max_features=5000,
    lowercase=True,
    strip_accents='unicode'
)

X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

model = RandomForestClassifier(
    n_estimators=100,
    max_depth=20,
    random_state=42
)

print("جاري التدريب...")
model.fit(X_train_vec, y_train)

y_pred = model.predict(X_test_vec)

accuracy = accuracy_score(y_test, y_pred)
print(f"الدقة: {accuracy * 100:.2f}%")
print()

print("تقرير التصنيف:")
print(classification_report(y_test, y_pred, target_names=['Normal', 'Attack']))

joblib.dump(model, "model.pkl")
joblib.dump(vectorizer, "vectorizer.pkl")

print("تم حفظ الموديل بنجاح!")
