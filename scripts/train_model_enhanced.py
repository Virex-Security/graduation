"""
Enhanced ML Training Script - Virex Security System
====================================================
يولد:
  - model.pkl + vectorizer.pkl
  - ml_evaluation_report.png  (Confusion Matrix + ROC + Feature Importance + Distribution)
"""

import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import seaborn as sns

from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import (
    classification_report, accuracy_score, confusion_matrix,
    roc_curve, auc, precision_recall_curve, average_precision_score
)
import joblib
import warnings
warnings.filterwarnings('ignore')

# ─────────────────────────────────────────────
# 1. LOAD DATA
# ─────────────────────────────────────────────
print("=" * 55)
print("  Virex ML Model Training & Evaluation")
print("=" * 55)

data = pd.read_csv("ml_training_data.csv")

print(f"\n📊 Dataset Statistics:")
print(f"   Total Samples  : {len(data)}")
print(f"   Normal (0)     : {len(data[data['label'] == 0])}")
print(f"   Attack (1)     : {len(data[data['label'] == 1])}")
print(f"   Balance Ratio  : {len(data[data['label']==0])/len(data[data['label']==1]):.2f}:1\n")

# ─────────────────────────────────────────────
# 2. SPLIT & VECTORIZE
# ─────────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    data['text'], data['label'],
    test_size=0.2, random_state=42, stratify=data['label']
)

vectorizer = TfidfVectorizer(
    ngram_range=(1, 2),
    max_features=5000,
    lowercase=True,
    strip_accents='unicode'
)

X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec  = vectorizer.transform(X_test)

# ─────────────────────────────────────────────
# 3. TRAIN MODEL
# ─────────────────────────────────────────────
print("🔧 Training Random Forest model...")
model = RandomForestClassifier(
    n_estimators=100,
    max_depth=20,
    random_state=42,
    n_jobs=-1
)
model.fit(X_train_vec, y_train)

# ─────────────────────────────────────────────
# 4. EVALUATE
# ─────────────────────────────────────────────
y_pred      = model.predict(X_test_vec)
y_prob      = model.predict_proba(X_test_vec)[:, 1]

accuracy    = accuracy_score(y_test, y_pred)
cm          = confusion_matrix(y_test, y_pred)
report      = classification_report(y_test, y_pred, target_names=['Normal', 'Attack'], output_dict=True)

fpr, tpr, _ = roc_curve(y_test, y_prob)
roc_auc     = auc(fpr, tpr)

precision_curve, recall_curve, _ = precision_recall_curve(y_test, y_prob)
ap_score    = average_precision_score(y_test, y_prob)

# Cross-validation
cv          = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
cv_scores   = cross_val_score(model, X_train_vec, y_train, cv=cv, scoring='accuracy')

print(f"\n✅ Results:")
print(f"   Accuracy         : {accuracy * 100:.2f}%")
print(f"   ROC-AUC          : {roc_auc:.4f}")
print(f"   Avg Precision    : {ap_score:.4f}")
print(f"   CV Score (5-fold): {cv_scores.mean()*100:.2f}% ± {cv_scores.std()*100:.2f}%")
print(f"\n📋 Classification Report:")
print(classification_report(y_test, y_pred, target_names=['Normal', 'Attack']))

# ─────────────────────────────────────────────
# 5. TOP FEATURES
# ─────────────────────────────────────────────
feature_names    = vectorizer.get_feature_names_out()
importances      = model.feature_importances_
top_idx          = np.argsort(importances)[::-1][:15]
top_features     = [feature_names[i] for i in top_idx]
top_importances  = [importances[i] for i in top_idx]

# ─────────────────────────────────────────────
# 6. PLOT — 2×2 DASHBOARD
# ─────────────────────────────────────────────
DARK_BG   = "#0f172a"
CARD_BG   = "#1e293b"
ACCENT    = "#00d2ff"
ACCENT2   = "#a855f7"
TEXT      = "#f8fafc"
GREEN     = "#10b981"
RED       = "#ef4444"
YELLOW    = "#f59e0b"

fig = plt.figure(figsize=(18, 14), facecolor=DARK_BG)
fig.suptitle(
    "Virex ML Security Model — Evaluation Report",
    fontsize=22, fontweight='bold', color=TEXT, y=0.98
)

gs = gridspec.GridSpec(2, 2, figure=fig, hspace=0.40, wspace=0.35,
                       left=0.07, right=0.97, top=0.93, bottom=0.07)

# ── Panel 1: Confusion Matrix ─────────────────
ax1 = fig.add_subplot(gs[0, 0])
ax1.set_facecolor(CARD_BG)

cm_norm = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
cmap    = sns.diverging_palette(240, 10, as_cmap=True)

sns.heatmap(
    cm_norm, annot=False, fmt='.2f', cmap='Blues',
    ax=ax1, linewidths=2, linecolor=DARK_BG,
    cbar_kws={'shrink': 0.8}
)

labels = [['Normal', 'Attack'], ['Normal', 'Attack']]
for i in range(2):
    for j in range(2):
        val_pct = f"{cm_norm[i,j]*100:.1f}%"
        val_abs = f"({cm[i,j]})"
        color   = TEXT if cm_norm[i,j] < 0.6 else DARK_BG
        ax1.text(j + 0.5, i + 0.42, val_pct,
                 ha='center', va='center', fontsize=16,
                 fontweight='bold', color=color)
        ax1.text(j + 0.5, i + 0.62, val_abs,
                 ha='center', va='center', fontsize=11, color=color, alpha=0.8)

ax1.set_title("Confusion Matrix", color=TEXT, fontsize=14, fontweight='bold', pad=12)
ax1.set_xlabel("Predicted Label", color=TEXT, fontsize=11)
ax1.set_ylabel("True Label",      color=TEXT, fontsize=11)
ax1.set_xticklabels(['Normal', 'Attack'], color=TEXT, fontsize=11)
ax1.set_yticklabels(['Normal', 'Attack'], color=TEXT, fontsize=11, rotation=0)
ax1.tick_params(colors=TEXT)

tn, fp, fn, tp = cm.ravel()
stats_text = f"TN={tn}  FP={fp}\nFN={fn}  TP={tp}"
ax1.text(1.35, -0.18, stats_text, transform=ax1.transAxes,
         fontsize=9, color=ACCENT, ha='center',
         bbox=dict(boxstyle='round,pad=0.3', facecolor=CARD_BG, edgecolor=ACCENT, alpha=0.8))

# ── Panel 2: ROC Curve ───────────────────────
ax2 = fig.add_subplot(gs[0, 1])
ax2.set_facecolor(CARD_BG)

ax2.plot(fpr, tpr, color=ACCENT, lw=2.5,
         label=f'ROC Curve (AUC = {roc_auc:.4f})')
ax2.fill_between(fpr, tpr, alpha=0.15, color=ACCENT)
ax2.plot([0, 1], [0, 1], color='gray', lw=1.5, linestyle='--',
         label='Random Classifier')

ax2.set_xlim([0, 1])
ax2.set_ylim([0, 1.02])
ax2.set_title("ROC Curve", color=TEXT, fontsize=14, fontweight='bold', pad=12)
ax2.set_xlabel("False Positive Rate", color=TEXT, fontsize=11)
ax2.set_ylabel("True Positive Rate",  color=TEXT, fontsize=11)
ax2.tick_params(colors=TEXT)
ax2.spines[:].set_color('#334155')
for spine in ax2.spines.values():
    spine.set_color('#334155')
legend = ax2.legend(loc='lower right', fontsize=10,
                    facecolor=DARK_BG, edgecolor=ACCENT, labelcolor=TEXT)

# Annotate AUC value on chart
ax2.annotate(f'AUC = {roc_auc:.4f}',
             xy=(0.6, 0.25), fontsize=13, color=ACCENT,
             fontweight='bold',
             bbox=dict(boxstyle='round,pad=0.4', facecolor=CARD_BG,
                       edgecolor=ACCENT, alpha=0.9))

# ── Panel 3: Feature Importance ──────────────
ax3 = fig.add_subplot(gs[1, 0])
ax3.set_facecolor(CARD_BG)

colors_feat = [ACCENT if i == 0 else ACCENT2 if i < 5 else '#475569'
               for i in range(len(top_features))]
bars = ax3.barh(range(len(top_features)), top_importances,
                color=colors_feat, edgecolor='none', height=0.7)

ax3.set_yticks(range(len(top_features)))
ax3.set_yticklabels(top_features, color=TEXT, fontsize=9)
ax3.invert_yaxis()
ax3.set_title("Top 15 Feature Importances", color=TEXT, fontsize=14,
              fontweight='bold', pad=12)
ax3.set_xlabel("Importance Score", color=TEXT, fontsize=11)
ax3.tick_params(colors=TEXT)
ax3.spines[:].set_color('#334155')

for bar, val in zip(bars, top_importances):
    ax3.text(bar.get_width() + 0.0002, bar.get_y() + bar.get_height() / 2,
             f'{val:.4f}', va='center', ha='left', color=TEXT, fontsize=8)

# ── Panel 4: Metrics Summary ─────────────────
ax4 = fig.add_subplot(gs[1, 1])
ax4.set_facecolor(CARD_BG)
ax4.axis('off')

metrics = [
    ("Accuracy",          f"{accuracy*100:.2f}%",         GREEN),
    ("ROC-AUC",           f"{roc_auc:.4f}",               ACCENT),
    ("Avg Precision",     f"{ap_score:.4f}",               ACCENT2),
    ("CV Score (5-fold)", f"{cv_scores.mean()*100:.1f}% ± {cv_scores.std()*100:.1f}%", YELLOW),
    ("Precision (Attack)",f"{report['Attack']['precision']*100:.2f}%", GREEN),
    ("Recall (Attack)",   f"{report['Attack']['recall']*100:.2f}%",    GREEN),
    ("F1-Score (Attack)", f"{report['Attack']['f1-score']*100:.2f}%",  ACCENT),
    ("Training Samples",  f"{len(X_train)}",               TEXT),
    ("Test Samples",      f"{len(X_test)}",                TEXT),
    ("Vocabulary Size",   f"{len(feature_names):,}",       TEXT),
]

ax4.set_title("Model Performance Summary", color=TEXT,
              fontsize=14, fontweight='bold', pad=12)

for idx, (name, value, color) in enumerate(metrics):
    y_pos = 0.93 - idx * 0.092
    # background row
    rect = plt.Rectangle((0, y_pos - 0.038), 1, 0.075,
                          facecolor='#0f172a', alpha=0.5,
                          transform=ax4.transAxes, clip_on=False)
    ax4.add_patch(rect)
    ax4.text(0.04, y_pos, name,  transform=ax4.transAxes,
             fontsize=11, color='#94a3b8', va='center')
    ax4.text(0.96, y_pos, value, transform=ax4.transAxes,
             fontsize=12, color=color, va='center', ha='right', fontweight='bold')

# Footer
fig.text(0.5, 0.01,
         f"Model: RandomForest (100 trees, max_depth=20)  |  "
         f"Vectorizer: TF-IDF (1-2 ngrams, 5000 features)  |  "
         f"Dataset: {len(data)} samples",
         ha='center', color='#475569', fontsize=9)

# ─────────────────────────────────────────────
# 7. SAVE
# ─────────────────────────────────────────────
output_img = "ml_evaluation_report.png"
plt.savefig(output_img, dpi=150, bbox_inches='tight',
            facecolor=DARK_BG, edgecolor='none')
plt.close()

joblib.dump(model,      "model.pkl")
joblib.dump(vectorizer, "vectorizer.pkl")

print(f"\n✅ Saved: model.pkl, vectorizer.pkl")
print(f"✅ Saved: {output_img}")
print(f"\n{'='*55}")
print(f"  Training Complete!")
print(f"{'='*55}")
