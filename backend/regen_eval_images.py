"""
regen_eval_images.py
Regenerates ROC Curve and Confusion Matrix PNGs with:
  - Dark background matching VIREX dashboard (#0f172a)
  - 220 DPI (sharp on HiDPI screens)
  - Larger fonts and tighter layout (minimal white margins)
  - Pink ROC curve line + white dashed baseline
  - White semi-transparent grid

USAGE (from backend/ folder):
    python regen_eval_images.py

Constraints:
  - Does NOT retrain or re-evaluate the model
  - Does NOT change any metric values
  - Reads existing model artifacts to rebuild predictions
  - Only overwrites the PNG files in models/evaluation/
"""

import sys
import logging
from pathlib import Path

import numpy as np
import pandas as pd
import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mtick
import seaborn as sns
from scipy.sparse import hstack
from sklearn.metrics import (
    roc_curve, auc, confusion_matrix
)
from sklearn.preprocessing import label_binarize

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("regen_eval_images")

ROOT     = Path(__file__).parent
DATA_DIR = ROOT / "data"
MODELS   = ROOT / "models"
EVAL_DIR = MODELS / "evaluation"
EVAL_DIR.mkdir(exist_ok=True, parents=True)

# ── Dark palette matching VIREX ──────────────────────────────────────────────
BG       = "#0f172a"   # panel background
FG       = "#f1f5f9"   # text / labels
GRID_C   = "#1e3a5f"   # grid lines
PINK     = "#db2777"   # primary accent (ROC line / heatmap)
PURPLE   = "#9a277d"   # secondary accent
WHITE_DIM= "#ffffff"   # dashed baseline

DPI = 220

def _dark_fig(w=9, h=7):
    """Return a (fig, ax) with the VIREX dark background."""
    fig, ax = plt.subplots(figsize=(w, h), dpi=DPI)
    fig.patch.set_facecolor(BG)
    ax.set_facecolor(BG)
    return fig, ax

def load_artifacts():
    paths = {
        "clf": MODELS / "model_lightgbm.pkl",
        "vec": MODELS / "vectorizer_lightgbm.pkl",
        "sec": MODELS / "preprocessor_lightgbm.pkl",
        "le":  MODELS / "label_encoder_lightgbm.pkl",
        "test": DATA_DIR / "test.csv",
    }
    missing = [str(p) for p in paths.values() if not p.exists()]
    if missing:
        log.error("Missing artifacts: %s", missing)
        sys.exit(1)

    log.info("Loading artifacts…")
    clf = joblib.load(paths["clf"])
    vec = joblib.load(paths["vec"])
    sec = joblib.load(paths["sec"])
    le  = joblib.load(paths["le"])

    log.info("Loading test set…")
    test_df = pd.read_csv(paths["test"])
    test_df["payload"] = test_df["payload"].fillna("")
    X_raw = test_df["payload"].values
    y_test = le.transform(test_df["label"].values)

    log.info("Running predictions…")
    X = hstack([vec.transform(X_raw), sec.transform(X_raw)])
    y_pred  = clf.predict(X)
    y_prob  = clf.predict_proba(X)
    classes = le.classes_

    return classes, y_test, y_pred, y_prob

# ── ROC Curve ────────────────────────────────────────────────────────────────
def regen_roc(classes, y_test, y_prob):
    out = EVAL_DIR / "roc_curve.png"
    log.info("Regenerating ROC curve → %s", out)

    y_bin = label_binarize(y_test, classes=range(len(classes)))

    fig, ax = _dark_fig(9, 7)

    # Per-class curves (thin, low opacity)
    cmap = plt.cm.get_cmap("cool", len(classes))
    auc_vals = {}
    for i, cls in enumerate(classes):
        fpr, tpr, _ = roc_curve(y_bin[:, i], y_prob[:, i])
        auc_vals[cls] = auc(fpr, tpr)
        ax.plot(fpr, tpr, lw=1.2, alpha=0.55, color=cmap(i),
                label=f"{cls}  (AUC={auc_vals[cls]:.3f})")

    # Macro average curve
    from sklearn.metrics import roc_curve as _roc
    fpr_all, tpr_all = {}, {}
    for i, cls in enumerate(classes):
        fpr_all[i], tpr_all[i], _ = _roc(y_bin[:, i], y_prob[:, i])
    all_fpr = np.unique(np.concatenate([fpr_all[i] for i in range(len(classes))]))
    mean_tpr = np.zeros_like(all_fpr)
    for i in range(len(classes)):
        mean_tpr += np.interp(all_fpr, fpr_all[i], tpr_all[i])
    mean_tpr /= len(classes)
    macro_auc = auc(all_fpr, mean_tpr)
    ax.plot(all_fpr, mean_tpr, color=PINK, lw=3,
            label=f"Macro avg  (AUC={macro_auc:.4f})", zorder=5)

    # Baseline
    ax.plot([0, 1], [0, 1], color=WHITE_DIM, lw=1.2, linestyle="--",
            alpha=0.4, label="Random classifier")

    # Styling
    ax.set_xlim([-0.01, 1.01])
    ax.set_ylim([-0.01, 1.05])
    ax.set_xlabel("False Positive Rate", color=FG, fontsize=13, labelpad=8)
    ax.set_ylabel("True Positive Rate",  color=FG, fontsize=13, labelpad=8)
    ax.set_title("ROC Curve — One-vs-Rest", color=FG, fontsize=14, pad=12, fontweight="bold")
    ax.tick_params(colors=FG, labelsize=11)
    for spine in ax.spines.values():
        spine.set_edgecolor(GRID_C)
    ax.grid(True, color=GRID_C, linewidth=0.7, alpha=0.5)
    ax.xaxis.set_major_formatter(mtick.FormatStrFormatter("%.1f"))
    ax.yaxis.set_major_formatter(mtick.FormatStrFormatter("%.1f"))

    leg = ax.legend(loc="lower right", fontsize=8.5, framealpha=0.2,
                    facecolor=BG, edgecolor=GRID_C,
                    labelcolor=FG, ncol=1)

    fig.tight_layout(pad=1.0)
    fig.savefig(out, dpi=DPI, facecolor=BG, bbox_inches="tight")
    plt.close(fig)
    log.info("Saved ROC curve  (%d DPI, %.0f KB)", DPI, out.stat().st_size / 1024)
    return macro_auc

# ── Confusion Matrix ─────────────────────────────────────────────────────────
def regen_confusion(classes, y_test, y_pred):
    out_norm = EVAL_DIR / "confusion_matrix_normalized.png"
    out_raw  = EVAL_DIR / "confusion_matrix.png"

    cm_raw  = confusion_matrix(y_test, y_pred)
    cm_norm = confusion_matrix(y_test, y_pred, normalize="true")

    short_labels = [c.replace("_", "\n") for c in classes]

    # ── Normalized ──────────────────────────────────────────────
    log.info("Regenerating normalized confusion matrix → %s", out_norm)
    n = len(classes)
    fig_w = max(10, n * 1.15)
    fig_h = max(8,  n * 0.95)
    fig, ax = _dark_fig(fig_w, fig_h)

    from matplotlib.colors import LinearSegmentedColormap
    dark_pink = LinearSegmentedColormap.from_list(
        "dark_pink", [BG, PURPLE, PINK, "#f9a8d4"], N=256)

    sns.heatmap(
        cm_norm, annot=True, fmt=".2f", cmap=dark_pink,
        xticklabels=short_labels, yticklabels=short_labels,
        linewidths=0.5, linecolor=BG,
        ax=ax, annot_kws={"size": 10, "color": FG},
        cbar_kws={"shrink": 0.75, "pad": 0.02},
        vmin=0, vmax=1,
    )

    ax.set_title("Normalized Confusion Matrix", color=FG, fontsize=14,
                 pad=14, fontweight="bold")
    ax.set_xlabel("Predicted Label", color=FG, fontsize=12, labelpad=8)
    ax.set_ylabel("True Label",      color=FG, fontsize=12, labelpad=8)
    ax.tick_params(axis="both", colors=FG, labelsize=10)
    plt.setp(ax.get_xticklabels(), rotation=40, ha="right", fontsize=9.5)
    plt.setp(ax.get_yticklabels(), rotation=0,  ha="right", fontsize=9.5)

    # Style colorbar
    cbar = ax.collections[0].colorbar
    cbar.ax.tick_params(colors=FG, labelsize=9)
    cbar.outline.set_edgecolor(GRID_C)

    fig.tight_layout(pad=0.8)
    fig.savefig(out_norm, dpi=DPI, facecolor=BG, bbox_inches="tight")
    plt.close(fig)
    log.info("Saved normalized CM  (%d DPI, %.0f KB)", DPI, out_norm.stat().st_size / 1024)

    # ── Raw counts ──────────────────────────────────────────────
    log.info("Regenerating raw confusion matrix → %s", out_raw)
    fig, ax = _dark_fig(fig_w, fig_h)
    sns.heatmap(
        cm_raw, annot=True, fmt="d", cmap=dark_pink,
        xticklabels=short_labels, yticklabels=short_labels,
        linewidths=0.5, linecolor=BG,
        ax=ax, annot_kws={"size": 10, "color": FG},
        cbar_kws={"shrink": 0.75, "pad": 0.02},
    )
    ax.set_title("Confusion Matrix (Counts)", color=FG, fontsize=14,
                 pad=14, fontweight="bold")
    ax.set_xlabel("Predicted Label", color=FG, fontsize=12, labelpad=8)
    ax.set_ylabel("True Label",      color=FG, fontsize=12, labelpad=8)
    ax.tick_params(axis="both", colors=FG, labelsize=10)
    plt.setp(ax.get_xticklabels(), rotation=40, ha="right", fontsize=9.5)
    plt.setp(ax.get_yticklabels(), rotation=0,  ha="right", fontsize=9.5)
    cbar = ax.collections[0].colorbar
    cbar.ax.tick_params(colors=FG, labelsize=9)
    cbar.outline.set_edgecolor(GRID_C)
    fig.tight_layout(pad=0.8)
    fig.savefig(out_raw, dpi=DPI, facecolor=BG, bbox_inches="tight")
    plt.close(fig)
    log.info("Saved raw CM  (%d DPI, %.0f KB)", DPI, out_raw.stat().st_size / 1024)


def main():
    classes, y_test, y_pred, y_prob = load_artifacts()
    macro_auc = regen_roc(classes, y_test, y_prob)
    regen_confusion(classes, y_test, y_pred)
    log.info("Done. Macro AUC = %.4f", macro_auc)
    log.info("Images saved to: %s", EVAL_DIR)

if __name__ == "__main__":
    main()
