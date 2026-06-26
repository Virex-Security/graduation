/**
 * ml_stats.js — ML Model Performance Stats
 * Virex Security Dashboard
 *
 * يجيب البيانات من /api/ml/stats ويعرضها في الـ dashboard
 * بيشتغل تلقائي لما الصفحة تفتح
 */

const MLStats = {
  // ── State ────────────────────────────────────────────────────
  loaded: false,
  retryCount: 0,
  maxRetries: 3,

  // ── Init ─────────────────────────────────────────────────────
  init() {
    // page may use either the old IDs used by the standalone ML pages
    // or the newer "mlp-s-*" ids that appear on the dashboard summary
    if (
      !document.getElementById("ml-accuracy") &&
      !document.getElementById("mlp-s-accuracy")
    ) {
      return; // not relevant to current page
    }
    this.load();
  },

  // ── Main Load ─────────────────────────────────────────────────
  async load() {
    this._setStatus("loading");
    this._spinRefresh(true);

    try {
      const res = await fetch("/api/ml/stats", { credentials: "same-origin" });

      if (res.status === 401) {
        this._setStatus("error", "Auth required");
        return;
      }

      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }

      const data = await res.json();

      if (data.status === "error") {
        throw new Error(data.message);
      }

      this._render(data);
      this._setStatus("ok", "Model Active");
      this.loaded = true;
      this.retryCount = 0;
    } catch (err) {
      console.warn("[MLStats] Failed to load:", err.message);
      this._setStatus("error", "Load Failed");

      // Auto-retry up to 3 times (مفيد لو الـ model files بتتحمل)
      if (this.retryCount < this.maxRetries) {
        this.retryCount++;
        setTimeout(() => this.load(), 4000 * this.retryCount);
      }
    } finally {
      this._spinRefresh(false);
    }
  },

  // ── Render All ────────────────────────────────────────────────
  _render(d) {
    // KPI Cards – one set for standalone pages, another for dashboard
    const hasDashboardIds = !!document.getElementById("mlp-s-accuracy");

    if (hasDashboardIds) {
      // dashboard summary uses mlp-s-* ids and a badge instead of bars
      const setVal = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.textContent = val != null ? `${val.toFixed(1)}%` : "--%";
      };
      setVal("mlp-s-accuracy", d.accuracy);
      setVal("mlp-s-recall", d.recall);
      setVal("mlp-s-f1", d.f1_score);
      // TODO: you could also update the mini‐chart here if needed
      return;
    }

    // KPI Cards (standalone ML pages)
    this._setKPI("ml-accuracy", d.accuracy, d.accuracy);
    this._setKPI("ml-precision", d.precision, d.precision);
    this._setKPI("ml-recall", d.recall, d.recall);
    this._setKPI("ml-f1", d.f1_score, d.f1_score);
    // AUC is 0-1 scale, convert to % for bar only
    this._setKPI("ml-auc", d.roc_auc, d.roc_auc * 100, true);

    // Confusion Matrix
    const cm = d.confusion_matrix || {};
    this._setCMCell("cm-tn", cm.tn);
    this._setCMCell("cm-fp", cm.fp);
    this._setCMCell("cm-fn", cm.fn);
    this._setCMCell("cm-tp", cm.tp);

    // Feature Importance
    this._renderFeatures(d.top_features || []);

    // Model Info
    this._setText("ml-model-type", d.model_type || "--");
    this._setText("ml-vectorizer", d.vectorizer_type || "--");
    this._setText(
      "ml-dataset-size",
      d.dataset_size ? `${d.dataset_size.toLocaleString()} samples` : "--",
    );
    this._setText(
      "ml-test-size",
      d.test_size ? `${d.test_size} samples` : "--",
    );
  },

  // ── KPI Card ──────────────────────────────────────────────────
  _setKPI(id, displayValue, barPercent, isRaw = false) {
    const valEl = document.getElementById(id);
    const fillEl = document.getElementById(`${id}-fill`);

    if (!valEl) return;

    // Animate number counting up
    const target = parseFloat(displayValue) || 0;
    const display = isRaw
      ? target.toFixed(4) // AUC shown as 0.XXXX
      : `${target.toFixed(1)}%`; // others as XX.X%

    this._animateValue(valEl, display);

    // Progress bar
    if (fillEl) {
      setTimeout(() => {
        fillEl.style.width = `${Math.min(barPercent, 100)}%`;
      }, 100);
    }
  },

  // ── Confusion Matrix Cell ─────────────────────────────────────
  _setCMCell(id, value) {
    const el = document.getElementById(id);
    if (!el) return;
    const span = el.querySelector("span");
    if (span) this._animateValue(span, value ?? "--");
  },

  // ── Feature Importance List ───────────────────────────────────
  _renderFeatures(features) {
    const container = document.getElementById("ml-features-list");
    if (!container) return;

    if (!features.length) {
      container.innerHTML = `<div class="ml-loading">No feature data available</div>`;
      return;
    }

    // Max importance for relative bar widths
    const maxImp = features[0].importance || 1;

    container.innerHTML = features
      .map((f, i) => {
        const pct = ((f.importance / maxImp) * 100).toFixed(1);
        const score = f.importance.toFixed(4);
        return `
        <div class="ml-feature-item">
          <span class="ml-feature-rank">${i + 1}.</span>
          <span class="ml-feature-name" title="${f.feature}">${f.feature}</span>
          <div class="ml-feature-bar-wrap">
            <div class="ml-feature-bar-fill" style="width:0%" data-target="${pct}%"></div>
          </div>
          <span class="ml-feature-score">${score}</span>
        </div>
      `;
      })
      .join("");

    // Animate bars after render
    setTimeout(() => {
      container.querySelectorAll(".ml-feature-bar-fill").forEach((bar) => {
        bar.style.width = bar.dataset.target;
      });
    }, 120);
  },

  // ── Status Badge ─────────────────────────────────────────────
  _setStatus(state, text) {
    const badge = document.getElementById("ml-status-badge");
    const label = document.getElementById("ml-status-text");
    const dot = badge?.querySelector(".ml-status-dot");

    if (!badge || !label) return;

    badge.classList.remove("error");

    if (state === "ok") {
      label.textContent = text || "Model Active";
    } else if (state === "error") {
      badge.classList.add("error");
      label.textContent = text || "Error";
    } else {
      label.textContent = "Loading...";
    }
  },

  // ── Refresh Spinner ───────────────────────────────────────────
  _spinRefresh(on) {
    const btn = document.querySelector(".btn-ml-refresh");
    if (!btn) return;
    btn.classList.toggle("spinning", on);
    btn.disabled = on;
  },

  // ── Helpers ───────────────────────────────────────────────────
  _setText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
  },

  _animateValue(el, finalVal) {
    // Simple fade-in swap (number too short to count meaningfully)
    el.style.opacity = "0";
    el.style.transform = "translateY(4px)";
    el.style.transition = "opacity 0.4s, transform 0.4s";
    setTimeout(() => {
      el.textContent = finalVal;
      el.style.opacity = "1";
      el.style.transform = "translateY(0)";
    }, 150);
  },
};

// ── Auto-init on DOMContentLoaded ─────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  MLStats.init();
});


