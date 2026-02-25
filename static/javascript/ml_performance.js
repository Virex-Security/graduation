/**
 * ml_performance.js — ML Model Performance Dedicated Page
 * Virex Security Dashboard
 *
 * Fetches data from /api/ml/stats and renders:
 *  - KPI cards (Accuracy, Precision, Recall, F1)
 *  - ROC-AUC hero
 *  - Confusion Matrix
 *  - Top Attack Indicators
 *  - Model Details
 */

const MLPerf = {

  // ── State ─────────────────────────────────────────────────────────
  retryCount: 0,
  maxRetries: 4,
  autoRefreshMs: 60000, // refresh every 60s
  _timer: null,

  // ── Init ──────────────────────────────────────────────────────────
  init() {
    this._updateTimestamp();
    this.load();
    // Auto-refresh
    this._timer = setInterval(() => {
      this._updateTimestamp();
      this.load();
    }, this.autoRefreshMs);
  },

  // ── Main Load ─────────────────────────────────────────────────────
  async load() {
    this._setStatus("loading");
    this._spinBtn(true);

    try {
      const res = await fetch("/api/ml/stats", { credentials: "same-origin" });

      if (res.status === 401) {
        window.location.href = "/login";
        return;
      }

      if (!res.ok) throw new Error(`HTTP ${res.status}`);

      const data = await res.json();
      if (data.status === "error") throw new Error(data.message);

      this._render(data);
      this._setStatus("ok", "ACTIVE");
      this.retryCount = 0;

    } catch (err) {
      console.warn("[MLPerf] Load failed:", err.message);
      this._setStatus("error", "LOAD FAILED");

      if (this.retryCount < this.maxRetries) {
        this.retryCount++;
        setTimeout(() => this.load(), 4000 * this.retryCount);
      }
    } finally {
      this._spinBtn(false);
    }
  },

  // ── Render All ────────────────────────────────────────────────────
  _render(d) {
    // KPI Cards
    this._setKPI("mlp-accuracy",  d.accuracy,  d.accuracy);
    this._setKPI("mlp-precision", d.precision, d.precision);
    this._setKPI("mlp-recall",    d.recall,    d.recall);
    this._setKPI("mlp-f1",        d.f1_score,  d.f1_score);

    // ROC-AUC (display as % string, bar as percent of 100)
    this._setAUC(d.roc_auc);

    // Confusion Matrix
    const cm = d.confusion_matrix || {};
    this._setCM("mlp-cm-tn", cm.tn);
    this._setCM("mlp-cm-fp", cm.fp);
    this._setCM("mlp-cm-fn", cm.fn);
    this._setCM("mlp-cm-tp", cm.tp);

    // Top Indicators
    this._renderIndicators(d.top_features || []);

    // Model Details
    this._setText("mlp-algo",    d.model_type       || "--");
    this._setText("mlp-vec",     d.vectorizer_type  || "--");
    this._setText("mlp-dataset", d.dataset_size ? `${d.dataset_size.toLocaleString()} samples` : "--");
    this._setText("mlp-test",    d.test_size    ? `${d.test_size.toLocaleString()} samples`    : "--");
  },

  // ── KPI Card ──────────────────────────────────────────────────────
  _setKPI(id, value, barPct) {
    const valEl  = document.getElementById(id);
    const fillEl = document.getElementById(`${id}-fill`);
    if (!valEl) return;

    const num = parseFloat(value) || 0;
    this._countUp(valEl, num, true); // percentage

    if (fillEl) {
      setTimeout(() => {
        fillEl.style.width = `${Math.min(barPct, 100)}%`;
      }, 120);
    }
  },

  // ── ROC-AUC ───────────────────────────────────────────────────────
  _setAUC(raw) {
    const valEl  = document.getElementById("mlp-auc");
    const fillEl = document.getElementById("mlp-auc-fill");
    if (!valEl) return;

    const pct = parseFloat(raw) * 100 || 0;
    this._countUp(valEl, pct, true); // show as %

    if (fillEl) {
      setTimeout(() => {
        fillEl.style.width = `${Math.min(pct, 100)}%`;
      }, 150);
    }
  },

  // ── Confusion Matrix Cell ─────────────────────────────────────────
  _setCM(id, value) {
    const el = document.getElementById(id);
    if (!el) return;
    this._countUpInt(el, parseInt(value) || 0);
  },

  // ── Top Indicators List ───────────────────────────────────────────
  _renderIndicators(features) {
    const container = document.getElementById("mlp-indicators-list");
    if (!container) return;

    if (!features.length) {
      container.innerHTML = `<div class="mlp-loading">No feature data available</div>`;
      return;
    }

    const maxImp = features[0].importance || 1;

    container.innerHTML = features.map((f, i) => {
      const pct   = ((f.importance / maxImp) * 100).toFixed(1);
      const score = f.importance.toFixed(3);
      return `
        <div class="mlp-indicator-item">
          <span class="mlp-ind-rank">${i + 1}.</span>
          <span class="mlp-ind-name" title="${f.feature}">${f.feature}</span>
          <div class="mlp-ind-bar-wrap">
            <div class="mlp-ind-bar-fill" style="width:0%" data-target="${pct}%"></div>
          </div>
          <span class="mlp-ind-score">${score}</span>
        </div>`;
    }).join("");

    // Animate bars after DOM update
    setTimeout(() => {
      container.querySelectorAll(".mlp-ind-bar-fill").forEach(bar => {
        bar.style.width = bar.dataset.target;
      });
    }, 150);
  },

  // ── Status Badge ──────────────────────────────────────────────────
  _setStatus(state, text) {
    const badge = document.getElementById("mlp-status-badge");
    const label = document.getElementById("mlp-status-text");
    if (!badge || !label) return;

    badge.classList.remove("error");

    if (state === "ok") {
      label.textContent = text || "ACTIVE";
    } else if (state === "error") {
      badge.classList.add("error");
      label.textContent = text || "ERROR";
    } else {
      label.textContent = "LOADING...";
    }
  },

  // ── Refresh Button Spinner ────────────────────────────────────────
  _spinBtn(on) {
    const btn  = document.getElementById("mlp-refresh-btn");
    const icon = document.getElementById("mlp-refresh-icon");
    if (!btn) return;
    btn.classList.toggle("spinning", on);
    btn.disabled = on;
    if (icon) {
      icon.classList.toggle("fa-spin", on);
    }
  },

  // ── Timestamp ─────────────────────────────────────────────────────
  _updateTimestamp() {
    const el = document.getElementById("mlp-timestamp");
    if (!el) return;
    const now = new Date();
    el.textContent = now.toLocaleTimeString("en-US", {
      hour:   "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: true
    });
  },

  // ── Helpers ───────────────────────────────────────────────────────
  _setText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
  },

  /**
   * Animate counting up to a percentage value
   * @param {HTMLElement} el
   * @param {number} target
   * @param {boolean} asPct - append % sign
   */
  _countUp(el, target, asPct = false) {
    el.style.opacity   = "0";
    el.style.transform = "translateY(6px)";
    el.style.transition = "opacity 0.35s, transform 0.35s";

    setTimeout(() => {
      const start    = 0;
      const duration = 900; // ms
      const startTs  = performance.now();

      const step = (ts) => {
        const elapsed  = ts - startTs;
        const progress = Math.min(elapsed / duration, 1);
        // ease-out cubic
        const ease     = 1 - Math.pow(1 - progress, 3);
        const current  = start + (target - start) * ease;
        el.textContent = asPct ? `${current.toFixed(1)}%` : current.toFixed(4);
        if (progress < 1) requestAnimationFrame(step);
      };

      el.style.opacity   = "1";
      el.style.transform = "translateY(0)";
      requestAnimationFrame(step);
    }, 160);
  },

  /**
   * Animate integer count-up (for confusion matrix cells)
   */
  _countUpInt(el, target) {
    el.style.opacity    = "0";
    el.style.transform  = "scale(0.85)";
    el.style.transition = "opacity 0.35s, transform 0.35s";

    setTimeout(() => {
      const duration = 800;
      const startTs  = performance.now();

      const step = (ts) => {
        const elapsed  = ts - startTs;
        const progress = Math.min(elapsed / duration, 1);
        const ease     = 1 - Math.pow(1 - progress, 3);
        const current  = Math.round(target * ease);
        el.textContent = current.toLocaleString();
        if (progress < 1) requestAnimationFrame(step);
      };

      el.style.opacity   = "1";
      el.style.transform = "scale(1)";
      requestAnimationFrame(step);
    }, 160);
  }
};

// ── Auto-init ────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  MLPerf.init();
});
