/**
 * Dashboard Logic for CyberShield Pro
 * Handles real-time updates, charts, and UI interactions
 */

// Sanitize user data before inserting into DOM to prevent XSS
function escapeHTML(str) {
  const d = document.createElement("div");
  d.appendChild(document.createTextNode(String(str ?? "")));
  return d.innerHTML;
}

const Dashboard = {
  updateInterval: 1000,
  previousStats: {},
  charts: {},
  theme: localStorage.getItem("theme") || "dark",

  /**
   * Initialize Dashboard
   */
  init() {
    this.setupTheme();
    this.initCharts();
    this.checkAdmin();
    this.startAutoRefresh();
    this.startHealthPolling();
    this.bindEvents();
    this.updateData();

    // Listen for theme changes
    window.addEventListener("themeChanged", (event) => {
      this.onThemeChanged(event.detail.theme);
    });

    // real-time alerts from notification system
    document.addEventListener("newSecurityAlert", (evt) => {
      if (evt && evt.detail) {
        this.addThreat(evt.detail);
      }
    });
  },

  checkAdmin() {
    const user = Auth.getUser();
    if (user && user.role === "admin") {
      const resetBtn = document.getElementById("reset-btn");
      if (resetBtn) resetBtn.style.display = "block";
    }
  },

  async startHealthPolling() {
    // Backend now handles the 3-state logic
    // JS just updates the UI based on dashboard.data.state
  },

  updateConnectionUI(status) {
    const el = document.getElementById("conn-status");
    if (!el) {
      console.log(
        "[Dashboard] conn-status element not found, skipping updateConnectionUI",
      );
      return;
    }

    const dot = el.parentElement.querySelector(".status-dot");
    if (!dot) {
      console.log(
        "[Dashboard] status-dot element not found, skipping updateConnectionUI",
      );
      return;
    }

    el.textContent = status;

    switch (status) {
      case "Connected":
        dot.style.backgroundColor = "var(--success)";
        break;
      case "Disconnected":
      default:
        dot.style.backgroundColor = "var(--danger)";
        break;
    }
  },

  /**
   * Setup Theme (Dark/Light Mode)
   */
  setupTheme() {
    document.documentElement.setAttribute("data-theme", this.theme);
    const icon = document.querySelector("#theme-toggle i");
    if (icon) {
      icon.className = this.theme === "dark" ? "fas fa-sun" : "fas fa-moon";
    }
  },

  /**
   * Toggle Light/Dark Mode
   */
  toggleTheme() {
    // Use ThemeManager for consistency across all pages
    if (typeof ThemeManager !== "undefined") {
      ThemeManager.toggleTheme();
    } else {
      // Fallback for backward compatibility
      this.theme = this.theme === "dark" ? "light" : "dark";
      localStorage.setItem("theme", this.theme);
      this.setupTheme();
    }
  },

  /**
   * Handle theme change event from ThemeManager
   */
  onThemeChanged(newTheme) {
    this.theme = newTheme;

    // Re-initialize charts to match theme
    Object.values(this.charts).forEach((chart) => {
      chart.options.scales.x.grid.color =
        newTheme === "dark" ? "rgba(255,255,255,0.08)" : "rgba(0,0,0,0.06)";
      chart.options.scales.y.grid.color =
        newTheme === "dark" ? "rgba(255,255,255,0.08)" : "rgba(0,0,0,0.06)";
      chart.update();
    });
  },

  /**
   * Initialize Charts using Chart.js
   */
  initCharts() {
    const ctxTimeline = document
      .getElementById("timelineChart")
      .getContext("2d");
    const ctxDistribution = document
      .getElementById("distributionChart")
      .getContext("2d");

    // Timeline Chart
    this.charts.timeline = new Chart(ctxTimeline, {
      type: "line",
      data: {
        labels: [],
        datasets: [
          {
            label: "Total Requests",
            borderColor: "#6366f1",
            backgroundColor: "rgba(99, 102, 241, 0.1)",
            data: [],
            tension: 0.4,
            fill: true,
          },
          {
            label: "Blocked Requests",
            borderColor: "#ef4444",
            backgroundColor: "rgba(239, 68, 68, 0.1)",
            data: [],
            tension: 0.4,
            fill: true,
          },
          {
            label: "Rate Limited",
            borderColor: "#f97316",
            backgroundColor: "rgba(249, 115, 22, 0.1)",
            data: [],
            tension: 0.4,
            fill: true,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: {
            grid: { color: "rgba(255,255,255,0.08)" },
            ticks: { color: "#a1a1aa" },
          },
          y: {
            grid: { color: "rgba(255,255,255,0.08)" },
            ticks: { color: "#a1a1aa" },
          },
        },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: 'rgba(24, 24, 27, 0.9)',
            titleColor: '#fafafa',
            bodyColor: '#a1a1aa',
            borderColor: 'rgba(255,255,255,0.1)',
            borderWidth: 1,
            padding: 10,
            displayColors: true,
            usePointStyle: true,
          }
        },
      },
    });

    // Distribution Chart (Pie)
    this.charts.distribution = new Chart(ctxDistribution, {
      type: "doughnut",
      data: {
        labels: ["SQLi", "XSS", "Brute Force", "Scanner", "ML", "Rate Limit"],
        datasets: [
          {
            data: [0, 0, 0, 0, 0, 0],
            backgroundColor: [
              "#f59e0b", // Amber
              "#06b6d4", // Cyan
              "#f43f5e", // Rose
              "#10b981", // Emerald
              "#8b5cf6", // Violet
              "#f97316", // Orange
            ],
            borderWidth: 0,
            hoverOffset: 4,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "bottom",
            labels: { color: "#a1a1aa", padding: 20, usePointStyle: true },
          },
          tooltip: {
            backgroundColor: 'rgba(15, 23, 42, 0.9)',
            bodyColor: '#f1f5f9',
            borderColor: 'rgba(99, 102, 241, 0.2)',
            borderWidth: 1,
            padding: 10,
          }
        },
        cutout: "75%",
      },
    });
  },

  /**
   * Start data refresh timer
   */
  startAutoRefresh() {
    setInterval(() => this.updateData(), this.updateInterval);
  },

  /**
   * Bind UI events
   */
  bindEvents() {
    document
      .getElementById("logout-btn")
      .addEventListener("click", () => Auth.logout());
    // Theme toggle is handled by ThemeManager
    document
      .getElementById("refresh-btn")
      .addEventListener("click", () => this.updateData());

    const resetBtn = document.getElementById("reset-btn");
    if (resetBtn) {
      resetBtn.addEventListener("click", async () => {
        const confirmed = await this.showConfirmation(
          "Are you sure you want to reset all security statistics?",
          async () => {
            const resp = await fetch("/api/dashboard/reset", {
              method: "POST",
            });
            if (resp.ok) {
              this.updateData();
            }
          },
          null,
        );
      });
    }
  },

  /**
   * Show custom confirmation dialog
   */
  showConfirmation(message, onConfirm, onCancel) {
    return new Promise((resolve) => {
      // Create modal if not exists
      let modal = document.getElementById("confirmation-modal");
      if (!modal) {
        modal = document.createElement("div");
        modal.id = "confirmation-modal";
        modal.className = "confirmation-modal";
        modal.innerHTML = `
                    <div class="confirmation-modal-content">
                        <div class="confirmation-modal-title">⚠️ Confirm Action</div>
                        <div class="confirmation-modal-message" id="confirmation-message"></div>
                        <div class="confirmation-modal-buttons">
                            <button class="confirmation-modal-btn confirmation-modal-btn-cancel" id="btn-cancel">No</button>
                            <button class="confirmation-modal-btn confirmation-modal-btn-confirm" id="btn-confirm">Yes</button>
                        </div>
                    </div>
                `;
        document.body.appendChild(modal);

        document.getElementById("btn-cancel").addEventListener("click", () => {
          modal.classList.remove("active");
          if (onCancel) onCancel();
          resolve(false);
        });

        document.getElementById("btn-confirm").addEventListener("click", () => {
          modal.classList.remove("active");
          if (onConfirm) onConfirm();
          resolve(true);
        });
      }

      document.getElementById("confirmation-message").textContent = message;
      modal.classList.add("active");
    });
  },
  async updateData() {
    try {
      console.log("[Dashboard] Fetching /api/dashboard/data");
      const response = await fetch("/api/dashboard/data");
      console.log(
        "[Dashboard] Response received:",
        response.status,
        response.ok,
      );

      if (response.status === 401) {
        console.log("[Dashboard] 401 Unauthorized - logging out");
        Auth.logout();
        return;
      }

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      console.log("[Dashboard] Data received successfully");

      this.updateStats(data.stats);
      this.updateTimeline(data.timeline);
      this.updateDistribution(data.threat_distribution);
      this.updateRecentThreats(data.recent_threats);
      this.updateTopAttackers(data.top_attackers);

      const connectionState = data.connection_state || "Connected";
      const effectiveStatus =
        connectionState === "Connected" ? "Connected" : "Disconnected";
      this.updateConnectionUI(effectiveStatus);

      const sidebarState =
        connectionState === "Connected" ? "connected" : "disconnected";
      console.log("[Dashboard] Setting sidebar state to", sidebarState);
      this.updateSidebarConnectionStatus(sidebarState);

      const lastUpdateEl = document.getElementById("last-update");
      if (lastUpdateEl) {
        lastUpdateEl.textContent = new Date().toLocaleTimeString();
      }
    } catch (error) {
      console.error("[Dashboard] Failed to fetch dashboard data:", error);
      console.error("[Dashboard] Error details:", error.message);
      console.log("[Dashboard] Setting disconnected state");
      this.updateSidebarConnectionStatus("disconnected");
      this.updateConnectionUI("Disconnected");
      // clear security score since API is offline
      const scoreEl = document.getElementById("security-score");
      if (scoreEl) scoreEl.textContent = "--/100";
      // update navbar as well
      this.updateNavbarSecurityScore(undefined);
    }
  },

  /**
   * Update Sidebar Connection Status
   */
  updateSidebarConnectionStatus(status) {
    console.log("[Dashboard] Updating sidebar connection status to:", status);
    const statusElement = document.getElementById("sidebar-connection-status");

    if (!statusElement) {
      console.error("[Dashboard] sidebar-connection-status element not found!");
      return;
    }

    console.log("[Dashboard] Element found, updating classes and content");
    statusElement.classList.remove(
      "status-connecting",
      "status-connected",
      "status-disconnected",
    );

    if (status === "connected") {
      statusElement.classList.add("status-connected");
      statusElement.innerHTML =
        '<i class="fas fa-circle"></i><span>Connected</span>';
      console.log("[Dashboard] Set to CONNECTED");
    } else if (status === "disconnected") {
      statusElement.classList.add("status-disconnected");
      statusElement.innerHTML =
        '<i class="fas fa-circle"></i><span>Disconnected</span>';
      console.log("[Dashboard] Set to DISCONNECTED");
    } else if (status === "connecting") {
      statusElement.classList.add("status-connecting");
      statusElement.innerHTML =
        '<i class="fas fa-circle"></i><span>Wait for API</span>';
      console.log("[Dashboard] Set to CONNECTING");
    }
  },

  /**
   * Update KPI Cards
   */
  updateStats(stats) {
    const mappings = {
      "total-requests": { val: stats.total_requests, type: "info" },
      "blocked-requests": { val: stats.blocked_requests, type: "blocked" },
      "ml-detections": { val: stats.ml_detections, type: "ml" },
      "sqli-attempts": { val: stats.sql_injection_attempts, type: "sqli" },
      "xss-attempts": { val: stats.xss_attempts, type: "xss" },
      "brute-force": { val: stats.brute_force_attempts, type: "brute" },
      "scanner-probes": { val: stats.scanner_attempts, type: "scanner" },
      "rate-limited": { val: stats.rate_limit_hits, type: "rate" },
    };

    for (const [id, config] of Object.entries(mappings)) {
      const el = document.getElementById(id);
      if (el) {
        this.animateNumber(el, config.val);
        this.previousStats[id] = config.val;
      }
    }

    // ML Model Performance card value
    const mlPerfEl = document.getElementById("ml-model-performance");
    if (mlPerfEl && typeof stats.ml_model_performance !== "undefined") {
      mlPerfEl.textContent = `${stats.ml_model_performance.toFixed(2)}%`;
    }

    // Display security score supplied by backend (calculated using
    // the project’s official formula).
    if (typeof stats.security_score !== "undefined") {
      const val = Math.max(0, Math.min(100, stats.security_score));
      const scoreEl = document.getElementById("security-score");
      if (scoreEl) {
        scoreEl.textContent = `${val}/100`;
      }
      this.updateNavbarSecurityScore(val);
    } else {
      // backend didn't send a score (perhaps offline) – compute locally
      const total = stats.total_requests || 0;
      const blocked = stats.blocked_requests || 0;
      // approximate detected incidents as sum of all non-clean categories
      const detected =
        (stats.ml_detections || 0) +
        (stats.sql_injection_attempts || 0) +
        (stats.xss_attempts || 0) +
        (stats.brute_force_attempts || 0) +
        (stats.scanner_attempts || 0) +
        (stats.rate_limit_hits || 0);
      // ml performance not available here; use neutral 0.5
      const ml_perf = 0.5;
      const DETECT_WEIGHT = 0.5;
      const BLOCK_WEIGHT = 0.3;
      const ML_WEIGHT = 0.2;
      let fallback = 0;
      if (total > 0) {
        const detect_rate = detected / (total + 1);
        const block_rate = blocked / (total + 1);
        fallback =
          100 *
          (detect_rate * DETECT_WEIGHT +
            block_rate * BLOCK_WEIGHT +
            ml_perf * ML_WEIGHT);
        fallback = Math.round(fallback * 100) / 100;
      }
      const scoreEl = document.getElementById("security-score");
      if (scoreEl) {
        scoreEl.textContent = `${fallback}/100`;
      }
      this.updateNavbarSecurityScore(fallback);
    }
  },

  /**
   * Animate Number Transition
   */
  animateNumber(element, target) {
    const current = parseInt(element.textContent) || 0;
    if (current === target) return;

    element.textContent = target;
    element.classList.add("number-animate");
    setTimeout(() => element.classList.remove("number-animate"), 500);
  },

  /**
   * Update Timeline Chart
   */
  updateTimeline(timeline) {
    const labels = timeline.map((t) =>
      new Date(t.timestamp * 1000).toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      }),
    );
    const totals = timeline.map((t) => t.total_requests);
    const blocked = timeline.map((t) => t.blocked_requests);
    const limited = timeline.map((t) => t.rate_limit_hits || 0);

    this.charts.timeline.data.labels = labels;
    this.charts.timeline.data.datasets[0].data = totals;
    this.charts.timeline.data.datasets[1].data = blocked;
    this.charts.timeline.data.datasets[2].data = limited;
    this.charts.timeline.update("none");
  },

  /**
   * Update Threat Distribution Pie
   */
  updateDistribution(dist) {
    const values = [
      dist["SQL Injection"] || 0,
      dist["XSS"] || 0,
      dist["Brute Force"] || 0,
      dist["Scanner"] || 0,
      dist["ML Detection"] || 0,
      dist["Rate Limit"] || 0,
    ];
    this.charts.distribution.data.datasets[0].data = values;
    this.charts.distribution.update();
  },

  /**
   * Map threat type string → CSS class + icon
   */
  getThreatTypeBadge(type) {
    const t = (type || "").toLowerCase();

    if (t.includes("sql"))
      return {
        cls: "threat-badge threat-sqli",
        icon: "fa-database",
        label: type,
      };
    if (t.includes("xss"))
      return { cls: "threat-badge threat-xss", icon: "fa-code", label: type };
    if (t.includes("brute"))
      return { cls: "threat-badge threat-brute", icon: "fa-key", label: type };
    if (t.includes("scan"))
      return {
        cls: "threat-badge threat-scanner",
        icon: "fa-eye",
        label: type,
      };
    if (t.includes("ml") || t.includes("anomaly"))
      return { cls: "threat-badge threat-ml", icon: "fa-brain", label: type };
    if (t.includes("rate"))
      return { cls: "threat-badge threat-rate", icon: "fa-bolt", label: type };
    if (t.includes("block"))
      return {
        cls: "threat-badge threat-blocked",
        icon: "fa-shield-virus",
        label: type,
      };
    return {
      cls: "threat-badge threat-unknown",
      icon: "fa-circle-question",
      label: type,
    };
  },

  /**
   * Update Threat Table
   */
  updateRecentThreats(threats) {
    const tbody = document.getElementById("threats-table-body");
    if (!tbody) return;

    if (threats.length === 0) {
      tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color:var(--text-muted)">No threats detected</td></tr>`;
      return;
    }

    // display the full IP address; no masking required

    tbody.innerHTML = threats
      .map((t) => {
        const badge = this.getThreatTypeBadge(t.type);
        const rawTs = t.timestamp ?? t.time ?? t.detected_at ?? "";
        const safeTimestamp = rawTs
          ? escapeHTML(
              typeof rawTs === "number"
                ? new Date(rawTs * 1000).toLocaleString()
                : new Date(rawTs).toLocaleString(),
            )
          : "-";

        const rawPath =
          t.request_path || t.path || t.url || t.request_url || "";
        const cleanPath = rawPath ? rawPath.split("?")[0] : "-";
        const safePath = escapeHTML(cleanPath);

        const method = escapeHTML((t.method || "").toUpperCase());

        const confRaw = t.confidence ?? t.score ?? t.probability ?? null;
        const confidence =
          confRaw != null
            ? `${Math.round(Number(confRaw) * 100)}%`
            : t.conf_pct
              ? `${Number(t.conf_pct).toFixed(0)}%`
              : "—";

        const rawIp = t.ip || t.source_ip || t.src || "";
        const maskedIp = rawIp; // show full address

        const safeLabel = escapeHTML(badge.label);
        const safeSeverity = escapeHTML(t.severity || "Unknown");

        // simplified admin-friendly details: type and location only
        const getSimpleDetail = (threat) => {
          const threatType = threat.type || threat.attack_type || "Unknown";
          let endpoint =
            threat.endpoint || threat.path || threat.request_path || "";
          if (endpoint) {
            // strip querystring if present
            endpoint = endpoint.split("?")[0];
            // remove any leading slashes for cleaner display
            endpoint = endpoint.replace(/^\/+/, "");
            // drop a leading "api/" segment so details read like "XSS at data"
            endpoint = endpoint.replace(/^api\//i, "");
            return `${threatType} at ${endpoint}`;
          }
          return threatType;
        };

        const simpleDetail = getSimpleDetail(t);
        const safeCategory = encodeURIComponent(t.type ?? "");
        const safeIPParam = encodeURIComponent(rawIp ?? "");

        const isBlocked =
          t.blocked === true ||
          String(t.severity || "").toLowerCase() === "high";

        return `
            <tr class="${isBlocked ? "row-blocked" : ""}">
                <td>${safeTimestamp}</td>
                <td>
                    <span class="${badge.cls}">
                        <i class="fas ${badge.icon}"></i> ${safeLabel}
                    </span>
                </td>
                <td class="attacker-ip">${escapeHTML(maskedIp)}</td>
                <td><span class="severity-badge severity-${safeSeverity.toLowerCase()}">${safeSeverity}</span></td>
                <td style="display:flex; justify-content:space-between; align-items:center">
                    <span>${escapeHTML(simpleDetail)}</span>
                    <button onclick="viewThreatDetails('${safeCategory}', '${safeIPParam}')" class="btn-view-more" title="View More Details" style="margin-left: 8px; padding: 4px 8px; font-size: 0.8rem; background: var(--brand-primary); color: white; border: none; border-radius: 4px; cursor: pointer;">
                        View More
                    </button>
                </td>
            </tr>
        `;
      })
      .join("");
  },

  /**
   * Update Top Attackers
   */
  updateTopAttackers(attackers) {
    const container = document.getElementById("top-attackers-list");
    if (!container) return;

    if (attackers.length === 0) {
      container.innerHTML = `<p style="color:var(--text-muted); text-align:center">No attacker data available</p>`;
      return;
    }

    container.innerHTML = attackers
      .map(
        ([ip, count]) => `
            <div class="attacker-item">
                <div class="attacker-ip">${escapeHTML(ip)}</div>
                <div class="attack-count">${escapeHTML(count)} attacks</div>
            </div>
        `,
      )
      .join("");
  },

  /**
   * Add a single threat to the table, used for real‑time updates.
   * This mirrors the logic in updateRecentThreats but only handles one
   * entry and preserves existing rows.
   */
  addThreat(threat) {
    const tbody = document.getElementById("threats-table-body");
    if (!tbody) return;

    // build row html using same helpers as updateRecentThreats
    const badge = this.getThreatTypeBadge(threat.type);
    const rawTs = threat.timestamp ?? threat.time ?? threat.detected_at ?? "";
    const safeTimestamp = rawTs
      ? escapeHTML(
          typeof rawTs === "number"
            ? new Date(rawTs * 1000).toLocaleString()
            : new Date(rawTs).toLocaleString(),
        )
      : "-";

    const rawPath =
      threat.request_path ||
      threat.path ||
      threat.url ||
      threat.request_url ||
      "";
    const cleanPath = rawPath ? rawPath.split("?")[0] : "-";
    const safePath = escapeHTML(cleanPath);

    const rawIp = threat.ip || threat.source_ip || threat.src || "";
    const maskedIp = rawIp;

    const safeLabel = escapeHTML(badge.label);
    const safeSeverity = escapeHTML(threat.severity || "Unknown");

    const isBlocked =
      threat.blocked === true ||
      String(threat.severity || "").toLowerCase() === "high";

    const simpleDetail = (() => {
      const threatType = threat.type || threat.attack_type || "Unknown";
      let endpoint =
        threat.endpoint || threat.path || threat.request_path || "";
      if (endpoint) {
        endpoint = endpoint.split("?")[0];
        endpoint = endpoint.replace(/^\/+/, "");
        endpoint = endpoint.replace(/^api\//i, "");
        return `${threatType} at ${endpoint}`;
      }
      return threatType;
    })();

    const row = document.createElement("tr");
    if (isBlocked) row.classList.add("row-blocked");
    row.innerHTML = `
                <td>${safeTimestamp}</td>
                <td>
                    <span class="${badge.cls}">
                        <i class="fas ${badge.icon}"></i> ${safeLabel}
                    </span>
                </td>
                <td class="attacker-ip">${escapeHTML(maskedIp)}</td>
                <td><span class="severity-badge severity-${safeSeverity.toLowerCase()}">${safeSeverity}</span></td>
                <td style="display:flex; justify-content:space-between; align-items:center">
                    <span>${escapeHTML(simpleDetail)}</span>
                    <button onclick="viewThreatDetails('${encodeURIComponent(threat.type ?? "")}', '${encodeURIComponent(rawIp ?? "")}')" class="btn-view-more" title="View More Details" style="margin-left: 8px; padding: 4px 8px; font-size: 0.8rem; background: var(--brand-primary); color: white; border: none; border-radius: 4px; cursor: pointer;">
                        View More
                    </button>
                </td>
            `;

    // insert at top of tbody
    if (tbody.firstChild) {
      tbody.insertBefore(row, tbody.firstChild);
    } else {
      tbody.appendChild(row);
    }
  },
};

// Close Security Alerts
document.addEventListener("DOMContentLoaded", () => {
  const closeAlertsBtn = document.getElementById("close-alerts");
  if (closeAlertsBtn) {
    closeAlertsBtn.addEventListener("click", () => {
      const alertCard = closeAlertsBtn.closest(".table-card");
      if (alertCard) {
        alertCard.style.animation = "slideDown 0.4s ease-out forwards";
        setTimeout(() => alertCard.remove(), 400);
      }
    });
  }
});

// Start Dashboard
document.addEventListener("DOMContentLoaded", () => {
  // Check if on dashboard page
  if (document.getElementById("total-requests")) {
    Dashboard.init();
  }
});
/**
 * ml_summary_card.js
 * المسار: /static/javascript/ml_summary_card.js
 * ─────────────────────────────────────────────────────────────
 * يجيب بيانات الـ ML من /api/ml/stats
 * ويحدث:
 *   - قيم Accuracy / Precision / F1 في الكارت
 *   - Mini line chart بتاريخ الأداء (أو generated sparkline لو مفيش history)
 *   - Status badge
 * ─────────────────────────────────────────────────────────────
 * Response shape expected from /api/ml/stats (percent values):
 * {
 *   accuracy:  94.12,       // 0–100 scale
 *   precision: 96.34,
 *   recall:    98.01,       // new field shown on detailed page
 *   f1_score:  97.17,
 *   roc_auc:   0.9923,      // roc_auc remains 0–1
 *   model_type:   "Random Forest",
 *   vectorizer:   "TF-IDF",
 *   // optional — array of {label, accuracy} for chart history (0–100 or 0–1)
 *   history: [ {label:"Mon", accuracy:95}, ... ]
 * }
 * ─────────────────────────────────────────────────────────────
 */

(function MLSummaryCard() {
  /* ── helpers ──────────────────────────────────────────────── */
  const $ = (id) => document.getElementById(id);
  let miniChart = null;

  function pct(val) {
    // API now returns percentages (0–100) rather than 0‑1 decimals, so
    // just format directly.  we keep the helper so the badge logic stays
    // consistent with the full ML page.
    return val != null ? `${val.toFixed(2)}%` : "--%";
  }

  function setVal(id, val) {
    const el = $(id);
    if (el) el.textContent = pct(val);
  }

  /* ── build / update mini chart ──────────────────────────── */
  function buildMiniChart(history, theme) {
    const canvas = $("mlpMiniChart");
    if (!canvas) return;

    const isDark = theme !== "light";

    /* generate fake smooth sparkline if no history provided */
    let labels, values;
    if (history && history.length >= 3) {
      labels = history.map((h) => h.label ?? "");
      values = history.map((h) => h.accuracy ?? h.value ?? 0);
    } else {
      /* synthetic 10-point sparkline around the base accuracy (normalized)
        if our history has already been converted above it will be <1, else
         default to 0.94. */
      const base = history?.[0]?.accuracy ?? 0.94;
      labels = ["", "", "", "", "", "", "", "", "", ""];
      values = Array.from({ length: 10 }, (_, i) => {
        const noise = Math.sin(i * 1.3) * 0.018 + Math.cos(i * 0.7) * 0.012;
        return Math.min(1, Math.max(0.8, base + noise));
      });
    }

    const gridColor = isDark ? "rgba(255,255,255,0.05)" : "rgba(0,0,0,0.06)";
    const tickColor = isDark ? "rgba(255,255,255,0.25)" : "rgba(0,0,0,0.3)";
    const lineColor = "#a855f7";
    const areaStart = isDark
      ? "rgba(168,85,247,0.22)"
      : "rgba(168,85,247,0.12)";
    const areaEnd = "rgba(168,85,247,0)";

    const ctx = canvas.getContext("2d");

    /* gradient fill */
    const grad = ctx.createLinearGradient(0, 0, 0, 140);
    grad.addColorStop(0, areaStart);
    grad.addColorStop(1, areaEnd);

    const cfg = {
      type: "line",
      data: {
        labels,
        datasets: [
          {
            data: values,
            borderColor: lineColor,
            backgroundColor: grad,
            borderWidth: 2,
            pointRadius: 0,
            pointHoverRadius: 4,
            pointHoverBackgroundColor: lineColor,
            tension: 0.45,
            fill: true,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 900, easing: "easeInOutQuart" },
        interaction: { mode: "nearest", axis: "x", intersect: false },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: isDark ? "#1a0a2e" : "#fff",
            borderColor: lineColor,
            borderWidth: 1,
            titleColor: lineColor,
            bodyColor: isDark ? "#fff" : "#1f1b2e",
            padding: 8,
            callbacks: {
              label: (ctx) => ` ${(ctx.raw * 100).toFixed(1)}%`,
            },
          },
        },
        scales: {
          x: {
            grid: { display: false },
            ticks: { display: false },
            border: { display: false },
          },
          y: {
            min: Math.max(0, Math.min(...values) - 0.03),
            max: Math.min(1, Math.max(...values) + 0.02),
            grid: { color: gridColor },
            ticks: {
              color: tickColor,
              font: { size: 9, family: "JetBrains Mono" },
              callback: (v) => `${(v * 100).toFixed(0)}%`,
              maxTicksLimit: 4,
            },
            border: { display: false },
          },
        },
      },
    };

    if (miniChart) {
      miniChart.data.labels = labels;
      miniChart.data.datasets[0].data = values;
      miniChart.update();
    } else {
      miniChart = new Chart(ctx, cfg);
    }
  }

  /* ── update status badge ────────────────────────────────── */
  function setStatus(ok) {
    const badge = $("mlp-summary-status");
    if (!badge) return;
    const textEl = badge.querySelector("span:last-child");
    if (ok) {
      badge.classList.remove("badge-error");
      badge.classList.add("badge-online");
      if (textEl) textEl.textContent = "Active";
    } else {
      badge.classList.remove("badge-online");
      badge.classList.add("badge-error");
      if (textEl) textEl.textContent = "Offline";
    }
  }

  /* ── update model label ─────────────────────────────────── */
  function setLabel(d) {
    const el = $("mlp-model-label");
    if (!el) return;
    // hide both model and vectorizer information per user request
    el.textContent = "";
    el.style.display = "none";
  }

  /* ── fetch & render ─────────────────────────────────────── */
  async function load() {
    try {
      const res = await fetch("/api/ml/stats?t=" + Date.now());
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const d = await res.json();

      console.log(
        "[Dashboard ML Summary] API Response accuracy:",
        d.accuracy,
        "type:",
        typeof d.accuracy,
      );
      setVal("mlp-s-accuracy", d.accuracy);
      // include recall so the small dashboard summary matches the full report
      setVal("mlp-s-recall", d.recall);
      setVal("mlp-s-f1", d.f1_score);
      setLabel(d);
      setStatus(true);

      const theme =
        document.documentElement.getAttribute("data-theme") ?? "dark";

      /* build history array for chart — use history key if present,
         otherwise generate a synthetic sparkline from the single value */
      // make sure history values are normalized to 0‑1 for the sparkline
      // (older code assumed 0‑1; the API now sends 0‑100).  we'll convert
      // here so the chart logic can stay mostly unchanged.
      let history = d.history ?? [{ accuracy: d.accuracy }];
      if (
        history.length &&
        (history[0].accuracy ?? history[0].value ?? 0) > 1
      ) {
        history = history.map((h) => ({
          ...h,
          accuracy: (h.accuracy ?? h.value ?? 0) / 100,
          value: (h.value ?? h.accuracy ?? 0) / 100,
        }));
      }
      buildMiniChart(history, theme);
    } catch (err) {
      console.warn("MLSummaryCard: could not load data", err);
      setStatus(false);
      /* still draw a flat placeholder chart */
      buildMiniChart(
        null,
        document.documentElement.getAttribute("data-theme") ?? "dark",
      );
    }
  }

  /* ── re-render chart on theme switch ────────────────────── */
  window.addEventListener("themeChanged", (e) => {
    if (miniChart) {
      miniChart.destroy();
      miniChart = null;
    }
    load();
  });

  /* ── init ───────────────────────────────────────────────── */
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", load);
  } else {
    load();
  }
})();

// Global function for threat details navigation
function viewThreatDetails(category, ip) {
  // Navigate to the appropriate threat details page
  if (category && ip) {
    window.location.href = `/threats/${encodeURIComponent(category)}?ip=${encodeURIComponent(ip)}`;
  } else if (category) {
    window.location.href = `/threats/${encodeURIComponent(category)}`;
  } else {
    // Fallback to incidents page
    window.location.href = "/incidents";
  }
}

// Add updateNavbarSecurityScore method to Dashboard object
Dashboard.updateNavbarSecurityScore = function (score) {
  const scoreElement = document.getElementById("navbar-score-value");
  const scoreContainer = document.getElementById("navbar-security-score");

  if (!scoreElement || !scoreContainer) return;

  if (typeof score !== "undefined") {
    const val = Math.max(0, Math.min(100, score));
    scoreElement.textContent = Math.round(val) + "/100";

    // Remove existing classes
    scoreContainer.classList.remove("score-warning", "score-danger");

    // Add appropriate class based on score
    if (val < 40) {
      scoreContainer.classList.add("score-danger");
    } else if (val < 70) {
      scoreContainer.classList.add("score-warning");
    }
  } else {
    scoreElement.textContent = "--/100";
  }
};
