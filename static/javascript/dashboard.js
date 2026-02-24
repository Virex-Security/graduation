/**
 * Dashboard Logic for CyberShield Pro
 * Handles real-time updates, charts, and UI interactions
 */

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
    const dot = el.parentElement.querySelector(".status-dot");
    if (!el || !dot) return;

    el.textContent = status;

    switch (status) {
      case "Connected":
        dot.style.backgroundColor = "var(--success)";
        break;
      case "Waiting for API":
        dot.style.backgroundColor = "var(--warning)";
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
        newTheme === "dark" ? "rgba(255,255,255,0.1)" : "rgba(0,0,0,0.1)";
      chart.options.scales.y.grid.color =
        newTheme === "dark" ? "rgba(255,255,255,0.1)" : "rgba(0,0,0,0.1)";
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
            borderColor: "#7C3AED",
            backgroundColor: "rgba(124, 58, 237, 0.1)",
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
            borderColor: "#f59e0b",
            backgroundColor: "rgba(245, 158, 11, 0.1)",
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
            grid: { color: "rgba(255,255,255,0.05)" },
            ticks: { color: "#9CA3AF" },
          },
          y: {
            grid: { color: "rgba(255,255,255,0.05)" },
            ticks: { color: "#9CA3AF" },
          },
        },
        plugins: {
          legend: { display: false },
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
              "#F59E0B",
              "#38BDF8",
              "#EF4444",
              "#22C55E",
              "#8B5CF6",
              "#1F1B2E",
            ],
            borderWidth: 0,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "bottom",
            labels: { color: "#9CA3AF", padding: 20 },
          },
        },
        cutout: "70%",
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
              this.showNotification(
                "✅ All statistics have been reset.",
                "success",
              );
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
      const response = await fetch("/api/dashboard/data");
      if (response.status === 401) {
        Auth.logout();
        return;
      }
      const data = await response.json();

      this.updateStats(data.stats);
      this.updateTimeline(data.timeline);
      this.updateDistribution(data.threat_distribution);
      this.updateRecentThreats(data.recent_threats);
      this.updateTopAttackers(data.top_attackers);

      this.updateConnectionUI(data.connection_state || "Waiting for API");

      document.getElementById("last-update").textContent =
        new Date().toLocaleTimeString();
    } catch (error) {
      console.error("Failed to fetch dashboard data:", error);
      // This is the dashboard connection, not the API connection.
      // The prompt asks for API connection status primarily.
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

        // Detect increases for notifications
        const prev = this.previousStats[id] || 0;
        if (config.val > prev && prev !== 0) {
          const alertMessages = {
            "total-requests":   null,
            "blocked-requests": `🚫 Request Blocked — total blocked: ${config.val}`,
            "ml-detections":    `🤖 ML Model Detected Anomaly — ${config.val} total ML detections`,
            "sqli-attempts":    `💉 SQL Injection Detected — ${config.val} attempts so far`,
            "xss-attempts":     `🔴 XSS Attack Detected — ${config.val} payloads caught`,
            "brute-force":      `🔑 Brute Force Detected — ${config.val} failed logins`,
            "scanner-probes":   `🔍 Scanner Probe Detected — ${config.val} suspicious paths`,
            "rate-limited":     `⚡ Rate Limit Exceeded — ${config.val} times`,
          };
          const msg = alertMessages[id];
          if (msg) this.showNotification(msg, config.type);
        }
        this.previousStats[id] = config.val;
      }
    }

    // Calculate dynamic security score (weighted formula)
    const total    = stats.total_requests   || 0;
    const blocked  = stats.blocked_requests || 0;
    const critical = (stats.sql_injection_attempts || 0)
                   + (stats.xss_attempts           || 0)
                   + (stats.brute_force_attempts    || 0);
    const ml       = stats.ml_detections    || 0;

    let score = 100;
    if (total > 0) {
      // Penalty: each blocked request costs up to 30 points total
      score -= (blocked  / total) * 30;
      // Penalty: critical attacks (SQLi, XSS, Brute) cost up to 40 points
      score -= (critical / total) * 40;
      // Penalty: ML anomalies cost up to 15 points
      score -= (ml       / total) * 15;
    }
    score = Math.max(5, Math.min(100, Math.round(score)));
    document.getElementById("security-score").textContent = `${score}/100`;
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

    if (t.includes("sql"))         return { cls: "threat-badge threat-sqli",    icon: "fa-database",       label: type };
    if (t.includes("xss"))         return { cls: "threat-badge threat-xss",     icon: "fa-code",           label: type };
    if (t.includes("brute"))       return { cls: "threat-badge threat-brute",   icon: "fa-key",            label: type };
    if (t.includes("scan"))        return { cls: "threat-badge threat-scanner", icon: "fa-eye",            label: type };
    if (t.includes("ml") ||
        t.includes("anomaly"))     return { cls: "threat-badge threat-ml",      icon: "fa-brain",          label: type };
    if (t.includes("rate"))        return { cls: "threat-badge threat-rate",    icon: "fa-bolt",           label: type };
    if (t.includes("block"))       return { cls: "threat-badge threat-blocked", icon: "fa-shield-virus",   label: type };
                                   return { cls: "threat-badge threat-unknown", icon: "fa-circle-question", label: type };
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

    tbody.innerHTML = threats
      .map((t) => {
        const isBlocked =
          t.description.toLowerCase().includes("blocked") ||
          t.severity === "High";
        const badge = this.getThreatTypeBadge(t.type);
        return `
            <tr class="${isBlocked ? "row-blocked" : ""}">
                <td>${t.timestamp}</td>
                <td>
                    <span class="${badge.cls}">
                        <i class="fas ${badge.icon}"></i> ${badge.label}
                    </span>
                </td>
                <td class="attacker-ip">${t.ip}</td>
                <td><span class="severity-badge severity-${t.severity.toLowerCase()}">${t.severity}</span></td>
                <td style="display:flex; justify-content:space-between; align-items:center">
                    <span>${t.description}</span>
                    <a href="/incidents?category=${t.type}&ip=${t.ip}" class="btn-icon" title="Manage Incident" style="color:var(--brand-primary)">
                        <i class="fas fa-arrow-up-right-from-square"></i>
                    </a>
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
                <div class="attacker-ip">${ip}</div>
                <div class="attack-count">${count} attacks</div>
            </div>
        `,
      )
      .join("");
  },

  /**
   * Show Silent Notification (Toast)
   */
  showNotification(message, type = "info") {
    const container = document.getElementById("notification-container");
    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;

    let icon = "fa-bell";
    if (type === "blocked" || type === "brute") icon = "fa-ban";
    if (type === "ml") icon = "fa-brain";
    if (type === "sqli") icon = "fa-database";
    if (type === "xss") icon = "fa-code";
    if (type === "scanner") icon = "fa-eye";
    if (type === "success") icon = "fa-check-circle";

    toast.innerHTML = `
      <i class="fas ${icon}"></i> 
      <span style="flex: 1">${message}</span>
      <button class="close-chat" title="Dismiss" style="width: 28px; height: 28px; font-size: 20px;">
        &times;
      </button>
    `;

    container.appendChild(toast);

    const closeBtn = toast.querySelector(".close-chat");
    closeBtn.addEventListener(
      "mouseover",
      () => (closeBtn.style.opacity = "1"),
    );
    closeBtn.addEventListener(
      "mouseout",
      () => (closeBtn.style.opacity = "0.6"),
    );
    closeBtn.addEventListener("click", () => {
      toast.style.animation = "slideUp 0.4s ease-in forwards";
      setTimeout(() => toast.remove(), 400);
    });


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