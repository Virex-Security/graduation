/**
 * Dashboard Controller
 * Handles metric updates, chart rendering, and real-time security alerts.
 */

const Dashboard = {
    updateInterval: 2000,
    charts: {},
    apiEnabled: true,

    init() {
        this.apiEnabled = window.DASHBOARD_CONFIG?.apiEnabled !== false;
        
        this.initCharts();
        this.bindEvents();
        this.initSubscriptions();

        if (this.apiEnabled) {
            this.refresh();
            setInterval(() => this.refresh(), this.updateInterval);
        } else {
            document.getElementById("last-update").textContent = "API Disabled";
        }

        // Handle Theme Changes
        window.addEventListener("themeChanged", (e) => this.updateChartThemes(e.detail.theme));
    },

    /**
     * Initial data load and polling refresh
     */
    async refresh() {
        try {
            const data = await API.get("/api/dashboard/data");
            
            this.updateStats(data.stats);
            this.updateCharts(data);
            this.updateTable(data.recent_threats);
            this.updateThreatRankings(data.top_attackers);

            document.getElementById("last-update").textContent = new Date().toLocaleTimeString();
        } catch (e) {
            console.error("[Dashboard] Refresh failed:", e);
        }
    },

    initSubscriptions() {
        // Connection status is now handled globally, but we can listen for score updates
        window.addEventListener("newSecurityAlert", (e) => {
            if (e.detail) this.appendAlertToTable(e.detail);
        });
    },

    bindEvents() {
        document.getElementById("refresh-btn")?.addEventListener("click", (e) => {
            const btn = e.currentTarget;
            btn.classList.add("spinning");
            this.refresh().finally(() => btn.classList.remove("spinning"));
        });

        // Reset functionality using StatService
        document.getElementById("reset-btn")?.addEventListener("click", async () => {
            if (confirm("Are you sure you want to reset all security statistics?")) {
                await StatService.reset();
                this.refresh();
            }
        });
    },

    /**
     * Update KPI Stat Cards
     */
    updateStats(stats) {
        UIUtils.animateNumber(document.getElementById("total-requests"), stats.total_requests);
        UIUtils.animateNumber(document.getElementById("blocked-requests"), stats.blocked_requests);
        UIUtils.animateNumber(document.getElementById("ml-detections"), stats.ml_detections);

        // Update Top Attack Card
        this.updateTopAttackCard(stats);

        // Update Security Score
        if (stats.security_score !== undefined) {
            const score = Math.round(stats.security_score);
            const scoreEl = document.getElementById("security-score");
            if (scoreEl) scoreEl.textContent = `${score}/100`;
            
            // Sync with navbar score
            const navScore = document.getElementById("navbar-score-value");
            if (navScore) navScore.textContent = `${score}/100`;
        }
    },

    updateTopAttackCard(stats) {
        const attacks = [
            { label: "SQL Injection", val: stats.sql_injection_attempts, icon: "fa-database", color: "#f59e0b" },
            { label: "XSS Attacks", val: stats.xss_attempts, icon: "fa-code", color: "#38bdf8" },
            { label: "Brute Force", val: stats.brute_force_attempts, icon: "fa-key", color: "#f87171" },
            { label: "Scanners", val: stats.scanner_attempts, icon: "fa-eye", color: "#22c55e" }
        ];

        const top = attacks.reduce((p, c) => (p.val > c.val) ? p : c);
        const valEl = document.getElementById("top-attack-value");
        const cardEl = document.getElementById("top-attack-card");

        if (valEl && cardEl) {
            if (top.val > 0) {
                valEl.textContent = top.label.toUpperCase();
                cardEl.style.setProperty("--card-accent", top.color);
                const icon = cardEl.querySelector(".stat-header i");
                if (icon) icon.className = `fas ${top.icon}`;
            } else {
                valEl.textContent = "No Attacks";
                cardEl.style.setProperty("--card-accent", "var(--brand-primary)");
            }
        }
    },

    /**
     * Update Alert Table
     */
    updateTable(threats) {
        const tbody = document.getElementById("threats-body");
        if (!tbody) return;

        if (!threats || threats.length === 0) {
            UIUtils.renderTableEmptyState("threats-body", "No threats detected", 5);
            return;
        }

        tbody.innerHTML = threats.map(t => this.renderThreatRow(t)).join('');
    },

    appendAlertToTable(threat) {
        const tbody = document.getElementById("threats-body");
        if (!tbody) return;
        
        // Remove empty state if present
        if (tbody.querySelector(".text-muted")) tbody.innerHTML = "";

        const row = document.createElement("tr");
        row.innerHTML = this.renderThreatRow(threat);
        tbody.prepend(row);
        
        // Keep only top 10
        if (tbody.rows.length > 10) tbody.deleteRow(10);
    },

    renderThreatRow(t) {
        const timestamp = UIUtils.formatRelativeTime(t.timestamp || t.detected_at);
        const badge = UIUtils.getThreatBadgeHTML(t.type);
        const severity = UIUtils.getSeverityChipHTML(t.severity || "Low");
        const ip = Formatters.escapeHTML(t.ip || "Unknown");
        const details = Formatters.escapeHTML(t.details || `${t.type} detected`);

        return `
            <td>${timestamp}</td>
            <td>${badge}</td>
            <td class="font-mono">${ip}</td>
            <td>${severity}</td>
            <td class="table-actions">
                <span class="text-sm truncate" title="${details}">${details}</span>
                <button onclick="location.href='/incident/${t.id}'" class="btn-text">View</button>
            </td>
        `;
    },

    updateThreatRankings(attackers) {
        const container = document.getElementById("top-attackers-list");
        if (!container) return;

        container.innerHTML = attackers.slice(0, 5).map(([ip, count]) => `
            <div class="attacker-item">
                <span class="attacker-ip">${Formatters.escapeHTML(ip)}</span>
                <span class="attack-count badge">${count} sessions</span>
            </div>
        `).join('');
    },

    /**
     * Chart Management
     */
    initCharts() {
        const ctxTimeline = document.getElementById("timelineChart")?.getContext("2d");
        const ctxDist = document.getElementById("distributionChart")?.getContext("2d");

        if (ctxTimeline) {
            this.charts.timeline = new Chart(ctxTimeline, {
                type: 'line',
                data: { labels: [], datasets: [
                    { label: 'Requests', borderColor: '#7c3aed', backgroundColor: 'rgba(124, 58, 237, 0.1)', data: [], fill: true, tension: 0.4 },
                    { label: 'Blocked', borderColor: '#ef4444', backgroundColor: 'rgba(239, 68, 68, 0.1)', data: [], fill: true, tension: 0.4 }
                ]},
                options: this.getChartOptions()
            });
        }

        if (ctxDist) {
            this.charts.distribution = new Chart(ctxDist, {
                type: 'doughnut',
                data: { labels: ['SQLi', 'XSS', 'Brute', 'Scanner', 'ML'], datasets: [{ data: [0,0,0,0,0], backgroundColor: ['#f59e0b', '#38bdf8', '#f87171', '#22c55e', '#a78bfa'] }]},
                options: { ...this.getChartOptions(), cutout: '70%', plugins: { legend: { position: 'bottom' }}}
            });
        }
    },

    updateCharts(data) {
        if (this.charts.timeline && data.timeline) {
            this.charts.timeline.data.labels = data.timeline.map(t => new Date(t.timestamp * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
            this.charts.timeline.data.datasets[0].data = data.timeline.map(t => t.total_requests);
            this.charts.timeline.data.datasets[1].data = data.timeline.map(t => t.blocked_requests);
            this.charts.timeline.update('none');
        }

        if (this.charts.distribution && data.threat_distribution) {
            const dist = data.threat_distribution;
            this.charts.distribution.data.datasets[0].data = [
                dist['SQL Injection'] || 0, dist['XSS'] || 0, dist['Brute Force'] || 0, dist['Scanner'] || 0, dist['ML Detection'] || 0
            ];
            this.charts.distribution.update();
        }
    },

    getChartOptions() {
        const isDark = document.documentElement.getAttribute("data-theme") === "dark";
        const gridColor = isDark ? "rgba(255,255,255,0.05)" : "rgba(0,0,0,0.05)";
        return {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: { grid: { color: gridColor }, ticks: { color: '#9CA3AF' }},
                y: { grid: { color: gridColor }, ticks: { color: '#9CA3AF' }}
            },
            plugins: { legend: { display: false }}
        };
    },

    updateChartThemes(theme) {
        const isDark = theme === "dark";
        const gridColor = isDark ? "rgba(255,255,255,0.05)" : "rgba(0,0,0,0.05)";
        Object.values(this.charts).forEach(chart => {
            if (chart.options.scales) {
                chart.options.scales.x.grid.color = gridColor;
                chart.options.scales.y.grid.color = gridColor;
            }
            chart.update();
        });
    }
};

document.addEventListener("DOMContentLoaded", () => Dashboard.init());
