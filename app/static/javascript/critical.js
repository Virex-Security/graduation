/**
 * Critical Intelligence Controller
 * Handles high-severity threat monitoring, deep analysis, and intelligence panels.
 */

const CriticalIntel = {
    allThreats: [],
    currentSelected: null,
    refreshInterval: 10000,

    init() {
        this.bindEvents();
        this.load();
        setInterval(() => this.load(), this.refreshInterval);
    },

    async load() {
        try {
            const data = await API.get("/api/high-threats");
            this.allThreats = data.threats || [];
            
            this.updateOverview(data);
            this.renderTable(this.allThreats);
            this.updateAnalytics();
        } catch (e) {
            console.error("[CriticalIntel] Load failed:", e);
            UIUtils.renderTableEmptyState("critical-threats-body", "Error loading data", 9);
        }
    },

    bindEvents() {
        const filters = ["threatSearch", "threatTypeFilter", "timeFilter"];
        filters.forEach(id => {
            document.getElementById(id)?.addEventListener("input", () => this.handleFilter());
            document.getElementById(id)?.addEventListener("change", () => this.handleFilter());
        });
    },

    updateOverview(data) {
        const mapping = {
            "totalCritical": data.total || 0,
            "newCritical": data.new_24h || 0,
            "affectedAssets": data.affected_assets || 0
        };

        Object.entries(mapping).forEach(([id, val]) => {
            const el = document.getElementById(id);
            if (el) el.textContent = val;
        });

        // Top Threat Type
        if (this.allThreats.length > 0) {
            const types = {};
            this.allThreats.forEach(t => types[t.attack_type] = (types[t.attack_type] || 0) + 1);
            const top = Object.entries(types).sort((a,b) => b[1]-a[1])[0];
            if (top) {
                document.getElementById("topThreatType").textContent = top[0];
                document.getElementById("topThreatCount").innerHTML = `<i class="fas fa-database"></i> ${top[1]} incidents`;
            }
            
            const maxScore = Math.max(...this.allThreats.map(t => t.threat_score || 0));
            document.getElementById("highestScore").textContent = maxScore;
        }
    },

    renderTable(threats) {
        const tbody = document.getElementById("critical-threats-body");
        if (!tbody) return;

        if (threats.length === 0) {
            UIUtils.renderTableEmptyState("critical-threats-body", "No priority threats found", 9);
            return;
        }

        tbody.innerHTML = threats.map((t, idx) => {
            const isHigh = t.threat_score >= 85;
            const rowCls = isHigh ? "critical-high" : "critical-medium";
            const badge = UIUtils.getThreatBadgeHTML(t.attack_type);
            const time = UIUtils.formatRelativeTime(t.timestamp);
            
            return `
                <tr class="threat-row ${rowCls}" onclick="CriticalIntel.selectThreat(this, ${idx})">
                    <td class="font-mono text-xs">${t.threat_id}</td>
                    <td>${Formatters.escapeHTML(t.ip)}</td>
                    <td>${Formatters.escapeHTML(t.endpoint || "N/A")}</td>
                    <td>${badge}</td>
                    <td><div class="score-bar ${isHigh ? 'critical' : 'warning'}"><span>${t.threat_score}</span></div></td>
                    <td><span class="confidence high">${t.ml_confidence}%</span></td>
                    <td>${time}</td>
                    <td><span class="frequency-badge">${t.frequency}x</span></td>
                    <td>${UIUtils.getSeverityChipHTML(t.status)}</td>
                </tr>
            `;
        }).join('');
    },

    selectThreat(el, idx) {
        const threat = this.allThreats[idx];
        if (!threat) return;

        document.querySelectorAll(".threat-row").forEach(r => r.classList.remove("selected"));
        el.classList.add("selected");

        this.updateIntelligence(threat);
        this.updateTimeline(threat);
    },

    updateIntelligence(t) {
        const panel = document.getElementById("intelligencePanel");
        const risk = t.threat_score >= 90 ? "Critical" : "High";
        
        panel.innerHTML = `
            <div class="intelligence-active">
                <div class="intel-row">
                    <div class="intel-label">AI Analysis</div>
                    <div class="intel-value">
                        <div class="score-bar critical mb-2"><span>${t.threat_score}</span></div>
                        <strong>${risk} Severity</strong> Classification
                    </div>
                </div>
                <div class="intel-row">
                    <div class="intel-label">ML Confidence</div>
                    <div class="intel-value">
                        <div class="progress-bar mb-1"><div class="progress-fill" style="width: ${t.ml_confidence}%"></div></div>
                        <span>${t.ml_confidence}% certainty</span>
                    </div>
                </div>
                <div class="intel-row">
                    <div class="intel-label">Behavioral Context</div>
                    <div class="intel-value text-sm text-secondary">${this.getBehavioralContext(t.attack_type)}</div>
                </div>
                <div class="intel-row">
                    <div class="intel-label">Actions</div>
                    <div class="intel-value">
                        <button class="btn btn-primary btn-sm" onclick="CriticalIntel.showTechnical('${t.threat_id}')">View Detailed Specs</button>
                    </div>
                </div>
            </div>
        `;
    },

    getBehavioralContext(type) {
        const contexts = {
            "SQL Injection": "Attempted database schema exploration via malformed parameters.",
            "XSS": "Script injection targeting client-side execution.",
            "Brute Force": "High-frequency authentication attempts from a single origin.",
            "Anomaly": "Statistically significant deviation from typical user behavior."
        };
        return contexts[type] || "Pattern consistent with automated attack vectors.";
    },

    updateTimeline(t) {
        const container = document.getElementById("timelineContainer");
        container.innerHTML = `
            <div class="timeline-active">
                <div class="timeline-item critical-event">
                    <div class="timeline-marker"></div>
                    <div class="timeline-time">${t.timestamp}</div>
                    <div class="timeline-event">Initial Detection</div>
                    <div class="timeline-description">${t.attack_type} identified at ${t.endpoint || "edge"}</div>
                </div>
                <div class="timeline-item">
                    <div class="timeline-marker"></div>
                    <div class="timeline-time">Analysis</div>
                    <div class="timeline-event">Volume Spike</div>
                    <div class="timeline-description">Detected ${t.frequency} occurrences. Score escalated to ${t.threat_score}</div>
                </div>
            </div>
        `;
    },

    handleFilter() {
        const search = document.getElementById("threatSearch").value.toLowerCase();
        const type = document.getElementById("threatTypeFilter").value;
        
        const filtered = this.allThreats.filter(t => {
            const matchesSearch = !search || t.threat_id.toLowerCase().includes(search) || t.ip.includes(search);
            const matchesType = !type || t.attack_type === type;
            return matchesSearch && matchesType;
        });

        this.renderTable(filtered);
    },

    showTechnical(id) {
        const t = this.allThreats.find(x => x.threat_id === id);
        if (!t) return;
        
        document.getElementById("modalThreatId").textContent = t.threat_id;
        document.getElementById("payloadSample").textContent = t.payload || "N/A";
        document.getElementById("reasoning").textContent = `Detected via ${t.detection_type} with ${t.ml_confidence}% confidence.`;
        
        document.getElementById("technicalModal").classList.add("active");
        document.getElementById("modalOverlay").classList.add("active");
    },

    updateAnalytics() {
        // Simplified dynamic chart rendering
        this.renderDistributionBars();
    },

    renderDistributionBars() {
        const container = document.getElementById("severityDistribution");
        const critical = this.allThreats.filter(t => t.threat_score >= 85).length;
        const high = this.allThreats.filter(t => t.threat_score < 85).length;
        const total = this.allThreats.length || 1;

        container.innerHTML = `
            ${this.renderBar("Critical", critical, total, "critical")}
            ${this.renderBar("High", high, total, "warning")}
        `;
    },

    renderBar(label, count, total, cls) {
        const pct = Math.round((count / total) * 100);
        return `
            <div class="severity-row">
                <div class="severity-label ${cls}">${label}</div>
                <div class="severity-bar ${cls}"><div class="severity-fill" style="width:${pct}%"></div></div>
                <span class="severity-count">${count}</span>
            </div>
        `;
    }
};

window.closeTechnicalDetails = () => {
    document.getElementById("technicalModal")?.classList.remove("active");
    document.getElementById("modalOverlay")?.classList.remove("active");
};

document.addEventListener("DOMContentLoaded", () => CriticalIntel.init());
