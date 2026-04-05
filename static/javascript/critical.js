// Critical Threats Dashboard - Dynamic Data Loading

let allThreats = [];
let currentSelectedThreat = null;
let refreshInterval = null;

// Event listeners
document.addEventListener("DOMContentLoaded", () => {
  setupSearchAndFilter();
  loadCriticalThreats();

  // Auto-refresh every 10 seconds
  refreshInterval = setInterval(loadCriticalThreats, 10000);
});

function loadCriticalThreats() {
  fetch("/api/critical-threats")
    .then((response) => {
      if (!response.ok) {
        if (response.status === 401) {
          window.location.href = "/login";
        }
        throw new Error("Failed to load critical threats");
      }
      return response.json();
    })
    .then((data) => {
      allThreats = data.threats || [];
      updateOverviewStats(data);
      populateThreatTable(allThreats);
      updateAnalytics();
    })
    .catch((error) => {
      console.error("Error loading threats:", error);
      showLoadingError();
    });
}

function updateOverviewStats(data) {
  document.getElementById("totalCritical").textContent = data.total || 0;
  document.getElementById("newCritical").textContent = data.new_24h || 0;
  document.getElementById("affectedAssets").textContent =
    data.affected_assets || 0;

  // Top threat type
  if (allThreats.length > 0) {
    const threatTypes = {};
    allThreats.forEach((t) => {
      const type = t.attack_type || "Unknown";
      threatTypes[type] = (threatTypes[type] || 0) + 1;
    });

    const topType = Object.entries(threatTypes).sort((a, b) => b[1] - a[1])[0];
    if (topType) {
      document.getElementById("topThreatType").textContent = topType[0];
      document.getElementById("topThreatCount").innerHTML =
        `<i class="fas fa-database"></i> ${topType[1]} incidents`;
    }

    // Highest score
    const highest = Math.max(...allThreats.map((t) => t.threat_score || 0));
    document.getElementById("highestScore").textContent = highest.toString();
  }
}

function populateThreatTable(threats) {
  const tbody = document.getElementById("threatTableBody");

  if (threats.length === 0) {
    tbody.innerHTML =
      '<tr style="text-align: center; padding: 2rem;"><td colspan="9">No critical threats found</td></tr>';
    return;
  }

  tbody.innerHTML = threats
    .map((threat, idx) => {
      const severityClass =
        threat.threat_score >= 85 ? "critical-high" : "critical-medium";
      const scoreClass = threat.threat_score >= 85 ? "critical" : "warning";
      const confidenceClass =
        threat.ml_confidence >= 80
          ? "high"
          : threat.ml_confidence >= 60
            ? "medium"
            : "low";
      const typeClass = getThreatTypeClass(threat.attack_type);

      return `
      <tr class="threat-row ${severityClass}" onclick="expandThreatDetails(this, '${threat.threat_id}', ${idx})">
        <td class="threat-id">${threat.threat_id}</td>
        <td>${threat.ip}</td>
        <td>${threat.endpoint || "N/A"}</td>
        <td><span class="threat-type ${typeClass}">${threat.attack_type || "Unknown"}</span></td>
        <td><div class="score-bar ${scoreClass}"><span>${threat.threat_score}</span></div></td>
        <td><span class="confidence ${confidenceClass}">${threat.ml_confidence}%</span></td>
        <td>${formatTime(threat.timestamp)}</td>
        <td><span class="frequency-badge">${threat.frequency}x</span></td>
        <td><span class="status ${formatStatus(threat.status).class}">${threat.status}</span></td>
      </tr>
    `;
    })
    .join("");
}

function getThreatTypeClass(type) {
  const typeMap = {
    "SQL Injection": "sql-injection",
    XSS: "xss",
    "XSS Attack": "xss",
    "Brute Force": "brute-force",
    DDoS: "ddos",
    Anomaly: "anomaly",
  };
  return typeMap[type] || "anomaly";
}

function formatTime(timestamp) {
  try {
    const threatTime = new Date(timestamp.replace(" ", "T"));
    const now = new Date();
    const diffSeconds = Math.floor((now - threatTime) / 1000);

    if (diffSeconds < 60) return `${diffSeconds}s ago`;
    if (diffSeconds < 3600) return `${Math.floor(diffSeconds / 60)}m ago`;
    if (diffSeconds < 86400) return `${Math.floor(diffSeconds / 3600)}h ago`;
    return `${Math.floor(diffSeconds / 86400)}d ago`;
  } catch {
    return timestamp;
  }
}

function formatStatus(status) {
  const statusMap = {
    Ongoing: { class: "ongoing" },
    Escalated: { class: "escalated" },
    Dormant: { class: "dormant" },
    Blocked: { class: "blocked" },
  };
  return statusMap[status] || { class: "dormant" };
}

function setupSearchAndFilter() {
  const searchInput = document.getElementById("threatSearch");
  const typeFilter = document.getElementById("threatTypeFilter");
  const timeFilter = document.getElementById("timeFilter");

  searchInput?.addEventListener("input", filterTable);
  typeFilter?.addEventListener("change", filterTable);
  timeFilter?.addEventListener("change", filterTable);
}

function filterTable() {
  const searchValue = document
    .getElementById("threatSearch")
    .value.toLowerCase();
  const typeValue = document.getElementById("threatTypeFilter").value;
  const timeValue = document.getElementById("timeFilter").value;

  const filtered = allThreats.filter((threat) => {
    const matches =
      threat.threat_id.toLowerCase().includes(searchValue) ||
      threat.ip.includes(searchValue) ||
      (threat.endpoint || "").includes(searchValue);

    const typeMatches = !typeValue || threat.attack_type === typeValue;
    const timeMatches =
      !timeValue || isWithinTimeRange(threat.timestamp, timeValue);

    return matches && typeMatches && timeMatches;
  });

  populateThreatTable(filtered);
}

function isWithinTimeRange(timestamp, timeValue) {
  try {
    const threatTime = new Date(timestamp.replace(" ", "T"));
    const now = new Date();
    const diffHours = (now - threatTime) / (1000 * 60 * 60);

    const hoursMap = { "1h": 1, "6h": 6, "24h": 24 };
    return diffHours <= hoursMap[timeValue];
  } catch {
    return true;
  }
}

function sortTable(column) {
  let sorted = [...allThreats];

  if (column === "id") {
    sorted.sort((a, b) => a.threat_id.localeCompare(b.threat_id));
  } else if (column === "score") {
    sorted.sort((a, b) => b.threat_score - a.threat_score);
  }

  populateThreatTable(sorted);
}

function expandThreatDetails(element, threatId, idx) {
  const threat = allThreats[idx];
  if (!threat) return;

  currentSelectedThreat = threat;

  // Remove previous selection
  document.querySelectorAll(".threat-row").forEach((row) => {
    row.classList.remove("selected");
  });
  element.classList.add("selected");

  // Update intelligence panel
  updateIntelligencePanel(threat);

  // Update timeline
  updateTimeline(threat);

  // Show technical details
  showTechnicalDetails(threat);
}

function updateIntelligencePanel(threat) {
  const panel = document.getElementById("intelligencePanel");

  const ipReputation =
    threat.threat_score >= 90
      ? "Malicious"
      : threat.threat_score >= 70
        ? "Suspicious"
        : "Unknown";
  const riskClassification =
    threat.threat_score >= 90
      ? "Critical"
      : threat.threat_score >= 70
        ? "High"
        : "Medium";

  panel.innerHTML = `
    <div class="intelligence-active">
      <div class="intel-row">
        <div class="intel-label">Threat Score</div>
        <div class="intel-value">
          <div style="display: flex; align-items: center; gap: 1rem;">
            <div class="score-bar critical" style="flex: 1; max-width: 200px;">
              <span>${threat.threat_score}</span>
            </div>
            <span>${threat.threat_score >= 85 ? "Critical" : "High"} Severity</span>
          </div>
        </div>
      </div>

      <div class="intel-row">
        <div class="intel-label">ML Confidence</div>
        <div class="intel-value">
          <div class="progress-bar" style="margin-bottom: 0.5rem;">
            <div class="progress-fill" style="width: ${threat.ml_confidence}%;"></div>
          </div>
          <span class="confidence-indicator">${threat.ml_confidence}% Confidence</span>
        </div>
      </div>

      <div class="intel-row">
        <div class="intel-label">Behavioral Pattern</div>
        <div class="intel-value">
          ${getBehavioralPattern(threat)}
        </div>
      </div>

      <div class="intel-row">
        <div class="intel-label">Detection Details</div>
        <div class="intel-value">
          • Attack Type: ${threat.attack_type}<br>
          • Blocked: ${threat.blocked ? "Yes" : "No"}<br>
          • Detection Method: ${threat.detection_type}<br>
          • Frequency: ${threat.frequency} occurrences
        </div>
      </div>

      <div class="intel-row">
        <div class="intel-label">IP Reputation</div>
        <div class="intel-value">
          <div style="padding: 0.5rem 0.75rem; background: rgba(220, 38, 38, 0.15); border-radius: 4px; color: var(--critical); font-weight: 600;">
            ${ipReputation}
          </div>
        </div>
      </div>

      <div class="intel-row">
        <div class="intel-label">Risk Classification</div>
        <div class="intel-value">
          <strong style="color: var(--critical); font-size: 1.1rem;">${riskClassification}</strong>
        </div>
      </div>
    </div>
  `;
}

function getBehavioralPattern(threat) {
  const patterns = {
    "SQL Injection":
      "Automated SQL query manipulation attempt. Pattern suggests parameterized query bypass.",
    "XSS Attack":
      "JavaScript payload injection targeting DOM manipulation. Potential credential theft detected.",
    "Brute Force":
      "Distributed dictionary attack. Sequential authentication attempts detected.",
    DDoS: "Volumetric attack pattern. High request frequency from single source detected.",
    Anomaly:
      "Machine learning model identified suspicious behavioral deviation from baseline.",
  };
  return (
    patterns[threat.attack_type] || "Suspicious behavioral pattern detected"
  );
}

function updateTimeline(threat) {
  const container = document.getElementById("timelineContainer");

  const timelineHtml = `
    <div class="timeline-active">
      <div class="timeline-item critical-event">
        <div class="timeline-marker"></div>
        <div class="timeline-time">${threat.timestamp}</div>
        <div class="timeline-event">Initial Detection</div>
        <div class="timeline-description">${threat.attack_type} attack detected on ${threat.endpoint || "unknown endpoint"}</div>
      </div>
      <div class="timeline-item ${threat.frequency > 3 ? "critical-event" : ""}">
        <div class="timeline-marker"></div>
        <div class="timeline-time">Threat Analysis</div>
        <div class="timeline-event">Escalation Analysis</div>
        <div class="timeline-description">Detected ${threat.frequency} occurrences with threat score of ${threat.threat_score}</div>
      </div>
      <div class="timeline-item">
        <div class="timeline-marker"></div>
        <div class="timeline-time">Current</div>
        <div class="timeline-event">Status: ${threat.status}</div>
        <div class="timeline-description">ML Confidence: ${threat.ml_confidence}% - Detection Method: ${threat.detection_type}</div>
      </div>
    </div>
  `;

  container.innerHTML = timelineHtml;
}

function showTechnicalDetails(threat) {
  const modal = document.getElementById("technicalModal");
  const overlay = document.getElementById("modalOverlay");

  document.getElementById("modalThreatId").textContent = threat.threat_id;
  document.getElementById("payloadSample").textContent =
    threat.payload || threat.snippet || "Payload data not available";
  document.getElementById("requestHeaders").textContent =
    `Method: ${threat.method || "POST"}\nEndpoint: ${threat.endpoint}\nAttack Type: ${threat.attack_type}`;
  document.getElementById("targetEndpoint").textContent =
    threat.endpoint || "N/A";
  document.getElementById("signature").textContent =
    `Attack Signature: ${threat.attack_type}\nSeverity: ${threat.severity}\nBlocked: ${threat.blocked ? "Yes" : "No"}`;
  document.getElementById("reasoning").textContent =
    `The ML model detected this threat with ${threat.ml_confidence}% confidence. ${getBehavioralPattern(threat)} This threat has been encountered ${threat.frequency} times.`;

  const featureHTML = `
    <div class="feature-list">
      <div class="feature-item">
        <span class="feature-name">Threat Score</span>
        <span class="feature-weight">${threat.threat_score}</span>
      </div>
      <div class="feature-item">
        <span class="feature-name">ML Confidence</span>
        <span class="feature-weight">${threat.ml_confidence}%</span>
      </div>
      <div class="feature-item">
        <span class="feature-name">Frequency</span>
        <span class="feature-weight">${threat.frequency}x</span>
      </div>
      <div class="feature-item">
        <span class="feature-name">Detection Type</span>
        <span class="feature-weight">${threat.detection_type}</span>
      </div>
    </div>
  `;

  document.getElementById("featureWeights").innerHTML = featureHTML;

  modal.classList.add("active");
  overlay.classList.add("active");
}

function closeTechnicalDetails() {
  const modal = document.getElementById("technicalModal");
  const overlay = document.getElementById("modalOverlay");

  modal.classList.remove("active");
  overlay.classList.remove("active");
}

function refreshCriticalThreats() {
  const btn = document.getElementById("refreshBtn");
  btn.style.animation = "spin 1s linear";

  loadCriticalThreats();
  setTimeout(() => {
    btn.style.animation = "";
  }, 1000);
}

function updateAnalytics() {
  // Generate all analytics charts dynamically
  generateThreatTypesChart();
  generateSeverityDistribution();
  generateFrequencySpikeChart();
  generateMonitoringIndicators();
}

function generateThreatTypesChart() {
  const threatTypes = {};
  allThreats.forEach((t) => {
    const type = t.attack_type || "Unknown";
    threatTypes[type] = (threatTypes[type] || 0) + 1;
  });

  if (Object.keys(threatTypes).length === 0) {
    document.getElementById("threatTypesChart").innerHTML =
      "<p style='text-align: center; padding: 2rem; color: #9CA3AF;'>No threat data available</p>";
    return;
  }

  const chartContainer = document.getElementById("threatTypesChart");
  const entries = Object.entries(threatTypes).sort((a, b) => b[1] - a[1]);
  const maxCount = Math.max(...entries.map((e) => e[1]));

  // Define colors for threat types
  const typeColors = {
    "SQL Injection": "#DC2626",
    XSS: "#F59E0B",
    "Brute Force": "#DC2626",
    Anomaly: "#3B82F6",
    DDoS: "#10B981",
  };

  const barWidth = 30;
  const barSpacing = 40;
  const maxHeight = 90;
  const padding = 20;
  const chartWidth = padding + entries.length * barSpacing + padding;
  const chartHeight = 150;

  let svg = `<svg class="chart-bar" viewBox="0 0 ${chartWidth} ${chartHeight}" preserveAspectRatio="xMidYMid meet">`;

  entries.forEach((entry, idx) => {
    const [type, count] = entry;
    const barHeight = (count / maxCount) * maxHeight;
    const x = padding + idx * barSpacing;
    const y = 130 - barHeight;
    const color = typeColors[type] || "#8B5CF6";

    svg += `
      <rect
        x="${x}"
        y="${y}"
        width="${barWidth}"
        height="${barHeight}"
        fill="${color}"
        opacity="0.8"
      />
      <text
        x="${x + barWidth / 2}"
        y="145"
        text-anchor="middle"
        font-size="12"
        fill="var(--text-primary)"
      >${type.substring(0, 3)}</text>
      <text
        x="${x + barWidth / 2}"
        y="${y - 5}"
        text-anchor="middle"
        font-size="11"
        fill="var(--text-primary)"
      >${count}</text>
    `;
  });

  svg += `</svg>`;
  chartContainer.innerHTML = svg;
}

function generateSeverityDistribution() {
  const severityContainer = document.getElementById("severityDistribution");

  // Count threats by severity (score ranges)
  const criticalCount = allThreats.filter((t) => t.threat_score >= 85).length;
  const highCount = allThreats.filter(
    (t) => t.threat_score >= 70 && t.threat_score < 85,
  ).length;
  const mediumCount = allThreats.filter((t) => t.threat_score < 70).length;
  const total = allThreats.length || 1;

  const criticalPct = Math.round((criticalCount / total) * 100);
  const highPct = Math.round((highCount / total) * 100);
  const mediumPct = Math.round((mediumCount / total) * 100);

  const html = `
    <div class="severity-row">
      <div class="severity-label critical">Critical</div>
      <div class="severity-bar critical">
        <div class="severity-fill" style="width: ${criticalPct}%"></div>
      </div>
      <span class="severity-count">${criticalCount}</span>
    </div>
    <div class="severity-row">
      <div class="severity-label warning">High</div>
      <div class="severity-bar warning">
        <div class="severity-fill" style="width: ${highPct}%"></div>
      </div>
      <span class="severity-count">${highCount}</span>
    </div>
    <div class="severity-row">
      <div class="severity-label info">Medium</div>
      <div class="severity-bar info">
        <div class="severity-fill" style="width: ${mediumPct}%"></div>
      </div>
      <span class="severity-count">${mediumCount}</span>
    </div>
  `;

  severityContainer.innerHTML = html;
}

function generateFrequencySpikeChart() {
  const chartContainer = document.getElementById("frequencySpikeChart");

  if (allThreats.length === 0) {
    chartContainer.innerHTML =
      "<p style='text-align: center; padding: 2rem; color: #9CA3AF;'>No threat data available</p>";
    return;
  }

  // Group threats by hour (last 24 hours)
  const now = new Date();
  const hourCounts = {};

  // Initialize 24 hours with 0
  for (let i = 0; i < 24; i++) {
    const hour = new Date(now.getTime() - i * 60 * 60 * 1000);
    const key = hour.toISOString().substring(0, 13);
    hourCounts[key] = 0;
  }

  // Count threats by hour
  allThreats.forEach((threat) => {
    const timestamp = new Date(threat.timestamp);
    const key = timestamp.toISOString().substring(0, 13);
    if (hourCounts[key] !== undefined) {
      hourCounts[key]++;
    }
  });

  const hours = Object.keys(hourCounts).reverse();
  const counts = hours.map((h) => hourCounts[h]);
  const maxCount = Math.max(...counts, 1);

  // Generate polyline points
  const pointSpacing = 280 / (hours.length - 1 || 1);
  let points = "";

  counts.forEach((count, idx) => {
    const x = 10 + idx * pointSpacing;
    const y = 85 - (count / maxCount) * 70;
    points += `${x},${y} `;
  });

  const svg = `
    <svg class="chart-line" viewBox="0 0 300 100" preserveAspectRatio="xMidYMid meet">
      <polyline
        points="${points}"
        fill="none"
        stroke="#DC2626"
        stroke-width="2"
        stroke-linecap="round"
        stroke-linejoin="round"
      />
      <circle cx="${10}" cy="${85 - (counts[0] / maxCount) * 70}" r="3" fill="#DC2626" />
      <circle cx="${10 + (counts.length - 1) * pointSpacing}" cy="${85 - (counts[counts.length - 1] / maxCount) * 70}" r="3" fill="#DC2626" />
    </svg>
  `;

  chartContainer.innerHTML = svg;
}

function generateMonitoringIndicators() {
  // 1. Anomaly Level - percentage of high-confidence threats
  const highConfidenceThreats = allThreats.filter(
    (t) => t.ml_confidence >= 80,
  ).length;
  const anomalyLevel =
    allThreats.length > 0
      ? Math.round((highConfidenceThreats / allThreats.length) * 100)
      : 0;
  const anomalyText =
    anomalyLevel > 70
      ? "High Risk"
      : anomalyLevel > 40
        ? "Medium Risk"
        : "Low Risk";
  const anomalyClass =
    anomalyLevel > 70 ? "critical" : anomalyLevel > 40 ? "warning" : "info";

  const anomalyHTML = `
    <div class="indicator-gauge">
      <div class="gauge-bar ${anomalyClass}">
        <span>${anomalyText}</span>
        <div class="gauge-level" style="width: ${anomalyLevel}%"></div>
      </div>
    </div>
    <div class="indicator-subtitle">${anomalyLevel}% Above Baseline</div>
  `;

  document.getElementById("anomalyIndicator").innerHTML = anomalyHTML;

  // 2. Threat Trend - compare last 2 hours vs previous 2 hours
  const now = new Date();
  const twoHoursAgo = new Date(now.getTime() - 2 * 60 * 60 * 1000);
  const fourHoursAgo = new Date(now.getTime() - 4 * 60 * 60 * 1000);

  const recentThreats = allThreats.filter(
    (t) => new Date(t.timestamp) >= twoHoursAgo,
  ).length;
  const olderThreats = allThreats.filter((t) => {
    const threatTime = new Date(t.timestamp);
    return threatTime >= fourHoursAgo && threatTime < twoHoursAgo;
  }).length;

  const trend =
    recentThreats > olderThreats
      ? "Rising"
      : recentThreats < olderThreats
        ? "Falling"
        : "Stable";
  const trendClass =
    trend === "Rising" ? "rising" : trend === "Falling" ? "falling" : "stable";
  const trendIcon =
    trend === "Rising"
      ? "fa-arrow-up"
      : trend === "Falling"
        ? "fa-arrow-down"
        : "fa-equals";
  const threatChange = recentThreats - olderThreats;
  const threatChangeText =
    threatChange > 0 ? `+${threatChange}` : `${threatChange}`;

  const trendHTML = `
    <div class="trend-indicator ${trendClass}">
      <i class="fas ${trendIcon}"></i>
      <span>${trend}</span>
    </div>
    <div class="indicator-subtitle">${threatChangeText} threats in last 2 hours</div>
  `;

  document.getElementById("trendIndicator").innerHTML = trendHTML;

  // 3. System Risk Level - based on highest threat score
  const maxScore =
    allThreats.length > 0
      ? Math.max(...allThreats.map((t) => t.threat_score))
      : 0;
  let riskLevel = "LOW";
  let riskClass = "success";
  let actionText = "No immediate action required";

  if (maxScore >= 90) {
    riskLevel = "CRITICAL";
    riskClass = "critical";
    actionText = "IMMEDIATE ATTENTION REQUIRED";
  } else if (maxScore >= 75) {
    riskLevel = "HIGH";
    riskClass = "warning";
    actionText = "Urgent investigation needed";
  } else if (maxScore >= 60) {
    riskLevel = "MEDIUM";
    riskClass = "info";
    actionText = "Standard investigation recommended";
  }

  const riskHTML = `
    <div class="risk-level ${riskClass}">
      <span>${riskLevel}</span>
    </div>
    <div class="indicator-subtitle">${actionText}</div>
  `;

  document.getElementById("riskLevelIndicator").innerHTML = riskHTML;
}

function showLoadingError() {
  const tbody = document.getElementById("threatTableBody");
  tbody.innerHTML =
    '<tr style="text-align: center; padding: 2rem;"><td colspan="9">Error loading threats. Please try again.</td></tr>';
}