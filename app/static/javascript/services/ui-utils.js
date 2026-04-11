/**
 * UIUtils Service
 * Centralizes UI logic for formatting, badges, and shared DOM helpers.
 */
const UIUtils = {
    /**
     * Get HTML for a threat badge (synchronized with uikit.html macro)
     */
    getThreatBadgeHTML(type, label = null) {
        const t = (type || "").toLowerCase();
        const displayLabel = Formatters.escapeHTML(label || type || "Unknown");
        let icon = "fa-circle-question";
        let cls = "threat-unknown";

        if (t.includes('sql')) {
            icon = "fa-database"; cls = "threat-sqli";
        } else if (t.includes('xss')) {
            icon = "fa-code"; cls = "threat-xss";
        } else if (t.includes('brute')) {
            icon = "fa-key"; cls = "threat-brute";
        } else if (t.includes('scan')) {
            icon = "fa-eye"; cls = "threat-scanner";
        } else if (t.includes('ml') || t.includes('anomaly')) {
            icon = "fa-brain"; cls = "threat-ml";
        } else if (t.includes('rate')) {
            icon = "fa-bolt"; cls = "threat-rate";
        } else if (t.includes('block')) {
            icon = "fa-shield-virus"; cls = "threat-blocked";
        }

        return `<span class="threat-badge ${cls}"><i class="fas ${icon}"></i> ${displayLabel}</span>`;
    },

    /**
     * Get HTML for a severity chip
     */
    getSeverityChipHTML(severity) {
        const s = (severity || "Unknown").toLowerCase();
        const safeLabel = Formatters.escapeHTML(severity || "Unknown");
        return `<span class="severity-badge severity-${s}">${safeLabel}</span>`;
    },

    /**
     * Format a timestamp to a relative string (e.g. "5m ago")
     */
    formatRelativeTime(timestamp) {
        if (!timestamp) return "-";
        try {
            // Handle both ISO strings and unix timestamps
            const date = typeof timestamp === 'number' ? new Date(timestamp * 1000) : new Date(timestamp.replace(" ", "T"));
            const now = new Date();
            const diffSeconds = Math.floor((now - date) / 1000);

            if (diffSeconds < 60) return `${Math.max(0, diffSeconds)}s ago`;
            if (diffSeconds < 3600) return `${Math.floor(diffSeconds / 60)}m ago`;
            if (diffSeconds < 86400) return `${Math.floor(diffSeconds / 3600)}h ago`;
            return `${Math.floor(diffSeconds / 86400)}d ago`;
        } catch (e) {
            return timestamp;
        }
    },

    /**
     * Animate a number change in an element
     */
    animateNumber(element, targetValue) {
        if (!element) return;
        const current = parseInt(element.textContent.replace(/[^0-9]/g, '')) || 0;
        if (current === targetValue) return;

        element.textContent = targetValue;
        element.classList.add("number-animate");
        setTimeout(() => element.classList.remove("number-animate"), 500);
    },

    /**
     * Render an empty state row in a table
     */
    renderTableEmptyState(tbodyId, message, colCount) {
        const tbody = document.getElementById(tbodyId);
        if (tbody) {
            tbody.innerHTML = `<tr><td colspan="${colCount}" class="text-muted text-center py-4">${Formatters.escapeHTML(message)}</td></tr>`;
        }
    }
};

window.UIUtils = UIUtils;
