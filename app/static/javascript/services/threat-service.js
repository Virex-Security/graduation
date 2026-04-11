/**
 * ThreatService
 * Logic for fetching, filtering, and managing threat-related data.
 */
const ThreatService = {
    async fetchRecent() {
        const data = await API.get('/api/dashboard/data');
        return data.recent_threats || [];
    },

    async fetchHighAlerts() {
        const data = await API.get('/api/high-threats');
        return data.threats || [];
    },

    async fetchHistory(params = {}) {
        // Implementation for broader query support
        return await API.get('/api/threats/history', { params });
    },

    filterThreats(threats, criteria) {
        if (!criteria) return threats;
        return threats.filter(t => {
            const matchesSearch = !criteria.search || 
                (t.ip && t.ip.includes(criteria.search)) || 
                (t.type && t.type.toLowerCase().includes(criteria.search.toLowerCase()));
            const matchesType = !criteria.type || t.type === criteria.type;
            const matchesSeverity = !criteria.severity || t.severity === criteria.severity;
            return matchesSearch && matchesType && matchesSeverity;
        });
    }
};

/**
 * StatService
 * State management and fetching for system-wide statistics.
 */
const StatService = {
    async getGlobalStats() {
        const data = await API.get('/api/dashboard/data');
        return data.stats || {};
    },

    async reset() {
        return await API.post('/api/dashboard/reset');
    }
};

window.ThreatService = ThreatService;
window.StatService = StatService;
