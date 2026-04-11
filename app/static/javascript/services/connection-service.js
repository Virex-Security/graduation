/**
 * ConnectionService
 * Handles system health polling and global connection state.
 */
const ConnectionService = {
    intervalId: null,
    status: 'connecting',
    subscribers: [],

    init(pollingInterval = 15000) {
        this.check();
        this.intervalId = setInterval(() => this.check(), pollingInterval);
    },

    async check() {
        try {
            const data = await API.get('/api/system/health');
            const isConnected = data.status === 'ok' || data.api_online === true;
            this.updateStatus(isConnected ? 'connected' : 'disconnected', data.connection_state);
        } catch (e) {
            this.updateStatus('disconnected', 'API Offline');
        }
    },

    updateStatus(newStatus, message) {
        if (this.status === newStatus && this.lastMessage === message) return;
        
        this.status = newStatus;
        this.lastMessage = message;
        
        // Notify subscribers (Observable pattern)
        this.subscribers.forEach(callback => callback(newStatus, message));
        
        // Dispatch global event for legacy components
        window.dispatchEvent(new CustomEvent('connectionStateChanged', { 
            detail: { status: newStatus, message: message } 
        }));
    },

    subscribe(callback) {
        this.subscribers.push(callback);
        // Immediate call with current state
        callback(this.status, this.lastMessage);
    }
};

window.ConnectionService = ConnectionService;
