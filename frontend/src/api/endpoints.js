import API from './client';

// Security & Analytics
export const getSecurityStats = () => API.get('/dashboard/stats');
export const getAttackHistory = () => API.get('/attack-history');
export const getIncidents = () => API.get('/incidents');
export const getIncident = (id) => API.get(`/incidents/${id}`);
export const updateIncident = (id, data) => API.put(`/incidents/${id}`, data);

// ML Engine
export const getMLLogs = () => API.get('/ml/detections');
export const getMLStats = () => API.get('/ml/stats');

// Traffic & Network
export const getAllRequests = () => API.get('/requests');
export const getBlacklist = () => API.get('/blacklist');
export const addBlacklist = (data) => API.post('/blacklist', data);
export const removeBlacklist = (ip) => API.delete(`/blacklist/${ip}`);

// User Management
export const getUsers = () => API.get('/users');
export const updateUser = (id, data) => API.put(`/users/${id}`, data);
export const deleteUser = (id) => API.delete(`/users/${id}`);

// Authentication
export const login = (creds) => API.post('/auth/login', creds);
export const logout = () => API.post('/auth/logout', {});
export const requestResetOtp = (identifier) => API.post('/request-reset-otp', { identifier });
export const verifyResetOtp = (data) => API.post('/verify-reset-otp', data);

// Settings & Profile
export const getProfile = () => API.get('/profile');
export const updateProfile = (data) => API.put('/profile', data);
export const getSettings = () => API.get('/settings');
export const updateSettings = (data) => API.put('/settings', data);
export const getNotifications = () => API.get('/notifications');
export const resetStats = () => API.post('/security/reset', {});
