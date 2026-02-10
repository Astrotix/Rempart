// API client for ZTNA Sovereign Control Plane
const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8080';

const getHeaders = () => {
  const token = localStorage.getItem('ztna_token');
  return {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
};

const handleResponse = async (res) => {
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(body.error || `Erreur HTTP ${res.status}`);
  }
  return body;
};

const api = {
  // Auth
  checkSetup: () =>
    fetch(`${API_BASE}/api/auth/check`).then(handleResponse),

  setup: (email, name, password) =>
    fetch(`${API_BASE}/api/auth/setup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, name, password }),
    }).then(handleResponse),

  login: (email, password) =>
    fetch(`${API_BASE}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    }).then(handleResponse),

  // Health
  health: () =>
    fetch(`${API_BASE}/api/health`).then(handleResponse),

  // Stats
  getStats: () =>
    fetch(`${API_BASE}/api/stats`, { headers: getHeaders() }).then(handleResponse),

  // Users
  listUsers: () =>
    fetch(`${API_BASE}/api/users`, { headers: getHeaders() }).then(handleResponse),

  createUser: (user) =>
    fetch(`${API_BASE}/api/users`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(user),
    }).then(handleResponse),

  deleteUser: (id) =>
    fetch(`${API_BASE}/api/users/${id}`, {
      method: 'DELETE',
      headers: getHeaders(),
    }).then(handleResponse),

  // PoPs
  listPoPs: () =>
    fetch(`${API_BASE}/api/pops`, { headers: getHeaders() }).then(handleResponse),

  createPoP: (pop) =>
    fetch(`${API_BASE}/api/pops`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(pop),
    }).then(handleResponse),

  // Connectors
  listConnectors: () =>
    fetch(`${API_BASE}/api/connectors`, { headers: getHeaders() }).then(handleResponse),

  createConnector: (conn) =>
    fetch(`${API_BASE}/api/connectors`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(conn),
    }).then(handleResponse),

  // Policies
  listPolicies: () =>
    fetch(`${API_BASE}/api/policies`, { headers: getHeaders() }).then(handleResponse),

  createPolicy: (policy) =>
    fetch(`${API_BASE}/api/policies`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(policy),
    }).then(handleResponse),

  deletePolicy: (id) =>
    fetch(`${API_BASE}/api/policies/${id}`, {
      method: 'DELETE',
      headers: getHeaders(),
    }).then(handleResponse),

  // Audit Logs
  listAuditLogs: () =>
    fetch(`${API_BASE}/api/audit-logs`, { headers: getHeaders() }).then(handleResponse),
};

export default api;
