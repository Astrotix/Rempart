// API client for ZTNA Sovereign Control Plane
// Utilise /api par défaut (proxy nginx) ou VITE_API_URL si défini
// En dev local, on peut override avec VITE_API_URL=http://localhost:8080
const API_BASE = import.meta.env.VITE_API_URL || '/api';

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
    fetch(`${API_BASE}/auth/check`).then(handleResponse),

  setup: (email, name, password) =>
    fetch(`${API_BASE}/auth/setup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, name, password }),
    }).then(handleResponse),

  login: (email, password) =>
    fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    }).then(handleResponse),

  // Health
  health: () =>
    fetch(`${API_BASE}/health`).then(handleResponse),

  // Stats
  getStats: () =>
    fetch(`${API_BASE}/stats`, { headers: getHeaders() }).then(handleResponse),

  // Users
  listUsers: () =>
    fetch(`${API_BASE}/users`, { headers: getHeaders() }).then(handleResponse),

  createUser: (user) =>
    fetch(`${API_BASE}/users`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(user),
    }).then(handleResponse),

  deleteUser: (id) =>
    fetch(`${API_BASE}/users/${id}`, {
      method: 'DELETE',
      headers: getHeaders(),
    }).then(handleResponse),

  // PoPs
  listPoPs: () =>
    fetch(`${API_BASE}/pops`, { headers: getHeaders() }).then(handleResponse),

  createPoP: (pop) =>
    fetch(`${API_BASE}/pops`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(pop),
    }).then(handleResponse),

  // Connectors
  listConnectors: () =>
    fetch(`${API_BASE}/connectors`, { headers: getHeaders() }).then(handleResponse),

  createConnector: (conn) =>
    fetch(`${API_BASE}/connectors`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(conn),
    }).then(handleResponse),

  getConnector: (id) =>
    fetch(`${API_BASE}/connectors/${id}`, { headers: getHeaders() }).then(handleResponse),

  deleteConnector: (id) =>
    fetch(`${API_BASE}/connectors/${id}`, {
      method: 'DELETE',
      headers: getHeaders(),
    }).then(handleResponse),

  // Policies
  listPolicies: () =>
    fetch(`${API_BASE}/policies`, { headers: getHeaders() }).then(handleResponse),

  createPolicy: (policy) =>
    fetch(`${API_BASE}/policies`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(policy),
    }).then(handleResponse),

  deletePolicy: (id) =>
    fetch(`${API_BASE}/policies/${id}`, {
      method: 'DELETE',
      headers: getHeaders(),
    }).then(handleResponse),

  // Audit Logs
  listAuditLogs: () =>
    fetch(`${API_BASE}/audit-logs`, { headers: getHeaders() }).then(handleResponse),
};

export default api;
