import React, { useState, useEffect, useCallback } from 'react';
import api from './api';
import './App.css';

function App() {
  const [token, setToken] = useState(localStorage.getItem('ztna_token'));
  const [setupDone, setSetupDone] = useState(null); // null = loading
  const [error, setError] = useState('');

  useEffect(() => {
    api.checkSetup()
      .then(data => setSetupDone(data.setup_done))
      .catch(() => setError('Impossible de contacter le Control Plane (http://localhost:8080). Lancez le serveur API.'));
  }, []);

  const handleAuth = (newToken) => {
    localStorage.setItem('ztna_token', newToken);
    setToken(newToken);
    setSetupDone(true);
  };

  const handleLogout = () => {
    localStorage.removeItem('ztna_token');
    setToken(null);
  };

  if (error) return <ErrorScreen message={error} />;
  if (setupDone === null) return <LoadingScreen />;
  if (!setupDone) return <SetupScreen onAuth={handleAuth} />;
  if (!token) return <LoginScreen onAuth={handleAuth} />;

  return <Dashboard token={token} onLogout={handleLogout} />;
}

// --- Loading ---
function LoadingScreen() {
  return (
    <div className="fullscreen-center">
      <div className="brand-icon-lg">&#128274;</div>
      <h1>ZTNA Sovereign</h1>
      <p className="text-muted">Connexion au Control Plane...</p>
      <div className="spinner" />
    </div>
  );
}

// --- Error ---
function ErrorScreen({ message }) {
  return (
    <div className="fullscreen-center">
      <div className="brand-icon-lg">&#9888;&#65039;</div>
      <h1>Erreur de connexion</h1>
      <p className="text-muted">{message}</p>
      <div className="code-block" style={{ marginTop: 20, textAlign: 'left' }}>
        <code>
          cd ztna-sovereign<br />
          go run ./cmd/api<br />
        </code>
      </div>
      <button className="btn btn-primary" style={{ marginTop: 20 }} onClick={() => window.location.reload()}>
        Reessayer
      </button>
    </div>
  );
}

// --- Setup Screen ---
function SetupScreen({ onAuth }) {
  const [email, setEmail] = useState('');
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const data = await api.setup(email, name, password);
      onAuth(data.token);
    } catch (err) {
      setError(err.message);
    }
    setLoading(false);
  };

  return (
    <div className="fullscreen-center">
      <div className="auth-card">
        <div className="brand-icon-lg">&#128274;</div>
        <h1>ZTNA Sovereign</h1>
        <p className="text-muted">Configuration initiale - Creez le compte administrateur</p>

        <form onSubmit={handleSubmit} className="auth-form">
          <input type="text" placeholder="Nom complet" value={name} onChange={e => setName(e.target.value)} required />
          <input type="email" placeholder="Email" value={email} onChange={e => setEmail(e.target.value)} required />
          <input type="password" placeholder="Mot de passe" value={password} onChange={e => setPassword(e.target.value)} required minLength={6} />
          {error && <div className="form-error">{error}</div>}
          <button type="submit" className="btn btn-primary btn-full" disabled={loading}>
            {loading ? 'Creation...' : 'Creer le compte admin'}
          </button>
        </form>
      </div>
    </div>
  );
}

// --- Login Screen ---
function LoginScreen({ onAuth }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const data = await api.login(email, password);
      onAuth(data.token);
    } catch (err) {
      setError(err.message);
    }
    setLoading(false);
  };

  return (
    <div className="fullscreen-center">
      <div className="auth-card">
        <div className="brand-icon-lg">&#128274;</div>
        <h1>ZTNA Sovereign</h1>
        <p className="text-muted">Connectez-vous au Control Plane</p>

        <form onSubmit={handleSubmit} className="auth-form">
          <input type="email" placeholder="Email" value={email} onChange={e => setEmail(e.target.value)} required />
          <input type="password" placeholder="Mot de passe" value={password} onChange={e => setPassword(e.target.value)} required />
          {error && <div className="form-error">{error}</div>}
          <button type="submit" className="btn btn-primary btn-full" disabled={loading}>
            {loading ? 'Connexion...' : 'Se connecter'}
          </button>
        </form>
      </div>
    </div>
  );
}

// --- Main Dashboard ---
function Dashboard({ token, onLogout }) {
  const [page, setPage] = useState('dashboard');
  const [stats, setStats] = useState(null);
  const [users, setUsers] = useState([]);
  const [pops, setPops] = useState([]);
  const [connectors, setConnectors] = useState([]);
  const [policies, setPolicies] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [loading, setLoading] = useState(true);

  const refreshAll = useCallback(async () => {
    try {
      const [s, u, p, c, pol, logs] = await Promise.all([
        api.getStats(),
        api.listUsers(),
        api.listPoPs(),
        api.listConnectors(),
        api.listPolicies(),
        api.listAuditLogs(),
      ]);
      setStats(s);
      setUsers(u);
      setPops(p);
      setConnectors(c);
      setPolicies(pol);
      setAuditLogs(logs);
    } catch (err) {
      if (err.message.includes('401') || err.message.includes('token')) {
        onLogout();
      }
    }
    setLoading(false);
  }, [onLogout]);

  useEffect(() => {
    refreshAll();
    const interval = setInterval(refreshAll, 10000); // Refresh every 10s
    return () => clearInterval(interval);
  }, [refreshAll]);

  if (loading) return <LoadingScreen />;

  return (
    <div className="app">
      <Sidebar page={page} setPage={setPage} onLogout={onLogout} stats={stats} />
      <main className="main-content">
        <Header />
        {page === 'dashboard' && <DashboardPage stats={stats} pops={pops} connectors={connectors} />}
        {page === 'users' && <UsersPage users={users} onRefresh={refreshAll} />}
        {page === 'pops' && <PoPsPage pops={pops} onRefresh={refreshAll} />}
        {page === 'connectors' && <ConnectorsPage connectors={connectors} pops={pops} onRefresh={refreshAll} />}
        {page === 'agents' && <AgentsPage />}
        {page === 'policies' && <PoliciesPage policies={policies} connectors={connectors} users={users} onRefresh={refreshAll} />}
        {page === 'logs' && <AuditLogsPage logs={auditLogs} />}
      </main>
    </div>
  );
}

// --- Sidebar ---
function Sidebar({ page, setPage, onLogout, stats }) {
  const items = [
    { key: 'dashboard', icon: '\u{1F4CA}', label: 'Tableau de bord' },
    { key: 'users', icon: '\u{1F465}', label: 'Utilisateurs' },
    { key: 'pops', icon: '\u{1F310}', label: 'PoPs' },
    { key: 'connectors', icon: '\u{1F50C}', label: 'Connecteurs' },
    { key: 'agents', icon: '\u{1F4BB}', label: 'Agent Client' },
    { key: 'policies', icon: '\u{1F6E1}\uFE0F', label: 'Politiques' },
    { key: 'logs', icon: '\u{1F4CB}', label: "Logs d'audit" },
  ];

  return (
    <nav className="sidebar">
      <div className="sidebar-brand">
        <div className="brand-icon">&#128274;</div>
      <div>
          <div className="brand-name">ZTNA Sovereign</div>
          <div className="brand-sub">Control Plane</div>
        </div>
      </div>
      <div className="sidebar-nav">
        {items.map(item => (
          <button
            key={item.key}
            className={`nav-item ${page === item.key ? 'active' : ''}`}
            onClick={() => setPage(item.key)}
          >
            <span className="nav-icon">{item.icon}</span>
            <span className="nav-label">{item.label}</span>
          </button>
        ))}
      </div>
      <div className="sidebar-footer">
        <button className="btn btn-small" onClick={onLogout}>Deconnexion</button>
        <div className="version">v0.1.0</div>
      </div>
    </nav>
  );
}

// --- Header ---
function Header() {
  return (
    <header className="header">
      <div className="header-left">
        <h1 className="page-title">ZTNA Sovereign</h1>
        <span className="header-badge">Infrastructure souveraine francaise</span>
      </div>
      <div className="header-right">
        <span className="header-provider">OVHcloud</span>
        <span className="header-flag">{'\u{1F1EB}\u{1F1F7}'}</span>
      </div>
    </header>
  );
}

// --- Dashboard Page ---
function DashboardPage({ stats, pops, connectors }) {
  if (!stats) return <EmptyState message="Chargement des statistiques..." />;

  const s = stats.tunnel_stats || {};
  return (
    <div className="page">
      <div className="stats-grid">
        <StatCard title="Utilisateurs" value={stats.total_users} subtitle="enregistres" color="blue" />
        <StatCard title="Sessions actives" value={s.active_sessions || 0} subtitle="tunnels WireGuard" color="green" />
        <StatCard title="PoPs" value={`${stats.online_pops || 0}/${stats.total_pops || 0}`} subtitle="en ligne" color="purple" />
        <StatCard title="Connecteurs" value={`${stats.online_connectors || 0}/${stats.total_connectors || 0}`} subtitle="actifs" color="orange" />
      </div>

      <div className="grid-2col">
        <div className="card">
          <h3 className="card-title">PoPs France</h3>
          {pops.length === 0 ? (
            <EmptyState message="Aucun PoP configure. Ajoutez-en dans l'onglet PoPs." />
          ) : (
            <div className="item-list">
              {pops.map(pop => (
                <div key={pop.id} className="list-item">
                  <StatusDot status={pop.status} />
                  <div className="list-item-info">
                    <div className="list-item-title">{pop.name}</div>
                    <div className="list-item-sub">{pop.location} - {pop.provider}</div>
                  </div>
                  <div className="list-item-right mono">{pop.public_ip}:{pop.wg_port}</div>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="card">
          <h3 className="card-title">Connecteurs Sites</h3>
          {connectors.length === 0 ? (
            <EmptyState message="Aucun connecteur. Ajoutez-en dans l'onglet Connecteurs." />
          ) : (
            <div className="item-list">
              {connectors.map(conn => (
                <div key={conn.id} className="list-item">
                  <StatusDot status={conn.status} />
                  <div className="list-item-info">
                    <div className="list-item-title">{conn.name}</div>
                    <div className="list-item-sub">{conn.site_name}</div>
                  </div>
                  <div className="list-item-right">{pops.find(p => p.id === conn.assigned_pop_id)?.location || '-'}</div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="card">
        <h3 className="card-title">Architecture Double Tunnel WireGuard</h3>
        <div className="architecture-diagram">
          <div className="arch-col">
            <div className="arch-title">Utilisateurs distants</div>
            <div className="arch-box arch-user">Agent Client</div>
          </div>
          <div className="arch-arrow">Tunnel WG 1</div>
          <div className="arch-col">
            <div className="arch-title">PoP France (OVHcloud)</div>
            <div className="arch-box arch-pop">WireGuard Relay<br />+ Zero Trust</div>
          </div>
          <div className="arch-arrow">Tunnel WG 2</div>
          <div className="arch-col">
            <div className="arch-title">Site Client</div>
            <div className="arch-box arch-site">Connecteur Site</div>
          </div>
        </div>
      </div>
    </div>
  );
}

// --- Users Page ---
function UsersPage({ users, onRefresh }) {
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ email: '', name: '', role: 'user', password: '' });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleCreate = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await api.createUser(form);
      setForm({ email: '', name: '', role: 'user', password: '' });
      setShowForm(false);
      await onRefresh();
    } catch (err) {
      setError(err.message);
    }
    setLoading(false);
  };

  const handleDelete = async (id) => {
    if (!confirm('Supprimer cet utilisateur ?')) return;
    try {
      await api.deleteUser(id);
      await onRefresh();
    } catch (err) {
      alert(err.message);
    }
  };

  return (
    <div className="page">
      <div className="page-header">
        <h2>Utilisateurs ({users.length})</h2>
        <button className="btn btn-primary" onClick={() => setShowForm(!showForm)}>
          {showForm ? 'Annuler' : '+ Ajouter'}
        </button>
      </div>

      {showForm && (
        <div className="card form-card">
          <form onSubmit={handleCreate}>
            <div className="form-row">
              <input placeholder="Email" type="email" value={form.email} onChange={e => setForm({ ...form, email: e.target.value })} required />
              <input placeholder="Nom" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} required />
              <input placeholder="Mot de passe" type="password" value={form.password} onChange={e => setForm({ ...form, password: e.target.value })} />
              <select value={form.role} onChange={e => setForm({ ...form, role: e.target.value })}>
                <option value="user">Utilisateur</option>
                <option value="admin">Administrateur</option>
                <option value="viewer">Lecteur</option>
              </select>
              <button type="submit" className="btn btn-primary" disabled={loading}>
                {loading ? '...' : 'Creer'}
              </button>
            </div>
            {error && <div className="form-error">{error}</div>}
          </form>
        </div>
      )}

      {users.length === 0 ? (
        <EmptyState message="Aucun utilisateur." />
      ) : (
        <div className="card">
          <table className="table">
            <thead>
              <tr><th>Nom</th><th>Email</th><th>Role</th><th>Statut</th><th>Cree le</th><th>Actions</th></tr>
            </thead>
            <tbody>
              {users.map(user => (
                <tr key={user.id}>
                  <td className="cell-bold">{user.name || '-'}</td>
                  <td>{user.email}</td>
                  <td><RoleBadge role={user.role} /></td>
                  <td>{user.disabled ? <span className="badge badge-red">Desactive</span> : <span className="badge badge-green">Actif</span>}</td>
                  <td className="cell-muted">{formatDate(user.created_at)}</td>
                  <td>
                    <button className="btn btn-small btn-danger" onClick={() => handleDelete(user.id)}>Supprimer</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// --- PoPs Page ---
function PoPsPage({ pops, onRefresh }) {
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ name: '', location: '', public_ip: '', wg_port: 51820, provider: 'OVHcloud' });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleCreate = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await api.createPoP({ ...form, wg_port: parseInt(form.wg_port) });
      setForm({ name: '', location: '', public_ip: '', wg_port: 51820, provider: 'OVHcloud' });
      setShowForm(false);
      await onRefresh();
    } catch (err) {
      setError(err.message);
    }
    setLoading(false);
  };

  return (
    <div className="page">
      <div className="page-header">
        <h2>Points of Presence ({pops.length})</h2>
        <button className="btn btn-primary" onClick={() => setShowForm(!showForm)}>
          {showForm ? 'Annuler' : '+ Ajouter un PoP'}
        </button>
      </div>

      {showForm && (
        <div className="card form-card">
          <form onSubmit={handleCreate}>
            <div className="form-row">
              <input placeholder="Nom (ex: PoP Gravelines)" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} required />
              <input placeholder="Localisation (ex: Gravelines)" value={form.location} onChange={e => setForm({ ...form, location: e.target.value })} required />
              <input placeholder="IP publique" value={form.public_ip} onChange={e => setForm({ ...form, public_ip: e.target.value })} required />
              <input placeholder="Port WG" type="number" value={form.wg_port} onChange={e => setForm({ ...form, wg_port: e.target.value })} style={{ width: 100 }} />
              <button type="submit" className="btn btn-primary" disabled={loading}>{loading ? '...' : 'Creer'}</button>
            </div>
            {error && <div className="form-error">{error}</div>}
          </form>
        </div>
      )}

      {pops.length === 0 ? (
        <EmptyState message="Aucun PoP configure. Ajoutez votre premier Point of Presence." />
      ) : (
        <div className="stats-grid">
          {pops.map(pop => (
            <div key={pop.id} className="card pop-card">
              <div className="pop-card-header">
                <StatusDot status={pop.status} />
                <h3>{pop.name}</h3>
              </div>
              <div className="pop-card-body">
                <InfoRow label="Localisation" value={pop.location} />
                <InfoRow label="Fournisseur" value={pop.provider} />
                <InfoRow label="IP publique" value={pop.public_ip} mono />
                <InfoRow label="Port WireGuard" value={pop.wg_port} mono />
                <InfoRow label="Cle publique" value={pop.public_key ? pop.public_key.slice(0, 20) + '...' : '-'} mono />
                <InfoRow label="Statut" value={<StatusBadge status={pop.status} />} />
                <InfoRow label="Dernier contact" value={timeAgo(pop.last_seen)} />
              </div>
            </div>
          ))}
        </div>
      )}

      {pops.length > 0 && (
        <div className="card">
          <h3 className="card-title">Installation du PoP sur le serveur</h3>
          <p className="card-desc">Une fois le PoP cree ci-dessus, installez-le sur votre serveur Ubuntu avec les commandes suivantes. L'ID du PoP est deja pre-rempli.</p>

          {pops.map(pop => (
            <div key={pop.id} style={{ marginBottom: 24, paddingBottom: 24, borderBottom: '1px solid var(--border)' }}>
              <h4 className="code-section-title" style={{ marginTop: 0 }}>Installation pour : {pop.name} (ID: <span className="mono">{pop.id}</span>)</h4>

              <h5 className="code-section-title" style={{ fontSize: 12, marginTop: 12 }}>1. Prerequis sur le serveur Ubuntu</h5>
              <div className="code-block">
                <code>
                  sudo apt update && sudo apt install -y wireguard-tools git<br />
                  sudo sysctl -w net.ipv4.ip_forward=1<br />
                  echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf<br />
                  sudo ufw allow 51820/udp<br />
                  sudo ufw allow 22/tcp<br />
                  sudo ufw --force enable
                </code>
              </div>

              <h5 className="code-section-title" style={{ fontSize: 12, marginTop: 12 }}>2. Installer Go</h5>
              <div className="code-block">
                <code>
                  wget https://go.dev/dl/go1.23.6.linux-amd64.tar.gz<br />
                  sudo rm -rf /usr/local/go<br />
                  sudo tar -C /usr/local -xzf go1.23.6.linux-amd64.tar.gz<br />
                  export PATH=$PATH:/usr/local/go/bin<br />
                  echo 'export PATH=$PATH:/usr/local/go/bin' &gt;&gt; ~/.bashrc<br />
                  source ~/.bashrc
                </code>
              </div>

              <h5 className="code-section-title" style={{ fontSize: 12, marginTop: 12 }}>3. Cloner et compiler</h5>
              <div className="code-block">
                <code>
                  git clone https://github.com/Astrotix/Rempart.git<br />
                  cd Rempart<br />
                  go mod tidy<br />
                  go build -o ztna-pop ./cmd/pop
                </code>
              </div>

              <h5 className="code-section-title" style={{ fontSize: 12, marginTop: 12 }}>4. Lancer le PoP</h5>
              <div className="code-block">
                <code>
                  sudo ./ztna-pop \<br />
                  &nbsp;&nbsp;--pop-id "{pop.id}" \<br />
                  &nbsp;&nbsp;--control-plane http://&lt;IP_CONTROL_PLANE&gt;:8080 \<br />
                  &nbsp;&nbsp;--wg-interface wg0 \<br />
                  &nbsp;&nbsp;--wg-port {pop.wg_port} \<br />
                  &nbsp;&nbsp;--heartbeat 30
                </code>
              </div>

              <p className="card-desc" style={{ marginTop: 8, fontSize: 12 }}>
                <strong>Note :</strong> Remplacez <code>&lt;IP_CONTROL_PLANE&gt;</code> par l'IP publique de votre Control Plane (ex: 176.136.202.205).
                Le PoP enverra des heartbeats toutes les 30 secondes et son statut passera a <strong>ONLINE</strong> dans le dashboard.
              </p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// --- Connectors Page ---
function ConnectorsPage({ connectors, pops, onRefresh }) {
  const [step, setStep] = useState('list'); // 'list', 'configure', 'install'
  const [form, setForm] = useState({ name: '', site_name: '', assigned_pop_id: '', networks: '192.168.1.0/24' });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [createdConnector, setCreatedConnector] = useState(null);
  const [controlPlaneIP, setControlPlaneIP] = useState('176.136.202.205'); // IP par défaut, peut être changée
  const [regeneratedTokenModal, setRegeneratedTokenModal] = useState(null); // { token, connector }

  const handleConfigure = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const conn = {
        ...form,
        networks: form.networks.split(',').map(s => s.trim()).filter(Boolean),
      };
      const newConn = await api.createConnector(conn);
      setCreatedConnector(newConn);
      setStep('install');
      await onRefresh();
    } catch (err) {
      setError(err.message);
    }
    setLoading(false);
  };

  const handleBackToList = () => {
    setStep('list');
    setCreatedConnector(null);
    setForm({ name: '', site_name: '', assigned_pop_id: '', networks: '192.168.1.0/24' });
    setError('');
  };

  const handleShowInstructions = async (conn) => {
    try {
      // Récupérer le connecteur complet avec son token depuis l'API
      const fullConn = await api.getConnector(conn.id);
      setCreatedConnector(fullConn);
      setStep('install');
    } catch (err) {
      // Si l'API ne renvoie pas le token, utiliser le connecteur de la liste
      setCreatedConnector(conn);
      setStep('install');
    }
  };

  const copyToClipboard = async (text) => {
    try {
      await navigator.clipboard.writeText(text);
      alert('✅ Copié dans le presse-papiers !');
    } catch (err) {
      // Fallback pour les navigateurs qui ne supportent pas clipboard API
      const textArea = document.createElement('textarea');
      textArea.value = text;
      textArea.style.position = 'fixed';
      textArea.style.opacity = '0';
      document.body.appendChild(textArea);
      textArea.select();
      try {
        document.execCommand('copy');
        alert('✅ Copié dans le presse-papiers !');
      } catch (e) {
        alert('❌ Impossible de copier. Sélectionnez le texte manuellement.');
      }
      document.body.removeChild(textArea);
    }
  };

  const handleDeleteConnector = async (id) => {
    if (!confirm('Êtes-vous sûr de vouloir supprimer ce connecteur ? Cette action est irréversible.')) {
      return;
    }
    try {
      await api.deleteConnector(id);
      loadConnectors();
      setError('');
    } catch (err) {
      setError('Erreur lors de la suppression : ' + err.message);
    }
  };

  return (
    <div className="page">
      {/* Modal nouveau token après régénération : copie exacte, pas d'alert() qui fausse I/1 et O/0 */}
      {regeneratedTokenModal && (
        <div style={{
          position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', zIndex: 9999,
          display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 20
        }} onClick={() => setRegeneratedTokenModal(null)}>
          <div style={{
            background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 12, padding: 24, maxWidth: 520,
            boxShadow: '0 8px 32px rgba(0,0,0,0.3)'
          }} onClick={e => e.stopPropagation()}>
            <h3 style={{ marginTop: 0, marginBottom: 12 }}>Nouveau token généré</h3>
            <p style={{ color: 'var(--text-muted)', fontSize: 13, marginBottom: 16 }}>
              Copiez-le avec le bouton ci-dessous pour éviter les erreurs (I/1, O/0). Il ne sera plus affiché après fermeture.
            </p>
            <pre style={{
              fontFamily: 'ui-monospace, monospace', fontSize: 14, letterSpacing: '0.05em', padding: 12, background: 'var(--bg)', borderRadius: 8,
              overflow: 'auto', marginBottom: 16, wordBreak: 'break-all'
            }}>
              {regeneratedTokenModal.token}
            </pre>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
              <button
                type="button"
                className="btn btn-primary"
                onClick={async () => {
                  await copyToClipboard(regeneratedTokenModal.token);
                }}
              >
                📋 Copier le token
              </button>
              <button
                type="button"
                className="btn"
                style={{ background: 'var(--bg)', border: '1px solid var(--border)' }}
                onClick={async () => {
                  const cmd = `sudo ./ztna-connector --token "${regeneratedTokenModal.token}" --control-plane http://${controlPlaneIP}:8080 --networks ${(regeneratedTokenModal.connector?.networks || ['192.168.75.0/24']).join(',')}`;
                  await copyToClipboard(cmd);
                }}
              >
                📋 Copier la commande
              </button>
              <button type="button" className="btn" onClick={() => setRegeneratedTokenModal(null)}>
                OK
              </button>
            </div>
          </div>
        </div>
      )}

      <div className="page-header">
        <h2>Connecteurs Site ({connectors.length})</h2>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          {step === 'list' && (
            <>
              <button 
                className="btn btn-small" 
                onClick={onRefresh}
                title="Rafraîchir la liste"
                style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', color: 'var(--text)' }}
              >
                🔄 Rafraîchir
              </button>
              <button className="btn btn-primary" onClick={() => setStep('configure')}>
                + Nouveau connecteur
              </button>
            </>
          )}
          {step !== 'list' && (
            <button className="btn btn-small" onClick={handleBackToList}>
              ← Retour à la liste
            </button>
          )}
        </div>
      </div>

      {/* Étape 1 : Configuration */}
      {step === 'configure' && (
        <div className="card">
          <div style={{ marginBottom: 20 }}>
            <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
              <div style={{ padding: '8px 16px', background: 'var(--accent-blue)', borderRadius: 8, fontSize: 13, fontWeight: 600 }}>1. Configuration</div>
              <div style={{ padding: '8px 16px', background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 13, color: 'var(--text-muted)' }}>2. Installation</div>
            </div>
            <p className="card-desc">
              Configurez votre connecteur de site. Le connecteur établit un tunnel WireGuard sortant vers le PoP pour exposer les réseaux internes de votre site.
            </p>
          </div>

          <form onSubmit={handleConfigure}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div>
                <label style={{ display: 'block', marginBottom: 6, fontSize: 13, fontWeight: 600 }}>Nom du connecteur *</label>
                <input 
                  type="text" 
                  placeholder="Ex: Siege Paris" 
                  value={form.name} 
                  onChange={e => setForm({ ...form, name: e.target.value })} 
                  required 
                  style={{ width: '100%', padding: '10px 14px', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--bg-primary)', color: 'var(--text-primary)' }}
                />
                <p style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4 }}>Un nom qui identifie le réseau sur lequel le connecteur est installé.</p>
              </div>

              <div>
                <label style={{ display: 'block', marginBottom: 6, fontSize: 13, fontWeight: 600 }}>Nom du site *</label>
                <input 
                  type="text" 
                  placeholder="Ex: Bureau Paris" 
                  value={form.site_name} 
                  onChange={e => setForm({ ...form, site_name: e.target.value })} 
                  required 
                  style={{ width: '100%', padding: '10px 14px', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--bg-primary)', color: 'var(--text-primary)' }}
                />
                <p style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4 }}>Nom descriptif du site client.</p>
              </div>

              <div>
                <label style={{ display: 'block', marginBottom: 6, fontSize: 13, fontWeight: 600 }}>PoP assigné *</label>
                <select 
                  value={form.assigned_pop_id} 
                  onChange={e => setForm({ ...form, assigned_pop_id: e.target.value })} 
                  required
                  style={{ width: '100%', padding: '10px 14px', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--bg-primary)', color: 'var(--text-primary)' }}
                >
                  <option value="">-- Sélectionner un PoP --</option>
                  {pops.map(p => <option key={p.id} value={p.id}>{p.name} ({p.location})</option>)}
                </select>
                <p style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4 }}>Le Point of Presence vers lequel le connecteur établira le tunnel.</p>
              </div>

              <div>
                <label style={{ display: 'block', marginBottom: 6, fontSize: 13, fontWeight: 600 }}>Réseaux internes à exposer *</label>
                <input 
                  type="text" 
                  placeholder="Ex: 192.168.1.0/24, 10.0.0.0/24" 
                  value={form.networks} 
                  onChange={e => setForm({ ...form, networks: e.target.value })} 
                  required
                  style={{ width: '100%', padding: '10px 14px', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--bg-primary)', color: 'var(--text-primary)' }}
                />
                <p style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4 }}>Réseaux CIDR séparés par des virgules. Ces réseaux seront accessibles via le tunnel WireGuard.</p>
              </div>

              {error && <div className="form-error">{error}</div>}

              <div style={{ display: 'flex', gap: 12, marginTop: 8 }}>
                <button type="button" className="btn" onClick={handleBackToList} style={{ flex: 1 }}>Annuler</button>
                <button type="submit" className="btn btn-primary" disabled={loading} style={{ flex: 1 }}>
                  {loading ? 'Création...' : 'Créer et afficher les instructions'}
                </button>
              </div>
            </div>
          </form>
        </div>
      )}

      {/* Étape 2 : Instructions d'installation */}
      {step === 'install' && createdConnector && (
        <div className="card">
          <div style={{ marginBottom: 20 }}>
            <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
              <div style={{ padding: '8px 16px', background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 13, color: 'var(--text-muted)' }}>1. Configuration</div>
              <div style={{ padding: '8px 16px', background: 'var(--accent-blue)', borderRadius: 8, fontSize: 13, fontWeight: 600 }}>2. Installation</div>
            </div>
            <h3 style={{ marginBottom: 8 }}>Instructions d'installation</h3>
            <p className="card-desc">
              Connecteur <strong>{createdConnector.name}</strong> créé avec succès. Copiez et exécutez les commandes suivantes sur le serveur du site.
            </p>
          </div>

          <div style={{ marginBottom: 16 }}>
            <label style={{ display: 'block', marginBottom: 6, fontSize: 13, fontWeight: 600 }}>IP du Control Plane</label>
            <input 
              type="text" 
              value={controlPlaneIP} 
              onChange={e => setControlPlaneIP(e.target.value)}
              placeholder="176.136.202.205"
              style={{ width: '100%', padding: '8px 12px', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--bg-primary)', color: 'var(--text-primary)', fontFamily: 'monospace' }}
            />
            <p style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4 }}>L'IP publique de votre Control Plane. Les commandes ci-dessous seront mises à jour automatiquement.</p>
          </div>

          <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 12, padding: 20, marginBottom: 16 }}>
            <h4 style={{ fontSize: 14, fontWeight: 600, marginBottom: 12 }}>1. Prérequis sur le serveur du site</h4>
            <div className="code-block" style={{ position: 'relative' }}>
              <button 
                onClick={() => copyToClipboard(`sudo apt update && sudo apt install -y wireguard iptables git wget\n# Installer Go 1.23 (requis)\nwget -O /tmp/go1.23.linux-amd64.tar.gz https://go.dev/dl/go1.23.0.linux-amd64.tar.gz\nsudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf /tmp/go1.23.linux-amd64.tar.gz\necho 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc\nexport PATH=$PATH:/usr/local/go/bin\n# Configurer IP forwarding\nsudo sysctl -w net.ipv4.ip_forward=1\necho "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf`)}
                style={{ position: 'absolute', top: 8, right: 8, padding: '4px 8px', fontSize: 11, background: 'var(--accent-blue)', border: 'none', borderRadius: 4, cursor: 'pointer', color: 'white' }}
              >
                Copier
              </button>
              <code>
                sudo apt update &amp;&amp; sudo apt install -y wireguard iptables git wget<br />
                # Installer Go 1.23 (requis)<br />
                wget -O /tmp/go1.23.linux-amd64.tar.gz https://go.dev/dl/go1.23.0.linux-amd64.tar.gz<br />
                sudo rm -rf /usr/local/go &amp;&amp; sudo tar -C /usr/local -xzf /tmp/go1.23.linux-amd64.tar.gz<br />
                {"echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc"}<br />
                export PATH=$PATH:/usr/local/go/bin<br />
                # Configurer IP forwarding<br />
                sudo sysctl -w net.ipv4.ip_forward=1<br />
                {"echo \"net.ipv4.ip_forward=1\" | sudo tee -a /etc/sysctl.conf"}
              </code>
            </div>
            <p style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 8 }}>
              <strong>Note :</strong> Le projet nécessite Go 1.23. Si vous avez déjà Go installé mais en version inférieure, cette commande le remplacera par Go 1.23.
            </p>
          </div>

          <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 12, padding: 20, marginBottom: 16 }}>
            <h4 style={{ fontSize: 14, fontWeight: 600, marginBottom: 12 }}>2. Télécharger le connecteur</h4>
            <p style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 8 }}>
              Téléchargez le binaire précompilé pour votre architecture :
            </p>
            <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
              <a 
                href={`http://${controlPlaneIP}:8080/api/downloads/connector/linux`}
                download
                style={{ 
                  padding: '8px 16px', 
                  background: 'var(--accent-blue)', 
                  color: 'white', 
                  borderRadius: 6, 
                  textDecoration: 'none', 
                  fontSize: 13,
                  fontWeight: 600
                }}
              >
                📥 Linux (amd64)
              </a>
              <a 
                href={`http://${controlPlaneIP}:8080/api/downloads/connector/linux-arm`}
                download
                style={{ 
                  padding: '8px 16px', 
                  background: 'var(--bg-primary)', 
                  border: '1px solid var(--border)',
                  color: 'var(--text-primary)', 
                  borderRadius: 6, 
                  textDecoration: 'none', 
                  fontSize: 13,
                  fontWeight: 600
                }}
              >
                📥 Linux (ARM64)
              </a>
            </div>
            <p style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 8 }}>
              Ou téléchargez directement depuis le serveur :
            </p>
            <div className="code-block" style={{ position: 'relative' }}>
              <button 
                onClick={() => copyToClipboard(`curl -L http://${controlPlaneIP}:8080/api/downloads/connector/linux -o ztna-connector\nchmod +x ztna-connector`)}
                style={{ position: 'absolute', top: 8, right: 8, padding: '4px 8px', fontSize: 11, background: 'var(--accent-blue)', border: 'none', borderRadius: 4, cursor: 'pointer', color: 'white' }}
              >
                Copier
              </button>
              <code>
                curl -L http://<span style={{ color: 'var(--accent-blue)' }}>{controlPlaneIP}</span>:8080/api/downloads/connector/linux -o ztna-connector<br />
                chmod +x ztna-connector
              </code>
            </div>
          </div>

          <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 12, padding: 20, marginBottom: 16 }}>
            <h4 style={{ fontSize: 14, fontWeight: 600, marginBottom: 12 }}>3. Lancer le connecteur avec le token d'activation</h4>
            <p style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 8 }}>
              Le token d'activation peut être réutilisé pour redémarrer le connecteur. Les clés sont sauvegardées automatiquement.
            </p>
            {createdConnector.token ? (
              <>
                <div className="code-block" style={{ position: 'relative' }}>
                  <button 
                    onClick={() => copyToClipboard(`sudo ./ztna-connector \\\n  --token ${createdConnector.token} \\\n  --control-plane http://${controlPlaneIP}:8080 \\\n  --networks ${createdConnector.networks?.join(',') || form.networks}`)}
                    style={{ position: 'absolute', top: 8, right: 8, padding: '4px 8px', fontSize: 11, background: 'var(--accent-blue)', border: 'none', borderRadius: 4, cursor: 'pointer', color: 'white' }}
                  >
                    Copier
                  </button>
                  <code>
                    sudo ./ztna-connector \<br />
                    &nbsp;&nbsp;--token <span style={{ color: 'var(--accent-orange)', fontWeight: 600 }}>{createdConnector.token}</span> \<br />
                    &nbsp;&nbsp;--control-plane http://<span style={{ color: 'var(--accent-blue)' }}>{controlPlaneIP}</span>:8080 \<br />
                    &nbsp;&nbsp;--networks <span style={{ color: 'var(--accent-green)' }}>{createdConnector.networks?.join(',') || form.networks}</span>
                  </code>
                </div>
                <div style={{ marginTop: 12, padding: 12, background: 'rgba(245, 158, 11, 0.1)', border: '1px solid rgba(245, 158, 11, 0.3)', borderRadius: 8 }}>
                  <p style={{ fontSize: 12, color: 'var(--accent-orange)', margin: 0 }}>
                    <strong>⚠️ Important :</strong> Le token <code style={{ fontSize: 11 }}>{createdConnector.token}</code> est affiché une seule fois. 
                    Sauvegardez-le ou copiez-le maintenant. Il expire dans 24h et devient inutilisable après la première activation.
                  </p>
                </div>
              </>
            ) : (
              <div style={{ padding: 16, background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.3)', borderRadius: 8 }}>
                <p style={{ fontSize: 13, color: 'var(--accent-red)', margin: 0 }}>
                  <strong>Token non disponible :</strong> Le token d'activation n'est affiché qu'une seule fois lors de la création du connecteur. 
                  Si vous n'avez pas sauvegardé le token, vous devez créer un nouveau connecteur.
                </p>
              </div>
            )}
          </div>

          <div style={{ display: 'flex', gap: 12, marginTop: 20 }}>
            <button className="btn" onClick={handleBackToList} style={{ flex: 1 }}>Terminé</button>
            <button className="btn btn-primary" onClick={() => { setStep('configure'); setCreatedConnector(null); }} style={{ flex: 1 }}>
              Créer un autre connecteur
            </button>
          </div>
        </div>
      )}

      {/* Liste des connecteurs existants */}
      {step === 'list' && (
        <>
          {connectors.length === 0 ? (
            <EmptyState message="Aucun connecteur. Creez-en un et installez-le sur votre reseau." />
          ) : (
            <div className="card">
              <div className="stats-grid">
                {connectors.map(conn => {
                  const isOnline = conn.status === 'online';
                  const lastSeenDate = conn.last_seen ? new Date(conn.last_seen) : null;
                  const isRecent = lastSeenDate && (Date.now() - lastSeenDate.getTime()) < 60000; // < 1 min
                  return (
                    <div key={conn.id} className="card" style={{ padding: 20 }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                          <StatusDot status={conn.status} />
                          <div>
                            <h3 style={{ fontSize: 16, fontWeight: 700, margin: 0 }}>{conn.name}</h3>
                            <p style={{ fontSize: 12, color: 'var(--text-muted)', margin: '2px 0 0 0' }}>{conn.site_name}</p>
                          </div>
                        </div>
                        <StatusBadge status={conn.status} />
                      </div>

                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px 16px', marginBottom: 16 }}>
                        <InfoRow label="PoP assigné" value={pops.find(p => p.id === conn.assigned_pop_id)?.name || '-'} />
                        <InfoRow label="Dernier contact" value={timeAgo(conn.last_seen)} />
                        <InfoRow label="Réseaux" value={conn.networks?.join(', ') || '-'} mono />
                        <InfoRow label="Token utilisé" value={conn.token_used ? '✅ Oui' : '❌ Non'} />
                      </div>

                      {/* Indicateur de connexion */}
                      {isOnline && isRecent ? (
                        <div style={{ padding: 10, background: 'rgba(34, 197, 94, 0.1)', border: '1px solid rgba(34, 197, 94, 0.3)', borderRadius: 8, marginBottom: 12 }}>
                          <p style={{ fontSize: 12, color: '#22c55e', margin: 0, fontWeight: 600 }}>
                            ✅ Connecteur connecté — Heartbeat actif (dernier : {timeAgo(conn.last_seen)})
                          </p>
                        </div>
                      ) : isOnline ? (
                        <div style={{ padding: 10, background: 'rgba(245, 158, 11, 0.1)', border: '1px solid rgba(245, 158, 11, 0.3)', borderRadius: 8, marginBottom: 12 }}>
                          <p style={{ fontSize: 12, color: 'var(--accent-orange)', margin: 0, fontWeight: 600 }}>
                            ⚠️ Connecteur marqué online mais dernier contact : {timeAgo(conn.last_seen)}
                          </p>
                        </div>
                      ) : conn.status === 'registering' ? (
                        <div style={{ padding: 10, background: 'rgba(59, 130, 246, 0.1)', border: '1px solid rgba(59, 130, 246, 0.3)', borderRadius: 8, marginBottom: 12 }}>
                          <p style={{ fontSize: 12, color: 'var(--accent-blue)', margin: 0, fontWeight: 600 }}>
                            🔄 En attente d'activation — Le connecteur n'a pas encore été lancé sur le serveur
                          </p>
                        </div>
                      ) : (
                        <div style={{ padding: 10, background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.3)', borderRadius: 8, marginBottom: 12 }}>
                          <p style={{ fontSize: 12, color: 'var(--accent-red)', margin: 0, fontWeight: 600 }}>
                            ❌ Connecteur hors ligne — Dernier contact : {timeAgo(conn.last_seen)}
                          </p>
                        </div>
                      )}

                      {/* Commande de lancement si non connecté */}
                      {conn.status !== 'online' && conn.token && (
                        <div style={{ marginBottom: 12 }}>
                          <p style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6 }}>Lancez cette commande sur le serveur du site :</p>
                          <div className="code-block" style={{ position: 'relative', margin: 0 }}>
                            <button 
                              onClick={() => copyToClipboard(`sudo ./ztna-connector \\\n  --token ${conn.token} \\\n  --control-plane http://${controlPlaneIP}:8080 \\\n  --networks ${conn.networks?.join(',') || ''}`)}
                              style={{ position: 'absolute', top: 8, right: 8, padding: '4px 8px', fontSize: 11, background: 'var(--accent-blue)', border: 'none', borderRadius: 4, cursor: 'pointer', color: 'white' }}
                            >
                              Copier
                            </button>
                            <code style={{ fontSize: 11 }}>
                              sudo ./ztna-connector \<br />
                              &nbsp;&nbsp;--token <span style={{ color: 'var(--accent-orange)', fontWeight: 600 }}>{conn.token}</span> \<br />
                              &nbsp;&nbsp;--control-plane http://<span style={{ color: 'var(--accent-blue)' }}>{controlPlaneIP}</span>:8080 \<br />
                              &nbsp;&nbsp;--networks <span style={{ color: 'var(--accent-green)' }}>{conn.networks?.join(',') || ''}</span>
                            </code>
                          </div>
                        </div>
                      )}

                      <div style={{ display: 'flex', gap: 8 }}>
                        <button 
                          className="btn btn-small" 
                          onClick={() => handleShowInstructions(conn)}
                          title="Voir les instructions d'installation"
                          style={{ flex: 1 }}
                        >
                          📋 Instructions
                        </button>
                        <button 
                          className="btn btn-small" 
                          onClick={async () => {
                            if (!confirm('Régénérer le token d\'activation ? Le token actuel ne fonctionnera plus.')) return;
                            try {
                              const updated = await api.regenerateConnectorToken(conn.id);
                              setRegeneratedTokenModal({ token: updated.token, connector: conn });
                              loadConnectors();
                            } catch (err) {
                              alert('Erreur : ' + err.message);
                            }
                          }}
                          title="Régénérer le token d'activation"
                          style={{ background: 'var(--accent-orange)', color: 'white' }}
                        >
                          🔄 Régénérer Token
                        </button>
                        <button 
                          className="btn btn-small" 
                          onClick={() => handleDeleteConnector(conn.id)}
                          title="Supprimer le connecteur"
                          style={{ background: 'var(--accent-red)', color: 'white' }}
                        >
                          🗑️ Supprimer
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

// --- Agents Page ---
function AgentsPage() {
  const [downloads, setDownloads] = useState([]);
  const [loading, setLoading] = useState(true);
  const controlPlaneIP = window.location.hostname;

  useEffect(() => {
    api.listDownloads()
      .then(data => setDownloads(data))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  const formatSize = (bytes) => {
    const mb = parseInt(bytes) / (1024 * 1024);
    return mb >= 1 ? `${mb.toFixed(1)} MB` : `${(parseInt(bytes) / 1024).toFixed(0)} KB`;
  };

  const platformIcons = {
    windows: '🪟',
    linux: '🐧',
    macos: '🍎',
    'macos-arm': '🍎',
  };

  const platformOrder = ['windows', 'linux', 'macos', 'macos-arm'];

  const sortedDownloads = [...downloads].sort(
    (a, b) => platformOrder.indexOf(a.platform) - platformOrder.indexOf(b.platform)
  );

  return (
    <div className="page">
      <div className="page-header">
        <h2>Agent Client ZTNA</h2>
      </div>

      <div className="card" style={{ marginBottom: 20, background: 'rgba(59, 130, 246, 0.05)', border: '1px solid rgba(59, 130, 246, 0.3)' }}>
        <h3 style={{ fontSize: 16, marginBottom: 12 }}>🚀 Comment ca marche ?</h3>
        <div style={{ fontSize: 13, lineHeight: 1.8 }}>
          <p style={{ marginBottom: 8 }}>
            <strong>1.</strong> Creez un <strong>utilisateur</strong> dans la section Utilisateurs
          </p>
          <p style={{ marginBottom: 8 }}>
            <strong>2.</strong> Creez une <strong>politique</strong> dans la section Politiques pour autoriser cet utilisateur
          </p>
          <p style={{ marginBottom: 8 }}>
            <strong>3.</strong> <strong>Telechargez</strong> l&apos;agent ci-dessous
          </p>
          <p style={{ marginBottom: 8 }}>
            <strong>4.</strong> <strong>Double-cliquez</strong> sur l&apos;exe — une interface futuriste s&apos;ouvre dans le navigateur
          </p>
          <p style={{ marginBottom: 0 }}>
            <strong>5.</strong> Entrez vos identifiants → Cliquez <strong>&quot;Connexion Securisee&quot;</strong> → C&apos;est connecte !
          </p>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 20 }}>
        <h3 style={{ fontSize: 16, marginBottom: 16 }}>Telechargements</h3>
        {loading ? (
          <p className="text-muted">Chargement...</p>
        ) : downloads.length === 0 ? (
          <p className="text-muted">Aucun binaire disponible. Reconstruisez le conteneur API.</p>
        ) : (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 16 }}>
            {sortedDownloads.map(dl => (
              <div key={dl.platform} className="card" style={{
                padding: 20,
                textAlign: 'center',
                opacity: dl.available === 'true' ? 1 : 0.5,
                border: dl.platform === 'windows' ? '2px solid var(--accent-blue)' : '1px solid var(--border)',
              }}>
                <div style={{ fontSize: 40, marginBottom: 8 }}>{platformIcons[dl.platform] || '💻'}</div>
                <div style={{ fontWeight: 700, fontSize: 15, marginBottom: 4 }}>{dl.name}</div>
                <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 12 }}>
                  {dl.available === 'true' ? formatSize(dl.size) : 'Non disponible'}
                </div>
                {dl.available === 'true' ? (
                  <a
                    href={api.getDownloadURL(dl.platform)}
                    className="btn btn-primary"
                    style={{ display: 'inline-block', textDecoration: 'none' }}
                    download
                  >
                    Telecharger
                  </a>
                ) : (
                  <button className="btn" disabled>Non disponible</button>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="card" style={{ marginBottom: 20 }}>
        <h3 style={{ fontSize: 16, marginBottom: 12 }}>🪟 Windows</h3>
        <div style={{ fontSize: 13, lineHeight: 1.6 }}>
          <p style={{ marginBottom: 12 }}>
            <strong>Prerequis :</strong> Installez <a href="https://www.wireguard.com/install/" target="_blank" rel="noreferrer" style={{ color: 'var(--accent-blue)' }}>WireGuard pour Windows</a>
          </p>
          <p style={{ marginBottom: 8 }}>
            <strong>1.</strong> Telechargez <code>ztna-agent-windows-amd64.exe</code> ci-dessus
          </p>
          <p style={{ marginBottom: 8 }}>
            <strong>2.</strong> Clic droit → <strong>&quot;Executer en tant qu&apos;administrateur&quot;</strong>
          </p>
          <p style={{ marginBottom: 8 }}>
            <strong>3.</strong> L&apos;interface s&apos;ouvre automatiquement dans votre navigateur
          </p>
          <p style={{ marginBottom: 8 }}>
            <strong>4.</strong> Entrez votre email et mot de passe → Cliquez <strong>&quot;Connexion Securisee&quot;</strong>
          </p>
          <p style={{ marginBottom: 8, fontSize: 12, color: 'var(--text-muted)' }}>
            💡 Le serveur Control Plane est pre-configure a <code>http://{controlPlaneIP}:8080</code> (modifiable dans Parametres avances)
          </p>
          <p style={{ marginBottom: 0, fontSize: 12, color: 'var(--text-muted)' }}>
            🖥️ Mode CLI disponible : <code>ztna-agent-windows-amd64.exe --cli --email X --password Y --control-plane URL</code>
          </p>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 20 }}>
        <h3 style={{ fontSize: 16, marginBottom: 12 }}>🐧 Linux / 🍎 macOS</h3>
        <div style={{ fontSize: 13, lineHeight: 1.6 }}>
          <div className="code-block" style={{ fontSize: 12 }}>
            <code>
              chmod +x ztna-agent-linux-amd64<br />
              sudo ./ztna-agent-linux-amd64
            </code>
          </div>
          <p style={{ marginTop: 8, fontSize: 12, color: 'var(--text-muted)' }}>
            L&apos;interface s&apos;ouvre dans le navigateur. Utilisez <code>--cli</code> pour le mode terminal.
          </p>
        </div>
      </div>

      <div className="card info-banner">
        <strong>Zero Trust :</strong> Sans politique d&apos;acces configuree, le tunnel sera etabli mais aucun trafic ne sera autorise. Creez une politique dans la section &quot;Politiques&quot; pour autoriser l&apos;utilisateur a acceder aux ressources du connecteur.
      </div>
    </div>
  );
}

// --- Policies Page ---
function PoliciesPage({ policies, connectors, users, onRefresh }) {
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({
    name: '', source_type: 'user', source_id: '', dest_connector_id: '',
    dest_networks: '', dest_ports: '', action: 'allow', priority: 100, enabled: true,
  });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleCreate = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const pol = {
        ...form,
        priority: parseInt(form.priority),
        dest_networks: form.dest_networks.split(',').map(s => s.trim()).filter(Boolean),
        dest_ports: form.dest_ports.split(',').map(s => s.trim()).filter(Boolean),
      };
      await api.createPolicy(pol);
      setForm({ name: '', source_type: 'user', source_id: '', dest_connector_id: '', dest_networks: '', dest_ports: '', action: 'allow', priority: 100, enabled: true });
      setShowForm(false);
      await onRefresh();
    } catch (err) {
      setError(err.message);
    }
    setLoading(false);
  };

  const handleDelete = async (id) => {
    if (!confirm('Supprimer cette politique ?')) return;
    try {
      await api.deletePolicy(id);
      await onRefresh();
    } catch (err) {
      alert(err.message);
    }
  };

  return (
    <div className="page">
      <div className="page-header">
        <h2>Politiques Zero Trust ({policies.length})</h2>
        <button className="btn btn-primary" onClick={() => setShowForm(!showForm)}>
          {showForm ? 'Annuler' : '+ Nouvelle politique'}
        </button>
      </div>

      <div className="card info-banner">
        <strong>Zero Trust :</strong> Par defaut, TOUT le trafic est bloque. Seules les politiques explicites autorisent l'acces.
      </div>



      {showForm && (
        <div className="card form-card">
          <form onSubmit={handleCreate}>
            <div className="form-grid">
              <input placeholder="Nom de la politique" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} required />
              <input placeholder="Priorite (1=haute)" type="number" value={form.priority} onChange={e => setForm({ ...form, priority: e.target.value })} />
              <select value={form.source_type} onChange={e => setForm({ ...form, source_type: e.target.value })}>
                <option value="user">Utilisateur</option>
                <option value="group">Groupe</option>
              </select>
              <select value={form.source_id} onChange={e => setForm({ ...form, source_id: e.target.value })} required>
                <option value="">-- Source --</option>
                {form.source_type === 'user' && users.map(u => <option key={u.id} value={u.id}>{u.name || u.email}</option>)}
              </select>
              <select value={form.dest_connector_id} onChange={e => setForm({ ...form, dest_connector_id: e.target.value })} required>
                <option value="">-- Connecteur destination --</option>
                {connectors.map(c => <option key={c.id} value={c.id}>{c.name} ({c.site_name})</option>)}
              </select>
              <input placeholder="Reseaux (ex: 192.168.1.0/24)" value={form.dest_networks} onChange={e => setForm({ ...form, dest_networks: e.target.value })} />
              <input placeholder="Ports (ex: 443,22,80)" value={form.dest_ports} onChange={e => setForm({ ...form, dest_ports: e.target.value })} />
              <select value={form.action} onChange={e => setForm({ ...form, action: e.target.value })}>
                <option value="allow">ALLOW</option>
                <option value="deny">DENY</option>
              </select>
            </div>
            {error && <div className="form-error">{error}</div>}
            <button type="submit" className="btn btn-primary" style={{ marginTop: 12 }} disabled={loading}>{loading ? '...' : 'Creer la politique'}</button>
          </form>
        </div>
      )}

      {policies.length === 0 ? (
        <EmptyState message="Aucune politique. Tout le trafic est bloque par defaut (Zero Trust)." />
      ) : (
        <div className="card">
          <table className="table">
            <thead>
              <tr><th>P.</th><th>Nom</th><th>Source</th><th>Destination</th><th>Ports</th><th>Action</th><th>Actif</th><th></th></tr>
            </thead>
            <tbody>
              {policies.map(pol => (
                <tr key={pol.id} className={!pol.enabled ? 'row-disabled' : ''}>
                  <td className="cell-center">{pol.priority}</td>
                  <td className="cell-bold">{pol.name}</td>
                  <td>
                    <span className="badge badge-blue">{pol.source_type}</span>{' '}
                    <span className="mono">{users.find(u => u.id === pol.source_id)?.email || pol.source_id}</span>
                  </td>
                  <td>
                    <span>{connectors.find(c => c.id === pol.dest_connector_id)?.name || pol.dest_connector_id}</span>
                    <br /><span className="cell-muted">{pol.dest_networks?.join(', ') || '*'}</span>
                  </td>
                  <td className="mono">{pol.dest_ports?.join(', ') || '*'}</td>
                  <td>{pol.action === 'allow' ? <span className="badge badge-green">ALLOW</span> : <span className="badge badge-red">DENY</span>}</td>
                  <td>{pol.enabled ? '\u2705' : '\u274C'}</td>
                  <td><button className="btn btn-small btn-danger" onClick={() => handleDelete(pol.id)}>X</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// --- Audit Logs Page ---
function AuditLogsPage({ logs }) {
  return (
    <div className="page">
      <div className="page-header">
        <h2>Logs d'audit</h2>
        <span className="cell-muted">{logs.length} evenements</span>
      </div>

      {logs.length === 0 ? (
        <EmptyState message="Aucun evenement enregistre." />
      ) : (
        <div className="card">
          <table className="table">
            <thead>
              <tr><th>Heure</th><th>Utilisateur</th><th>Action</th><th>Destination</th><th>Port</th><th>Resultat</th><th>IP client</th></tr>
            </thead>
            <tbody>
              {logs.map(log => (
                <tr key={log.id}>
                  <td className="mono">{formatTime(log.timestamp)}</td>
                  <td>{log.user_email || '-'}</td>
                  <td><ActionBadge action={log.action} /></td>
                  <td className="mono">{log.dest_network || '-'}</td>
                  <td className="mono">{log.dest_port || '-'}</td>
                  <td>{log.result === 'allowed' ? <span className="badge badge-green">OK</span> : <span className="badge badge-red">Refuse</span>}</td>
                  <td className="mono cell-muted">{log.client_ip || '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// --- Shared Components ---
function StatCard({ title, value, subtitle, color }) {
  return (
    <div className={`stat-card stat-${color}`}>
      <div className="stat-value">{value}</div>
      <div className="stat-title">{title}</div>
      <div className="stat-subtitle">{subtitle}</div>
    </div>
  );
}

function StatusDot({ status }) {
  const colors = { online: '#22c55e', offline: '#ef4444', degraded: '#f59e0b', registering: '#3b82f6' };
  return <span className="status-dot" style={{ backgroundColor: colors[status] || '#6b7280' }} />;
}

function StatusBadge({ status }) {
  const cls = status === 'online' ? 'badge-green' : status === 'offline' ? 'badge-red' : 'badge-yellow';
  return <span className={`badge ${cls}`}>{status}</span>;
}

function RoleBadge({ role }) {
  const cls = role === 'admin' ? 'badge-purple' : role === 'viewer' ? 'badge-gray' : 'badge-blue';
  return <span className={`badge ${cls}`}>{role}</span>;
}

function ActionBadge({ action }) {
  const map = {
    login: { cls: 'badge-blue', label: 'Login' },
    setup: { cls: 'badge-purple', label: 'Setup' },
    connect: { cls: 'badge-green', label: 'Connect' },
    disconnect: { cls: 'badge-gray', label: 'Disconnect' },
    access_denied: { cls: 'badge-red', label: 'Acces refuse' },
    user_created: { cls: 'badge-blue', label: 'User cree' },
    user_deleted: { cls: 'badge-red', label: 'User supprime' },
    policy_created: { cls: 'badge-green', label: 'Policy creee' },
    policy_deleted: { cls: 'badge-red', label: 'Policy supprimee' },
    pop_created: { cls: 'badge-purple', label: 'PoP cree' },
    connector_created: { cls: 'badge-orange', label: 'Connecteur cree' },
  };
  const info = map[action] || { cls: 'badge-gray', label: action };
  return <span className={`badge ${info.cls}`}>{info.label}</span>;
}

function InfoRow({ label, value, mono }) {
  return (
    <div className="pop-info-row">
      <span>{label}</span>
      <span className={mono ? 'mono' : ''}>{value}</span>
    </div>
  );
}

function EmptyState({ message }) {
  return <div className="empty-state">{message}</div>;
}

function timeAgo(dateStr) {
  if (!dateStr) return '-';
  const diff = Date.now() - new Date(dateStr).getTime();
  if (diff < 0) return "a l'instant";
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "a l'instant";
  if (mins < 60) return `il y a ${mins}min`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `il y a ${hours}h`;
  return `il y a ${Math.floor(hours / 24)}j`;
}

function formatDate(dateStr) {
  if (!dateStr) return '-';
  return new Date(dateStr).toLocaleDateString('fr-FR');
}

function formatTime(dateStr) {
  if (!dateStr) return '-';
  return new Date(dateStr).toLocaleString('fr-FR', { hour: '2-digit', minute: '2-digit', second: '2-digit', day: '2-digit', month: '2-digit' });
}

export default App;
