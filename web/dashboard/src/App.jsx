import { useState, useEffect, useCallback } from 'react';
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
    </div>
  );
}

// --- Connectors Page ---
function ConnectorsPage({ connectors, pops, onRefresh }) {
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ name: '', site_name: '', assigned_pop_id: '', networks: '' });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleCreate = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const conn = {
        ...form,
        networks: form.networks.split(',').map(s => s.trim()).filter(Boolean),
      };
      await api.createConnector(conn);
      setForm({ name: '', site_name: '', assigned_pop_id: '', networks: '192.168.1.0/24' });
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
        <h2>Connecteurs Site ({connectors.length})</h2>
        <button className="btn btn-primary" onClick={() => setShowForm(!showForm)}>
          {showForm ? 'Annuler' : '+ Nouveau connecteur'}
        </button>
      </div>

      {showForm && (
        <div className="card form-card">
          <form onSubmit={handleCreate}>
            <div className="form-row">
              <input placeholder="Nom (ex: Siege Paris)" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} required />
              <input placeholder="Nom du site (ex: Bureau Paris)" value={form.site_name} onChange={e => setForm({ ...form, site_name: e.target.value })} required />
              <select value={form.assigned_pop_id} onChange={e => setForm({ ...form, assigned_pop_id: e.target.value })} required>
                <option value="">-- PoP --</option>
                {pops.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
              </select>
              <input placeholder="Reseaux internes du site (ex: 10.0.0.0/24, 172.16.0.0/24)" value={form.networks} onChange={e => setForm({ ...form, networks: e.target.value })} />
              <button type="submit" className="btn btn-primary" disabled={loading}>{loading ? '...' : 'Creer'}</button>
            </div>
            {error && <div className="form-error">{error}</div>}
          </form>
        </div>
      )}

      {connectors.length === 0 ? (
        <EmptyState message="Aucun connecteur. Creez-en un et installez-le sur votre reseau." />
      ) : (
        <div className="card">
          <table className="table">
            <thead>
              <tr><th>Statut</th><th>Nom</th><th>Site</th><th>PoP assigne</th><th>Token</th><th>Dernier contact</th></tr>
            </thead>
            <tbody>
              {connectors.map(conn => (
                <tr key={conn.id}>
                  <td><StatusDot status={conn.status} /></td>
                  <td className="cell-bold">{conn.name}</td>
                  <td>{conn.site_name}</td>
                  <td>{pops.find(p => p.id === conn.assigned_pop_id)?.name || '-'}</td>
                  <td className="mono" style={{ fontSize: 10 }}>{conn.token ? conn.token.slice(0, 16) + '...' : '-'}</td>
                  <td className="cell-muted">{timeAgo(conn.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="card">
        <h3 className="card-title">Installation du connecteur sur le site</h3>
        <p className="card-desc">Le connecteur se compile depuis les sources Go. Il necessite WireGuard installe sur la machine.</p>

        <h4 className="code-section-title">1. Prerequis (sur le serveur du site client)</h4>
        <div className="code-block">
          <code>
            sudo apt update && sudo apt install -y wireguard git golang<br />
            sudo sysctl -w net.ipv4.ip_forward=1<br />
            echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
          </code>
        </div>

        <h4 className="code-section-title">2. Compiler le connecteur</h4>
        <div className="code-block">
          <code>
            git clone &lt;VOTRE_REPO&gt; ztna-sovereign<br />
            cd ztna-sovereign<br />
            go build -o ztna-connector ./cmd/connector
          </code>
        </div>

        <h4 className="code-section-title">3. Lancer avec le token d'activation</h4>
        <div className="code-block">
          <code>
            sudo ./ztna-connector \<br />
            &nbsp;&nbsp;--token &lt;TOKEN_DU_CONNECTEUR&gt; \<br />
            &nbsp;&nbsp;--control-plane http://&lt;IP_CONTROL_PLANE&gt;:8080 \<br />
            &nbsp;&nbsp;--networks &lt;RESEAU_INTERNE_DU_SITE&gt;<br />
            <br />
            # Exemple : --networks 10.0.0.0/24,172.16.0.0/24
          </code>
        </div>
        <p className="card-desc">Le token est genere automatiquement a la creation du connecteur (colonne Token ci-dessus). Le connecteur etablit un tunnel WireGuard sortant vers le PoP assigne — aucune ouverture de port entrant n'est necessaire sur le firewall du site.</p>
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
