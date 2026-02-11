// Package models provides database initialization, migrations, and repository
// methods for all ZTNA data models using PostgreSQL.
package models

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// DB wraps the sql.DB connection and provides repository methods.
type DB struct {
	*sql.DB
}

// DBConfig holds the PostgreSQL connection parameters.
type DBConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	DBName   string
	SSLMode  string
}

// NewDB creates a new database connection.
func NewDB(cfg DBConfig) (*DB, error) {
	dsn := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.DBName, cfg.SSLMode,
	)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &DB{db}, nil
}

// Migrate runs the database migrations to create all tables.
func (db *DB) Migrate(ctx context.Context) error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id          TEXT PRIMARY KEY,
			email       TEXT UNIQUE NOT NULL,
			name        TEXT NOT NULL DEFAULT '',
			role        TEXT NOT NULL DEFAULT 'user',
			oidc_sub    TEXT UNIQUE,
			disabled    BOOLEAN NOT NULL DEFAULT false,
			created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,

		`CREATE TABLE IF NOT EXISTS groups (
			id          TEXT PRIMARY KEY,
			name        TEXT UNIQUE NOT NULL,
			created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,

		`CREATE TABLE IF NOT EXISTS group_members (
			group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
			user_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			PRIMARY KEY (group_id, user_id)
		)`,

		`CREATE TABLE IF NOT EXISTS pops (
			id          TEXT PRIMARY KEY,
			name        TEXT NOT NULL,
			location    TEXT NOT NULL,
			provider    TEXT NOT NULL DEFAULT 'OVHcloud',
			public_ip   TEXT NOT NULL,
			wg_port     INTEGER NOT NULL DEFAULT 51820,
			public_key  TEXT NOT NULL,
			private_key TEXT NOT NULL,
			status      TEXT NOT NULL DEFAULT 'offline',
			last_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,

		`CREATE TABLE IF NOT EXISTS site_connectors (
			id              TEXT PRIMARY KEY,
			name            TEXT NOT NULL,
			site_name       TEXT NOT NULL,
			token           TEXT UNIQUE NOT NULL,
			token_used      BOOLEAN NOT NULL DEFAULT false,
			token_expiry    TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '24 hours',
			public_key      TEXT NOT NULL DEFAULT '',
			private_key     TEXT NOT NULL DEFAULT '',
			assigned_pop_id TEXT REFERENCES pops(id),
			networks        JSONB NOT NULL DEFAULT '[]',
			status          TEXT NOT NULL DEFAULT 'registering',
			last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,

		`CREATE TABLE IF NOT EXISTS client_agents (
			id          TEXT PRIMARY KEY,
			user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			device_name TEXT NOT NULL,
			os          TEXT NOT NULL DEFAULT '',
			public_key  TEXT NOT NULL,
			private_key TEXT NOT NULL,
			assigned_ip TEXT NOT NULL,
			last_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,

		`CREATE TABLE IF NOT EXISTS policies (
			id                TEXT PRIMARY KEY,
			name              TEXT NOT NULL,
			description       TEXT NOT NULL DEFAULT '',
			enabled           BOOLEAN NOT NULL DEFAULT true,
			priority          INTEGER NOT NULL DEFAULT 100,
			source_type       TEXT NOT NULL,
			source_id         TEXT NOT NULL,
			dest_connector_id TEXT NOT NULL REFERENCES site_connectors(id) ON DELETE CASCADE,
			dest_networks     JSONB NOT NULL DEFAULT '[]',
			dest_ports        JSONB NOT NULL DEFAULT '[]',
			action            TEXT NOT NULL DEFAULT 'allow',
			created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,

		`CREATE TABLE IF NOT EXISTS audit_logs (
			id            TEXT PRIMARY KEY,
			timestamp     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			user_id       TEXT NOT NULL,
			user_email    TEXT NOT NULL DEFAULT '',
			action        TEXT NOT NULL,
			pop_id        TEXT NOT NULL DEFAULT '',
			connector_id  TEXT NOT NULL DEFAULT '',
			dest_network  TEXT NOT NULL DEFAULT '',
			dest_port     TEXT NOT NULL DEFAULT '',
			policy_id     TEXT NOT NULL DEFAULT '',
			result        TEXT NOT NULL,
			client_ip     TEXT NOT NULL DEFAULT ''
		)`,

		// Indexes for performance
		`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`,
		`CREATE INDEX IF NOT EXISTS idx_users_oidc_sub ON users(oidc_sub)`,
		`CREATE INDEX IF NOT EXISTS idx_client_agents_user_id ON client_agents(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_policies_source ON policies(source_type, source_id)`,
		`CREATE INDEX IF NOT EXISTS idx_policies_dest ON policies(dest_connector_id)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_site_connectors_token ON site_connectors(token)`,
	}

	for _, m := range migrations {
		if _, err := db.ExecContext(ctx, m); err != nil {
			return fmt.Errorf("migration failed: %w\nSQL: %s", err, m)
		}
	}

	return nil
}

// --- User Repository ---

// CreateUser inserts a new user into the database.
func (db *DB) CreateUser(ctx context.Context, user *User) error {
	if user.ID == "" {
		user.ID = uuid.New().String()
	}
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()

	_, err := db.ExecContext(ctx,
		`INSERT INTO users (id, email, name, role, oidc_sub, disabled, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		user.ID, user.Email, user.Name, user.Role, user.OIDCSub, user.Disabled, user.CreatedAt, user.UpdatedAt,
	)
	return err
}

// GetUser retrieves a user by ID.
func (db *DB) GetUser(ctx context.Context, id string) (*User, error) {
	user := &User{}
	err := db.QueryRowContext(ctx,
		`SELECT id, email, name, role, oidc_sub, disabled, created_at, updated_at FROM users WHERE id = $1`, id,
	).Scan(&user.ID, &user.Email, &user.Name, &user.Role, &user.OIDCSub, &user.Disabled, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// GetUserByEmail retrieves a user by email.
func (db *DB) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	user := &User{}
	err := db.QueryRowContext(ctx,
		`SELECT id, email, name, role, oidc_sub, disabled, created_at, updated_at FROM users WHERE email = $1`, email,
	).Scan(&user.ID, &user.Email, &user.Name, &user.Role, &user.OIDCSub, &user.Disabled, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// GetUserByOIDCSub retrieves a user by their OIDC subject identifier.
func (db *DB) GetUserByOIDCSub(ctx context.Context, sub string) (*User, error) {
	user := &User{}
	err := db.QueryRowContext(ctx,
		`SELECT id, email, name, role, oidc_sub, disabled, created_at, updated_at FROM users WHERE oidc_sub = $1`, sub,
	).Scan(&user.ID, &user.Email, &user.Name, &user.Role, &user.OIDCSub, &user.Disabled, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// ListUsers retrieves all users.
func (db *DB) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, email, name, role, oidc_sub, disabled, created_at, updated_at FROM users ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Email, &u.Name, &u.Role, &u.OIDCSub, &u.Disabled, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, nil
}

// UpdateUser updates an existing user.
func (db *DB) UpdateUser(ctx context.Context, user *User) error {
	user.UpdatedAt = time.Now()
	_, err := db.ExecContext(ctx,
		`UPDATE users SET email=$2, name=$3, role=$4, disabled=$5, updated_at=$6 WHERE id=$1`,
		user.ID, user.Email, user.Name, user.Role, user.Disabled, user.UpdatedAt,
	)
	return err
}

// DeleteUser deletes a user by ID.
func (db *DB) DeleteUser(ctx context.Context, id string) error {
	_, err := db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, id)
	return err
}

// --- PoP Repository ---

// CreatePoP inserts a new PoP.
func (db *DB) CreatePoP(ctx context.Context, pop *PoP) error {
	if pop.ID == "" {
		pop.ID = uuid.New().String()
	}
	pop.CreatedAt = time.Now()

	_, err := db.ExecContext(ctx,
		`INSERT INTO pops (id, name, location, provider, public_ip, wg_port, public_key, private_key, status, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		pop.ID, pop.Name, pop.Location, pop.Provider, pop.PublicIP, pop.WGPort, pop.PublicKey, pop.PrivateKey, pop.Status, pop.CreatedAt,
	)
	return err
}

// GetPoP retrieves a PoP by ID.
func (db *DB) GetPoP(ctx context.Context, id string) (*PoP, error) {
	pop := &PoP{}
	err := db.QueryRowContext(ctx,
		`SELECT id, name, location, provider, public_ip, wg_port, public_key, private_key, status, last_seen, created_at
		 FROM pops WHERE id = $1`, id,
	).Scan(&pop.ID, &pop.Name, &pop.Location, &pop.Provider, &pop.PublicIP, &pop.WGPort,
		&pop.PublicKey, &pop.PrivateKey, &pop.Status, &pop.LastSeen, &pop.CreatedAt)
	if err != nil {
		return nil, err
	}
	return pop, nil
}

// ListPoPs retrieves all PoPs.
func (db *DB) ListPoPs(ctx context.Context) ([]PoP, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, name, location, provider, public_ip, wg_port, public_key, status, last_seen, created_at
		 FROM pops ORDER BY name`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var pops []PoP
	for rows.Next() {
		var p PoP
		if err := rows.Scan(&p.ID, &p.Name, &p.Location, &p.Provider, &p.PublicIP, &p.WGPort,
			&p.PublicKey, &p.Status, &p.LastSeen, &p.CreatedAt); err != nil {
			return nil, err
		}
		pops = append(pops, p)
	}
	return pops, nil
}

// UpdatePoPStatus updates PoP status and last_seen.
func (db *DB) UpdatePoPStatus(ctx context.Context, id string, status PoPStatus) error {
	_, err := db.ExecContext(ctx,
		`UPDATE pops SET status=$2, last_seen=NOW() WHERE id=$1`,
		id, status,
	)
	return err
}

// --- Site Connector Repository ---

// CreateSiteConnector inserts a new site connector.
func (db *DB) CreateSiteConnector(ctx context.Context, conn *SiteConnector) error {
	if conn.ID == "" {
		conn.ID = uuid.New().String()
	}
	conn.CreatedAt = time.Now()

	networksJSON, _ := json.Marshal(conn.Networks)

	_, err := db.ExecContext(ctx,
		`INSERT INTO site_connectors (id, name, site_name, token, token_used, token_expiry, public_key, private_key, assigned_pop_id, networks, status, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		conn.ID, conn.Name, conn.SiteName, conn.Token, conn.TokenUsed, conn.TokenExpiry,
		conn.PublicKey, conn.PrivateKey, conn.AssignedPoPID, networksJSON, conn.Status, conn.CreatedAt,
	)
	return err
}

// GetSiteConnector retrieves a site connector by ID.
func (db *DB) GetSiteConnector(ctx context.Context, id string) (*SiteConnector, error) {
	conn := &SiteConnector{}
	var networksJSON []byte
	err := db.QueryRowContext(ctx,
		`SELECT id, name, site_name, token, token_used, token_expiry, public_key, private_key, assigned_pop_id, networks, status, last_seen, created_at
		 FROM site_connectors WHERE id = $1`, id,
	).Scan(&conn.ID, &conn.Name, &conn.SiteName, &conn.Token, &conn.TokenUsed, &conn.TokenExpiry,
		&conn.PublicKey, &conn.PrivateKey, &conn.AssignedPoPID, &networksJSON, &conn.Status, &conn.LastSeen, &conn.CreatedAt)
	if err != nil {
		return nil, err
	}
	json.Unmarshal(networksJSON, &conn.Networks)
	return conn, nil
}

// GetSiteConnectorByToken retrieves a site connector by activation token.
func (db *DB) GetSiteConnectorByToken(ctx context.Context, token string) (*SiteConnector, error) {
	conn := &SiteConnector{}
	var networksJSON []byte
	err := db.QueryRowContext(ctx,
		`SELECT id, name, site_name, token, token_used, token_expiry, public_key, private_key, assigned_pop_id, networks, status, last_seen, created_at
		 FROM site_connectors WHERE token = $1`, token,
	).Scan(&conn.ID, &conn.Name, &conn.SiteName, &conn.Token, &conn.TokenUsed, &conn.TokenExpiry,
		&conn.PublicKey, &conn.PrivateKey, &conn.AssignedPoPID, &networksJSON, &conn.Status, &conn.LastSeen, &conn.CreatedAt)
	if err != nil {
		return nil, err
	}
	json.Unmarshal(networksJSON, &conn.Networks)
	return conn, nil
}

// ListSiteConnectors retrieves all site connectors.
func (db *DB) ListSiteConnectors(ctx context.Context) ([]SiteConnector, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, name, site_name, token, token_used, token_expiry, public_key, assigned_pop_id, networks, status, last_seen, created_at
		 FROM site_connectors ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var connectors []SiteConnector
	for rows.Next() {
		var c SiteConnector
		var networksJSON []byte
		if err := rows.Scan(&c.ID, &c.Name, &c.SiteName, &c.Token, &c.TokenUsed, &c.TokenExpiry,
			&c.PublicKey, &c.AssignedPoPID, &networksJSON, &c.Status, &c.LastSeen, &c.CreatedAt); err != nil {
			return nil, err
		}
		json.Unmarshal(networksJSON, &c.Networks)
		connectors = append(connectors, c)
	}
	return connectors, nil
}

// UpdateSiteConnectorStatus updates connector status and last_seen.
func (db *DB) UpdateSiteConnectorStatus(ctx context.Context, id string, status ConnectorStatus) error {
	_, err := db.ExecContext(ctx,
		`UPDATE site_connectors SET status=$2, last_seen=NOW() WHERE id=$1`,
		id, status,
	)
	return err
}

// ActivateSiteConnector sets the keys and marks the connector as online.
func (db *DB) ActivateSiteConnector(ctx context.Context, id, publicKey, privateKey string) error {
	_, err := db.ExecContext(ctx,
		`UPDATE site_connectors SET public_key=$2, private_key=$3, status='online', last_seen=NOW() WHERE id=$1`,
		id, publicKey, privateKey,
	)
	return err
}

// MarkTokenUsed marks a connector's activation token as consumed.
func (db *DB) MarkTokenUsed(ctx context.Context, id string) error {
	_, err := db.ExecContext(ctx,
		`UPDATE site_connectors SET token_used=true, token='' WHERE id=$1`, id,
	)
	return err
}

// RegenerateConnectorToken generates a new activation token for an existing connector.
func (db *DB) RegenerateConnectorToken(ctx context.Context, id string, newToken string, expiry time.Time) error {
	_, err := db.ExecContext(ctx,
		`UPDATE site_connectors SET token=$2, token_used=false, token_expiry=$3 WHERE id=$1`,
		id, newToken, expiry,
	)
	return err
}

// DeleteSiteConnector removes a connector from the database.
func (db *DB) DeleteSiteConnector(ctx context.Context, id string) error {
	_, err := db.ExecContext(ctx,
		`DELETE FROM site_connectors WHERE id=$1`, id,
	)
	return err
}

// --- Policy Repository ---

// CreatePolicy inserts a new policy.
func (db *DB) CreatePolicy(ctx context.Context, policy *Policy) error {
	if policy.ID == "" {
		policy.ID = uuid.New().String()
	}
	policy.CreatedAt = time.Now()
	policy.UpdatedAt = time.Now()

	networksJSON, _ := json.Marshal(policy.DestNetworks)
	portsJSON, _ := json.Marshal(policy.DestPorts)

	_, err := db.ExecContext(ctx,
		`INSERT INTO policies (id, name, description, enabled, priority, source_type, source_id, dest_connector_id, dest_networks, dest_ports, action, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		policy.ID, policy.Name, policy.Description, policy.Enabled, policy.Priority,
		policy.SourceType, policy.SourceID, policy.DestConnectorID,
		networksJSON, portsJSON, policy.Action, policy.CreatedAt, policy.UpdatedAt,
	)
	return err
}

// ListPolicies retrieves all policies ordered by priority.
func (db *DB) ListPolicies(ctx context.Context) ([]Policy, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, name, description, enabled, priority, source_type, source_id, dest_connector_id, dest_networks, dest_ports, action, created_at, updated_at
		 FROM policies ORDER BY priority ASC, created_at ASC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policies []Policy
	for rows.Next() {
		var p Policy
		var networksJSON, portsJSON []byte
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Enabled, &p.Priority,
			&p.SourceType, &p.SourceID, &p.DestConnectorID,
			&networksJSON, &portsJSON, &p.Action, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		json.Unmarshal(networksJSON, &p.DestNetworks)
		json.Unmarshal(portsJSON, &p.DestPorts)
		policies = append(policies, p)
	}
	return policies, nil
}

// DeletePolicy deletes a policy by ID.
func (db *DB) DeletePolicy(ctx context.Context, id string) error {
	_, err := db.ExecContext(ctx, `DELETE FROM policies WHERE id = $1`, id)
	return err
}

// --- Client Agent Repository ---

// CreateClientAgent inserts a new client agent.
func (db *DB) CreateClientAgent(ctx context.Context, agent *ClientAgent) error {
	if agent.ID == "" {
		agent.ID = uuid.New().String()
	}
	agent.CreatedAt = time.Now()

	_, err := db.ExecContext(ctx,
		`INSERT INTO client_agents (id, user_id, device_name, os, public_key, private_key, assigned_ip, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		agent.ID, agent.UserID, agent.DeviceName, agent.OS, agent.PublicKey, agent.PrivateKey, agent.AssignedIP, agent.CreatedAt,
	)
	return err
}

// GetClientAgentsByUser retrieves all agents for a user.
func (db *DB) GetClientAgentsByUser(ctx context.Context, userID string) ([]ClientAgent, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, user_id, device_name, os, public_key, assigned_ip, last_seen, created_at
		 FROM client_agents WHERE user_id = $1 ORDER BY created_at DESC`, userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var agents []ClientAgent
	for rows.Next() {
		var a ClientAgent
		if err := rows.Scan(&a.ID, &a.UserID, &a.DeviceName, &a.OS, &a.PublicKey, &a.AssignedIP, &a.LastSeen, &a.CreatedAt); err != nil {
			return nil, err
		}
		agents = append(agents, a)
	}
	return agents, nil
}

// ListClientAgents retrieves all registered client agents.
func (db *DB) ListClientAgents(ctx context.Context) ([]ClientAgent, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, user_id, device_name, os, public_key, assigned_ip, last_seen, created_at
		 FROM client_agents ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var agents []ClientAgent
	for rows.Next() {
		var a ClientAgent
		if err := rows.Scan(&a.ID, &a.UserID, &a.DeviceName, &a.OS, &a.PublicKey, &a.AssignedIP, &a.LastSeen, &a.CreatedAt); err != nil {
			return nil, err
		}
		agents = append(agents, a)
	}
	return agents, nil
}

// --- Audit Log Repository ---

// CreateAuditLog inserts a new audit log entry.
func (db *DB) CreateAuditLog(ctx context.Context, log *AuditLog) error {
	if log.ID == "" {
		log.ID = uuid.New().String()
	}
	log.Timestamp = time.Now()

	_, err := db.ExecContext(ctx,
		`INSERT INTO audit_logs (id, timestamp, user_id, user_email, action, pop_id, connector_id, dest_network, dest_port, policy_id, result, client_ip)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		log.ID, log.Timestamp, log.UserID, log.UserEmail, log.Action, log.PoPID, log.ConnectorID,
		log.DestNetwork, log.DestPort, log.PolicyID, log.Result, log.ClientIP,
	)
	return err
}

// ListAuditLogs retrieves recent audit logs.
func (db *DB) ListAuditLogs(ctx context.Context, limit int) ([]AuditLog, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, timestamp, user_id, user_email, action, pop_id, connector_id, dest_network, dest_port, policy_id, result, client_ip
		 FROM audit_logs ORDER BY timestamp DESC LIMIT $1`, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []AuditLog
	for rows.Next() {
		var l AuditLog
		if err := rows.Scan(&l.ID, &l.Timestamp, &l.UserID, &l.UserEmail, &l.Action, &l.PoPID, &l.ConnectorID,
			&l.DestNetwork, &l.DestPort, &l.PolicyID, &l.Result, &l.ClientIP); err != nil {
			return nil, err
		}
		logs = append(logs, l)
	}
	return logs, nil
}
