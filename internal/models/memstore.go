// Package models provides an in-memory data store that implements the same
// interface as the PostgreSQL store. This allows the Control Plane to run
// without a database for development and testing.
package models

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

// MemStore is a thread-safe in-memory data store.
type MemStore struct {
	mu             sync.RWMutex
	users          map[string]*User
	groups         map[string]*Group
	groupMembers   map[string][]string // group_id -> []user_id
	pops           map[string]*PoP
	connectors     map[string]*SiteConnector
	agents         map[string]*ClientAgent
	policies       map[string]*Policy
	auditLogs      []*AuditLog
}

// NewMemStore creates a new in-memory store.
func NewMemStore() *MemStore {
	return &MemStore{
		users:        make(map[string]*User),
		groups:       make(map[string]*Group),
		groupMembers: make(map[string][]string),
		pops:         make(map[string]*PoP),
		connectors:   make(map[string]*SiteConnector),
		agents:       make(map[string]*ClientAgent),
		policies:     make(map[string]*Policy),
		auditLogs:    make([]*AuditLog, 0),
	}
}

// --- User ---

func (m *MemStore) CreateUser(ctx context.Context, user *User) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if user.ID == "" {
		user.ID = uuid.New().String()
	}
	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now

	// Check email uniqueness
	for _, u := range m.users {
		if u.Email == user.Email {
			return fmt.Errorf("user with email %s already exists", user.Email)
		}
	}

	copy := *user
	m.users[user.ID] = &copy
	return nil
}

func (m *MemStore) GetUser(ctx context.Context, id string) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	user, ok := m.users[id]
	if !ok {
		return nil, fmt.Errorf("user not found: %s", id)
	}
	copy := *user
	return &copy, nil
}

func (m *MemStore) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, u := range m.users {
		if u.Email == email {
			copy := *u
			return &copy, nil
		}
	}
	return nil, fmt.Errorf("user not found: %s", email)
}

func (m *MemStore) GetUserByOIDCSub(ctx context.Context, sub string) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, u := range m.users {
		if u.OIDCSub == sub {
			copy := *u
			return &copy, nil
		}
	}
	return nil, fmt.Errorf("user not found with OIDC sub: %s", sub)
}

func (m *MemStore) ListUsers(ctx context.Context) ([]User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	users := make([]User, 0, len(m.users))
	for _, u := range m.users {
		users = append(users, *u)
	}
	sort.Slice(users, func(i, j int) bool {
		return users[i].CreatedAt.After(users[j].CreatedAt)
	})
	return users, nil
}

func (m *MemStore) UpdateUser(ctx context.Context, user *User) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	existing, ok := m.users[user.ID]
	if !ok {
		return fmt.Errorf("user not found: %s", user.ID)
	}

	if user.Email != "" {
		existing.Email = user.Email
	}
	if user.Name != "" {
		existing.Name = user.Name
	}
	if user.Role != "" {
		existing.Role = user.Role
	}
	existing.Disabled = user.Disabled
	existing.UpdatedAt = time.Now()
	return nil
}

func (m *MemStore) DeleteUser(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.users[id]; !ok {
		return fmt.Errorf("user not found: %s", id)
	}
	delete(m.users, id)
	return nil
}

// --- PoP ---

func (m *MemStore) CreatePoP(ctx context.Context, pop *PoP) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if pop.ID == "" {
		pop.ID = uuid.New().String()
	}
	pop.CreatedAt = time.Now()
	pop.LastSeen = time.Now()

	copy := *pop
	m.pops[pop.ID] = &copy
	return nil
}

func (m *MemStore) GetPoP(ctx context.Context, id string) (*PoP, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	pop, ok := m.pops[id]
	if !ok {
		return nil, fmt.Errorf("PoP not found: %s", id)
	}
	copy := *pop
	return &copy, nil
}

func (m *MemStore) ListPoPs(ctx context.Context) ([]PoP, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	pops := make([]PoP, 0, len(m.pops))
	for _, p := range m.pops {
		copy := *p
		copy.PrivateKey = "" // never expose
		pops = append(pops, copy)
	}
	sort.Slice(pops, func(i, j int) bool {
		return pops[i].Name < pops[j].Name
	})
	return pops, nil
}

func (m *MemStore) UpdatePoPStatus(ctx context.Context, id string, status PoPStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	pop, ok := m.pops[id]
	if !ok {
		return fmt.Errorf("PoP not found: %s", id)
	}
	pop.Status = status
	pop.LastSeen = time.Now()
	return nil
}

// --- SiteConnector ---

func (m *MemStore) CreateSiteConnector(ctx context.Context, conn *SiteConnector) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if conn.ID == "" {
		conn.ID = uuid.New().String()
	}
	conn.CreatedAt = time.Now()
	conn.LastSeen = time.Now()

	copy := *conn
	copy.Networks = make([]string, len(conn.Networks))
	copy2 := conn.Networks
	_ = copy2
	if conn.Networks != nil {
		copy.Networks = append([]string{}, conn.Networks...)
	}
	m.connectors[conn.ID] = &copy
	return nil
}

func (m *MemStore) GetSiteConnector(ctx context.Context, id string) (*SiteConnector, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	conn, ok := m.connectors[id]
	if !ok {
		return nil, fmt.Errorf("connector not found: %s", id)
	}
	copy := *conn
	return &copy, nil
}

func (m *MemStore) GetSiteConnectorByToken(ctx context.Context, token string) (*SiteConnector, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, c := range m.connectors {
		if c.Token == token {
			copy := *c
			return &copy, nil
		}
	}
	return nil, fmt.Errorf("connector not found with token")
}

func (m *MemStore) ListSiteConnectors(ctx context.Context) ([]SiteConnector, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	conns := make([]SiteConnector, 0, len(m.connectors))
	for _, c := range m.connectors {
		conns = append(conns, *c)
	}
	sort.Slice(conns, func(i, j int) bool {
		return conns[i].CreatedAt.After(conns[j].CreatedAt)
	})
	return conns, nil
}

func (m *MemStore) UpdateSiteConnectorStatus(ctx context.Context, id string, status ConnectorStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	conn, ok := m.connectors[id]
	if !ok {
		return fmt.Errorf("connector not found: %s", id)
	}
	conn.Status = status
	conn.LastSeen = time.Now()
	return nil
}

func (m *MemStore) ActivateSiteConnector(ctx context.Context, id, publicKey, privateKey string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	conn, ok := m.connectors[id]
	if !ok {
		return fmt.Errorf("connector not found: %s", id)
	}
	conn.PublicKey = publicKey
	conn.PrivateKey = privateKey
	conn.Status = ConnectorStatusOnline
	conn.LastSeen = time.Now()
	return nil
}

func (m *MemStore) MarkTokenUsed(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	conn, ok := m.connectors[id]
	if !ok {
		return fmt.Errorf("connector not found: %s", id)
	}
	conn.TokenUsed = true
	conn.Token = "" // Efface le token après utilisation
	return nil
}

func (m *MemStore) DeleteSiteConnector(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.connectors[id]; !ok {
		return fmt.Errorf("connector not found: %s", id)
	}
	delete(m.connectors, id)
	return nil
}

// --- Policy ---

func (m *MemStore) CreatePolicy(ctx context.Context, pol *Policy) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if pol.ID == "" {
		pol.ID = uuid.New().String()
	}
	now := time.Now()
	pol.CreatedAt = now
	pol.UpdatedAt = now

	copy := *pol
	if pol.DestNetworks != nil {
		copy.DestNetworks = append([]string{}, pol.DestNetworks...)
	}
	if pol.DestPorts != nil {
		copy.DestPorts = append([]string{}, pol.DestPorts...)
	}
	m.policies[pol.ID] = &copy
	return nil
}

func (m *MemStore) ListPolicies(ctx context.Context) ([]Policy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	policies := make([]Policy, 0, len(m.policies))
	for _, p := range m.policies {
		policies = append(policies, *p)
	}
	sort.Slice(policies, func(i, j int) bool {
		if policies[i].Priority != policies[j].Priority {
			return policies[i].Priority < policies[j].Priority
		}
		return policies[i].CreatedAt.Before(policies[j].CreatedAt)
	})
	return policies, nil
}

func (m *MemStore) DeletePolicy(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.policies[id]; !ok {
		return fmt.Errorf("policy not found: %s", id)
	}
	delete(m.policies, id)
	return nil
}

// --- ClientAgent ---

func (m *MemStore) CreateClientAgent(ctx context.Context, agent *ClientAgent) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if agent.ID == "" {
		agent.ID = uuid.New().String()
	}
	agent.CreatedAt = time.Now()
	agent.LastSeen = time.Now()

	copy := *agent
	m.agents[agent.ID] = &copy
	return nil
}

func (m *MemStore) GetClientAgentsByUser(ctx context.Context, userID string) ([]ClientAgent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var agents []ClientAgent
	for _, a := range m.agents {
		if a.UserID == userID {
			agents = append(agents, *a)
		}
	}
	return agents, nil
}

// --- AuditLog ---

func (m *MemStore) CreateAuditLog(ctx context.Context, log *AuditLog) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if log.ID == "" {
		log.ID = uuid.New().String()
	}
	log.Timestamp = time.Now()

	copy := *log
	m.auditLogs = append([]*AuditLog{&copy}, m.auditLogs...)
	return nil
}

func (m *MemStore) ListAuditLogs(ctx context.Context, limit int) ([]AuditLog, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	end := limit
	if end > len(m.auditLogs) {
		end = len(m.auditLogs)
	}

	logs := make([]AuditLog, end)
	for i := 0; i < end; i++ {
		logs[i] = *m.auditLogs[i]
	}
	return logs, nil
}

// Migrate is a no-op for the memory store.
func (m *MemStore) Migrate(ctx context.Context) error {
	return nil
}

// --- DataStore interface ---

// DataStore defines the interface that both MemStore and DB implement.
type DataStore interface {
	Migrate(ctx context.Context) error

	CreateUser(ctx context.Context, user *User) error
	GetUser(ctx context.Context, id string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	GetUserByOIDCSub(ctx context.Context, sub string) (*User, error)
	ListUsers(ctx context.Context) ([]User, error)
	UpdateUser(ctx context.Context, user *User) error
	DeleteUser(ctx context.Context, id string) error

	CreatePoP(ctx context.Context, pop *PoP) error
	GetPoP(ctx context.Context, id string) (*PoP, error)
	ListPoPs(ctx context.Context) ([]PoP, error)
	UpdatePoPStatus(ctx context.Context, id string, status PoPStatus) error

	CreateSiteConnector(ctx context.Context, conn *SiteConnector) error
	GetSiteConnector(ctx context.Context, id string) (*SiteConnector, error)
	GetSiteConnectorByToken(ctx context.Context, token string) (*SiteConnector, error)
	ListSiteConnectors(ctx context.Context) ([]SiteConnector, error)
	UpdateSiteConnectorStatus(ctx context.Context, id string, status ConnectorStatus) error
	ActivateSiteConnector(ctx context.Context, id, publicKey, privateKey string) error
	MarkTokenUsed(ctx context.Context, id string) error
	DeleteSiteConnector(ctx context.Context, id string) error

	CreatePolicy(ctx context.Context, pol *Policy) error
	ListPolicies(ctx context.Context) ([]Policy, error)
	DeletePolicy(ctx context.Context, id string) error

	CreateClientAgent(ctx context.Context, agent *ClientAgent) error
	GetClientAgentsByUser(ctx context.Context, userID string) ([]ClientAgent, error)

	CreateAuditLog(ctx context.Context, log *AuditLog) error
	ListAuditLogs(ctx context.Context, limit int) ([]AuditLog, error)
}

// Ensure both stores implement DataStore
var _ DataStore = (*MemStore)(nil)

// ExportJSON exports all data as JSON (for debugging).
func (m *MemStore) ExportJSON() ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	data := map[string]interface{}{
		"users":      m.users,
		"pops":       m.pops,
		"connectors": m.connectors,
		"policies":   m.policies,
		"agents":     m.agents,
		"audit_logs": m.auditLogs,
	}
	return json.MarshalIndent(data, "", "  ")
}
