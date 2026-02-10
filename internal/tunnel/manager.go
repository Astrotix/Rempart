// Package tunnel manages the double-tunnel WireGuard architecture.
// It handles the routing of traffic between user tunnels and site tunnels
// through the PoP relay.
package tunnel

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/ztna-sovereign/ztna/internal/models"
)

// Session represents an active user tunnel session through a PoP.
type Session struct {
	ID          string
	UserID      string
	AgentID     string
	PoPID       string
	ConnectorID string
	TunnelIP    string
	ConnectedAt time.Time
	LastActive  time.Time
}

// Manager coordinates tunnel sessions between users and site connectors.
type Manager struct {
	mu         sync.RWMutex
	sessions   map[string]*Session // Key: session ID
	userIndex  map[string][]string // Key: user ID -> session IDs
	popIndex   map[string][]string // Key: PoP ID -> session IDs
	connIndex  map[string][]string // Key: connector ID -> session IDs
}

// NewManager creates a new tunnel manager.
func NewManager() *Manager {
	return &Manager{
		sessions:  make(map[string]*Session),
		userIndex: make(map[string][]string),
		popIndex:  make(map[string][]string),
		connIndex: make(map[string][]string),
	}
}

// CreateSession registers a new tunnel session.
func (m *Manager) CreateSession(session *Session) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.sessions[session.ID] = session
	m.userIndex[session.UserID] = append(m.userIndex[session.UserID], session.ID)
	m.popIndex[session.PoPID] = append(m.popIndex[session.PoPID], session.ID)
	if session.ConnectorID != "" {
		m.connIndex[session.ConnectorID] = append(m.connIndex[session.ConnectorID], session.ID)
	}
}

// RemoveSession removes a tunnel session.
func (m *Manager) RemoveSession(sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, ok := m.sessions[sessionID]
	if !ok {
		return
	}

	delete(m.sessions, sessionID)
	m.userIndex[session.UserID] = removeFromSlice(m.userIndex[session.UserID], sessionID)
	m.popIndex[session.PoPID] = removeFromSlice(m.popIndex[session.PoPID], sessionID)
	if session.ConnectorID != "" {
		m.connIndex[session.ConnectorID] = removeFromSlice(m.connIndex[session.ConnectorID], sessionID)
	}
}

// GetSession returns a session by ID.
func (m *Manager) GetSession(sessionID string) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[sessionID]
	return s, ok
}

// GetUserSessions returns all active sessions for a user.
func (m *Manager) GetUserSessions(userID string) []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*Session
	for _, sid := range m.userIndex[userID] {
		if s, ok := m.sessions[sid]; ok {
			result = append(result, s)
		}
	}
	return result
}

// GetPoPSessions returns all active sessions on a PoP.
func (m *Manager) GetPoPSessions(popID string) []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*Session
	for _, sid := range m.popIndex[popID] {
		if s, ok := m.sessions[sid]; ok {
			result = append(result, s)
		}
	}
	return result
}

// GetConnectorSessions returns all active sessions using a connector.
func (m *Manager) GetConnectorSessions(connectorID string) []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*Session
	for _, sid := range m.connIndex[connectorID] {
		if s, ok := m.sessions[sid]; ok {
			result = append(result, s)
		}
	}
	return result
}

// GetStats returns current tunnel statistics.
func (m *Manager) GetStats() TunnelStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	uniqueUsers := make(map[string]bool)
	uniquePoPs := make(map[string]bool)
	uniqueConns := make(map[string]bool)

	for _, s := range m.sessions {
		uniqueUsers[s.UserID] = true
		uniquePoPs[s.PoPID] = true
		if s.ConnectorID != "" {
			uniqueConns[s.ConnectorID] = true
		}
	}

	return TunnelStats{
		ActiveSessions:     len(m.sessions),
		ConnectedUsers:     len(uniqueUsers),
		ActivePoPs:         len(uniquePoPs),
		ActiveConnectors:   len(uniqueConns),
	}
}

// TunnelStats holds aggregate tunnel statistics.
type TunnelStats struct {
	ActiveSessions   int `json:"active_sessions"`
	ConnectedUsers   int `json:"connected_users"`
	ActivePoPs       int `json:"active_pops"`
	ActiveConnectors int `json:"active_connectors"`
}

// RouteDecision determines which site connector should handle traffic for a given request.
type RouteDecision struct {
	ConnectorID string
	PoPID       string
	SiteNetwork string
}

// FindRoute determines the best route for traffic from a user to a destination.
func (m *Manager) FindRoute(userPoPID string, destIP string, connectors []models.SiteConnector) (*RouteDecision, error) {
	for _, conn := range connectors {
		if conn.Status != models.ConnectorStatusOnline {
			continue
		}
		for _, network := range conn.Networks {
			if isIPInNetwork(destIP, network) {
				return &RouteDecision{
					ConnectorID: conn.ID,
					PoPID:       conn.AssignedPoPID,
					SiteNetwork: network,
				}, nil
			}
		}
	}
	return nil, fmt.Errorf("no route found for destination %s", destIP)
}

// isIPInNetwork checks if an IP is within a CIDR network.
func isIPInNetwork(ipStr string, cidr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return network.Contains(ip)
}

// removeFromSlice removes an element from a string slice.
func removeFromSlice(slice []string, item string) []string {
	result := make([]string, 0, len(slice))
	for _, s := range slice {
		if s != item {
			result = append(result, s)
		}
	}
	return result
}
