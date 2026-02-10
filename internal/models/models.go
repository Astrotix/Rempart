// Package models defines all data structures used across the ZTNA platform.
package models

import (
	"time"
)

// User represents an authenticated user in the system.
type User struct {
	ID        string    `json:"id" db:"id"`
	Email     string    `json:"email" db:"email"`
	Name      string    `json:"name" db:"name"`
	Role      UserRole  `json:"role" db:"role"`
	GroupIDs  []string  `json:"group_ids" db:"-"`
	OIDCSub   string    `json:"-" db:"oidc_sub"`
	Disabled  bool      `json:"disabled" db:"disabled"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// UserRole defines the role of a user.
type UserRole string

const (
	RoleAdmin  UserRole = "admin"
	RoleUser   UserRole = "user"
	RoleViewer UserRole = "viewer"
)

// Group represents a group of users for policy assignment.
type Group struct {
	ID        string    `json:"id" db:"id"`
	Name      string    `json:"name" db:"name"`
	UserIDs   []string  `json:"user_ids" db:"-"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// PoP represents a Point of Presence server.
type PoP struct {
	ID         string    `json:"id" db:"id"`
	Name       string    `json:"name" db:"name"`
	Location   string    `json:"location" db:"location"`    // e.g. "Gravelines", "Strasbourg", "Roubaix"
	Provider   string    `json:"provider" db:"provider"`    // e.g. "OVHcloud"
	PublicIP   string    `json:"public_ip" db:"public_ip"`
	WGPort     int       `json:"wg_port" db:"wg_port"`
	PublicKey  string    `json:"public_key" db:"public_key"`
	PrivateKey string    `json:"-" db:"private_key"` // Never exposed via API
	Status     PoPStatus `json:"status" db:"status"`
	LastSeen   time.Time `json:"last_seen" db:"last_seen"`
	CreatedAt  time.Time `json:"created_at" db:"created_at"`
}

// PoPStatus represents the health status of a PoP.
type PoPStatus string

const (
	PoPStatusOnline  PoPStatus = "online"
	PoPStatusOffline PoPStatus = "offline"
	PoPStatusDegraded PoPStatus = "degraded"
)

// SiteConnector represents an on-site connector agent.
type SiteConnector struct {
	ID            string             `json:"id" db:"id"`
	Name          string             `json:"name" db:"name"`
	SiteName      string             `json:"site_name" db:"site_name"`
	Token         string             `json:"token,omitempty" db:"token"` // Activation token, shown once
	TokenUsed     bool               `json:"token_used" db:"token_used"` // Token already consumed
	TokenExpiry   time.Time          `json:"token_expiry" db:"token_expiry"` // Token expiration
	PublicKey     string             `json:"public_key" db:"public_key"`
	PrivateKey    string             `json:"-" db:"private_key"`
	AssignedPoPID string             `json:"assigned_pop_id" db:"assigned_pop_id"`
	Networks      []string           `json:"networks" db:"-"` // Internal networks exposed, e.g. ["10.0.0.0/24", "172.16.0.0/24"]
	Status        ConnectorStatus    `json:"status" db:"status"`
	LastSeen      time.Time          `json:"last_seen" db:"last_seen"`
	CreatedAt     time.Time          `json:"created_at" db:"created_at"`
}

// ConnectorStatus represents the connection state of a site connector.
type ConnectorStatus string

const (
	ConnectorStatusOnline      ConnectorStatus = "online"
	ConnectorStatusOffline     ConnectorStatus = "offline"
	ConnectorStatusRegistering ConnectorStatus = "registering"
)

// ClientAgent represents a registered client agent (user device).
type ClientAgent struct {
	ID         string    `json:"id" db:"id"`
	UserID     string    `json:"user_id" db:"user_id"`
	DeviceName string    `json:"device_name" db:"device_name"`
	OS         string    `json:"os" db:"os"` // "windows", "macos", "linux"
	PublicKey  string    `json:"public_key" db:"public_key"`
	PrivateKey string    `json:"-" db:"private_key"`
	AssignedIP string    `json:"assigned_ip" db:"assigned_ip"` // WireGuard tunnel IP
	LastSeen   time.Time `json:"last_seen" db:"last_seen"`
	CreatedAt  time.Time `json:"created_at" db:"created_at"`
}

// Policy defines a Zero Trust access policy.
type Policy struct {
	ID              string       `json:"id" db:"id"`
	Name            string       `json:"name" db:"name"`
	Description     string       `json:"description" db:"description"`
	Enabled         bool         `json:"enabled" db:"enabled"`
	Priority        int          `json:"priority" db:"priority"` // Lower = higher priority
	SourceType      SourceType   `json:"source_type" db:"source_type"`
	SourceID        string       `json:"source_id" db:"source_id"`   // User ID or Group ID
	DestConnectorID string       `json:"dest_connector_id" db:"dest_connector_id"`
	DestNetworks    []string     `json:"dest_networks" db:"-"`       // Allowed destination CIDRs
	DestPorts       []string     `json:"dest_ports" db:"-"`          // Allowed ports, e.g. ["443", "80", "22"]
	Action          PolicyAction `json:"action" db:"action"`
	CreatedAt       time.Time    `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time    `json:"updated_at" db:"updated_at"`
}

// SourceType defines whether a policy applies to a user or a group.
type SourceType string

const (
	SourceTypeUser  SourceType = "user"
	SourceTypeGroup SourceType = "group"
)

// PolicyAction defines the action a policy takes.
type PolicyAction string

const (
	PolicyActionAllow PolicyAction = "allow"
	PolicyActionDeny  PolicyAction = "deny"
)

// WireGuardPeer represents a WireGuard peer configuration.
type WireGuardPeer struct {
	PublicKey    string   `json:"public_key"`
	AllowedIPs  []string `json:"allowed_ips"`
	Endpoint    string   `json:"endpoint,omitempty"`
	PresharedKey string  `json:"preshared_key,omitempty"`
	KeepAlive   int      `json:"keepalive,omitempty"` // In seconds
}

// WireGuardConfig represents a full WireGuard interface configuration.
type WireGuardConfig struct {
	PrivateKey string          `json:"private_key"`
	Address    string          `json:"address"`    // Tunnel IP, e.g. "10.0.0.1/24"
	ListenPort int             `json:"listen_port,omitempty"`
	DNS        []string        `json:"dns,omitempty"`
	Peers      []WireGuardPeer `json:"peers"`
}

// AuditLog represents an access audit log entry.
type AuditLog struct {
	ID           string    `json:"id" db:"id"`
	Timestamp    time.Time `json:"timestamp" db:"timestamp"`
	UserID       string    `json:"user_id" db:"user_id"`
	UserEmail    string    `json:"user_email" db:"user_email"`
	Action       string    `json:"action" db:"action"`       // "connect", "disconnect", "access_granted", "access_denied"
	PoPID        string    `json:"pop_id" db:"pop_id"`
	ConnectorID  string    `json:"connector_id" db:"connector_id"`
	DestNetwork  string    `json:"dest_network" db:"dest_network"`
	DestPort     string    `json:"dest_port" db:"dest_port"`
	PolicyID     string    `json:"policy_id" db:"policy_id"`
	Result       string    `json:"result" db:"result"`       // "allowed", "denied"
	ClientIP     string    `json:"client_ip" db:"client_ip"`
}

// PoPMetrics represents real-time metrics from a PoP.
type PoPMetrics struct {
	PoPID           string    `json:"pop_id"`
	Timestamp       time.Time `json:"timestamp"`
	ActiveTunnels   int       `json:"active_tunnels"`
	ConnectedUsers  int       `json:"connected_users"`
	ConnectedSites  int       `json:"connected_sites"`
	BandwidthInMbps float64   `json:"bandwidth_in_mbps"`
	BandwidthOutMbps float64  `json:"bandwidth_out_mbps"`
	CPUPercent      float64   `json:"cpu_percent"`
	MemoryPercent   float64   `json:"memory_percent"`
	LatencyMs       float64   `json:"latency_ms"`
}
