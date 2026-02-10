// Package pop implements the PoP (Point of Presence) service that runs on each
// PoP server. It manages WireGuard interfaces, handles tunnel routing between
// users and site connectors, and reports metrics to the Control Plane.
package pop

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"runtime"
	"time"

	"github.com/ztna-sovereign/ztna/internal/models"
	"github.com/ztna-sovereign/ztna/internal/wireguard"
)

// Config holds the PoP service configuration.
type Config struct {
	PoPID          string `json:"pop_id"`
	ControlPlaneURL string `json:"control_plane_url"`
	WGInterface    string `json:"wg_interface"`
	WGPort         int    `json:"wg_port"`
	HeartbeatSec   int    `json:"heartbeat_sec"`
}

// Service is the main PoP service.
type Service struct {
	config    Config
	logger    *log.Logger
	publicKey string
	privateKey string
	running   bool
}

// NewService creates a new PoP service.
func NewService(cfg Config, logger *log.Logger) (*Service, error) {
	// Generate or load WireGuard keys
	keyPair, err := wireguard.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate WG keys: %w", err)
	}

	if cfg.WGInterface == "" {
		cfg.WGInterface = "wg0"
	}
	if cfg.WGPort == 0 {
		cfg.WGPort = 51820
	}
	if cfg.HeartbeatSec == 0 {
		cfg.HeartbeatSec = 30
	}

	return &Service{
		config:     cfg,
		logger:     logger,
		publicKey:  keyPair.PublicKey,
		privateKey: keyPair.PrivateKey,
	}, nil
}

// Start begins the PoP service: configures WireGuard and starts the heartbeat loop.
func (s *Service) Start() error {
	s.logger.Printf("Starting PoP service (ID: %s)", s.config.PoPID)

	// Setup WireGuard interface
	if err := s.setupWireGuard(); err != nil {
		s.logger.Printf("WARNING: WireGuard setup failed: %v (continuing without WG)", err)
	}

	// Start heartbeat to Control Plane
	s.running = true
	go s.heartbeatLoop()

	// Start metrics collection
	go s.metricsLoop()

	s.logger.Println("PoP service started successfully")
	return nil
}

// Stop gracefully stops the PoP service.
func (s *Service) Stop() {
	s.running = false
	s.logger.Println("PoP service stopped")
}

// setupWireGuard configures the WireGuard interface on the PoP server.
func (s *Service) setupWireGuard() error {
	if runtime.GOOS != "linux" {
		s.logger.Println("WireGuard kernel module only available on Linux. Skipping interface setup.")
		return nil
	}

	// Create WireGuard interface
	commands := [][]string{
		{"ip", "link", "add", "dev", s.config.WGInterface, "type", "wireguard"},
		{"wg", "set", s.config.WGInterface,
			"listen-port", fmt.Sprintf("%d", s.config.WGPort),
			"private-key", "/dev/stdin"},
		{"ip", "link", "set", "up", "dev", s.config.WGInterface},
	}

	for _, cmd := range commands {
		c := exec.Command(cmd[0], cmd[1:]...)
		if output, err := c.CombinedOutput(); err != nil {
			return fmt.Errorf("command %v failed: %s: %w", cmd, string(output), err)
		}
	}

	s.logger.Printf("WireGuard interface %s configured on port %d", s.config.WGInterface, s.config.WGPort)
	return nil
}

// AddPeer adds a new WireGuard peer (user or connector).
func (s *Service) AddPeer(peer models.WireGuardPeer) error {
	if runtime.GOOS != "linux" {
		s.logger.Printf("Simulating add peer: %s", peer.PublicKey[:16]+"...")
		return nil
	}

	args := []string{"set", s.config.WGInterface,
		"peer", peer.PublicKey,
		"allowed-ips", joinStrings(peer.AllowedIPs, ","),
	}

	if peer.PresharedKey != "" {
		args = append(args, "preshared-key", "/dev/stdin")
	}

	cmd := exec.Command("wg", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("wg set peer failed: %s: %w", string(output), err)
	}

	s.logger.Printf("Peer added: %s", peer.PublicKey[:16]+"...")
	return nil
}

// RemovePeer removes a WireGuard peer.
func (s *Service) RemovePeer(publicKey string) error {
	if runtime.GOOS != "linux" {
		s.logger.Printf("Simulating remove peer: %s", publicKey[:16]+"...")
		return nil
	}

	cmd := exec.Command("wg", "set", s.config.WGInterface, "peer", publicKey, "remove")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("wg remove peer failed: %s: %w", string(output), err)
	}

	s.logger.Printf("Peer removed: %s", publicKey[:16]+"...")
	return nil
}

// heartbeatLoop sends periodic heartbeats to the Control Plane.
func (s *Service) heartbeatLoop() {
	ticker := time.NewTicker(time.Duration(s.config.HeartbeatSec) * time.Second)
	defer ticker.Stop()

	for s.running {
		select {
		case <-ticker.C:
			s.sendHeartbeat()
		}
	}
}

// sendHeartbeat sends a heartbeat with metrics to the Control Plane.
func (s *Service) sendHeartbeat() {
	metrics := s.collectMetrics()

	data, err := json.Marshal(metrics)
	if err != nil {
		s.logger.Printf("Failed to marshal metrics: %v", err)
		return
	}

	url := fmt.Sprintf("%s/api/pop/heartbeat", s.config.ControlPlaneURL)
	resp, err := http.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		s.logger.Printf("Heartbeat failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		s.logger.Printf("Heartbeat returned status %d", resp.StatusCode)
	}
}

// collectMetrics gathers current PoP metrics.
func (s *Service) collectMetrics() models.PoPMetrics {
	// In production, read from WireGuard interface stats
	return models.PoPMetrics{
		PoPID:           s.config.PoPID,
		Timestamp:       time.Now(),
		ActiveTunnels:   0, // Would read from wg show
		ConnectedUsers:  0,
		ConnectedSites:  0,
		BandwidthInMbps: 0,
		BandwidthOutMbps: 0,
		CPUPercent:      0,
		MemoryPercent:   0,
		LatencyMs:       0,
	}
}

// metricsLoop periodically collects and logs metrics.
func (s *Service) metricsLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for s.running {
		select {
		case <-ticker.C:
			metrics := s.collectMetrics()
			s.logger.Printf("Metrics: tunnels=%d users=%d sites=%d",
				metrics.ActiveTunnels, metrics.ConnectedUsers, metrics.ConnectedSites)
		}
	}
}

func joinStrings(ss []string, sep string) string {
	result := ""
	for i, s := range ss {
		if i > 0 {
			result += sep
		}
		result += s
	}
	return result
}
