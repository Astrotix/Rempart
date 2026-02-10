// Package connector implements the site connector service that runs on the
// client's internal network. It establishes an outbound WireGuard tunnel to the
// PoP and exposes internal resources.
package connector

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

// Config holds the site connector configuration.
type Config struct {
	ControlPlaneURL string   `json:"control_plane_url"`
	Token           string   `json:"token"`            // Activation token from Control Plane
	ConnectorID     string   `json:"connector_id"`     // Set after registration
	WGInterface     string   `json:"wg_interface"`
	Networks        []string `json:"networks"`         // Internal networks to expose
	HeartbeatSec    int      `json:"heartbeat_sec"`
}

// Service is the site connector service.
type Service struct {
	config    Config
	logger    *log.Logger
	wgConfig  *models.WireGuardConfig
	running   bool
}

// NewService creates a new site connector service.
func NewService(cfg Config, logger *log.Logger) *Service {
	if cfg.WGInterface == "" {
		cfg.WGInterface = "wg-connector"
	}
	if cfg.HeartbeatSec == 0 {
		cfg.HeartbeatSec = 30
	}

	return &Service{
		config: cfg,
		logger: logger,
	}
}

// Start begins the site connector: registers with Control Plane, configures WireGuard,
// and starts the heartbeat loop.
func (s *Service) Start() error {
	s.logger.Println("Starting site connector...")

	// Step 1: Register with Control Plane
	if err := s.register(); err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}

	// Step 2: Configure WireGuard tunnel
	if err := s.setupWireGuard(); err != nil {
		s.logger.Printf("WARNING: WireGuard setup failed: %v (continuing without WG)", err)
	}

	// Step 3: Enable IP forwarding for internal network access
	if err := s.enableForwarding(); err != nil {
		s.logger.Printf("WARNING: IP forwarding setup failed: %v", err)
	}

	// Step 4: Start heartbeat loop
	s.running = true
	go s.heartbeatLoop()

	s.logger.Println("Site connector started successfully")
	s.logger.Printf("Connector ID: %s", s.config.ConnectorID)
	s.logger.Printf("Exposing networks: %v", s.config.Networks)

	return nil
}

// Stop gracefully stops the site connector.
func (s *Service) Stop() {
	s.running = false

	// Tear down WireGuard interface
	if runtime.GOOS == "linux" {
		exec.Command("ip", "link", "del", "dev", s.config.WGInterface).Run()
	}

	s.logger.Println("Site connector stopped")
}

// register sends the activation token to the Control Plane and receives the WireGuard config.
func (s *Service) register() error {
	// Generate local WireGuard keys
	keyPair, err := wireguard.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate keys: %w", err)
	}

	reqBody := map[string]string{
		"token":      s.config.Token,
		"public_key": keyPair.PublicKey,
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/api/connector/register", s.config.ControlPlaneURL)
	resp, err := http.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("registration request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("registration failed with status %d", resp.StatusCode)
	}

	var result struct {
		ConnectorID string              `json:"connector_id"`
		Config      models.WireGuardConfig `json:"config"`
		ConfigINI   string              `json:"config_ini"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to parse registration response: %w", err)
	}

	s.config.ConnectorID = result.ConnectorID
	s.wgConfig = &result.Config

	s.logger.Printf("Registered with Control Plane as connector %s", s.config.ConnectorID)
	return nil
}

// setupWireGuard configures the outbound WireGuard tunnel to the PoP.
func (s *Service) setupWireGuard() error {
	if s.wgConfig == nil {
		return fmt.Errorf("no WireGuard config received from Control Plane")
	}

	if runtime.GOOS != "linux" {
		s.logger.Println("WireGuard kernel module only available on Linux. Printing config instead:")
		s.logger.Println(wireguard.RenderINI(s.wgConfig))
		return nil
	}

	// Write config to temp file
	configINI := wireguard.RenderINI(s.wgConfig)
	configPath := fmt.Sprintf("/etc/wireguard/%s.conf", s.config.WGInterface)

	if err := writeFile(configPath, configINI); err != nil {
		return fmt.Errorf("failed to write WG config: %w", err)
	}

	// Bring up the interface using wg-quick
	cmd := exec.Command("wg-quick", "up", s.config.WGInterface)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("wg-quick up failed: %s: %w", string(output), err)
	}

	s.logger.Printf("WireGuard tunnel %s established to PoP", s.config.WGInterface)
	return nil
}

// enableForwarding enables IP forwarding so the connector can route traffic to internal networks.
func (s *Service) enableForwarding() error {
	if runtime.GOOS != "linux" {
		s.logger.Println("IP forwarding only configured on Linux")
		return nil
	}

	cmd := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %s: %w", string(output), err)
	}

	// Add iptables rules for NAT/masquerade
	for _, network := range s.config.Networks {
		cmd = exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING",
			"-s", "100.64.0.0/16", "-d", network, "-j", "MASQUERADE")
		if output, err := cmd.CombinedOutput(); err != nil {
			s.logger.Printf("iptables rule failed for %s: %s", network, string(output))
		}
	}

	s.logger.Println("IP forwarding and NAT rules configured")
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

// sendHeartbeat sends a heartbeat to the Control Plane.
func (s *Service) sendHeartbeat() {
	data, _ := json.Marshal(map[string]string{
		"connector_id": s.config.ConnectorID,
		"token":        s.config.Token,
	})

	url := fmt.Sprintf("%s/api/connector/heartbeat", s.config.ControlPlaneURL)
	resp, err := http.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		s.logger.Printf("Heartbeat failed: %v", err)
		return
	}
	defer resp.Body.Close()
}

// writeFile is a helper that writes content to a file.
func writeFile(path, content string) error {
	cmd := exec.Command("tee", path)
	cmd.Stdin = bytes.NewReader([]byte(content))
	return cmd.Run()
}
