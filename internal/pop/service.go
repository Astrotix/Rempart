// Package pop implements the PoP (Point of Presence) service that runs on each
// PoP server. It manages WireGuard interfaces, handles tunnel routing between
// users and site connectors, and reports metrics to the Control Plane.
package pop

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
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
	// Try to load keys from Control Plane first
	var publicKey, privateKey string
	pop, err := loadPoPKeysFromControlPlane(cfg.PoPID, cfg.ControlPlaneURL)
	if err != nil {
		logger.Printf("WARNING: Could not load PoP keys from Control Plane: %v (will generate new keys)", err)
		// Generate new keys if we can't load from Control Plane
		keyPair, err := wireguard.GenerateKeyPair()
		if err != nil {
			return nil, fmt.Errorf("failed to generate WG keys: %w", err)
		}
		publicKey = keyPair.PublicKey
		privateKey = keyPair.PrivateKey
	} else {
		logger.Printf("PoP keys loaded from Control Plane")
		publicKey = pop.PublicKey
		privateKey = pop.PrivateKey
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
		publicKey:  publicKey,
		privateKey: privateKey,
	}, nil
}

// loadPoPKeysFromControlPlane fetches PoP keys from the Control Plane.
func loadPoPKeysFromControlPlane(popID, controlPlaneURL string) (*models.PoP, error) {
	url := fmt.Sprintf("%s/api/pop/%s/keys", controlPlaneURL, popID)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch PoP keys: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Control Plane returned status %d", resp.StatusCode)
	}

	var result struct {
		PublicKey  string `json:"public_key"`
		PrivateKey string `json:"private_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse PoP keys response: %w", err)
	}

	if result.PublicKey == "" || result.PrivateKey == "" {
		return nil, fmt.Errorf("PoP has no keys in database")
	}

	return &models.PoP{
		PublicKey:  result.PublicKey,
		PrivateKey: result.PrivateKey,
	}, nil
}

// Start begins the PoP service: configures WireGuard and starts the heartbeat loop.
func (s *Service) Start() error {
	s.logger.Printf("Starting PoP service (ID: %s)", s.config.PoPID)

	// Enable IP forwarding for routing traffic to connectors
	if err := s.enableForwarding(); err != nil {
		s.logger.Printf("WARNING: Failed to enable IP forwarding: %v", err)
	}

	// Setup WireGuard interface
	if err := s.setupWireGuard(); err != nil {
		s.logger.Printf("WARNING: WireGuard setup failed: %v (continuing without WG)", err)
		// If interface exists, try to configure it anyway
		if runtime.GOOS == "linux" {
			s.logger.Printf("WireGuard interface %s already exists, configuring keys on existing interface", s.config.WGInterface)
			// Configure keys on existing interface
			if err := s.configureWireGuardKeys(); err != nil {
				s.logger.Printf("WARNING: Failed to configure keys on existing interface: %v", err)
			} else {
				s.logger.Printf("Keys configured on existing WireGuard interface")
			}
		}
	}

	// Start heartbeat to Control Plane
	s.running = true
	s.logger.Printf("Starting heartbeat loop (interval: %d seconds)", s.config.HeartbeatSec)
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

	// Step 1: Create WireGuard interface
	cmd := exec.Command("ip", "link", "add", "dev", s.config.WGInterface, "type", "wireguard")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ip link add failed: %s: %w", string(output), err)
	}

	// Step 2: Set private key via stdin (CRITICAL: must pipe key to stdin)
	cmd = exec.Command("wg", "set", s.config.WGInterface,
		"listen-port", fmt.Sprintf("%d", s.config.WGPort),
		"private-key", "/dev/stdin")
	cmd.Stdin = strings.NewReader(s.privateKey)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("wg set failed: %s: %w", string(output), err)
	}

	// Step 3: Assign IP addresses for routing between users and connectors
	// Users get IPs from 100.64.0.0/16, connectors from 100.65.0.0/16
	// PoP acts as the router between both networks
	ipAddresses := []string{
		"100.64.0.1/16", // PoP address in user tunnel network
		"100.65.0.1/16", // PoP address in connector tunnel network
	}
	for _, addr := range ipAddresses {
		cmd = exec.Command("ip", "addr", "add", addr, "dev", s.config.WGInterface)
		if output, err := cmd.CombinedOutput(); err != nil {
			// Ignore "already exists" errors
			if !strings.Contains(string(output), "RTNETLINK answers: File exists") {
				s.logger.Printf("WARNING: ip addr add %s failed: %s", addr, string(output))
			}
		}
	}

	// Step 4: Bring interface up
	cmd = exec.Command("ip", "link", "set", "up", "dev", s.config.WGInterface)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ip link set up failed: %s: %w", string(output), err)
	}

	s.logger.Printf("WireGuard interface %s configured on port %d with IPs 100.64.0.1 + 100.65.0.1", s.config.WGInterface, s.config.WGPort)
	return nil
}

// configureWireGuardKeys configures WireGuard keys on an existing interface.
func (s *Service) configureWireGuardKeys() error {
	if runtime.GOOS != "linux" {
		return nil
	}

	// Set private key via stdin
	cmd := exec.Command("wg", "set", s.config.WGInterface, "private-key", "/dev/stdin")
	cmd.Stdin = strings.NewReader(s.privateKey)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set private key: %s: %w", string(output), err)
	}

	// Set listen port
	cmd = exec.Command("wg", "set", s.config.WGInterface, "listen-port", fmt.Sprintf("%d", s.config.WGPort))
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set listen port: %s: %w", string(output), err)
	}

	// Ensure IP addresses are assigned (critical for routing)
	ipAddresses := []string{
		"100.64.0.1/16", // PoP address in user tunnel network
		"100.65.0.1/16", // PoP address in connector tunnel network
	}
	for _, addr := range ipAddresses {
		cmd = exec.Command("ip", "addr", "add", addr, "dev", s.config.WGInterface)
		if output, err := cmd.CombinedOutput(); err != nil {
			if !strings.Contains(string(output), "RTNETLINK answers: File exists") {
				s.logger.Printf("WARNING: ip addr add %s failed: %s", addr, string(output))
			}
		}
	}

	s.logger.Printf("WireGuard keys and IPs configured on interface %s", s.config.WGInterface)
	return nil
}

// enableForwarding enables IP forwarding so the PoP can route traffic to connectors.
func (s *Service) enableForwarding() error {
	if runtime.GOOS != "linux" {
		s.logger.Println("IP forwarding only configured on Linux")
		return nil
	}

	// Enable IP forwarding
	cmd := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %s: %w", string(output), err)
	}

	// Add iptables FORWARD rules to allow traffic between users and connectors through wg0
	// Allow forwarding from user network to connector network
	forwardRules := [][]string{
		// Users (100.64.0.0/16) → Connectors (100.65.0.0/16) and their internal networks
		{"-A", "FORWARD", "-i", s.config.WGInterface, "-o", s.config.WGInterface, "-j", "ACCEPT"},
		// Allow established/related return traffic
		{"-A", "FORWARD", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
	}

	for _, rule := range forwardRules {
		// Check if rule already exists
		checkArgs := make([]string, len(rule))
		copy(checkArgs, rule)
		checkArgs[0] = "-C" // Change -A to -C for check
		checkCmd := exec.Command("iptables", checkArgs...)
		if checkCmd.Run() == nil {
			s.logger.Printf("iptables rule already exists, skipping")
			continue
		}

		cmd = exec.Command("iptables", rule...)
		if output, err := cmd.CombinedOutput(); err != nil {
			s.logger.Printf("WARNING: iptables rule %v failed: %s", rule, string(output))
		} else {
			s.logger.Printf("iptables rule added: %v", rule)
		}
	}

	// MASQUERADE for traffic going to connector internal networks (e.g., 192.168.x.x)
	// This rewrites the source IP so return traffic comes back through the PoP
	natRules := [][]string{
		{"-t", "nat", "-A", "POSTROUTING", "-o", s.config.WGInterface, "-s", "100.64.0.0/16", "-j", "MASQUERADE"},
	}
	for _, rule := range natRules {
		checkArgs := make([]string, len(rule))
		copy(checkArgs, rule)
		// Replace -A with -C for check
		for i, arg := range checkArgs {
			if arg == "-A" {
				checkArgs[i] = "-C"
				break
			}
		}
		checkCmd := exec.Command("iptables", checkArgs...)
		if checkCmd.Run() == nil {
			continue
		}
		cmd = exec.Command("iptables", rule...)
		if output, err := cmd.CombinedOutput(); err != nil {
			s.logger.Printf("WARNING: iptables NAT rule failed: %s", string(output))
		} else {
			s.logger.Printf("iptables NAT rule added: %v", rule)
		}
	}

	s.logger.Println("IP forwarding and iptables rules configured for PoP routing")
	return nil
}

// AddPeer adds a new WireGuard peer (user or connector).
func (s *Service) AddPeer(peer models.WireGuardPeer) error {
	if runtime.GOOS != "linux" {
		s.logger.Printf("Simulating add peer: %s", peer.PublicKey[:16]+"...")
		return nil
	}

	if len(peer.AllowedIPs) == 0 {
		return fmt.Errorf("peer has no AllowedIPs")
	}

	args := []string{"set", s.config.WGInterface,
		"peer", peer.PublicKey,
		"allowed-ips", joinStrings(peer.AllowedIPs, ","),
	}

	if peer.PresharedKey != "" {
		args = append(args, "preshared-key", "/dev/stdin")
	}

	s.logger.Printf("Adding peer %s with AllowedIPs: %v", peer.PublicKey[:16]+"...", peer.AllowedIPs)
	cmd := exec.Command("wg", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		s.logger.Printf("ERROR: wg set peer failed: %s (error: %v)", string(output), err)
		return fmt.Errorf("wg set peer failed: %s: %w", string(output), err)
	}

	s.logger.Printf("✓ Peer added successfully: %s (AllowedIPs: %v)", peer.PublicKey[:16]+"...", peer.AllowedIPs)
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
	// Send immediate heartbeat on startup
	s.logger.Printf("Sending initial heartbeat to Control Plane...")
	s.sendHeartbeat()

	// Then send periodic heartbeats
	ticker := time.NewTicker(time.Duration(s.config.HeartbeatSec) * time.Second)
	defer ticker.Stop()

	for s.running {
		select {
		case <-ticker.C:
			s.logger.Printf("Sending periodic heartbeat...")
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
	s.logger.Printf("POST %s (PoPID: %s)", url, metrics.PoPID)
	resp, err := http.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		s.logger.Printf("Heartbeat failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		s.logger.Printf("Heartbeat returned status %d", resp.StatusCode)
		bodyBytes, _ := io.ReadAll(resp.Body)
		s.logger.Printf("Response body: %s", string(bodyBytes))
		return
	}

	// Parse response to get peer configuration
	var response struct {
		Status         string                  `json:"status"`
		ConnectorPeers []models.WireGuardPeer `json:"connector_peers"`
		AgentPeers     []models.WireGuardPeer `json:"agent_peers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		s.logger.Printf("Failed to parse heartbeat response: %v", err)
		// Read body for debugging
		bodyBytes, _ := io.ReadAll(resp.Body)
		s.logger.Printf("Response body: %s", string(bodyBytes))
		return
	}

	s.logger.Printf("Heartbeat response: status=%s, %d connector peers, %d agent peers",
		response.Status, len(response.ConnectorPeers), len(response.AgentPeers))

	// Merge all peers (connectors + agents) and update WireGuard
	allPeers := make([]models.WireGuardPeer, 0, len(response.ConnectorPeers)+len(response.AgentPeers))
	allPeers = append(allPeers, response.ConnectorPeers...)
	allPeers = append(allPeers, response.AgentPeers...)
	s.updatePeers(allPeers)
}

// updatePeers updates WireGuard peers to match Control Plane configuration.
func (s *Service) updatePeers(desiredPeers []models.WireGuardPeer) {
	// Get current peers from WireGuard
	currentPeers := make(map[string]bool)
	if runtime.GOOS == "linux" {
		cmd := exec.Command("wg", "show", s.config.WGInterface, "peers")
		output, err := cmd.Output()
		if err == nil {
			for _, line := range bytes.Split(output, []byte("\n")) {
				if len(line) > 0 {
					currentPeers[string(line)] = true
				}
			}
		}
	}

	// Add or update desired peers
	desiredPeerKeys := make(map[string]bool)
	for _, peer := range desiredPeers {
		desiredPeerKeys[peer.PublicKey] = true
		
		// Check if peer already exists
		if !currentPeers[peer.PublicKey] {
			// Add new peer
			if err := s.AddPeer(peer); err != nil {
				s.logger.Printf("Failed to add peer %s: %v", peer.PublicKey[:16]+"...", err)
			} else {
				s.logger.Printf("Peer added: %s (AllowedIPs: %v)", peer.PublicKey[:16]+"...", peer.AllowedIPs)
			}
		} else {
			// Update existing peer (WireGuard allows updating AllowedIPs)
			if err := s.AddPeer(peer); err != nil {
				s.logger.Printf("Failed to update peer %s: %v", peer.PublicKey[:16]+"...", err)
			}
		}
	}

	// Remove peers that are no longer in desired list
	if runtime.GOOS == "linux" {
		for peerKey := range currentPeers {
			if !desiredPeerKeys[peerKey] {
				// Don't remove user peers, only connector peers
				// For now, we'll keep all peers to avoid disconnecting users
				// In production, we'd track which peers are connectors vs users
			}
		}
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
